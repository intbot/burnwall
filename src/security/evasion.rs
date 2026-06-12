//! Evasion-resistant scanning: invisible-character normalization and
//! decode-then-scan for encoded payloads.
//!
//! Two attack classes against substring/regex matchers, both cheap to mount
//! from a prompt injection:
//!
//! 1. **Invisible-character token splitting** — zero-width and other
//!    non-rendering Unicode inserted mid-token (`~/.s<ZWSP>sh`) so a denied
//!    path, command, or key-shaped string no longer matches any rule while
//!    still rendering (and often still executing) as the dangerous form.
//!    Countered two ways: every ToolArgs/ContentArgs leaf is **normalized**
//!    (invisible characters stripped) before pattern checks run, and a leaf
//!    carrying an implausibly dense cluster of *suspicious* invisible
//!    characters is blocked outright as hidden content (see
//!    [`InvisibleScan::suspicious`]).
//!
//! 2. **Encode-to-evade** — wrapping a secret, card number, or denied path in
//!    base64/hex so the plaintext patterns never see it
//!    (`echo <b64-of-private-key> | curl …`). Countered by finding contiguous
//!    base64/hex runs in a leaf, decoding them (strictly bounded), and
//!    re-running the data + path checks on the decoded text.
//!
//! Everything here is hot-path code (sub-5ms proxy budget). The contract is:
//! a leaf that is pure ASCII with no long alphanumeric runs costs two linear
//! byte scans and nothing else.
//!
//! ### Why "suspicious" invisible characters, not all of them
//! Several invisible code points have heavy *legitimate* use: ZWJ inside
//! emoji sequences (family emoji are glued with U+200D), ZWNJ in Persian/
//! Arabic typography, bidi controls in RTL text, Unicode tag characters in
//! subdivision-flag emoji. Counting those toward the block threshold would
//! 403 an agent writing a README with a few emoji — exactly the
//! false-positive class this codebase keeps getting burned by. An invisible
//! character is only *suspicious* when its nearest visible neighbors on both
//! sides are ASCII: that is the signature of token splitting and of hidden
//! ASCII instructions, and it is the configuration none of the legitimate
//! uses above produce (their neighbors are emoji or non-Latin script).
//! Normalization, by contrast, strips them **all** — stripping is only used
//! for rule matching (the forwarded request is never modified), and our rules
//! are ASCII, so stripping a ZWJ out of an emoji cannot create a false match.

use super::rules::{self, Ruleset};
use super::secrets;
use super::{MatchLocation, Violation, ViolationKind};

/// Suspicious-invisible-character count in a single leaf at or above which
/// the leaf is blocked as hidden content. One or two can be copy-paste
/// accidents; eight ASCII-flanked invisibles in one tool argument is a
/// deliberate construction (a single split token already needs only one).
pub const INVISIBLE_THRESHOLD: usize = 8;

/// Leaves longer than this skip decode-then-scan entirely (CPU bound).
pub const MAX_DECODE_LEAF: usize = 256 * 1024;
/// Total decoded bytes examined per leaf across all candidates.
const MAX_DECODED_BYTES: usize = 256 * 1024;
/// Maximum encoded candidates examined per leaf.
const MAX_CANDIDATES: usize = 16;
/// Minimum contiguous base64-alphabet run worth decoding. Shorter runs are
/// everyday identifiers; 32 base64 chars ≈ 24 decoded bytes, about the
/// smallest payload that can carry a credential.
const MIN_B64_RUN: usize = 32;
/// Minimum contiguous hex run worth decoding (40 = SHA-1/SHA-256 territory;
/// shorter hex runs are ubiquitous in ordinary tool traffic).
const MIN_HEX_RUN: usize = 40;

/// Is `c` an invisible / zero-width / direction-control character usable to
/// hide or split text? Covers zero-width space/non-joiner/joiner, word
/// joiner, BOM/ZWNBSP, the bidi embedding/override/isolate controls, and the
/// Unicode tag block (invisible ASCII clones used for instruction smuggling).
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200D}'   // ZWSP, ZWNJ, ZWJ
        | '\u{2060}'              // word joiner
        | '\u{FEFF}'              // BOM / ZWNBSP
        | '\u{202A}'..='\u{202E}' // bidi embedding/override (LRE..RLO)
        | '\u{2066}'..='\u{2069}' // bidi isolates (LRI..PDI)
        | '\u{E0000}'..='\u{E007F}' // Unicode tag characters
    )
}

/// Result of one pass over a leaf: how many invisible characters it carries
/// in total, and how many sit in the *suspicious* configuration (nearest
/// visible neighbor on each side is ASCII — see module docs). String
/// start/end count as ASCII sides, so a leaf that is *entirely* hidden text
/// (pure tag characters) is maximally suspicious.
#[derive(Debug, Default, Clone, Copy)]
pub struct InvisibleScan {
    pub total: usize,
    pub suspicious: usize,
}

/// Single-pass invisible-character census. Callers should fast-path with
/// `s.is_ascii()` first — an ASCII leaf cannot contain any of these.
pub fn scan_invisible(s: &str) -> InvisibleScan {
    let mut out = InvisibleScan::default();
    // ASCII-ness of the last visible char seen; start-of-string counts ASCII.
    let mut last_visible_ascii = true;
    // Invisible chars seen since the last visible char, awaiting their
    // right-hand neighbor.
    let mut pending = 0usize;
    for c in s.chars() {
        if is_invisible(c) {
            out.total += 1;
            pending += 1;
            continue;
        }
        if pending > 0 {
            if last_visible_ascii && c.is_ascii() {
                out.suspicious += pending;
            }
            pending = 0;
        }
        last_visible_ascii = c.is_ascii();
    }
    // End-of-string counts as an ASCII side.
    if pending > 0 && last_visible_ascii {
        out.suspicious += pending;
    }
    out
}

/// `s` with every invisible character removed — the text the pattern checks
/// actually run against. Never used to modify the forwarded request.
pub fn strip_invisible(s: &str) -> String {
    s.chars().filter(|&c| !is_invisible(c)).collect()
}

// ───────────────────────── decode-then-scan ─────────────────────────

/// Find base64/hex candidate runs in `s`, decode them within strict bounds,
/// and run the data + path checks (secrets, DLP, denied paths, canaries) on
/// the decoded text. Returns the first violation, with the matched-rule label
/// annotated so the block explains the value was *inside encoded content*.
///
/// Bounds: leaves longer than [`MAX_DECODE_LEAF`] are skipped, at most
/// [`MAX_CANDIDATES`] runs are tried, at most [`MAX_DECODED_BYTES`] decoded
/// bytes are examined in total, and at most one extra decode round runs when
/// a decoded text is itself a single encoded run (base64-of-base64).
/// Non-UTF-8 decode output (binary) is skipped — our patterns are text.
pub fn scan_encoded(
    s: &str,
    rules: &Ruleset,
    location: MatchLocation,
    tool: Option<&str>,
) -> Option<Violation> {
    if s.len() > MAX_DECODE_LEAF {
        return None;
    }
    let mut budget = MAX_DECODED_BYTES;
    for run in candidate_runs(s).take(MAX_CANDIDATES) {
        if budget == 0 {
            break;
        }
        for text in decode_run(run, &mut budget) {
            if let Some(v) = check_decoded(&text, rules, location, tool) {
                return Some(v);
            }
            // One bounded second round: a decoded text that is itself a
            // single encoded run (base64-of-base64, hex-in-base64).
            let inner = text.trim();
            if inner.len() >= MIN_B64_RUN
                && inner.bytes().all(is_b64_byte)
                && inner.len() <= s.len()
            {
                for text2 in decode_run(inner, &mut budget) {
                    if let Some(v) = check_decoded(&text2, rules, location, tool) {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Cheap pre-check used by the scanner's fast path: does `s` contain any
/// contiguous run of base64-alphabet bytes long enough to be a candidate?
/// One linear byte scan, no allocation.
pub fn has_encoded_run(s: &str) -> bool {
    let mut run = 0usize;
    for &b in s.as_bytes() {
        if is_b64_byte(b) {
            run += 1;
            if run >= MIN_B64_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Run the decoded-content checks: denied paths (respecting `allow_paths`),
/// canaries, then secrets and DLP under their existing toggles. The matched
/// label carries an "(inside encoded content)" note so the block message is
/// self-explaining.
fn check_decoded(
    text: &str,
    rules: &Ruleset,
    location: MatchLocation,
    tool: Option<&str>,
) -> Option<Violation> {
    // Decoded text can use the same invisible-char splitting as plaintext;
    // normalize before matching (cheap: only non-ASCII text pays).
    let normalized;
    let text: &str = if !text.is_ascii() && scan_invisible(text).total > 0 {
        normalized = strip_invisible(text);
        &normalized
    } else {
        text
    };
    const NOTE: &str = " (inside encoded content)";
    let path_allowed = rules
        .allow_paths
        .iter()
        .any(|allow| rules::path_matches(text, allow));
    if !path_allowed {
        for rule in &rules.deny_paths {
            if rules::path_matches(text, rule) {
                return Some(
                    Violation::new(ViolationKind::Path, format!("{rule}{NOTE}"), location)
                        .with_tool(tool),
                );
            }
        }
    }
    for canary in &rules.canaries {
        if canary.len() >= rules::MIN_CANARY_LEN && text.contains(canary.as_str()) {
            return Some(
                Violation::new(
                    ViolationKind::Canary,
                    format!("planted canary credential{NOTE}"),
                    location,
                )
                .with_tool(tool)
                .with_preview(secrets::mask_match(canary)),
            );
        }
    }
    if rules.detect_secrets {
        if let Some((name, preview)) = secrets::first_match_masked(text) {
            return Some(
                Violation::new(ViolationKind::Secret, format!("{name}{NOTE}"), location)
                    .with_tool(tool)
                    .with_preview(preview),
            );
        }
    }
    if rules.detect_egress {
        if let Some((name, preview)) = super::dlp::first_match_masked(text) {
            return Some(
                Violation::new(ViolationKind::Dlp, format!("{name}{NOTE}"), location)
                    .with_tool(tool)
                    .with_preview(preview),
            );
        }
    }
    None
}

/// Iterator over contiguous base64-alphabet runs of candidate length.
fn candidate_runs(s: &str) -> impl Iterator<Item = &str> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            // Skip to the next alphabet byte.
            while i < bytes.len() && !is_b64_byte(bytes[i]) {
                i += 1;
            }
            let start = i;
            while i < bytes.len() && is_b64_byte(bytes[i]) {
                i += 1;
            }
            if i - start >= MIN_B64_RUN {
                // Alphabet bytes are ASCII, so the slice is on char bounds.
                return Some(&s[start..i]);
            }
        }
        None
    })
}

fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// Decode one candidate run as hex and/or base64 (a hex run is also a valid
/// base64-alphabet run, so both interpretations may yield text). Deducts
/// every decoded byte from `budget`; output is truncated to what the budget
/// allows. Non-UTF-8 results are dropped.
fn decode_run(run: &str, budget: &mut usize) -> Vec<String> {
    let mut out = Vec::with_capacity(2);
    if run.len() >= MIN_HEX_RUN && run.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some(text) = decode_hex(run, budget) {
            out.push(text);
        }
    }
    if run.len() >= MIN_B64_RUN {
        if let Some(text) = decode_b64(run, budget) {
            // A run of pure hex digits usually decodes to the same garbage
            // both ways; only keep a distinct second reading.
            if out.first().map(String::as_str) != Some(text.as_str()) {
                out.push(text);
            }
        }
    }
    out
}

/// Base64 decode (standard and URL-safe alphabets, padding optional, stops at
/// the first `=`). Emits at most `*budget` bytes and deducts what it emitted.
/// Returns `None` for non-alphabet input or non-UTF-8 output.
fn decode_b64(run: &str, budget: &mut usize) -> Option<String> {
    let max_out = *budget;
    if max_out == 0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity((run.len() / 4 * 3).min(max_out));
    let mut quad = [0u8; 4];
    let mut n = 0usize;
    'outer: for &b in run.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        quad[n] = v;
        n += 1;
        if n == 4 {
            for byte in [
                (quad[0] << 2) | (quad[1] >> 4),
                (quad[1] << 4) | (quad[2] >> 2),
                (quad[2] << 6) | quad[3],
            ] {
                if out.len() >= max_out {
                    break 'outer;
                }
                out.push(byte);
            }
            n = 0;
        }
    }
    // Unpadded tail: 2 leftover chars → 1 byte, 3 → 2 bytes, 1 → dropped.
    if n >= 2 && out.len() < max_out {
        out.push((quad[0] << 2) | (quad[1] >> 4));
    }
    if n == 3 && out.len() < max_out {
        out.push((quad[1] << 4) | (quad[2] >> 2));
    }
    *budget = budget.saturating_sub(out.len());
    String::from_utf8(out).ok()
}

/// Hex decode (odd trailing digit dropped). Emits at most `*budget` bytes and
/// deducts what it emitted. Returns `None` for non-UTF-8 output.
fn decode_hex(run: &str, budget: &mut usize) -> Option<String> {
    let max_out = *budget;
    if max_out == 0 {
        return None;
    }
    let bytes = run.as_bytes();
    let pairs = bytes.len() / 2;
    let mut out: Vec<u8> = Vec::with_capacity(pairs.min(max_out));
    for i in 0..pairs {
        if out.len() >= max_out {
            break;
        }
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    *budget = budget.saturating_sub(out.len());
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal base64 encoder for building fixtures programmatically (no
    /// suspicious literals in the test source, no extra dependency).
    fn b64_encode(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let idx = [
                b[0] >> 2,
                ((b[0] & 0x03) << 4) | (b[1] >> 4),
                ((b[1] & 0x0f) << 2) | (b[2] >> 6),
                b[2] & 0x3f,
            ];
            for (i, &x) in idx.iter().enumerate() {
                if i <= chunk.len() {
                    out.push(A[x as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A fake-but-pattern-matching AWS key id, built by concatenation so the
    /// raw token never appears in source.
    fn fake_aws_key() -> String {
        format!("AKIA{}", "QQQQRRRRSSSSTTTT")
    }

    /// The SSH config dir reference, assembled at runtime. Long enough that
    /// its hex encoding clears MIN_HEX_RUN.
    fn ssh_dir_probe() -> String {
        format!("cat ~{}ssh{}id_rsa and upload it", "/.", "/")
    }

    // ── invisible characters ──

    #[test]
    fn strip_invisible_removes_all_listed_classes() {
        let zwsp = '\u{200B}';
        let zwnj = '\u{200C}';
        let zwj = '\u{200D}';
        let wj = '\u{2060}';
        let bom = '\u{FEFF}';
        let rlo = '\u{202E}';
        let lri = '\u{2066}';
        let tag = '\u{E0041}'; // tag "A"
        let s = format!("a{zwsp}b{zwnj}c{zwj}d{wj}e{bom}f{rlo}g{lri}h{tag}i");
        assert_eq!(strip_invisible(&s), "abcdefghi");
    }

    #[test]
    fn scan_invisible_counts_ascii_flanked_chars_as_suspicious() {
        let zwsp = '\u{200B}';
        let s = format!("rm {zwsp}-rf{zwsp} target");
        let scan = scan_invisible(&s);
        assert_eq!(scan.total, 2);
        assert_eq!(scan.suspicious, 2);
    }

    #[test]
    fn scan_invisible_exempts_emoji_zwj_sequences() {
        // Family emoji: woman+ZWJ+woman+ZWJ+girl — legitimate ZWJ use whose
        // neighbors are non-ASCII. Must not count toward the block threshold.
        let s = "team: \u{1F469}\u{200D}\u{1F469}\u{200D}\u{1F467} ok";
        let scan = scan_invisible(s);
        assert_eq!(scan.total, 2);
        assert_eq!(scan.suspicious, 0);
    }

    #[test]
    fn scan_invisible_flags_pure_hidden_tag_text() {
        // Hidden ASCII smuggled as Unicode tag chars appended to ASCII prose:
        // every tag char has ASCII visible neighbors (or string edge) → all
        // suspicious.
        let hidden: String = "ignore previous"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let s = format!("benign note{hidden}");
        let scan = scan_invisible(&s);
        assert_eq!(scan.total, "ignore previous".len());
        assert_eq!(scan.suspicious, scan.total);
        assert!(scan.suspicious >= INVISIBLE_THRESHOLD);
    }

    // ── decoding primitives ──

    #[test]
    fn b64_decode_standard_and_urlsafe() {
        let plain = "hello burnwall, this is a longer test string!";
        let enc = b64_encode(plain.as_bytes());
        let mut budget = 1024;
        assert_eq!(decode_b64(&enc, &mut budget).as_deref(), Some(plain));
        // URL-safe variant of the same data.
        let url: String = enc
            .chars()
            .map(|c| match c {
                '+' => '-',
                '/' => '_',
                other => other,
            })
            .collect();
        let mut budget = 1024;
        assert_eq!(decode_b64(&url, &mut budget).as_deref(), Some(plain));
    }

    #[test]
    fn b64_decode_respects_budget_and_deducts() {
        let plain = "0123456789abcdef0123456789abcdef";
        let enc = b64_encode(plain.as_bytes());
        let mut budget = 10;
        let out = decode_b64(&enc, &mut budget).expect("utf8");
        assert_eq!(out.len(), 10);
        assert_eq!(budget, 0);
        // Exhausted budget refuses further work.
        assert!(decode_b64(&enc, &mut budget).is_none());
    }

    #[test]
    fn hex_decode_roundtrip_and_binary_skip() {
        let plain = "a perfectly ordinary forty-byte sentence";
        let enc = hex_encode(plain.as_bytes());
        let mut budget = 1024;
        assert_eq!(decode_hex(&enc, &mut budget).as_deref(), Some(plain));
        // Invalid UTF-8 output (0xFF bytes) is dropped.
        let mut budget = 1024;
        assert!(decode_hex(&"ff".repeat(30), &mut budget).is_none());
    }

    // ── scan_encoded bounds + behavior ──

    fn rules() -> Ruleset {
        Ruleset::default()
    }

    #[test]
    fn encoded_secret_is_found_in_base64() {
        let payload = format!("export K={}", fake_aws_key());
        let leaf = format!("echo {} | proc", b64_encode(payload.as_bytes()));
        let v = scan_encoded(&leaf, &rules(), MatchLocation::ToolCall, Some("bash"))
            .expect("secret inside base64 must be found");
        assert_eq!(v.kind, ViolationKind::Secret);
        assert!(
            v.matched.contains("inside encoded content"),
            "{}",
            v.matched
        );
    }

    #[test]
    fn encoded_denied_path_is_found_in_hex() {
        let leaf = hex_encode(ssh_dir_probe().as_bytes());
        let v = scan_encoded(&leaf, &rules(), MatchLocation::ToolCall, None)
            .expect("denied path inside hex must be found");
        assert_eq!(v.kind, ViolationKind::Path);
        assert!(
            v.matched.contains("inside encoded content"),
            "{}",
            v.matched
        );
    }

    #[test]
    fn double_encoded_secret_is_found_one_extra_round() {
        // Long enough that the inner encoding also clears MIN_B64_RUN.
        let payload = format!("aws credentials export: {}", fake_aws_key());
        let once = b64_encode(payload.as_bytes());
        assert!(once.len() >= MIN_B64_RUN);
        let twice = b64_encode(once.as_bytes());
        let v = scan_encoded(&twice, &rules(), MatchLocation::ToolCall, None)
            .expect("base64-of-base64 must be found via the second round");
        assert_eq!(v.kind, ViolationKind::Secret);
    }

    #[test]
    fn oversized_leaf_is_skipped() {
        let payload = format!("{} {}", "x".repeat(MAX_DECODE_LEAF), fake_aws_key());
        let leaf = b64_encode(payload.as_bytes());
        assert!(leaf.len() > MAX_DECODE_LEAF);
        assert!(scan_encoded(&leaf, &rules(), MatchLocation::ToolCall, None).is_none());
    }

    #[test]
    fn candidate_cap_bounds_work_per_leaf() {
        // MAX_CANDIDATES benign runs first, then the hot one: must be skipped.
        let benign = b64_encode(b"just an ordinary harmless filler string");
        let hot = b64_encode(format!("export K={}", fake_aws_key()).as_bytes());
        assert!(hot.len() >= MIN_B64_RUN);
        let mut leaf = String::new();
        for i in 0..MAX_CANDIDATES {
            leaf.push_str(&format!("{benign} #{i} "));
        }
        leaf.push_str(&hot);
        assert!(scan_encoded(&leaf, &rules(), MatchLocation::ToolCall, None).is_none());
        // Under the cap, the same hot run is found.
        let small = format!("{benign} {hot}");
        assert!(scan_encoded(&small, &rules(), MatchLocation::ToolCall, None).is_some());
    }

    #[test]
    fn ordinary_identifiers_do_not_false_positive() {
        // Long-but-benign runs: a git SHA, a lock-file hash, a long token of
        // word chars. None should produce a violation under default rules.
        for leaf in [
            "pinned to 3f786850e387550fdab836ed7e6dc881de23001b in the lockfile",
            "integrity sha512-0123456789abcdefABCDEF0123456789abcdefABCDEF012345",
            "the_quick_brown_fox_jumped_over_the_lazy_dog_indeed",
        ] {
            assert!(
                scan_encoded(leaf, &rules(), MatchLocation::ToolCall, None).is_none(),
                "false positive on: {leaf}"
            );
        }
    }

    #[test]
    fn has_encoded_run_fast_path() {
        assert!(!has_encoded_run("ls -la ./src"));
        assert!(!has_encoded_run("short b64 QUtJQQ== run"));
        assert!(has_encoded_run(&b64_encode(
            b"a payload long enough to clear the threshold"
        )));
    }
}
