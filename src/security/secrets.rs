//! Secret pattern detection.
//!
//! Each pattern is a distinctive prefix + length signature with a low false-
//! positive rate. We err on the side of recall — better to occasionally
//! flag a non-secret than to let a real credential leak. The matched value
//! is reported by name; the raw secret is never logged.
//!
//! ### Built-in vs pack-authored patterns
//! Built-in patterns are compile-time-correct constants ([`PATTERNS`]).
//! Rule packs (v0.6) may contribute additional patterns at runtime via
//! [`SecretPattern::compile`], which **safe-compiles** an untrusted pattern
//! with bounded program/DFA size (invariant I5) so a hostile regex fails to
//! compile rather than exhausting memory. Rust's `regex` is linear-time and
//! has no backreferences/lookaround, so catastrophic backtracking (ReDoS) is
//! not reachable — the size caps only bound memory. `name` is a
//! `Cow<'static, str>`: borrowed for built-ins, owned for pack patterns.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// Compiled-program size cap for a pack-authored pattern (bytes).
const MAX_REGEX_SIZE: usize = 64 * 1024;
/// Lazy-DFA size cap for a pack-authored pattern (bytes).
const MAX_REGEX_DFA_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: Cow<'static, str>,
    pub regex: Regex,
}

impl SecretPattern {
    /// A built-in (trusted, compile-time-correct) pattern.
    fn builtin(name: &'static str, pattern: &'static str) -> SecretPattern {
        SecretPattern {
            name: Cow::Borrowed(name),
            regex: Regex::new(pattern).expect("built-in secret pattern must compile"),
        }
    }

    /// Safe-compile an untrusted (rule-pack) pattern. Returns `None` if the
    /// pattern is invalid or its compiled size exceeds the cap — the caller
    /// skips it (fail-open). The name is owned (community names aren't
    /// `'static`).
    pub fn compile(name: &str, pattern: &str) -> Option<SecretPattern> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_SIZE)
            .dfa_size_limit(MAX_REGEX_DFA_SIZE)
            .build()
            .ok()?;
        Some(SecretPattern {
            name: Cow::Owned(name.to_string()),
            regex,
        })
    }
}

/// Built-in secret patterns. Compiled once on first use via `LazyLock`.
pub static PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern::builtin("AWS access key ID", r"\bAKIA[0-9A-Z]{16}\b"),
        // STS temporary access keys (S-M12).
        SecretPattern::builtin("AWS temporary access key ID", r"\bASIA[0-9A-Z]{16}\b"),
        SecretPattern::builtin("private key header", r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
        // ghp_ (classic), gho_/ghu_/ghs_/ghr_ (OAuth/user/server/refresh) — one
        // pattern covers all variants (S-M12).
        SecretPattern::builtin("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        // Modern OpenAI project keys use `sk-proj-…` with hyphens/underscores,
        // which the 48-alnum-run pattern misses (S-M12).
        SecretPattern::builtin("OpenAI project key", r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        SecretPattern::builtin("OpenAI API key", r"\bsk-[A-Za-z0-9]{48}\b"),
        SecretPattern::builtin("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{36,}\b"),
        SecretPattern::builtin(
            "GitLab personal access token",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        ),
        SecretPattern::builtin("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        // Added v0.6. All keep a distinctive prefix + length so the false-
        // positive rate stays low; deliberately NO generic-entropy or JWT
        // pattern (those over-block legitimate traffic at the always-block tier).
        SecretPattern::builtin("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        SecretPattern::builtin(
            "Google OAuth client secret",
            r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
        ),
        SecretPattern::builtin("Stripe secret key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        SecretPattern::builtin(
            "GitHub fine-grained PAT",
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
        ),
        SecretPattern::builtin("npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        SecretPattern::builtin(
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        ),
    ]
});

/// Well-known documentation / example credentials that vendors publish for
/// tutorials and that constantly appear in READMEs, fixtures, and SDK docs.
/// Flagging them was a top false-positive: an agent reading a file containing
/// AWS's canonical `AKIAIOSFODNN7EXAMPLE` would 403 every later request in the
/// session (S-C3). A match whose text is exactly one of these is not a secret.
const EXAMPLE_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE", // AWS docs access key id
    "ASIAIOSFODNN7EXAMPLE", // AWS docs STS key id
];

fn is_example_secret(matched: &str) -> bool {
    EXAMPLE_SECRETS
        .iter()
        .any(|e| e.eq_ignore_ascii_case(matched))
}

/// Name of the first **built-in** pattern that matches `value` with a match
/// that is not a known documentation/example credential, or `None`.
pub fn first_match(value: &str) -> Option<&'static str> {
    for p in PATTERNS.iter() {
        // Any non-example match counts; scan all matches so a real key elsewhere
        // in the leaf isn't masked by a leading example.
        if p.regex
            .find_iter(value)
            .any(|m| !is_example_secret(m.as_str()))
        {
            return match &p.name {
                Cow::Borrowed(s) => Some(*s),
                Cow::Owned(_) => unreachable!("built-in patterns carry borrowed names"),
            };
        }
    }
    None
}

/// Name of the first pattern in `patterns` that matches `value`, or `None`.
/// Used for pack-contributed patterns (owned names).
pub fn first_match_in<'a>(value: &str, patterns: &'a [SecretPattern]) -> Option<&'a str> {
    patterns
        .iter()
        .find(|p| p.regex.is_match(value))
        .map(|p| p.name.as_ref())
}

/// Like [`first_match`] but also returns a **masked, recognisable preview** of
/// the matched value (e.g. `AKIA…LKEY`) for the block message. The raw value is
/// never returned, echoed, or logged — only this masked form, and only to the
/// user's own terminal.
pub fn first_match_masked(value: &str) -> Option<(&'static str, String)> {
    for p in PATTERNS.iter() {
        if let Some(m) = p
            .regex
            .find_iter(value)
            .find(|m| !is_example_secret(m.as_str()))
        {
            let name = match &p.name {
                Cow::Borrowed(s) => *s,
                Cow::Owned(_) => unreachable!("built-in patterns carry borrowed names"),
            };
            return Some((name, mask_match(m.as_str())));
        }
    }
    None
}

/// The provider a recognized built-in credential belongs to, by pattern name —
/// `"openai"`, `"anthropic"`, or `"google"`. `None` for credentials with no
/// LLM-provider destination (AWS, GitHub, Stripe, …), which can't be
/// *misdirected* to a different LLM endpoint and so are out of scope for the
/// credential-misdirection check (feature #7). Keyed on the exact built-in
/// pattern name from [`PATTERNS`]; pack-contributed (owned-name) patterns are
/// not mapped (they carry no provider semantics).
pub fn provider_for_secret_name(name: &str) -> Option<&'static str> {
    match name {
        "OpenAI project key" | "OpenAI API key" => Some("openai"),
        "Anthropic API key" => Some("anthropic"),
        "Google API key" => Some("google"),
        _ => None,
    }
}

/// Like [`first_match_masked`] but only considers credentials that map to an
/// LLM provider via [`provider_for_secret_name`], returning that provider
/// alongside the pattern name and masked preview. Used by the
/// credential-misdirection check (feature #7): a provider-tagged key whose
/// provider differs from the request's destination is being sent to the wrong
/// endpoint. Documentation/example credentials are exempt, as everywhere.
pub fn first_provider_match_masked(value: &str) -> Option<(&'static str, &'static str, String)> {
    for p in PATTERNS.iter() {
        let name = match &p.name {
            Cow::Borrowed(s) => *s,
            Cow::Owned(_) => continue,
        };
        let Some(provider) = provider_for_secret_name(name) else {
            continue;
        };
        if let Some(m) = p
            .regex
            .find_iter(value)
            .find(|m| !is_example_secret(m.as_str()))
        {
            return Some((provider, name, mask_match(m.as_str())));
        }
    }
    None
}

/// [`first_match_in`] with a masked preview of the matched value (pack patterns).
pub fn first_match_in_masked<'a>(
    value: &str,
    patterns: &'a [SecretPattern],
) -> Option<(&'a str, String)> {
    for p in patterns {
        if let Some(m) = p.regex.find(value) {
            return Some((p.name.as_ref(), mask_match(m.as_str())));
        }
    }
    None
}

/// Mask a matched secret/PII value for display: keep a short recognisable head
/// and tail, redact the middle. The reveal is capped at 4 chars per end and at
/// a quarter of the value's length, so a short token shows very little (a 12-char
/// value reveals at most 3+3). Used only in the terminal block message — never
/// persisted, consistent with the never-log-secrets principle.
pub fn mask_match(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let reveal = (n / 4).min(4);
    if reveal == 0 {
        return "•".repeat(n.clamp(1, 8));
    }
    let head: String = chars[..reveal].iter().collect();
    let tail: String = chars[n - reveal..].iter().collect();
    format!("{head}…{tail}")
}
