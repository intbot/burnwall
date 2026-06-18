//! Catastrophic-command detection (v0.9.8).
//!
//! The literal deny-list (`rm -rf /`, `chmod 777`) only catches the exact
//! string. Real incidents — the Replit prod-data wipe, the Claude Code `rm -rf`
//! that cleared a machine — slipped past literal/approval checks because the
//! *expanded* or reordered form didn't match. This module detects the
//! **shape** of a few truly destructive operations regardless of flag order,
//! spacing, or target expansion. It is deliberately narrow (data-loss-grade
//! only) so it can be on by default without nagging.

/// First catastrophic pattern matched in `s`, or `None`. Returns the technique
/// label, safe to log.
pub fn first_match(s: &str) -> Option<&'static str> {
    let lower = s.to_ascii_lowercase();

    // Recursive force-delete is judged PER shell command segment (see
    // `command_segments`): a `$(...)`, a bare `/`, or a glob belonging to a
    // *different* command in a compound line must not combine with an unrelated
    // `rm` and trip a false catastrophic match (FP-review 2026-06-18:
    // `PID=$(...); rm -rf ./scoped` and `echo "a / b"; grep "rm -rf" src/`).
    if command_segments(&lower).any(segment_is_catastrophic_rm) {
        return Some("recursive force delete");
    }
    // Disk/filesystem destruction and destructive SQL are single-command shapes;
    // the collapsed whole string is fine for them.
    let collapsed = collapse_ws(&lower);
    if is_disk_destroyer(&collapsed) {
        return Some("disk/filesystem destruction");
    }
    if is_destructive_sql(&collapsed) {
        return Some("destructive SQL (drop/truncate)");
    }
    None
}

/// Collapse runs of whitespace to single spaces so spacing can't evade matching.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split a command line into individual command segments on shell control
/// operators — `;`, `&&`/`&`, pipelines (`|`/`||`), and newlines — so each
/// command is judged on its own. A dangerous indicator (a `$(...)`, a bare `/`,
/// a `*`) belonging to one command must not combine with an `rm` in a
/// *different* command and produce a false catastrophic match. A `$(...)`
/// substitution may itself contain these operators; splitting through it is
/// harmless because the actual `rm` invocation lives in its own segment, which
/// stays clean. Newlines are split here (not pre-collapsed) so a multi-line
/// script's commands don't merge into one giant segment.
fn command_segments(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split([';', '&', '|', '\n', '\r'])
        .filter(|seg| !seg.trim().is_empty())
}

/// One shell command segment that is a catastrophic recursive force-delete:
/// invokes `rm` with BOTH recursive AND force (`-rf`, `-fr`, `-r -f`,
/// `--recursive --force`, `-Rf`, …) AND either disables the safety rail
/// (`--no-preserve-root`), carries an expandable target (`$(...)`, backticks),
/// or aims at a broad target token (root, home, cwd, globs) — all evaluated
/// WITHIN this segment so a sibling command can't contaminate the verdict. A
/// scoped target like `./build`, `node_modules`, or an explicit project path is
/// left alone.
fn segment_is_catastrophic_rm(raw_segment: &str) -> bool {
    let seg = collapse_ws(raw_segment);
    let seg = seg.as_str();
    if !has_token(seg, "rm") {
        return false;
    }
    let recursive = contains_flag(seg, 'r') || seg.contains("--recursive");
    let force = contains_flag(seg, 'f') || seg.contains("--force");
    if !(recursive && force) {
        return false;
    }
    if seg.contains("--no-preserve-root") || seg.contains("$(") || seg.contains('`') {
        return true;
    }
    const BROAD: &[&str] = &["/", "/*", "~", "~/", ".", "./*", "*", "$home", "$home/"];
    tokens(seg).any(|t| BROAD.contains(&t))
}

/// Writing over a raw disk / making a filesystem — irreversible.
fn is_disk_destroyer(lower: &str) -> bool {
    // `mkfs`, `mkfs.ext4`, `mkfs.xfs`, … (token prefix).
    tokens(lower).any(|t| t.starts_with("mkfs"))
        || (has_token(lower, "dd") && lower.contains("of=/dev/"))
        || lower.contains("> /dev/sd")
        || lower.contains(">/dev/sd")
        || lower.contains("> /dev/nvme")
        || lower.contains(">/dev/nvme")
}

/// Destructive SQL: dropping or truncating. (Unscoped DELETE is intentionally
/// NOT flagged — too many legitimate uses; DROP/TRUNCATE are the catastrophic,
/// low-false-positive cases.)
fn is_destructive_sql(lower: &str) -> bool {
    lower.contains("drop table")
        || lower.contains("drop database")
        || lower.contains("drop schema")
        || lower.contains("truncate table")
        || lower.contains("truncate ")
}

/// `flag` present as a short flag in any `-…` cluster (so `f` matches `-rf`,
/// `-fr`, `-Rf`), without matching a bare word.
fn contains_flag(lower: &str, flag: char) -> bool {
    for tok in lower.split_whitespace() {
        if tok.starts_with('-') && !tok.starts_with("--") && tok[1..].contains(flag) {
            return true;
        }
    }
    false
}

/// Split a command line into tokens on whitespace, shell separators, and JSON
/// punctuation. The JSON delimiters (`"' {}:,`) matter because tool-call
/// arguments often arrive as a JSON-encoded string, so the command appears as
/// `{"command":"rm -rf /"}` — without splitting on the quote/brace the `rm`
/// token would be `{"command":"rm` and the recursive-delete check would miss
/// it (the gap exposed when the literal `rm -rf /` deny rule was dropped, S-C2).
/// We deliberately do NOT split on `/` so path targets stay intact (`./build`
/// must remain one token so a scoped delete isn't flagged).
fn tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '|' | '&' | '"' | '\'' | '{' | '}' | ':' | ',' | '(' | ')'
                )
        })
        .filter(|t| !t.is_empty())
}

/// `word` appears as a standalone command token (bordered by start/space and
/// space/end), so `rm` doesn't match `charm` and `dd` doesn't match `add`.
fn has_token(lower: &str, word: &str) -> bool {
    tokens(lower).any(|t| t == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_reordered_and_spaced_rm() {
        assert!(first_match("rm -rf /").is_some());
        assert!(first_match("rm -fr ~").is_some());
        assert!(first_match("rm   -rf   /").is_some()); // extra spaces
        assert!(first_match("rm --recursive --force ~/").is_some());
        assert!(first_match("rm -Rf /*").is_some());
        assert!(first_match("sudo rm -rf --no-preserve-root /").is_some());
        assert!(first_match("rm -rf $(cat list)").is_some()); // command-substituted target
    }

    #[test]
    fn does_not_flag_scoped_rm() {
        assert_eq!(first_match("rm -rf ./build"), None);
        assert_eq!(first_match("rm -rf node_modules"), None);
        assert_eq!(first_match("rm file.txt"), None); // not recursive+force
        assert_eq!(first_match("rm -r logs/old"), None); // recursive but not force
    }

    #[test]
    fn does_not_flag_rm_when_danger_is_in_a_sibling_command() {
        // FP-review 2026-06-18 — real dogfooding repros. The `rm` is judged per
        // command segment, so a `$(...)` or bare `/` from ANOTHER command in the
        // line can't make a scoped delete look catastrophic.
        //
        // (1) A scoped `rm -rf` after an unrelated `$()` (a PID capture). The
        //     subshell belongs to `netstat`, not the rm; the rm target is an
        //     explicit project artifact dir.
        let scoped_rm_after_subshell = "PID=$(netstat -ano | grep ':3210' | awk '{print $NF}')\n\
             rm -rf \"C:/Code/ng2-pdfjs-viewer/.playwright-mcp\"";
        assert_eq!(first_match(scoped_rm_after_subshell), None);

        // (2) Searching source FOR the literal: `rm` lives in a grep pattern, and
        //     a bare `/` lives in an unrelated echo on another line. Neither
        //     segment is a delete. This exact shape blocked the session fixing it.
        let grep_for_the_pattern = "echo \"=== destructive_blocked / rules ===\"\n\
             grep -rn \"rm -rf|disk wipe\" src/security/ | head";
        assert_eq!(first_match(grep_for_the_pattern), None);
    }

    #[test]
    fn still_flags_rm_with_danger_in_its_own_segment() {
        // The per-segment fix must NOT weaken real catches: danger in the rm's
        // own segment still trips, after a benign sibling command.
        assert!(first_match("ls -la; rm -rf /").is_some());
        assert!(first_match("echo hi && rm -rf $(cat targets)").is_some());
        assert!(first_match("rm -rf ~ | tee log").is_some());
        assert!(first_match("cd /tmp && rm -rf *").is_some());
    }

    #[test]
    fn flags_disk_destruction() {
        assert!(first_match("dd if=/dev/zero of=/dev/sda bs=1M").is_some());
        assert!(first_match("mkfs.ext4 /dev/sdb1").is_some());
        assert!(first_match("echo x > /dev/sda").is_some());
    }

    #[test]
    fn flags_destructive_sql() {
        assert!(first_match("DROP TABLE users").is_some());
        assert!(first_match("drop database production").is_some());
        assert!(first_match("TRUNCATE TABLE orders").is_some());
    }

    #[test]
    fn does_not_flag_benign() {
        assert_eq!(first_match("ls -la"), None);
        assert_eq!(first_match("cat add.rs && cd charm"), None); // token boundaries
        assert_eq!(first_match("SELECT * FROM users"), None);
        assert_eq!(first_match("git rm --cached file"), None); // not recursive+force broad
        assert_eq!(first_match("DELETE FROM tmp WHERE id = 1"), None); // scoped delete not flagged
    }
}
