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
    let lower = collapse_ws(&s.to_ascii_lowercase());

    if is_recursive_force_rm(&lower) {
        return Some("recursive force delete");
    }
    if is_disk_destroyer(&lower) {
        return Some("disk/filesystem destruction");
    }
    if is_destructive_sql(&lower) {
        return Some("destructive SQL (drop/truncate)");
    }
    None
}

/// Collapse runs of whitespace to single spaces so spacing can't evade matching.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `rm` that is BOTH recursive AND force, aimed at a broad/expandable target.
/// Catches `-rf`, `-fr`, `-r -f`, `--recursive --force`, `-Rf`, etc.
fn is_recursive_force_rm(lower: &str) -> bool {
    // Must invoke rm as a command token.
    if !has_token(lower, "rm") {
        return false;
    }
    let recursive = contains_flag(lower, 'r') || lower.contains("--recursive");
    let force = contains_flag(lower, 'f') || lower.contains("--force");
    if !(recursive && force) {
        return false;
    }
    // Anything that disables the safety rail, or an expandable target, is
    // catastrophic regardless of the rest.
    if lower.contains("--no-preserve-root") || lower.contains("$(") || lower.contains('`') {
        return true;
    }
    // Broad/expandable *target token*: root, home, cwd, globs. A scoped target
    // like `./build` or `node_modules` is left alone (token equality, so `.`
    // does not match `./build`).
    const BROAD: &[&str] = &["/", "/*", "~", "~/", ".", "./*", "*", "$home", "$home/"];
    tokens(lower).any(|t| BROAD.contains(&t))
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
