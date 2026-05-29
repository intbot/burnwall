//! Rule types, defaults, and per-rule matching primitives.
//!
//! Three rule families:
//! - **Paths** — strings like `~/.ssh`, `/etc/passwd`. Matched as substring
//!   against the *suffix* (so the agent's expanded form
//!   `/Users/developer/.ssh/...` matches the rule `~/.ssh` via the shared
//!   `/.ssh` suffix). On Windows the backslash form is also checked.
//! - **Commands** — exact substring match (`rm -rf /`, `chmod 777`, etc.).
//! - **Network mounts** — fixed prefixes (`/Volumes/`, `\\`, `smb://`,
//!   `nfs://`). A single boolean toggles them all.
//!
//! Secret detection lives in [`super::secrets`] and is also toggled by a
//! single boolean.
//!
//! `allow_paths` is an exception list, populated only from a per-project
//! `.burnwall.yaml` profile (see [`crate::config::project`]). A string leaf
//! that matches an allow path is exempt from *path* deny rules — command,
//! mount, and secret checks still apply. It is empty for the global config;
//! a project can carve out exceptions but never the other way around.

#[derive(Debug, Clone)]
pub struct Ruleset {
    /// Master switch. When `false`, [`super::SecurityEngine::scan`] forwards
    /// everything without inspecting it. Default `true`.
    pub enabled: bool,
    pub deny_paths: Vec<String>,
    /// Path exceptions from a project profile. A leaf matching one of these
    /// skips the path-deny checks. Empty unless a `.burnwall.yaml` was
    /// discovered at startup.
    pub allow_paths: Vec<String>,
    pub deny_commands: Vec<String>,
    pub block_network_mounts: bool,
    pub detect_secrets: bool,
    /// Egress / DLP detection (v0.6.5). When `true`, the scanner also flags
    /// exfiltration-prone data the credential denylist misses (Luhn-valid
    /// card numbers, US SSNs). Off by default — opt-in, errs toward precision.
    pub detect_egress: bool,
    /// Extra secret patterns contributed by installed rule packs (v0.6).
    /// Built-in patterns live in [`super::secrets::PATTERNS`] and are always
    /// checked first; these are *additive* and gated by `detect_secrets`.
    /// A rule pack can only ever EXTEND this list — never an allow list or a
    /// global toggle (invariant I2).
    pub secret_patterns: Vec<super::secrets::SecretPattern>,
    /// When true, storage rows for blocked requests strip the matched-rule
    /// detail (e.g. "~/.ssh") and keep only the event-type label. The 403
    /// response to the agent is unaffected so legitimate users still see
    /// what was blocked — only persisted data is redacted.
    pub log_redact_details: bool,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_paths: DEFAULT_DENY_PATHS.iter().map(|s| s.to_string()).collect(),
            allow_paths: Vec::new(),
            deny_commands: DEFAULT_DENY_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            block_network_mounts: true,
            detect_secrets: true,
            detect_egress: false,
            secret_patterns: Vec::new(),
            log_redact_details: false,
        }
    }
}

pub const DEFAULT_DENY_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.config/gcloud",
    "/etc/passwd",
    "/etc/shadow",
];

pub const DEFAULT_DENY_COMMANDS: &[&str] = &["rm -rf /", "rm -rf ~", "chmod 777", ":(){ :|:& };:"];

pub const NETWORK_MOUNT_NEEDLES: &[&str] = &[
    "/Volumes/",
    r"\\", // Windows UNC prefix (two backslashes)
    "smb://",
    "nfs://",
];

/// Does `value` reference a denied path?
///
/// Matching is case-insensitive and separator-agnostic: Windows and the
/// default macOS filesystem are case-insensitive, and Windows tools emit
/// mixed `\`/`/` separators, so `~/.SSH/id_rsa` and `C:\Users\me/.aws\creds`
/// must still trip the `~/.ssh` / `~/.aws` rules. We fold the value to
/// lowercase and unify separators to `/` before matching.
///
/// For rules starting with `~/`, we match the normalized form `/<rest>` or
/// `~/<rest>`, catching both literal (`~/.ssh/id_rsa`) and expanded
/// (`/Users/anyone/.ssh/id_rsa`, `C:\Users\anyone\.ssh\config`) forms. For
/// absolute rules (`/etc/passwd`), plain substring match on the normalized
/// value.
pub fn path_matches(value: &str, rule: &str) -> bool {
    let hay = normalize_path(value);
    if let Some(rest) = rule.strip_prefix("~/") {
        let rest = normalize_path(rest);
        hay.contains(&format!("/{rest}")) || hay.contains(&format!("~/{rest}"))
    } else {
        hay.contains(&normalize_path(rule))
    }
}

pub fn command_matches(value: &str, rule: &str) -> bool {
    // Case-insensitive: a dangerous command literal must not be evadable by
    // varying case (e.g. `CHMOD 777`). These rules are specific enough that
    // case-folding does not add meaningful false positives.
    value.to_ascii_lowercase().contains(&rule.to_ascii_lowercase())
}

pub fn mount_matches(value: &str) -> bool {
    // Case-fold only — do NOT unify separators here, or the UNC `\\` needle
    // would collide with `//` in ordinary URLs (e.g. `https://...`).
    let hay = value.to_ascii_lowercase();
    NETWORK_MOUNT_NEEDLES
        .iter()
        .any(|needle| hay.contains(&needle.to_ascii_lowercase()))
}

/// Lowercase and unify path separators (`\` → `/`) for case- and
/// separator-insensitive path matching. ASCII case-folding is sufficient for
/// the filesystem paths we match and avoids Unicode-casing surprises.
fn normalize_path(s: &str) -> String {
    s.replace('\\', "/").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matches_is_case_insensitive() {
        // Headline bypass: case variation on a case-insensitive filesystem.
        assert!(path_matches("/Users/dev/.SSH/id_rsa", "~/.ssh"));
        assert!(path_matches("/home/dev/.Ssh/config", "~/.ssh"));
        assert!(path_matches("C:\\Users\\Dev\\.AWS\\credentials", "~/.aws"));
        assert!(path_matches("/ETC/PASSWD", "/etc/passwd"));
    }

    #[test]
    fn path_matches_handles_mixed_separators() {
        // Windows tools (Git Bash / WSL / agents) emit mixed separators.
        assert!(path_matches("C:\\Users\\me/.aws/credentials", "~/.aws"));
        assert!(path_matches("C:\\Users\\me\\.config/gcloud\\creds", "~/.config/gcloud"));
        assert!(path_matches("\\\\.ssh\\id_rsa", "~/.ssh"));
    }

    #[test]
    fn path_matches_still_matches_canonical_forms() {
        assert!(path_matches("~/.ssh/id_rsa", "~/.ssh"));
        assert!(path_matches("/Users/anyone/.ssh/id_rsa", "~/.ssh"));
        assert!(path_matches("C:\\Users\\anyone\\.ssh\\config", "~/.ssh"));
    }

    #[test]
    fn path_matches_rejects_unrelated() {
        assert!(!path_matches("/Users/dev/projects/notes.txt", "~/.ssh"));
        assert!(!path_matches("/var/log/system.log", "/etc/passwd"));
    }

    #[test]
    fn command_matches_is_case_insensitive() {
        assert!(command_matches("CHMOD 777 /tmp/x", "chmod 777"));
        assert!(command_matches("sudo RM -RF /", "rm -rf /"));
        assert!(command_matches("rm -rf /", "rm -rf /"));
        assert!(!command_matches("rm -rf /tmp/safe", "rm -rf ~"));
    }

    #[test]
    fn mount_matches_case_insensitive_without_url_false_positive() {
        assert!(mount_matches("/VOLUMES/backup/secrets"));
        assert!(mount_matches("\\\\server\\share"));
        assert!(mount_matches("SMB://host/share"));
        // A plain https URL must not be flagged as a UNC mount.
        assert!(!mount_matches("https://api.anthropic.com/v1/messages"));
    }
}
