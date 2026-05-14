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

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub deny_paths: Vec<String>,
    pub deny_commands: Vec<String>,
    pub block_network_mounts: bool,
    pub detect_secrets: bool,
    /// When true, storage rows for blocked requests strip the matched-rule
    /// detail (e.g. "~/.ssh") and keep only the event-type label. The 403
    /// response to the agent is unaffected so legitimate users still see
    /// what was blocked — only persisted data is redacted.
    pub log_redact_details: bool,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self {
            deny_paths: DEFAULT_DENY_PATHS.iter().map(|s| s.to_string()).collect(),
            deny_commands: DEFAULT_DENY_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            block_network_mounts: true,
            detect_secrets: true,
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
/// For rules starting with `~/`, we strip the `~` and match the form
/// `/<rest>` (Unix-style) or `\<rest-with-backslashes>` (Windows). This
/// catches both literal (`~/.ssh/id_rsa`) and expanded
/// (`/Users/anyone/.ssh/id_rsa`, `C:\Users\anyone\.ssh\config`) forms.
///
/// For absolute rules (`/etc/passwd`), plain substring match.
pub fn path_matches(value: &str, rule: &str) -> bool {
    if let Some(rest) = rule.strip_prefix("~/") {
        let unix_needle = format!("/{}", rest);
        let tilde_needle = format!("~/{}", rest);
        if value.contains(&unix_needle) || value.contains(&tilde_needle) {
            return true;
        }
        let win_needle = format!("\\{}", rest.replace('/', "\\"));
        if value.contains(&win_needle) {
            return true;
        }
        false
    } else {
        value.contains(rule)
    }
}

pub fn command_matches(value: &str, rule: &str) -> bool {
    value.contains(rule)
}

pub fn mount_matches(value: &str) -> bool {
    NETWORK_MOUNT_NEEDLES
        .iter()
        .any(|needle| value.contains(needle))
}
