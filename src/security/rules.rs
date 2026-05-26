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
