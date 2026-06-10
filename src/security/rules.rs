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

// `rm -rf /` and `rm -rf ~` are deliberately NOT listed here: substring
// matching made `rm -rf /tmp/build-cache` and `rm -rf ~/.cache/pip` — everyday
// cleanup — read as the catastrophic literal (S-C2). The shape-aware
// `super::destructive` detector (always on for tool args) owns recursive-force
// deletes and only fires on broad/expandable targets, so scoped deletes pass.
pub const DEFAULT_DENY_COMMANDS: &[&str] = &["chmod 777", ":(){ :|:& };:"];

// Substring needles for genuine network-mount URI schemes. The Windows UNC
// prefix (`\\`) is matched separately by [`is_unc_mount`] (a bare-substring
// `\\` fired on every JSON-escaped Windows path — S-C1). `/Volumes/` was
// dropped (S-H7): it is where macOS mounts local USB drives, DMGs, and Time
// Machine, not specifically network shares, so a repo on an external SSD had
// every tool call blocked.
pub const NETWORK_MOUNT_NEEDLES: &[&str] = &["smb://", "nfs://", "cifs://", "afp://"];

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
    // Case-insensitive AND whitespace-normalized: a dangerous command literal
    // must not be evadable by varying case (`CHMOD 777`) or by padding it with
    // extra spaces/tabs/newlines (`rm   -rf   /`). We collapse internal runs of
    // whitespace on both sides before the substring check. These rules are
    // specific enough that this does not add meaningful false positives.
    collapse_ws(&value.to_ascii_lowercase()).contains(&collapse_ws(&rule.to_ascii_lowercase()))
}

/// Collapse all runs of whitespace to a single space (and trim ends).
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn mount_matches(value: &str) -> bool {
    let hay = value.to_ascii_lowercase();
    NETWORK_MOUNT_NEEDLES
        .iter()
        .any(|needle| hay.contains(needle))
        || is_unc_mount(value)
}

/// True when `value` contains a Windows **UNC network-share root** — `\\` at a
/// token boundary followed by a hostname-ish character. This deliberately does
/// NOT match a bare `\\` substring: JSON-escaped Windows paths decode to a leaf
/// like `C:\\Users\\me` (and OpenAI/Codex tool arguments are a JSON-encoded
/// string, so `{"path":"C:\\\\Users"}` decodes to `C:\\Users`), which contains
/// `\\` mid-token — not a network mount (S-C1). Local device namespaces
/// (`\\?\`, `\\.\`) and WSL (`\\wsl$`, `\\wsl.localhost`) are whitelisted: they
/// are local, not network.
pub fn is_unc_mount(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == b'\\' {
            let at_boundary = i == 0
                || matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'=' | b'(' | b',' | b':'
                );
            // `:` allows `path:\\server\share`-style prefixes but the doubled
            // backslash in a drive path (`C:\\Users`) has the `\\` preceded by
            // `:`? No — there it's `C` `:` `\` `\`, so the byte before `\\` is
            // `:`. Guard that: a single drive letter + colon before `\\` is a
            // local drive path, not UNC.
            let drive_path = i >= 2 && bytes[i - 1] == b':' && (bytes[i - 2] as char).is_ascii_alphabetic();
            if at_boundary && !drive_path {
                let rest = &value[i + 2..];
                let rest_lower = rest.to_ascii_lowercase();
                let local = rest.starts_with('?')
                    || rest.starts_with('.')
                    || rest_lower.starts_with("wsl$")
                    || rest_lower.starts_with("wsl.localhost");
                let hostnameish = rest
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphanumeric())
                    .unwrap_or(false);
                if !local && hostnameish {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Drop empty / whitespace-only rules. A blank deny rule makes `contains("")`
/// true for every leaf, blocking 100% of traffic (S-H8); filter it at ruleset
/// construction so a hand-edited config or installed pack can't brick the proxy.
pub fn non_empty_rules<I: IntoIterator<Item = String>>(rules: I) -> Vec<String> {
    rules
        .into_iter()
        .filter(|r| !r.trim().is_empty())
        .collect()
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
    fn mount_matches_real_network_schemes_and_unc_only() {
        assert!(mount_matches("\\\\server\\share")); // genuine UNC root
        assert!(mount_matches("SMB://host/share"));
        assert!(mount_matches("nfs://host/export"));
        // A plain https URL must not be flagged as a UNC mount.
        assert!(!mount_matches("https://api.anthropic.com/v1/messages"));
        // /Volumes/ is local on macOS (USB/DMG/Time Machine) — no longer flagged.
        assert!(!mount_matches("/Volumes/T7/code/project"));
    }

    #[test]
    fn unc_match_ignores_escaped_windows_paths() {
        // S-C1: the regression that blocked every Codex tool call and every
        // file write containing a Windows path.
        // A drive path with a doubled (JSON-escaped) backslash is NOT a mount.
        assert!(!is_unc_mount(r"C:\\Users\\me\\project"));
        assert!(!is_unc_mount(r#"{"path":"C:\\Users\\me"}"#));
        // Local device namespaces and WSL are local, not network.
        assert!(!is_unc_mount(r"\\?\C:\very\long\path"));
        assert!(!is_unc_mount(r"\\.\PhysicalDrive0"));
        assert!(!is_unc_mount(r"\\wsl$\Ubuntu\home\me"));
        assert!(!is_unc_mount(r"\\wsl.localhost\Ubuntu\home"));
        // A genuine UNC share root IS a mount.
        assert!(is_unc_mount(r"\\fileserver\share\secret"));
        assert!(is_unc_mount(r#"{"path":"\\fileserver\share"}"#));
    }

    #[test]
    fn non_empty_rules_drops_blanks() {
        // S-H8: a blank deny rule would match every leaf.
        let filtered = non_empty_rules(vec![
            "rm -rf /".to_string(),
            "".to_string(),
            "   ".to_string(),
            "chmod 777".to_string(),
        ]);
        assert_eq!(filtered, vec!["rm -rf /".to_string(), "chmod 777".to_string()]);
    }
}
