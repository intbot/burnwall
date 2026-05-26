//! Security engine — request-side filter that blocks dangerous payloads
//! before they leave the machine.
//!
//! Public surface:
//! - [`SecurityEngine`] — holds the [`Ruleset`] and is what the proxy calls
//!   per request.
//! - [`Violation`] — describes what was matched. The proxy turns this into
//!   an HTTP 403 with the JSON body shape from SPEC.md and writes a
//!   matching `security_events` row.
//!
//! The actual matchers live in [`rules`] and [`secrets`]; the JSON walker
//! is in [`scanner`]. See module-level docs in each for details.
//!
//! ### Fail-open
//! If the request body isn't valid JSON, [`SecurityEngine::scan`] returns
//! `None` (no violation) and the proxy forwards. Rationale: breaking the
//! user's workflow is worse than missing one scan, and non-JSON bodies are
//! typically non-chat endpoints (e.g. health checks).

pub mod packs;
pub mod rules;
pub mod scanner;
pub mod secrets;

pub use packs::RulePack;
pub use rules::Ruleset;

/// What kind of rule matched, used both to format the user-facing message
/// and to populate `security_events.event_type` in storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    Path,
    Command,
    Mount,
    Secret,
}

impl ViolationKind {
    /// String used for `security_events.event_type` per SPEC schema.
    pub fn event_type(&self) -> &'static str {
        match self {
            ViolationKind::Path => "path_blocked",
            ViolationKind::Command => "command_blocked",
            ViolationKind::Mount => "mount_blocked",
            ViolationKind::Secret => "secret_detected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub kind: ViolationKind,
    /// The rule that matched (a denied path, command, mount needle, or
    /// secret pattern name) — NOT the matched value, which can contain the
    /// secret itself.
    pub matched: String,
}

impl Violation {
    /// One-line user-facing message, as embedded in the 403 JSON body and
    /// printed to the terminal with the 🛡️ prefix.
    pub fn message(&self) -> String {
        match self.kind {
            ViolationKind::Path => {
                format!("attempted access to denied path: {}", self.matched)
            }
            ViolationKind::Command => {
                format!("attempted denied command: {}", self.matched)
            }
            ViolationKind::Mount => {
                format!("attempted access to network mount: {}", self.matched)
            }
            ViolationKind::Secret => {
                format!("payload contains a {} pattern", self.matched)
            }
        }
    }
}

pub struct SecurityEngine {
    rules: Ruleset,
}

impl SecurityEngine {
    pub fn new(rules: Ruleset) -> Self {
        Self { rules }
    }

    pub fn with_defaults() -> Self {
        Self::new(Ruleset::default())
    }

    pub fn rules(&self) -> &Ruleset {
        &self.rules
    }

    /// Scan a request body. `Some(Violation)` → block; `None` → forward.
    ///
    /// Non-JSON bodies return `None` (see fail-open in the module docs).
    pub fn scan(&self, body: &[u8]) -> Option<Violation> {
        // Master switch — `security.enabled = false` forwards without scanning.
        if !self.rules.enabled {
            return None;
        }
        // Strip a leading UTF-8 BOM: `serde_json` rejects it, which would
        // otherwise let a `\xef\xbb\xbf{…}` body slip past the scanner via
        // the fail-open path. Real clients never emit a BOM; this is
        // defense-in-depth.
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        scanner::scan(&json, &self.rules)
    }
}
