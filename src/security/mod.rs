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

pub mod destructive;
pub mod dlp;
pub mod exfil;
pub mod packs;
pub mod rules;
pub mod scanner;
pub mod secrets;
pub mod signing;

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
    /// Egress / DLP — exfiltration-prone data (card numbers, SSNs). v0.6.5.
    Dlp,
    /// Command-shaped data exfiltration (DNS exfil, secret piped to network).
    Exfil,
    /// Catastrophic, data-loss-grade command (recursive-force delete, disk
    /// destruction, destructive SQL) — detected by shape, not literal match.
    Destructive,
}

impl ViolationKind {
    /// String used for `security_events.event_type` per SPEC schema.
    pub fn event_type(&self) -> &'static str {
        match self {
            ViolationKind::Path => "path_blocked",
            ViolationKind::Command => "command_blocked",
            ViolationKind::Mount => "mount_blocked",
            ViolationKind::Secret => "secret_detected",
            ViolationKind::Dlp => "dlp_blocked",
            ViolationKind::Exfil => "exfil_blocked",
            ViolationKind::Destructive => "destructive_blocked",
        }
    }
}

/// Where in the request body the matching leaf sat. Decisive for the
/// false-positive judgment (S-C3): a hit "in the current tool call" is an
/// action the model is taking now; a hit "in earlier conversation history" is
/// almost always the model quoting/discussing something. The block message
/// surfaces this so the user can tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchLocation {
    /// In the current in-flight tool call's arguments.
    ToolCall,
    /// In earlier conversation history (a prior turn the client resent).
    History,
    /// Elsewhere in the request body (system prompt, chat text, tool defs,
    /// or non-shell tool content like a file being written).
    Body,
}

impl MatchLocation {
    pub fn describe(&self) -> &'static str {
        match self {
            MatchLocation::ToolCall => "in the current tool call",
            MatchLocation::History => "in earlier conversation history",
            MatchLocation::Body => "in the request body",
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
    /// Where the matching leaf sat in the payload.
    pub location: MatchLocation,
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
            ViolationKind::Dlp => {
                format!(
                    "payload contains possible data exfiltration: {}",
                    self.matched
                )
            }
            ViolationKind::Exfil => {
                format!("tool call looks like data exfiltration: {}", self.matched)
            }
            ViolationKind::Destructive => {
                format!("blocked a catastrophic command: {}", self.matched)
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

    /// Scan a payload that is tool-call-shaped end to end (MCP JSON-RPC
    /// bodies, rule testing): every string leaf gets the full check set.
    /// `Some(Violation)` → block; `None` → forward.
    ///
    /// Non-JSON bodies return `None` (see fail-open in the module docs).
    pub fn scan(&self, body: &[u8]) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan(&json, &self.rules)
    }

    /// Scan an LLM request body, scoping command-shaped checks (paths,
    /// commands, mounts, destructive, exfil) to tool-call argument subtrees.
    /// Prose — the system prompt, chat text, tool definitions, tool results —
    /// only gets the data checks (secrets, DLP), so a payload that merely
    /// *mentions* a denied path or command is not blocked. See
    /// [`scanner::scan_request`].
    pub fn scan_request(&self, body: &[u8]) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan_request(&json, &self.rules)
    }

    /// Scan an MCP JSON-RPC body. Like [`scan_request`] but for the JSON-RPC
    /// envelope: only `tools/call` `params.arguments` get command-shaped checks;
    /// the rest is prose (data checks only). See [`scanner::scan_mcp`].
    pub fn scan_mcp(&self, body: &[u8]) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan_mcp(&json, &self.rules)
    }

    fn parse_for_scan(&self, body: &[u8]) -> Option<serde_json::Value> {
        // Master switch — `security.enabled = false` forwards without scanning.
        if !self.rules.enabled {
            return None;
        }
        // Strip a leading UTF-8 BOM: `serde_json` rejects it, which would
        // otherwise let a `\xef\xbb\xbf{…}` body slip past the scanner via
        // the fail-open path. Real clients never emit a BOM; this is
        // defense-in-depth.
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
        match serde_json::from_slice(body) {
            Ok(v) => Some(v),
            Err(_) => {
                // Fail-open, but NOT silently (S-M9): a body the scanner can't
                // parse is a body it can't inspect. An empty body is a normal
                // GET; a non-empty unparseable one (e.g. an encoding we don't
                // handle) is the kind of blind spot that hid the cost-tracking
                // outage. Count it and warn periodically rather than never.
                if !body.is_empty() {
                    let n = UNSCANNED_BODIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    if n == 1 || n.is_multiple_of(100) {
                        tracing::warn!(
                            "security scan skipped: request body #{n} is not parseable JSON ({} bytes) — forwarded unscanned",
                            body.len()
                        );
                    }
                }
                None
            }
        }
    }
}

/// Count of request bodies the scanner could not parse (and therefore could not
/// inspect). Process-local; surfaced in the periodic warn above.
pub static UNSCANNED_BODIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
