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
pub mod evasion;
pub mod exfil;
pub mod filescan;
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
    /// A tool-call leaf dense with invisible/zero-width Unicode in the
    /// token-splitting configuration — content is being hidden from filters
    /// (and from the user's own review). See [`evasion`].
    Obfuscation,
    /// A user-planted canary credential (`security.canaries`) appeared in an
    /// outbound payload — the exfiltration tripwire fired. The canary has no
    /// legitimate use anywhere, so any request carrying it is hard-blocked.
    Canary,
    /// A recognized provider credential is being sent to a *different*
    /// provider's endpoint (e.g. an OpenAI `sk-` key in a body forwarded to the
    /// Anthropic upstream) — credential misdirection. Opt-in
    /// (`security.block_credential_misdirection`), v0.9.16. `matched` carries a
    /// human label of the form "<credential> credential sent to the <dest>
    /// endpoint"; a masked preview rides alongside.
    Misdirection,
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
            ViolationKind::Obfuscation => "obfuscation_blocked",
            ViolationKind::Canary => "canary_triggered",
            ViolationKind::Misdirection => "misdirection_blocked",
        }
    }
}

/// Where in the request body the matching leaf sat. Surfaced in the block
/// message ("… in the current tool call"). The false-positive insight behind
/// this (S-C3) is now acted on structurally: every check fires only inside
/// tool-call arguments, so a real block is always [`Self::ToolCall`] — an
/// action the model is taking now. The `Body`/`History` variants are retained
/// (the scope→location map stays total) as a guard against a future scope
/// change silently mislabeling a hit.
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
    /// The tool whose arguments held the match (`bash`, `write_file`, …), when
    /// the hit was inside a recognized tool call. Surfaced in the block message
    /// so the user knows *which action* tripped the firewall. Never persisted.
    pub tool: Option<String>,
    /// A masked, recognisable preview of the matched value (e.g. `AKIA…LKEY`),
    /// set only for secret/DLP hits. Lets the user identify *what* matched
    /// without the raw value ever being echoed or logged — terminal-only,
    /// never written to the DB or log (the redaction principle holds: the value
    /// is masked here and the stored row keeps only the rule label).
    pub preview: Option<String>,
}

impl Violation {
    /// A violation carrying just kind/matched/location; tool and preview unset.
    pub fn new(kind: ViolationKind, matched: impl Into<String>, location: MatchLocation) -> Self {
        Self {
            kind,
            matched: matched.into(),
            location,
            tool: None,
            preview: None,
        }
    }

    /// Attach the originating tool name (no-op if `None`).
    pub fn with_tool(mut self, tool: Option<&str>) -> Self {
        self.tool = tool.map(str::to_string);
        self
    }

    /// Attach a masked preview of the matched value.
    pub fn with_preview(mut self, preview: String) -> Self {
        self.preview = Some(preview);
        self
    }

    /// The headline sentence of a block: *which* action tripped *what* rule,
    /// naming the tool when known and showing a masked preview for secret/DLP
    /// hits. This is the "what/where" half the earlier message lacked (a bare
    /// "in earlier conversation history" left users unable to find the cause).
    pub fn headline(&self) -> String {
        let actor = match &self.tool {
            Some(t) => format!("Your `{t}` tool call"),
            None => "This tool call".to_string(),
        };
        let preview = self
            .preview
            .as_deref()
            .map(|p| format!(" (looks like: {p})"))
            .unwrap_or_default();
        match self.kind {
            ViolationKind::Path => {
                format!("{actor} tried to access a denied path: {}.", self.matched)
            }
            ViolationKind::Command => {
                format!("{actor} ran a denied command: {}.", self.matched)
            }
            ViolationKind::Mount => {
                format!("{actor} accessed a network mount: {}.", self.matched)
            }
            ViolationKind::Destructive => {
                format!("{actor} ran a destructive command: {}.", self.matched)
            }
            ViolationKind::Secret => {
                format!("{actor} contains a credential — {}{preview}.", self.matched)
            }
            ViolationKind::Dlp => {
                format!(
                    "{actor} contains sensitive data — {}{preview}.",
                    self.matched
                )
            }
            ViolationKind::Exfil => {
                format!("{actor} looks like data exfiltration: {}.", self.matched)
            }
            ViolationKind::Obfuscation => {
                format!(
                    "{actor} contains text hidden with invisible Unicode characters ({}).",
                    self.matched
                )
            }
            ViolationKind::Canary => {
                // A canary can fire outside a tool call (prose), where "tool
                // call" would mislead — name the request instead.
                let carrier = match &self.tool {
                    Some(t) => format!("Your `{t}` tool call"),
                    None => "This request".to_string(),
                };
                format!(
                    "{carrier} carries a planted canary credential{preview} — your tripwire fired."
                )
            }
            ViolationKind::Misdirection => {
                format!("{actor} is sending {}{preview}.", self.matched)
            }
        }
    }

    /// One line on *why* Burnwall blocks this class — so a block reads as a
    /// reasoned decision, not an opaque refusal.
    pub fn why(&self) -> &'static str {
        match self.kind {
            ViolationKind::Path | ViolationKind::Mount => {
                "Burnwall blocks reads of sensitive paths and network mounts so an agent can't scoop up your keys or credentials."
            }
            ViolationKind::Command | ViolationKind::Destructive => {
                "Burnwall blocks dangerous commands before they run on your machine."
            }
            ViolationKind::Secret | ViolationKind::Dlp | ViolationKind::Exfil => {
                "Burnwall blocks credentials and sensitive data inside tool calls so they can't be exfiltrated off your machine."
            }
            ViolationKind::Obfuscation => {
                "Burnwall found invisible characters hiding content — a technique for smuggling instructions or splitting forbidden tokens past filters. If this content is intentional, let the next request through with `burnwall allow-once`."
            }
            ViolationKind::Canary => {
                "A canary value exists only to detect exfiltration — no legitimate request ever carries it, so something just tried to send yours off your machine. Investigate before continuing; to disarm, remove the value from `security.canaries` in ~/.burnwall/config.toml."
            }
            ViolationKind::Misdirection => {
                "Burnwall blocks a credential for one provider from being sent to a different provider's endpoint — a sign a key is leaking into the wrong request (or that traffic was misrouted). Disable with `burnwall config set security.block_credential_misdirection false`."
            }
        }
    }

    /// The full "what + why" block embedded in the 403 (headline, then the
    /// rationale on its own line).
    pub fn block_explanation(&self) -> String {
        format!("{}\n{}", self.headline(), self.why())
    }

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
            ViolationKind::Obfuscation => {
                format!(
                    "invisible characters found hiding content: {}",
                    self.matched
                )
            }
            ViolationKind::Canary => {
                "a planted canary credential attempted to leave the machine".to_string()
            }
            ViolationKind::Misdirection => {
                format!("credential misdirection: {}", self.matched)
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

    /// Scan an LLM request body, scoping **all** checks — command-shaped (paths,
    /// commands, mounts, destructive, exfil) AND data-shaped (secrets, DLP) — to
    /// tool-call argument subtrees. Prose and resent history — the system
    /// prompt, chat text, tool definitions, tool results, earlier turns — get no
    /// checks, so a payload that merely *mentions* a denied path, a card number,
    /// or a key-shaped token is not blocked (it would re-block on every resend
    /// and wedge the session). See [`scanner::scan_request`].
    pub fn scan_request(&self, body: &[u8]) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan_request(&json, &self.rules)
    }

    /// Like [`scan_request`] but also knows the request's **destination
    /// provider** (`"anthropic"` / `"openai"` / `"google"`), enabling the
    /// credential-misdirection check (feature #7, opt-in via
    /// `security.block_credential_misdirection`): a recognized provider
    /// credential in a tool-call argument whose provider differs from the
    /// destination is blocked as [`ViolationKind::Misdirection`]. With the flag
    /// off this is identical to [`scan_request`]. The proxy calls this on the
    /// LLM request path; [`scan_request`] stays for callers/tests without a
    /// destination.
    pub fn scan_request_for(&self, body: &[u8], dest_provider: &str) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan_request_for(&json, &self.rules, dest_provider)
    }

    /// Scan a **raw, non-JSON** file-upload body (a multipart/form-data upload
    /// to a provider file endpoint) for secrets / DLP / canaries (feature #3).
    /// Closes the gap where [`scan_request`] fails open on a non-JSON body and
    /// the upload is never inspected. Gated by `detect_egress` (the existing
    /// `security.dlp` opt-in); the caller restricts this to known file-upload
    /// routes. Returns `None` (forward) when the feature is off, the body is
    /// largely binary, or nothing matches. See [`scanner::scan_raw_upload`].
    pub fn scan_upload(&self, body: &[u8]) -> Option<Violation> {
        if !self.rules.enabled {
            return None;
        }
        scanner::scan_raw_upload(body, &self.rules)
    }

    /// Scan an MCP JSON-RPC body. Like [`scan_request`] but for the JSON-RPC
    /// envelope: only `tools/call` `params.arguments` get checked (command-shaped
    /// for a shell tool, data + path checks otherwise); the rest of the envelope
    /// is prose and gets no checks. See [`scanner::scan_mcp`].
    pub fn scan_mcp(&self, body: &[u8]) -> Option<Violation> {
        let json = self.parse_for_scan(body)?;
        scanner::scan_mcp(&json, &self.rules)
    }

    /// Paranoid-mode helper: can the scanner actually inspect this body?
    /// True for an empty body (a normal GET) or parseable JSON (the only
    /// format the scanner understands). Pure check — no counters, no log
    /// noise — used by the opt-in `security.paranoid` fail-closed gate in
    /// the handler; the default fail-open path keeps its own accounting in
    /// [`Self::parse_for_scan`].
    pub fn scannable_json(&self, body: &[u8]) -> bool {
        if body.is_empty() {
            return true;
        }
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
        serde_json::from_slice::<serde::de::IgnoredAny>(body).is_ok()
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
