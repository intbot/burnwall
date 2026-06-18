//! MCP tool-poisoning + rug-pull detection for `burnwall mcp-watch`.
//!
//! The watcher already scans `tools/call` *request* bodies with the same
//! security engine the LLM proxy uses (path / command / mount / secret
//! denylist). This module adds the response-side half: inspecting the tools
//! an MCP server *advertises* in its `tools/list` reply.
//!
//! Two threats, both recognised in the OWASP MCP Top 10:
//!
//! - **Tool poisoning** — a malicious server hides instructions in a tool's
//!   `description` / `inputSchema` (e.g. "ignore previous instructions",
//!   "do not tell the user", zero-width hidden text, or an embedded secret /
//!   path). The model reads these on load, before any call is made.
//! - **Rug pull** — a tool the user already approved silently changes its
//!   definition later. We fingerprint each tool the first time we see it and
//!   flag any subsequent change (see [`AdvertisedTool::fingerprint`]).
//!
//! Everything here is **read-only inspection**: findings are recorded as
//! `security_events`, the response bytes are forwarded byte-for-byte
//! unchanged (CLAUDE.md: never modify a response), and a poisoned `tools/list`
//! is never blocked — blocking the listing would break the client, and the
//! value is the audit trail + the operator warning.
//!
//! Fail-open: a body that isn't a parseable `tools/list` response yields
//! zero tools and zero findings — never an error, never a false positive.

use serde_json::Value;

/// Whether MCP server `server` is permitted by a per-project allowlist
/// (`.burnwall.yaml` → `mcp_allowed_servers`).
///
/// Deny-by-omission applies *only* when `allowlist` is non-empty: an empty
/// list means "no per-project restriction" and always returns `true`, so a
/// user who never opts in is never blocked. `server` is matched **exactly**
/// against the configured names — the same routed server name the watcher's
/// router derives from the request path. This is the pure decision the MCP
/// handler calls; kept here so it is unit-testable without a live server.
pub fn server_allowed(allowlist: &[String], server: &str) -> bool {
    allowlist.is_empty() || allowlist.iter().any(|s| s == server)
}

/// Whether a `tools/call` routed to `server` is **blocked** by a per-project
/// allowlist. The allowlist scopes by server *name*, which is only meaningful
/// when named multi-server routing is configured (`[[mcp.servers]]`) — pass
/// `multi_server = true` in that case. In single-upstream mode there are no
/// named servers, so every call routes to the synthetic `"default"`; a list of
/// real names would then block *every* call, wedging a user who set the list
/// without the routing it scopes. So when `multi_server` is false the allowlist
/// does not apply and nothing is blocked. (FP-review Part 2, 2026-06-11: naming
/// servers is meaningless without `[[mcp.servers]]`.) An empty allowlist is
/// never a block regardless, via [`server_allowed`].
pub fn server_blocked(allowlist: &[String], server: &str, multi_server: bool) -> bool {
    multi_server && !server_allowed(allowlist, server)
}

/// One tool advertised in an MCP `tools/list` response.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisedTool {
    pub name: String,
    pub description: String,
    /// Stable content fingerprint over name + description + input schema —
    /// SHA-256 (hex). Deterministic across runs and platforms (so persisted
    /// fingerprints stay comparable across binary upgrades) and
    /// collision-resistant, so "the description matches" is a cryptographic
    /// claim, not just a change-tripwire.
    pub fingerprint: String,
    /// Fingerprint over name + input schema ONLY (M-C2) — SHA-256 (hex). This
    /// is the value persisted by the watcher and the one whose change resets an
    /// approved tool back to `pending`: a description-only edit (typo fix,
    /// version bump in prose) must WARN but never silently revoke approval,
    /// while a schema change alters what the tool can actually be asked to do
    /// and therefore must force re-approval.
    pub schema_fingerprint: String,
    /// The raw tool object, kept so the caller can re-scan it with the
    /// existing `SecurityEngine` (secret / path / command patterns).
    pub raw: Value,
}

/// Parse a JSON-RPC `tools/list` *response* body into its advertised tools.
///
/// Returns an empty vec for any non-`tools/list` shape, malformed JSON, or a
/// body with no `result.tools` array — fail-open, never errors. Tolerates
/// both a plain JSON body and MCP streamable-HTTP SSE framing (`data:` lines).
pub fn parse_tools_list(body: &[u8]) -> Vec<AdvertisedTool> {
    let Some(value) = parse_json_lenient(body) else {
        return Vec::new();
    };
    let Some(tools) = value
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.get("name").and_then(Value::as_str)?.to_string();
            let description = tool
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let schema = tool.get("inputSchema").cloned().unwrap_or(Value::Null);
            let fingerprint = fingerprint_tool(&name, &description, &schema);
            let schema_fingerprint = fingerprint_schema(&name, &schema);
            Some(AdvertisedTool {
                name,
                description,
                fingerprint,
                schema_fingerprint,
                raw: tool.clone(),
            })
        })
        .collect()
}

/// Parse `body` as JSON, tolerating a leading UTF-8 BOM and MCP
/// streamable-HTTP SSE framing. For SSE, the last non-empty `data:` payload
/// that parses as JSON wins (a `tools/list` reply is a single result object).
fn parse_json_lenient(body: &[u8]) -> Option<Value> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        return Some(v);
    }
    let text = std::str::from_utf8(body).ok()?;
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .next_back()
}

/// Phrases that appear in tool-poisoning proofs-of-concept but essentially
/// never in a legitimate tool description. Matched case-insensitively as
/// substrings. Kept deliberately tight to hold false positives near zero.
const INJECTION_MARKERS: &[&str] = &[
    "ignore previous instruction",
    "ignore all previous",
    "disregard previous",
    "disregard all previous",
    "do not tell the user",
    "do not inform the user",
    "without informing the user",
    "without telling the user",
    "do not mention this",
    "<important>",
    "</important>",
    "system prompt",
];

/// Return the first prompt-injection tell found in `text`, or `None`.
///
/// Detects both the [`INJECTION_MARKERS`] phrases and any zero-width / hidden
/// control character, which is a strong signal that instructions are being
/// smuggled in text the user will not see rendered.
pub fn injection_marker(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    for marker in INJECTION_MARKERS {
        if lower.contains(marker) {
            return Some(marker);
        }
    }
    if text.chars().any(is_hidden_char) {
        return Some("<hidden-unicode>");
    }
    None
}

/// Zero-width and other invisible characters used to hide instructions.
fn is_hidden_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // zero-width space/joiners + bidi marks
        | '\u{202A}'..='\u{202E}' // bidi embedding/override
        | '\u{2060}'..='\u{2064}' // word joiner + invisible math operators
        | '\u{FEFF}'              // zero-width no-break space (BOM)
    )
}

/// SHA-256 (hex) over name + description + canonicalised schema. serde_json
/// orders object keys deterministically, so the same tool always hashes the
/// same. 64 hex chars — distinguishable by length from the legacy FNV-1a
/// (16-hex) fingerprints, which the storage layer migrates in place on first
/// sight (see `observe_mcp_tool`).
fn fingerprint_tool(name: &str, description: &str, schema: &Value) -> String {
    let schema = serde_json::to_string(schema).unwrap_or_default();
    sha256_hex(&[
        name.as_bytes(),
        b"\0",
        description.as_bytes(),
        b"\0",
        schema.as_bytes(),
    ])
}

/// SHA-256 (hex) over name + canonicalised schema only — the persisted
/// fingerprint that drives enforce-mode re-pending (M-C2). Description text is
/// deliberately excluded; see [`AdvertisedTool::schema_fingerprint`].
fn fingerprint_schema(name: &str, schema: &Value) -> String {
    let schema = serde_json::to_string(schema).unwrap_or_default();
    sha256_hex(&[name.as_bytes(), b"\0", schema.as_bytes()])
}

/// SHA-256 of the concatenated `parts`, lower-hex encoded (64 chars).
fn sha256_hex(parts: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
