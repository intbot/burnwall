//! Domain types corresponding to rows in the storage tables.
//!
//! Domain code (proxy, CLI) deals in these structs; rusqlite conversions
//! live in `repository.rs`. Token counts use `u64` (matching
//! [`crate::providers::TokenUsage`]) and are cast to `i64` at the DB boundary
//! — SQLite INTEGER is signed but token counts can never approach `i64::MAX`.

use chrono::{DateTime, Utc};

use crate::providers::TokenUsage;

#[derive(Debug, Clone, PartialEq)]
pub struct RequestRecord {
    /// `None` before insert; the rowid is filled in after a successful insert
    /// (returned via [`crate::storage::Storage::insert_request`]).
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub blocked: bool,
    /// `Some` only when `blocked == true`; matches a security rule label like
    /// `"path_blocked: ~/.ssh/id_rsa"`.
    pub block_reason: Option<String>,
    /// Optional client-supplied session identifier (forwarded request header).
    pub session_id: Option<String>,
    /// Optional content hash for loop detection (v0.2). Always `None` in v0.1.
    pub request_hash: Option<String>,
    /// Upstream round-trip latency in ms (v0.7). `None` for blocked rows
    /// (nothing was forwarded) and rows from before this column existed.
    pub latency_ms: Option<i64>,
    /// Upstream HTTP status (v0.7). `None` for blocked rows.
    pub http_status: Option<i64>,
}

impl RequestRecord {
    /// Build a record for a forwarded, successfully-parsed request.
    pub fn successful(
        provider: &str,
        model: &str,
        usage: &TokenUsage,
        cost_usd: f64,
        session_id: Option<String>,
    ) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            provider: provider.to_string(),
            model: model.to_string(),
            input_tokens: usage.input_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            output_tokens: usage.output_tokens,
            cost_usd,
            blocked: false,
            block_reason: None,
            session_id,
            request_hash: None,
            latency_ms: None,
            http_status: None,
        }
    }

    /// Build a record for a request that was blocked before forwarding.
    /// All token counts and cost are zero — nothing left the machine.
    pub fn blocked(provider: &str, model: &str, reason: &str, session_id: Option<String>) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            provider: provider.to_string(),
            model: model.to_string(),
            input_tokens: 0,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            output_tokens: 0,
            cost_usd: 0.0,
            blocked: true,
            block_reason: Some(reason.to_string()),
            session_id,
            request_hash: None,
            latency_ms: None,
            http_status: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    /// One of: `path_blocked`, `command_blocked`, `secret_detected`,
    /// `mount_blocked`. Free-form string; the scanner sets it.
    pub event_type: String,
    /// What was blocked — e.g. the path, command, or matched pattern. This
    /// can leak filesystem layout, so the `log_redact_details` config
    /// option strips it down to the event-type label when set.
    pub details: String,
    pub provider: Option<String>,
    pub model: Option<String>,
}

impl SecurityEvent {
    pub fn new(event_type: &str, details: &str) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            details: details.to_string(),
            provider: None,
            model: None,
        }
    }

    pub fn with_provider(mut self, provider: &str, model: &str) -> Self {
        self.provider = Some(provider.to_string());
        self.model = Some(model.to_string());
        self
    }
}

/// One row of the `burnwall history` table: per-day aggregates.
#[derive(Debug, Clone, PartialEq)]
pub struct DailyTotal {
    /// UTC date in `YYYY-MM-DD` form.
    pub date: String,
    pub total_cost: f64,
    pub total_requests: i64,
    pub total_blocked: i64,
    /// Sum of cache_read tokens / (cache_read + input + cache_creation) for the day.
    pub cache_hit_rate: f64,
}

/// One pass-through event captured by `burnwall mcp-watch`: an MCP
/// JSON-RPC `tools/call` request that the watcher forwarded to its
/// upstream MCP server. Argument payloads are deliberately NOT stored —
/// they can contain prompt content.
#[derive(Debug, Clone, PartialEq)]
pub struct McpEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    /// JSON-RPC `id` field, stringified. `None` for notifications (no id).
    pub rpc_id: Option<String>,
    pub upstream_status: i64,
    pub upstream_uri: Option<String>,
}

impl McpEvent {
    pub fn new(tool_name: &str, rpc_id: Option<&str>, upstream_status: i64) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            tool_name: tool_name.to_string(),
            rpc_id: rpc_id.map(str::to_string),
            upstream_status,
            upstream_uri: None,
        }
    }

    pub fn with_upstream_uri(mut self, uri: &str) -> Self {
        self.upstream_uri = Some(uri.to_string());
        self
    }
}

/// One advertised MCP tool's trust record (v0.6.5), surfaced by
/// `burnwall mcp list`. Holds only the tool's advertised identity + approval
/// state — no argument payloads or prompt content.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolRow {
    pub server: String,
    pub tool_name: String,
    /// `"pending"` or `"approved"`.
    pub trust_state: String,
    pub last_seen: DateTime<Utc>,
}

/// One row of the `burnwall status` provider/model breakdown table.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelBreakdown {
    pub provider: String,
    pub model: String,
    pub cost: f64,
    pub requests: i64,
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
}

impl ModelBreakdown {
    /// Cache hit rate as a fraction [0.0, 1.0]. Cache reads divided by total
    /// prompt-side tokens (input + cache_creation + cache_read). 0.0 when
    /// no prompt-side tokens were billed.
    pub fn cache_hit_rate(&self) -> f64 {
        let prompt = self.input_tokens + self.cache_creation_tokens + self.cache_read_tokens;
        if prompt == 0 {
            0.0
        } else {
            self.cache_read_tokens as f64 / prompt as f64
        }
    }
}
