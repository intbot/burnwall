//! Aider analytics-log parser.
//!
//! When analytics are enabled (`aider --analytics`, opt-in), Aider appends a
//! JSONL event log to `~/.aider/analytics.jsonl`. The billable event is
//! `message_send`:
//!
//! ```json
//! {
//!   "event": "message_send",
//!   "properties": {
//!     "main_model": "openai/gpt-5.2",
//!     "prompt_tokens": 10006,
//!     "completion_tokens": 81,
//!     "total_tokens": 10087,
//!     "cost": 0.0133,
//!     "total_cost": 0.0133
//!   },
//!   "time": 1755100406
//! }
//! ```
//!
//! Aider's analytics carry no cache breakdown, so `cache_read` /
//! `cache_creation` are always 0 and `prompt_tokens` is the whole input.
//! `main_model` is a LiteLLM-style id that may carry a `provider/` prefix
//! (e.g. `openai/gpt-5.2`); the prefix is stripped so the name has a chance
//! of matching Burnwall's pricing table. `cost` is recomputed downstream from
//! the token counts like every other source.
//!
//! Fail-open: non-`message_send` lines, malformed lines, and zero-token
//! events contribute nothing. If analytics are disabled there is no file and
//! the parser yields nothing.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::UsageEntry;
use crate::providers::TokenUsage;

const TOOL: &str = "aider";

/// Parse the text of an `analytics.jsonl` file.
pub fn parse_str(contents: &str) -> Vec<UsageEntry> {
    contents.lines().filter_map(parse_line).collect()
}

/// Read and parse the Aider analytics log. Fail-open: returns empty if the
/// file is absent or unreadable (analytics off, or never run).
pub fn collect() -> Vec<UsageEntry> {
    let Some(path) = analytics_path() else {
        return Vec::new();
    };
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    parse_str(&contents)
}

/// Path to Aider's analytics log. `BURNWALL_AIDER_ANALYTICS` overrides it
/// (used by tests); otherwise `~/.aider/analytics.jsonl`.
fn analytics_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BURNWALL_AIDER_ANALYTICS") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".aider").join("analytics.jsonl"))
}

fn parse_line(line: &str) -> Option<UsageEntry> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("event").and_then(Value::as_str)? != "message_send" {
        return None;
    }
    let props = value.get("properties")?;
    let usage = TokenUsage {
        input_tokens: json_u64(props, "prompt_tokens"),
        output_tokens: json_u64(props, "completion_tokens"),
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    if usage.total() == 0 {
        return None;
    }
    let model = strip_provider_prefix(props.get("main_model").and_then(Value::as_str)?);
    // `time` is epoch seconds.
    let timestamp = value
        .get("time")
        .and_then(Value::as_i64)
        .and_then(|s| DateTime::from_timestamp(s, 0))?;
    Some(UsageEntry {
        tool: TOOL,
        model,
        timestamp,
        usage,
        reasoning_tokens: 0,
        session_id: None,
        workspace: None,
        context_window: None,
    })
}

/// Strip a leading `provider/` segment from a LiteLLM-style model id so the
/// bare model name can match the pricing table (`openai/gpt-5.2` → `gpt-5.2`).
/// Names without a slash pass through unchanged.
fn strip_provider_prefix(model: &str) -> String {
    match model.split_once('/') {
        Some((_, rest)) if !rest.is_empty() => rest.to_string(),
        _ => model.to_string(),
    }
}

fn json_u64(obj: &Value, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}
