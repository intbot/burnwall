//! OpenCode session-log parser.
//!
//! OpenCode (the `sst/opencode` terminal agent) stores one JSON file per
//! message under its data directory:
//!
//! ```text
//! <data dir>/storage/message/<session-id>/msg_<id>.json
//! ```
//!
//! Each file is a single JSON object (NOT JSONL). Only assistant messages
//! carry usage; the shape, from the OpenCode SDK `AssistantMessage` type, is:
//!
//! ```json
//! {
//!   "role": "assistant",
//!   "modelID": "claude-sonnet-4-6",
//!   "providerID": "anthropic",
//!   "cost": 0.0,
//!   "tokens": { "input": 1200, "output": 340, "reasoning": 0,
//!               "cache": { "read": 45000, "write": 8000 } },
//!   "time": { "created": 1755100406000, "completed": 1755100408000 }
//! }
//! ```
//!
//! OpenCode reports the cache buckets *separately* from `input` (unlike the
//! OpenAI/Codex shape where the cached count is folded into `input`), so the
//! buckets map straight across with no subtraction. `cost` on disk is often
//! 0 — Burnwall recomputes it from the token counts via its own pricing
//! table, same as every other source.
//!
//! Fail-open: a file that isn't an assistant message with a usable `tokens`
//! block, or reports zero tokens, contributes nothing.

use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::UsageEntry;
use crate::providers::TokenUsage;

const TOOL: &str = "opencode";

/// Discover and parse every OpenCode message file under the message root.
/// Fail-open: returns empty if the directory is absent or unreadable.
pub fn collect() -> Vec<UsageEntry> {
    collect_since(None)
}

/// [`collect`] with an optional mtime cutoff: message files untouched since
/// before the window start (minus the safety margin) are skipped unread.
/// Each file is one small JSON object (not JSONL), so whole-file reads stay.
pub fn collect_since(cutoff: Option<SystemTime>) -> Vec<UsageEntry> {
    let Some(root) = message_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for path in super::find_files_with_ext(&root, "json", cutoff) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&contents) else {
            continue;
        };
        // `time.completed`/`created` is authoritative; file mtime is the
        // fallback so an entry is never dropped for lack of a timestamp.
        let fallback = file_mtime_utc(&path).unwrap_or_else(Utc::now);
        if let Some(entry) = parse_message(&value, fallback) {
            out.push(entry);
        }
    }
    out
}

/// Root directory OpenCode message files live under.
/// `BURNWALL_OPENCODE_LOG_DIR` overrides it (used by tests); otherwise
/// `$OPENCODE_DATA_DIR/storage/message`, else `~/.local/share/opencode/
/// storage/message`.
fn message_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("BURNWALL_OPENCODE_LOG_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Some(data) = std::env::var_os("OPENCODE_DATA_DIR") {
        return Some(PathBuf::from(data).join("storage").join("message"));
    }
    dirs::home_dir().map(|h| {
        h.join(".local")
            .join("share")
            .join("opencode")
            .join("storage")
            .join("message")
    })
}

/// Parse one OpenCode message object. `fallback` dates the turn when the
/// message carries no usable `time`. Returns `None` for non-assistant
/// messages, a missing model, or zero usage.
pub fn parse_message(value: &Value, fallback: DateTime<Utc>) -> Option<UsageEntry> {
    if value.get("role").and_then(Value::as_str)? != "assistant" {
        return None;
    }
    let tokens = value.get("tokens")?;
    let cache = tokens.get("cache");
    let usage = TokenUsage {
        input_tokens: json_u64(tokens, "input"),
        output_tokens: json_u64(tokens, "output"),
        cache_read_tokens: cache.map(|c| json_u64(c, "read")).unwrap_or(0),
        cache_creation_tokens: cache.map(|c| json_u64(c, "write")).unwrap_or(0),
    };
    if usage.total() == 0 {
        return None;
    }
    let model = value.get("modelID").and_then(Value::as_str)?.to_string();
    // Reasoning is a subset of `output`, surfaced for the waste engine only.
    let reasoning_tokens = json_u64(tokens, "reasoning");
    let session_id = value
        .get("sessionID")
        .and_then(Value::as_str)
        .map(str::to_string);
    let timestamp = message_time(value).unwrap_or(fallback);
    Some(UsageEntry {
        tool: TOOL,
        model,
        timestamp,
        usage,
        reasoning_tokens,
        session_id,
        workspace: None,
        context_window: None,
    })
}

/// Prefer `time.completed`, then `time.created` — both epoch milliseconds.
fn message_time(value: &Value) -> Option<DateTime<Utc>> {
    let time = value.get("time")?;
    let ms = time
        .get("completed")
        .and_then(Value::as_i64)
        .or_else(|| time.get("created").and_then(Value::as_i64))?;
    DateTime::from_timestamp_millis(ms)
}

fn file_mtime_utc(path: &std::path::Path) -> Option<DateTime<Utc>> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

fn json_u64(obj: &Value, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}
