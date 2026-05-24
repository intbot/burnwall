//! Claude Code session-log parser.
//!
//! Claude Code writes one JSONL file per session under
//! `~/.claude/projects/<sanitized-cwd>/<session-uuid>.jsonl`. Each line is a
//! JSON event; the ones that carry billable usage are `type: "assistant"`
//! events, whose `message` object holds the `model` and a `usage` block:
//!
//! ```json
//! {
//!   "type": "assistant",
//!   "timestamp": "2026-05-14T09:00:05.000Z",
//!   "requestId": "req_...",
//!   "message": {
//!     "id": "msg_...",
//!     "model": "claude-opus-4-7",
//!     "usage": {
//!       "input_tokens": 12,
//!       "cache_creation_input_tokens": 8000,
//!       "cache_read_input_tokens": 45000,
//!       "output_tokens": 210
//!     }
//!   }
//! }
//! ```
//!
//! A single underlying API call can be logged in more than one file when a
//! session is resumed or forked, so each turn carries a `dedup_key`
//! (`message.id` + `requestId`); [`collect`] drops repeats across files.
//!
//! Fail-open: malformed lines, non-assistant lines, and lines missing a
//! model are skipped, never fatal.

use std::collections::HashSet;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::UsageEntry;
use crate::providers::TokenUsage;

const TOOL: &str = "claude-code";

/// A parsed Claude Code assistant turn plus the identity used to
/// de-duplicate the same API call across session files.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTurn {
    /// `message.id` + `requestId` when both are present — the stable key
    /// for one underlying API call. `None` when either is missing, in which
    /// case the turn cannot be de-duplicated and is always kept.
    pub dedup_key: Option<String>,
    pub entry: UsageEntry,
}

/// Parse the text of one Claude Code `*.jsonl` session file. Malformed
/// lines and non-assistant / model-less lines are silently skipped.
pub fn parse_str(contents: &str) -> Vec<ParsedTurn> {
    contents.lines().filter_map(parse_line).collect()
}

/// Discover and parse every Claude Code session log under the log root,
/// de-duplicated across files. Fail-open: returns empty if the log
/// directory is absent or unreadable.
pub fn collect() -> Vec<UsageEntry> {
    let Some(root) = log_root() else {
        return Vec::new();
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for path in super::find_jsonl_files(&root) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for turn in parse_str(&contents) {
            // Repeated (message.id, requestId) across files = the same API
            // call re-logged by a resumed/forked session — drop the repeat.
            if let Some(key) = turn.dedup_key {
                if !seen.insert(key) {
                    continue;
                }
            }
            out.push(turn.entry);
        }
    }
    out
}

/// Root directory Claude Code session logs live under. `BURNWALL_CLAUDE_LOG_DIR`
/// overrides it (used by tests); otherwise `~/.claude/projects`.
fn log_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("BURNWALL_CLAUDE_LOG_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir().map(|h| h.join(".claude").join("projects"))
}

fn parse_line(line: &str) -> Option<ParsedTurn> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("type")?.as_str()? != "assistant" {
        return None;
    }
    let message = value.get("message")?;
    let model = message.get("model")?.as_str()?.to_string();
    let usage_obj = message.get("usage")?;
    let usage = TokenUsage {
        input_tokens: json_u64(usage_obj, "input_tokens"),
        output_tokens: json_u64(usage_obj, "output_tokens"),
        cache_creation_tokens: json_u64(usage_obj, "cache_creation_input_tokens"),
        cache_read_tokens: json_u64(usage_obj, "cache_read_input_tokens"),
    };
    let timestamp = parse_timestamp(value.get("timestamp")?.as_str()?)?;

    // Dedup key only when both halves are present; a turn we can't key is
    // always kept rather than risk dropping a distinct call.
    let dedup_key = match (
        message.get("id").and_then(Value::as_str),
        value.get("requestId").and_then(Value::as_str),
    ) {
        (Some(id), Some(req)) => Some(format!("{id}:{req}")),
        _ => None,
    };

    Some(ParsedTurn {
        dedup_key,
        entry: UsageEntry {
            tool: TOOL,
            model,
            timestamp,
            usage,
            // Claude Code's usage block does not itemize thinking tokens; they
            // are billed inside `output_tokens` with no separate count we can
            // trust, so the reasoning-effort rule never fires on Claude data.
            reasoning_tokens: 0,
        },
    })
}

/// Read a token-count field, treating a missing or non-integer value as 0
/// (fail-open — a partial `usage` block still yields a usable entry).
fn json_u64(obj: &Value, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}
