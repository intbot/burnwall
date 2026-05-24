//! Codex CLI session-log parser.
//!
//! Codex CLI writes one JSONL rollout file per session under
//! `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`. Each line is a
//! `RolloutItem`, tagged `{"type": "<variant>", "payload": <content>}`:
//!
//! - `turn_context` / `session_meta` payloads carry the active `model`.
//! - `event_msg` payloads wrap an inner event; the billable one is
//!   `{"type": "token_count", "info": {"last_token_usage": {...}}}`, whose
//!   `last_token_usage` is that turn's usage (Codex also keeps a running
//!   `total_token_usage`, which we ignore — `last_token_usage` is already
//!   the per-turn delta).
//!
//! `token_count` events don't name their model, so parsing is stateful:
//! the most recent `turn_context` / `session_meta` model is attached to the
//! `token_count` events that follow it.
//!
//! Codex's `TokenUsage.input_tokens` includes the cached portion (mirroring
//! the OpenAI usage block), so it is split into non-cached `input_tokens` +
//! `cache_read_tokens` — the same normalization [`crate::providers::openai`]
//! does. Codex has no cache writes, so `cache_creation_tokens` is always 0.
//!
//! Fail-open: malformed lines, rate-limit-only re-emits (zero usage), and
//! events with no known model are skipped, never fatal.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, NaiveDate, Utc};
use serde_json::Value;

use super::UsageEntry;
use crate::providers::TokenUsage;

const TOOL: &str = "codex";

/// Parse the text of one Codex rollout `*.jsonl` file. `fallback_date` is
/// the session date recovered from the file path (`.../YYYY/MM/DD/...`); it
/// is used to date an event only when its line carries no `timestamp`.
pub fn parse_str(contents: &str, fallback_date: Option<NaiveDate>) -> Vec<UsageEntry> {
    let mut current_model: Option<String> = None;
    let mut out = Vec::new();

    for line in contents.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match value.get("type").and_then(Value::as_str) {
            Some("turn_context") | Some("session_meta") => {
                if let Some(model) = value
                    .get("payload")
                    .and_then(|p| p.get("model"))
                    .and_then(Value::as_str)
                {
                    current_model = Some(model.to_string());
                }
            }
            Some("event_msg") => {
                if let Some(entry) = parse_token_count(&value, &current_model, fallback_date) {
                    out.push(entry);
                }
            }
            _ => {}
        }
    }
    out
}

/// Discover and parse every Codex rollout log under the log root.
/// Fail-open: returns empty if the log directory is absent or unreadable.
pub fn collect() -> Vec<UsageEntry> {
    let Some(root) = log_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for path in super::find_jsonl_files(&root) {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(parse_str(&contents, date_from_path(&path)));
    }
    out
}

/// Root directory Codex rollout logs live under. `BURNWALL_CODEX_LOG_DIR`
/// overrides it (used by tests); otherwise `~/.codex/sessions`.
fn log_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("BURNWALL_CODEX_LOG_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir().map(|h| h.join(".codex").join("sessions"))
}

/// Extract one `token_count` event into a [`UsageEntry`], or `None` if the
/// line isn't a usage event, has no known model, carries no usable
/// timestamp, or reports zero tokens (a rate-limit-only re-emit).
fn parse_token_count(
    value: &Value,
    current_model: &Option<String>,
    fallback_date: Option<NaiveDate>,
) -> Option<UsageEntry> {
    let payload = value.get("payload")?;
    if payload.get("type").and_then(Value::as_str)? != "token_count" {
        return None;
    }
    let last = payload.get("info")?.get("last_token_usage")?;
    let usage = codex_usage(last);
    if usage.total() == 0 {
        return None;
    }
    // Reasoning tokens are a subset of `output_tokens` (Codex's `total_tokens`
    // = input + output, with no separate reasoning term), surfaced for the
    // waste engine. Never folded back into `usage` — that would double-count.
    let reasoning_tokens = json_i64(last, "reasoning_output_tokens").max(0) as u64;
    let model = current_model.clone()?;
    let timestamp = line_timestamp(value, fallback_date)?;
    Some(UsageEntry {
        tool: TOOL,
        model,
        timestamp,
        usage,
        reasoning_tokens,
    })
}

/// Map Codex's `last_token_usage` block onto the provider-neutral
/// [`TokenUsage`]. Codex `input_tokens` includes the cached portion, so the
/// cached count is split out; Codex has no cache writes.
fn codex_usage(last: &Value) -> TokenUsage {
    let input = json_i64(last, "input_tokens");
    let cached = json_i64(last, "cached_input_tokens");
    let output = json_i64(last, "output_tokens");
    TokenUsage {
        input_tokens: (input - cached).max(0) as u64,
        cache_read_tokens: cached.max(0) as u64,
        cache_creation_tokens: 0,
        output_tokens: output.max(0) as u64,
    }
}

/// Read an integer field, treating missing / non-integer as 0 (fail-open).
fn json_i64(obj: &Value, key: &str) -> i64 {
    obj.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// Per-line `timestamp` (RFC 3339) when present, else noon-local of the
/// session date recovered from the file path. Codex names session dirs by
/// local date; anchoring the fallback at noon local keeps that date stable
/// when `logscrape::aggregate` later re-derives it in local time.
fn line_timestamp(value: &Value, fallback_date: Option<NaiveDate>) -> Option<DateTime<Utc>> {
    if let Some(ts) = value.get("timestamp").and_then(Value::as_str) {
        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    fallback_date.and_then(|d| {
        d.and_hms_opt(12, 0, 0)?
            .and_local_timezone(Local)
            .single()
            .map(|local| local.with_timezone(&Utc))
    })
}

/// Recover the session date from a `.../YYYY/MM/DD/rollout-*.jsonl` path.
fn date_from_path(path: &Path) -> Option<NaiveDate> {
    // Skip the filename, then read DD / MM / YYYY off the trailing dirs.
    let mut dirs = path.components().rev().skip(1);
    let day: u32 = dirs.next()?.as_os_str().to_str()?.parse().ok()?;
    let month: u32 = dirs.next()?.as_os_str().to_str()?.parse().ok()?;
    let year: i32 = dirs.next()?.as_os_str().to_str()?.parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day)
}
