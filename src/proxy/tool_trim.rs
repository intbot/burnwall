//! Opt-in tool-output trimming (#17) — `proxy.trim_tool_output`.
//!
//! Bulky command/tool output (a 4 000-line `cargo build` log, a dumped JSON
//! blob, a whole file `cat`) re-enters the model's context on every turn and
//! is billed every time. This module replaces the **middle** of an oversized
//! tool result with a short marker, keeping a generous head and tail, before
//! the request is forwarded — so the model still sees the start and end (where
//! the signal usually is) at a fraction of the tokens.
//!
//! Three guard-rails, because this *modifies the outgoing request* (like cache
//! injection and the budget→fallback model rewrite, the other opt-in rewrites):
//!
//! - **Opt-in** — off by default (R2). Only runs when `proxy.trim_tool_output`.
//! - **Conservative** — only `tool_result` blocks (Anthropic) and `role:"tool"`
//!   messages (OpenAI) are touched, and only when they exceed `2*keep + slack`,
//!   so a normal-sized result is never altered. Prose, the system prompt, the
//!   user's own messages, and assistant text are never touched.
//! - **Fail-open** — any parse problem returns the body byte-for-byte unchanged
//!   and `modified = false`; trimming must never corrupt a request.
//!
//! Read-only on the *response* path is still absolute (CLAUDE.md); this is the
//! request path, and only when the user opts in.

use bytes::Bytes;
use serde_json::Value;

/// Characters of head AND tail to preserve on each side of a trimmed result.
/// Conservative: 1 200 each (≈ the first and last ~30 lines), so the model
/// keeps the command echo / error header and the final summary / exit status.
pub const DEFAULT_KEEP: usize = 1200;

/// Extra slack over `2*keep` a result must exceed before it is worth trimming —
/// trimming a string only a little larger than head+tail saves nothing once the
/// marker is added, so leave it alone.
const SLACK: usize = 200;

/// Result of a trim pass.
pub struct TrimOutcome {
    /// The (possibly rewritten) request body. Equals the input when nothing
    /// was trimmed.
    pub body: Bytes,
    /// Whether any tool output was actually trimmed.
    pub modified: bool,
    /// Bytes removed from the serialized body (a savings estimate; the token
    /// saving is roughly this / 4). Zero when nothing changed.
    pub saved_bytes: usize,
}

/// Trim oversized tool outputs in `body` when enabled. `keep` is the head/tail
/// size to preserve on each side ([`DEFAULT_KEEP`] in production).
///
/// Fail-open: a non-JSON body, or any structure we don't recognise, returns the
/// original bytes with `modified = false`.
pub fn trim(body: &Bytes, keep: usize) -> TrimOutcome {
    let unchanged = || TrimOutcome {
        body: body.clone(),
        modified: false,
        saved_bytes: 0,
    };

    // Strip a leading UTF-8 BOM the same way the scanner does, so a BOM-prefixed
    // body still parses (and, if we rewrite it, the BOM is dropped — serde never
    // re-emits one).
    let slice = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let Ok(mut value) = serde_json::from_slice::<Value>(slice) else {
        return unchanged();
    };

    let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) else {
        return unchanged();
    };

    let mut total_saved = 0usize;
    for msg in messages.iter_mut() {
        total_saved += trim_message(msg, keep);
    }

    if total_saved == 0 {
        return unchanged();
    }

    match serde_json::to_vec(&value) {
        Ok(v) => {
            let saved = body.len().saturating_sub(v.len());
            TrimOutcome {
                body: Bytes::from(v),
                // If re-serialization somehow grew the body, treat it as a no-op
                // saving but still forward the (semantically trimmed) body.
                modified: true,
                saved_bytes: saved,
            }
        }
        // Re-serialize failure is near-impossible for a Value we just parsed,
        // but if it happens, forward the original untouched (fail-open).
        Err(_) => unchanged(),
    }
}

/// Trim tool outputs within one message. Returns the char count removed.
fn trim_message(msg: &mut Value, keep: usize) -> usize {
    let role = msg.get("role").and_then(Value::as_str).unwrap_or("");

    // OpenAI: a whole message with role "tool" carries the output as `content`
    // (a plain string).
    if role == "tool" {
        if let Some(content) = msg.get_mut("content") {
            return trim_string_value(content, keep);
        }
        return 0;
    }

    // Anthropic: tool results are blocks inside a (usually user) message's
    // `content` array, each `{"type":"tool_result", "content": …}`. The inner
    // `content` is either a string or an array of `{"type":"text","text":…}`.
    let Some(blocks) = msg.get_mut("content").and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut saved = 0usize;
    for block in blocks.iter_mut() {
        if block.get("type").and_then(Value::as_str) != Some("tool_result") {
            continue;
        }
        let Some(inner) = block.get_mut("content") else {
            continue;
        };
        match inner {
            Value::String(_) => saved += trim_string_value(inner, keep),
            Value::Array(parts) => {
                for part in parts.iter_mut() {
                    if part.get("type").and_then(Value::as_str) == Some("text") {
                        if let Some(text) = part.get_mut("text") {
                            saved += trim_string_value(text, keep);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    saved
}

/// Trim a JSON string value in place. Returns the number of characters removed
/// (0 if it was left unchanged or wasn't a string).
fn trim_string_value(v: &mut Value, keep: usize) -> usize {
    let Some(s) = v.as_str() else {
        return 0;
    };
    let Some((trimmed, removed)) = trim_text(s, keep) else {
        return 0;
    };
    *v = Value::String(trimmed);
    removed
}

/// Replace the middle of an oversized string with a marker, keeping `keep`
/// characters of head and tail. Returns `None` (leave unchanged) when the
/// string is not large enough to be worth trimming. Slices on `char`
/// boundaries so multi-byte UTF-8 is never split mid-codepoint.
fn trim_text(s: &str, keep: usize) -> Option<(String, usize)> {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= 2 * keep + SLACK {
        return None;
    }
    let removed = len - 2 * keep;
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[len - keep..].iter().collect();
    let marker = format!(
        "\n\n…[burnwall trimmed {removed} characters of tool output to save tokens — head and tail kept]…\n\n"
    );
    Some((format!("{head}{marker}{tail}"), removed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn big(n: usize) -> String {
        "x".repeat(n)
    }

    #[test]
    fn trims_oversized_anthropic_tool_result_string() {
        let body = json!({
            "model": "claude-opus-4-8",
            "messages": [
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": big(10_000)}
                ]}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(out.modified, "a 10k tool result should be trimmed");
        assert!(out.saved_bytes > 5_000);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        let content = v["messages"][0]["content"][0]["content"].as_str().unwrap();
        assert!(content.contains("burnwall trimmed"));
        assert!(content.len() < 10_000);
    }

    #[test]
    fn trims_anthropic_tool_result_text_blocks() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "tool_result", "content": [
                        {"type": "text", "text": big(9_000)}
                    ]}
                ]}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(out.modified);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        let text = v["messages"][0]["content"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("burnwall trimmed"));
    }

    #[test]
    fn trims_openai_tool_role_message() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "tool", "tool_call_id": "c1", "content": big(8_000)}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(out.modified);
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        let content = v["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("burnwall trimmed"));
    }

    #[test]
    fn small_tool_result_is_left_untouched() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "tool_result", "content": "ok, done"}
                ]}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(!out.modified, "a tiny result must not be trimmed");
        assert_eq!(out.body, bytes);
    }

    #[test]
    fn never_touches_user_or_assistant_prose() {
        // A huge USER message (not a tool_result) must be left alone — we only
        // trim tool output, never the human's or model's own words.
        let body = json!({
            "messages": [
                {"role": "user", "content": big(20_000)},
                {"role": "assistant", "content": [{"type": "text", "text": big(20_000)}]}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(!out.modified, "prose must never be trimmed");
        assert_eq!(out.body, bytes);
    }

    #[test]
    fn non_json_body_is_returned_unchanged() {
        let bytes = Bytes::from_static(b"not json at all");
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(!out.modified);
        assert_eq!(out.body, bytes);
    }

    #[test]
    fn multibyte_content_is_not_split_mid_codepoint() {
        // A long run of multi-byte characters must round-trip as valid UTF-8.
        let body = json!({
            "messages": [
                {"role": "tool", "content": "日本語".repeat(2_000)}
            ]
        });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let out = trim(&bytes, DEFAULT_KEEP);
        assert!(out.modified);
        // If a codepoint were split, this parse (strict UTF-8 via serde) fails.
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert!(v["messages"][0]["content"].as_str().is_some());
    }
}
