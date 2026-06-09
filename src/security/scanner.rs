//! JSON scanner.
//!
//! Two entry points over the same walk:
//!
//! - [`scan`] applies the **full** check set to every string leaf. Right for
//!   payloads that are tool-call-shaped end to end: MCP JSON-RPC bodies
//!   (`tools/call` arguments), advertised MCP tool definitions, and the
//!   `burnwall rules test` playground.
//!
//! - [`scan_request`] is context-aware, for LLM request bodies. Command-shaped
//!   checks (denied paths, denied commands, network mounts, destructive
//!   commands, exfil techniques) run only inside **tool-call argument**
//!   subtrees — an Anthropic `tool_use.input`, an OpenAI `tool_calls` /
//!   `function_call`, a Gemini `functionCall`. Data-shaped checks (secrets,
//!   DLP) still run on every string leaf: a credential or card number is
//!   worth blocking wherever it sits in the payload.
//!
//! The split exists because an LLM request carries far more than tool calls:
//! system prompts, chat history, tool *definitions*, tool results. Those can
//! legitimately *mention* `~/.ssh` or `rm -rf` — project docs describing a
//! deny list, a conversation about backup scripts — and only an actual tool
//! invocation should trip the firewall. Returns the **first** violation found
//! and stops scanning — there's no value in collecting all violations, the
//! proxy blocks on any one.

use serde_json::Value;

use super::rules::{self, Ruleset};
use super::secrets;
use super::{Violation, ViolationKind};

/// Which checks apply to a string leaf, by where it sits in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Inside a tool-call argument subtree → full check set.
    ToolArgs,
    /// Anywhere else (system prompt, chat text, tool definitions, tool
    /// results) → data checks only (secrets, DLP).
    Prose,
}

/// Scan every string leaf with the full check set.
pub fn scan(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::ToolArgs)
}

/// Context-aware scan for an LLM request body — see the module docs.
pub fn scan_request(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::Prose)
}

fn walk(value: &Value, rules: &Ruleset, scope: Scope) -> Option<Violation> {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let child_scope = if scope == Scope::ToolArgs || holds_tool_args(k, map) {
                    Scope::ToolArgs
                } else {
                    Scope::Prose
                };
                if let Some(violation) = walk(v, rules, child_scope) {
                    return Some(violation);
                }
            }
            None
        }
        Value::Array(arr) => {
            for v in arr {
                if let Some(violation) = walk(v, rules, scope) {
                    return Some(violation);
                }
            }
            None
        }
        Value::String(s) => check_string(s, rules, scope),
        _ => None,
    }
}

/// Does `key` (an entry of `obj`) hold tool-call arguments? Matches the
/// tool-call shapes of the supported providers without full schema knowledge:
///
/// - Anthropic content blocks: `{"type": "tool_use", "input": {…}}` (also
///   `server_tool_use` / `mcp_tool_use` via the suffix match)
/// - OpenAI Chat Completions: `{"tool_calls": […]}`, legacy
///   `{"function_call": {…}}`
/// - OpenAI Responses API items: `{"type": "function_call", "arguments": "…"}`
///   (also `custom_tool_call`, `computer_call`, … via the suffix match)
/// - Gemini: `{"functionCall": {"name": …, "args": {…}}}`
///
/// Anything else — `tools` definitions, `tool_result` content, `system`,
/// message text — is prose.
fn holds_tool_args(key: &str, obj: &serde_json::Map<String, Value>) -> bool {
    match key {
        "tool_calls" | "function_call" | "functionCall" => true,
        "input" => matches!(
            obj.get("type").and_then(Value::as_str),
            Some(t) if t.ends_with("tool_use")
        ),
        "arguments" | "args" => matches!(
            obj.get("type").and_then(Value::as_str),
            Some(t) if t.ends_with("_call")
        ),
        _ => false,
    }
}

fn check_string(s: &str, rules: &Ruleset, scope: Scope) -> Option<Violation> {
    // Order: paths → commands → mounts → secrets. Paths are the highest-
    // signal category; secrets last so a path-blocked SSH key dump doesn't
    // also accidentally trip the private-key regex.
    if scope == Scope::ToolArgs {
        // A leaf matching a project `allow_paths` exception skips the path-deny
        // checks entirely — but command, mount, and secret checks below still
        // run, so `allow_paths` can never green-light a dangerous command.
        let path_allowed = rules
            .allow_paths
            .iter()
            .any(|allow| rules::path_matches(s, allow));
        if !path_allowed {
            for rule in &rules.deny_paths {
                if rules::path_matches(s, rule) {
                    return Some(Violation {
                        kind: ViolationKind::Path,
                        matched: rule.clone(),
                    });
                }
            }
        }
        for rule in &rules.deny_commands {
            if rules::command_matches(s, rule) {
                return Some(Violation {
                    kind: ViolationKind::Command,
                    matched: rule.clone(),
                });
            }
        }
        // Catastrophic-command detection by *shape* (flag-order / spacing /
        // target expansion independent) — always on when security is enabled,
        // since these are data-loss-grade and narrow enough to avoid false
        // positives.
        if let Some(label) = super::destructive::first_match(s) {
            return Some(Violation {
                kind: ViolationKind::Destructive,
                matched: label.to_string(),
            });
        }
        if rules.block_network_mounts && rules::mount_matches(s) {
            return Some(Violation {
                kind: ViolationKind::Mount,
                matched: extract_mount_prefix(s).to_string(),
            });
        }
    }
    if rules.detect_secrets {
        // Built-in patterns scan the FULL leaf — we must never miss a known
        // credential. (These are linear-time and few.)
        if let Some(name) = secrets::first_match(s) {
            return Some(Violation {
                kind: ViolationKind::Secret,
                matched: name.to_string(),
            });
        }
        // Pack-contributed patterns are additive (extra detection). Cap the
        // input they run against (invariant I5) — an adversarial pack can't
        // weaken the built-ins above, so a miss here only forgoes a bonus
        // catch, never a built-in one.
        if !rules.secret_patterns.is_empty() {
            let hay = capped(s, MAX_PACK_SCAN_INPUT);
            if let Some(name) = secrets::first_match_in(hay, &rules.secret_patterns) {
                return Some(Violation {
                    kind: ViolationKind::Secret,
                    matched: name.to_string(),
                });
            }
        }
    }
    // Egress detection last (opt-in, v0.6.5+): exfiltration the credential and
    // path denylists miss. Bounded like the pack-secret scan.
    if rules.detect_egress {
        let hay = capped(s, MAX_PACK_SCAN_INPUT);
        // Technique-shaped exfil (DNS exfil, secret→network) first — highest
        // signal and names the technique, not the data. Command-shaped, so
        // tool-args only.
        if scope == Scope::ToolArgs {
            if let Some(name) = super::exfil::first_match(hay) {
                return Some(Violation {
                    kind: ViolationKind::Exfil,
                    matched: name.to_string(),
                });
            }
        }
        // Then structured exfiltration-prone data (cards, SSNs).
        if let Some(name) = super::dlp::first_match(hay) {
            return Some(Violation {
                kind: ViolationKind::Dlp,
                matched: name.to_string(),
            });
        }
    }
    None
}

/// Upper bound on the input length that pack-authored secret patterns run
/// against. Built-in checks are uncapped; this only bounds the untrusted,
/// additive pack scan (invariant I5).
const MAX_PACK_SCAN_INPUT: usize = 1024 * 1024;

/// Largest prefix of `s` no longer than `max` bytes that ends on a UTF-8 char
/// boundary. Returns `s` unchanged when it already fits.
fn capped(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Best-effort label for which mount needle hit, for the violation message.
fn extract_mount_prefix(s: &str) -> &'static str {
    for needle in rules::NETWORK_MOUNT_NEEDLES {
        if s.contains(needle) {
            return needle;
        }
    }
    "network mount"
}
