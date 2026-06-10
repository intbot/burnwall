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
//!   `function_call`, a Gemini `functionCall` — and, within a conversation,
//!   only in the **latest turn's in-flight tool round** (see
//!   [`walk_turn_array`]). Data-shaped checks (secrets, DLP) still run on
//!   every string leaf: a credential or card number is worth blocking
//!   wherever it sits in the payload.
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
use super::{MatchLocation, Violation, ViolationKind};

/// Which checks apply to a string leaf, by where it sits in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Inside a **shell-ish** tool-call argument subtree (bash/exec/run/…) →
    /// full check set. The tool is one that runs a command, so its arguments
    /// are commands.
    ToolArgs,
    /// Inside an **editor/content** tool-call argument subtree (Write, Edit,
    /// apply_patch, …) → data checks only (secrets, DLP). The argument is file
    /// *content* the model is writing, not a command to run — a README that
    /// mentions `~/.ssh` or a runbook that mentions `chmod 777` must not 403
    /// (S-H4: the class that blocked this very review session). A secret or
    /// card number in that content is still worth catching, so data checks
    /// stay on.
    ContentArgs,
    /// Anywhere else (system prompt, chat text, tool definitions, tool
    /// results) → data checks only (secrets, DLP). Tool-call shapes found
    /// here promote their subtree to [`Scope::ToolArgs`] / [`Scope::ContentArgs`].
    Prose,
    /// An already-adjudicated conversation turn → data checks only, and
    /// tool-call shapes do NOT promote. See [`walk_turn_array`].
    History,
}

/// Scan every string leaf with the full check set.
pub fn scan(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::ToolArgs)
}

/// Context-aware scan for an LLM request body — see the module docs.
pub fn scan_request(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::Prose)
}

/// Context-aware scan for an MCP JSON-RPC body (M-C1). The envelope
/// (`jsonrpc`/`method`/`id` and most of `params`) is **prose** — a memory note
/// or issue title that merely mentions `rm -rf` or `~/.ssh` must not 403. Only
/// the `params.arguments` of a `tools/call` are real tool-call arguments and
/// get the full command set (or content-only checks for an editor-ish tool,
/// keyed on `params.name`). Data checks (secrets, DLP) still run across the
/// whole envelope. Mirrors the prose-safe scoping the LLM proxy already uses —
/// the MCP path was still running the full-strict `scan`.
pub fn scan_mcp(value: &Value, rules: &Ruleset) -> Option<Violation> {
    if value.get("method").and_then(Value::as_str) == Some("tools/call") {
        if let Some(params) = value.get("params") {
            if let Some(args) = params.get("arguments") {
                // MCP tools are overwhelmingly app integrations (memory, search,
                // GitHub, …) whose arguments are free text, not commands — so
                // the default is data-checks-only (catch credential exfil, the
                // real MCP risk). Command-shaped checks apply ONLY when the tool
                // name is identifiably a shell/exec tool. This is the inverse of
                // the LLM default (where Bash/Read are common and dangerous), and
                // is what keeps a memory note that mentions `rm -rf` from 403ing.
                let name = params.get("name").and_then(Value::as_str);
                let scope = if name.map(is_shell_tool).unwrap_or(false) {
                    Scope::ToolArgs
                } else {
                    Scope::ContentArgs
                };
                if let Some(v) = walk(args, rules, scope) {
                    return Some(v);
                }
            }
        }
    }
    // Data checks across the whole envelope; command-shaped checks stay scoped
    // to the arguments handled above (prose here, so they don't fire).
    walk(value, rules, Scope::Prose)
}

fn walk(value: &Value, rules: &Ruleset, scope: Scope) -> Option<Violation> {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                // Conversation turn arrays get latest-turn scoping; see
                // walk_turn_array. Only from Prose — under ToolArgs (full
                // scan) everything stays strict, and under History nothing
                // re-promotes. `input` covers the OpenAI Responses API, whose
                // items carry `type` instead of `role` (S-H6).
                if scope == Scope::Prose && (k == "messages" || k == "contents" || k == "input") {
                    if let Value::Array(turns) = v {
                        if turns
                            .iter()
                            .any(|t| t.get("role").is_some() || t.get("type").is_some())
                        {
                            if let Some(violation) = walk_turn_array(turns, rules) {
                                return Some(violation);
                            }
                            continue;
                        }
                    }
                }
                let child_scope = match scope {
                    Scope::ToolArgs => Scope::ToolArgs,
                    Scope::ContentArgs => Scope::ContentArgs,
                    Scope::Prose => tool_arg_scope(k, map).unwrap_or(Scope::Prose),
                    Scope::History => Scope::History,
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

/// Walk a conversation turn array (`messages` / `contents`) with
/// **latest-turn scoping**: only the most recent assistant/model turn can
/// carry an *actionable* tool call, and only while its round is still in
/// flight (followed by nothing but tool results). Everything earlier was the
/// latest turn of some previous request and was adjudicated then — re-scanning
/// it would make one (correctly) blocked tool call poison the conversation
/// forever, since clients resend the full history on every request. With this
/// rule a block is a speed bump, not a death sentence: the user's next
/// message ends the round, and data checks (secrets, DLP) still cover the
/// whole history.
fn walk_turn_array(turns: &[Value], rules: &Ruleset) -> Option<Violation> {
    let last_actor = turns.iter().rposition(is_actor_turn);
    let in_flight = match last_actor {
        // An empty tail means the round just started; a tail of tool results
        // means the client echoed the calls back with their outputs — the
        // moment those outputs would leave the machine.
        Some(i) => turns[i + 1..].iter().all(is_tool_result_turn),
        None => false,
    };
    for (idx, turn) in turns.iter().enumerate() {
        let scope = if in_flight && Some(idx) == last_actor {
            Scope::Prose // promotion active — its tool calls get the full set
        } else {
            Scope::History
        };
        if let Some(violation) = walk(turn, rules, scope) {
            return Some(violation);
        }
    }
    None
}

/// A turn authored by the model: Anthropic/OpenAI `assistant`, Gemini `model`,
/// or an OpenAI Responses API `function_call` item (which has no `role`).
fn is_actor_turn(turn: &Value) -> bool {
    if matches!(
        turn.get("role").and_then(Value::as_str),
        Some("assistant") | Some("model")
    ) {
        return true;
    }
    // Responses API: the model's tool call is a top-level `input` item with
    // `type: "function_call"` (or a `*_call` variant) and no role.
    matches!(
        turn.get("type").and_then(Value::as_str),
        Some(t) if t.ends_with("_call")
    )
}

/// A turn that only carries tool execution results back to the model:
/// OpenAI's `role: "tool"`, an Anthropic user message containing
/// `tool_result` blocks, a Gemini turn whose parts carry `functionResponse`.
/// (Anthropic/Gemini clients may attach extra text alongside the results —
/// reminders, environment notes — so one result block is enough to qualify.)
fn is_tool_result_turn(turn: &Value) -> bool {
    // Responses API: tool output is an `input` item with
    // `type: "function_call_output"` and no role.
    if matches!(
        turn.get("type").and_then(Value::as_str),
        Some(t) if t.ends_with("_call_output")
    ) {
        return true;
    }
    match turn.get("role").and_then(Value::as_str) {
        Some("tool") => true,
        Some("user") | Some("function") => {
            let blocks = turn
                .get("content")
                .or_else(|| turn.get("parts"))
                .and_then(Value::as_array);
            blocks.is_some_and(|blocks| {
                blocks.iter().any(|b| {
                    b.get("type").and_then(Value::as_str) == Some("tool_result")
                        || b.get("functionResponse").is_some()
                })
            })
        }
        _ => false,
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

/// If `key` (an entry of `obj`) holds tool-call arguments, return the scope its
/// subtree should get — [`Scope::ToolArgs`] for a shell-ish tool (its args are
/// commands) or [`Scope::ContentArgs`] for an editor/content tool (its args are
/// file content, S-H4). Unknown tool names default to strict `ToolArgs` so an
/// unrecognized tool keeps full coverage. Returns `None` if `key` isn't a
/// tool-args slot.
fn tool_arg_scope(key: &str, obj: &serde_json::Map<String, Value>) -> Option<Scope> {
    if !holds_tool_args(key, obj) {
        return None;
    }
    let name = tool_name(obj);
    Some(if name.map(is_editor_tool).unwrap_or(false) {
        Scope::ContentArgs
    } else {
        Scope::ToolArgs
    })
}

/// Best-effort tool name from a tool-call object: the sibling `name`
/// (Anthropic `tool_use`, OpenAI Responses `function_call`, legacy
/// `function_call`) or the nested `function.name` (OpenAI Chat `tool_calls`).
fn tool_name(obj: &serde_json::Map<String, Value>) -> Option<&str> {
    obj.get("name")
        .and_then(Value::as_str)
        .or_else(|| {
            obj.get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
        })
}

/// Does this tool name denote a shell/exec tool — one whose arguments are a
/// command line? Used for MCP scoping, where the default is data-only and only
/// a recognized shell tool gets full command-shaped checks.
fn is_shell_tool(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const SHELL_MARKERS: &[&str] = &[
        "bash",
        "shell",
        "exec",
        "terminal",
        "powershell",
        "run_command",
        "run_shell",
        "command_exec",
        "system_exec",
        "shell_command",
    ];
    n == "sh" || n == "cmd" || n == "run" || SHELL_MARKERS.iter().any(|m| n.contains(m))
}

/// Does this tool name denote an editor/content tool — one whose arguments are
/// file *content* being written, not a command to execute? Conservative: a name
/// we don't recognize stays strict (full command checks).
fn is_editor_tool(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const EDITOR_MARKERS: &[&str] = &[
        "write",
        "edit", // also matches multiedit / str_replace_editor
        "str_replace",
        "create_file",
        "apply_patch",
        "notebook",
        "new_file",
        "save_file",
        "update_file",
        "insert_edit",
    ];
    EDITOR_MARKERS.iter().any(|m| n.contains(m))
}

fn check_string(s: &str, rules: &Ruleset, scope: Scope) -> Option<Violation> {
    // Where this leaf sits — surfaced in the block message so a user can tell
    // a real action from the model quoting something (S-C3).
    let location = match scope {
        Scope::ToolArgs | Scope::ContentArgs => MatchLocation::ToolCall,
        Scope::Prose => MatchLocation::Body,
        Scope::History => MatchLocation::History,
    };
    // Which checks run where:
    // - Command/destructive/exfil checks: ONLY shell-ish tool args — a command
    //   is only dangerous where it will be executed.
    // - Path/mount checks: shell tool args, plus *path-shaped* leaves of
    //   content/editor tools — `read_file {"path": "~/.ssh/id_rsa"}` must block
    //   even though read_file is not a shell. A path-shaped leaf is short and
    //   single-line; a file body or note being written is neither, so a README
    //   that mentions `~/.ssh` in its prose passes (S-H4) while a path argument
    //   pointing AT `~/.ssh` blocks.
    // - Prose and history: data checks only.
    let command_set = scope == Scope::ToolArgs;
    let path_set = command_set || (scope == Scope::ContentArgs && path_shaped(s));

    if path_set && !command_set {
        // Path/mount checks for a content-tool's path-shaped argument.
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
                        location,
                    });
                }
            }
        }
        if rules.block_network_mounts && rules::mount_matches(s) {
            return Some(Violation {
                kind: ViolationKind::Mount,
                matched: extract_mount_prefix(s).to_string(),
                location,
            });
        }
    }

    // Order: paths → commands → mounts → secrets. Paths are the highest-
    // signal category; secrets last so a path-blocked SSH key dump doesn't
    // also accidentally trip the private-key regex.
    if command_set {
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
                        location,
                    });
                }
            }
        }
        for rule in &rules.deny_commands {
            if rules::command_matches(s, rule) {
                return Some(Violation {
                    kind: ViolationKind::Command,
                    matched: rule.clone(),
                    location,
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
                location,
            });
        }
        if rules.block_network_mounts && rules::mount_matches(s) {
            return Some(Violation {
                kind: ViolationKind::Mount,
                matched: extract_mount_prefix(s).to_string(),
                location,
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
                location,
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
                    location,
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
        if command_set {
            if let Some(name) = super::exfil::first_match(hay) {
                return Some(Violation {
                    kind: ViolationKind::Exfil,
                    matched: name.to_string(),
                    location,
                });
            }
        }
        // Then structured exfiltration-prone data (cards, SSNs).
        if let Some(name) = super::dlp::first_match(hay) {
            return Some(Violation {
                kind: ViolationKind::Dlp,
                matched: name.to_string(),
                location,
            });
        }
    }
    None
}

/// Upper bound on the input length that pack-authored secret patterns run
/// against. Built-in checks are uncapped; this only bounds the untrusted,
/// additive pack scan (invariant I5).
const MAX_PACK_SCAN_INPUT: usize = 1024 * 1024;

/// Is this leaf plausibly a *path argument* (as opposed to file content / a
/// note body)? Path arguments are short and single-line; content is long or
/// multi-line. Used to apply path checks to content-tool args without flagging
/// prose that merely mentions a protected path.
fn path_shaped(s: &str) -> bool {
    s.len() <= 512 && !s.contains('\n')
}

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
