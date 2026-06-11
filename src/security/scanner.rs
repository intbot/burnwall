//! JSON scanner.
//!
//! Two entry points over the same walk:
//!
//! - [`scan`] applies the **full** check set to every string leaf. Right for
//!   payloads that are tool-call-shaped end to end: MCP JSON-RPC bodies
//!   (`tools/call` arguments), advertised MCP tool definitions, and the
//!   `burnwall rules test` playground.
//!
//! - [`scan_request`] is context-aware, for LLM request bodies. Both the
//!   command-shaped checks (denied paths, denied commands, network mounts,
//!   destructive commands, exfil techniques) AND the data-shaped checks
//!   (secrets, DLP) run only inside **tool-call argument** subtrees — an
//!   Anthropic `tool_use.input`, an OpenAI `tool_calls` / `function_call`, a
//!   Gemini `functionCall` — and, within a conversation, only in the **latest
//!   turn's in-flight tool round** (see [`walk_turn_array`]). Prose and settled
//!   history (system prompt, chat text, tool definitions, tool results, resent
//!   earlier turns) get **no** rule checks: that text is natural language bound
//!   for the trusted provider and is resent verbatim every turn, so blocking on
//!   it merely *mentioning* a denied path, a card number, or a key-shaped token
//!   would permanently wedge the session. The harm Burnwall stops is an agent
//!   *action* — a credential or dangerous command inside a tool call — and that
//!   stays fully covered.
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
    /// apply_patch, …) → data checks (secrets, DLP) plus path/mount checks on
    /// path-shaped leaves. The argument is file *content* the model is writing,
    /// not a command to run — a README that mentions `~/.ssh` or a runbook that
    /// mentions `chmod 777` must not 403 (S-H4: the class that blocked this very
    /// review session) — but a secret or card number the agent is writing to a
    /// file, or a path argument pointing AT `~/.ssh`, still blocks.
    ContentArgs,
    /// Anywhere else (system prompt, chat text, tool definitions, tool
    /// results) → **no** rule checks. This text is prose bound for the trusted
    /// provider and is resent every turn; blocking on it merely mentioning a
    /// secret/card/path would wedge the session. Tool-call shapes found here
    /// promote their subtree to [`Scope::ToolArgs`] / [`Scope::ContentArgs`],
    /// which is where the actionable checks live.
    Prose,
    /// An already-adjudicated conversation turn → **no** rule checks, and
    /// tool-call shapes do NOT promote. See [`walk_turn_array`].
    History,
}

/// Scan every string leaf with the full check set.
pub fn scan(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::ToolArgs, None)
}

/// Context-aware scan for an LLM request body — see the module docs.
pub fn scan_request(value: &Value, rules: &Ruleset) -> Option<Violation> {
    walk(value, rules, Scope::Prose, None)
}

/// Context-aware scan for an MCP JSON-RPC body (M-C1). The envelope
/// (`jsonrpc`/`method`/`id` and most of `params`) is **prose** — a memory note
/// or issue title that merely mentions `rm -rf` or `~/.ssh` must not 403. Only
/// the `params.arguments` of a `tools/call` are real tool-call arguments and
/// get the full command set (or content + data checks for an editor-ish tool,
/// keyed on `params.name`) — including secret/DLP detection, since the args are
/// where a credential would be exfiltrated to a tool. The rest of the envelope
/// is prose and gets no checks. Mirrors the prose-safe scoping the LLM proxy
/// already uses — the MCP path was still running the full-strict `scan`.
pub fn scan_mcp(value: &Value, rules: &Ruleset) -> Option<Violation> {
    if value.get("method").and_then(Value::as_str) == Some("tools/call") {
        if let Some(params) = value.get("params") {
            if let Some(args) = params.get("arguments") {
                // MCP tools are overwhelmingly app integrations (memory, search,
                // GitHub, …) whose arguments are free text, not commands — so
                // the default (ContentArgs) is data + path checks, no command
                // checks: catch a credential exfiltrated to a tool, the real MCP
                // risk, without 403ing a memory note that merely mentions
                // `rm -rf`. Command-shaped checks apply ONLY when the tool name
                // is identifiably a shell/exec tool. This is the inverse of the
                // LLM default (where Bash/Read are common and dangerous).
                let name = params.get("name").and_then(Value::as_str);
                let scope = if name.map(is_shell_tool).unwrap_or(false) {
                    Scope::ToolArgs
                } else {
                    Scope::ContentArgs
                };
                if let Some(v) = walk(args, rules, scope, name) {
                    return Some(v);
                }
            }
        }
    }
    // The rest of the envelope is prose: no checks fire here. (The actionable
    // `tools/call` arguments were handled above.) Walked for completeness so a
    // future promotable shape inside `params` is still discovered.
    walk(value, rules, Scope::Prose, None)
}

fn walk<'a>(
    value: &'a Value,
    rules: &Ruleset,
    scope: Scope,
    tool: Option<&'a str>,
) -> Option<Violation> {
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
                // Descending into a tool-call argument subtree both sets the
                // scope and captures the tool's name, so a block can say which
                // tool (`bash`, `write_file`, …) tripped it.
                let (child_scope, child_tool) = match scope {
                    Scope::ToolArgs => (Scope::ToolArgs, tool),
                    Scope::ContentArgs => (Scope::ContentArgs, tool),
                    Scope::Prose => match tool_arg_scope(k, map) {
                        Some((sc, name)) => (sc, name.or(tool)),
                        None => (Scope::Prose, tool),
                    },
                    Scope::History => (Scope::History, tool),
                };
                if let Some(violation) = walk(v, rules, child_scope, child_tool) {
                    return Some(violation);
                }
            }
            None
        }
        Value::Array(arr) => {
            for v in arr {
                if let Some(violation) = walk(v, rules, scope, tool) {
                    return Some(violation);
                }
            }
            None
        }
        Value::String(s) => check_string(s, rules, scope, tool),
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
/// message ends the round. Data checks (secrets, DLP) follow the same scoping
/// — they fire on the in-flight tool round, not on settled/resent history (a
/// key-shaped token quoted in an old turn must not re-block forever).
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
        // Tool name is resolved deeper, on descent into the tool-call subtree.
        if let Some(violation) = walk(turn, rules, scope, None) {
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
/// subtree should get **and the tool's name** — [`Scope::ToolArgs`] for a
/// shell-ish tool (its args are commands) or [`Scope::ContentArgs`] for an
/// editor/content tool (its args are file content, S-H4). Unknown tool names
/// default to strict `ToolArgs` so an unrecognized tool keeps full coverage. The
/// name (when present) rides into the block message so a user knows which tool
/// tripped the firewall. Returns `None` if `key` isn't a tool-args slot.
fn tool_arg_scope<'a>(
    key: &str,
    obj: &'a serde_json::Map<String, Value>,
) -> Option<(Scope, Option<&'a str>)> {
    if !holds_tool_args(key, obj) {
        return None;
    }
    let name = tool_name(obj);
    let scope = if name.map(is_editor_tool).unwrap_or(false) {
        Scope::ContentArgs
    } else {
        Scope::ToolArgs
    };
    Some((scope, name))
}

/// Best-effort tool name from a tool-call object: the sibling `name`
/// (Anthropic `tool_use`, OpenAI Responses `function_call`, legacy
/// `function_call`) or the nested `function.name` (OpenAI Chat `tool_calls`).
fn tool_name(obj: &serde_json::Map<String, Value>) -> Option<&str> {
    obj.get("name").and_then(Value::as_str).or_else(|| {
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

fn check_string(s: &str, rules: &Ruleset, scope: Scope, tool: Option<&str>) -> Option<Violation> {
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
    // - Data checks (secrets, DLP): tool-call argument subtrees only — the
    //   agent ACTION surface. They do NOT run on prose or settled history
    //   (system prompt, chat text, tool results, resent earlier turns). That
    //   text is natural language bound for the trusted provider, it is resent
    //   verbatim on every turn, and re-blocking it permanently WEDGES a session
    //   over a key-shaped token that is merely discussed or quoted — the
    //   dogfooding failure that motivated this: an innocent one-line question
    //   403'd on every retry because the conversation's own /compact summary
    //   mentioned an example AWS key. The exfiltration vector that matters — a
    //   credential leaving the machine inside a tool call — stays fully covered
    //   (a secret in tool args is ToolArgs/ContentArgs and still blocks).
    let command_set = scope == Scope::ToolArgs;
    let scan_data = matches!(scope, Scope::ToolArgs | Scope::ContentArgs);
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
                    return Some(
                        Violation::new(ViolationKind::Path, rule.clone(), location).with_tool(tool),
                    );
                }
            }
        }
        if rules.block_network_mounts && rules::mount_matches(s) {
            return Some(
                Violation::new(ViolationKind::Mount, extract_mount_prefix(s), location)
                    .with_tool(tool),
            );
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
                    return Some(
                        Violation::new(ViolationKind::Path, rule.clone(), location).with_tool(tool),
                    );
                }
            }
        }
        for rule in &rules.deny_commands {
            if rules::command_matches(s, rule) {
                return Some(
                    Violation::new(ViolationKind::Command, rule.clone(), location).with_tool(tool),
                );
            }
        }
        // Catastrophic-command detection by *shape* (flag-order / spacing /
        // target expansion independent) — always on when security is enabled,
        // since these are data-loss-grade and narrow enough to avoid false
        // positives.
        if let Some(label) = super::destructive::first_match(s) {
            return Some(
                Violation::new(ViolationKind::Destructive, label, location).with_tool(tool),
            );
        }
        if rules.block_network_mounts && rules::mount_matches(s) {
            return Some(
                Violation::new(ViolationKind::Mount, extract_mount_prefix(s), location)
                    .with_tool(tool),
            );
        }
    }
    if rules.detect_secrets && scan_data {
        // Built-in patterns scan the FULL leaf — we must never miss a known
        // credential. (These are linear-time and few.) The masked preview lets
        // the block name *what* matched without echoing the raw value.
        if let Some((name, preview)) = secrets::first_match_masked(s) {
            return Some(
                Violation::new(ViolationKind::Secret, name, location)
                    .with_tool(tool)
                    .with_preview(preview),
            );
        }
        // Pack-contributed patterns are additive (extra detection). Cap the
        // input they run against (invariant I5) — an adversarial pack can't
        // weaken the built-ins above, so a miss here only forgoes a bonus
        // catch, never a built-in one.
        if !rules.secret_patterns.is_empty() {
            let hay = capped(s, MAX_PACK_SCAN_INPUT);
            if let Some((name, preview)) =
                secrets::first_match_in_masked(hay, &rules.secret_patterns)
            {
                return Some(
                    Violation::new(ViolationKind::Secret, name, location)
                        .with_tool(tool)
                        .with_preview(preview),
                );
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
                return Some(Violation::new(ViolationKind::Exfil, name, location).with_tool(tool));
            }
        }
        // Then structured exfiltration-prone data (cards, SSNs) — like secrets,
        // only inside tool-call arguments (the action), never resent prose.
        if scan_data {
            if let Some((name, preview)) = super::dlp::first_match_masked(hay) {
                return Some(
                    Violation::new(ViolationKind::Dlp, name, location)
                        .with_tool(tool)
                        .with_preview(preview),
                );
            }
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
