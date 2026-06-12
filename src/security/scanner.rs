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
    /// Inside an **editor/content or search/fetch** tool-call argument subtree
    /// (Write, Edit, apply_patch, Grep, WebFetch, …) → path/mount checks only on
    /// a genuine path *operand* (a short, single-line value under a path-valued
    /// key — `file_path`, `path`, `notebook_path`, the `dir` a grep runs in).
    /// The other arguments are file *content* the model is writing or a *query*
    /// it is searching for, not a command to run — a README that mentions
    /// `~/.ssh`, a runbook that mentions `chmod 777`, or a grep pattern of
    /// `~/.ssh` must not 403 (S-H4 / FP-review #2,#3: the class that blocked this
    /// very review session). Data checks (secrets, DLP) run on a *search/fetch*
    /// query and on MCP app-tool args — a query or an app argument can carry a
    /// credential to a third party — but NOT on an **editor tool's file-content
    /// body** (FP-review #6, 2026-06-11): that content is bound for a LOCAL file,
    /// not egress. Reading a credential-shaped value (a tool result) never
    /// blocks, so writing one — a test fixture, a `.env.example`, a key-detection
    /// regex — must not either, and blocking it wedges hands-off sessions (the
    /// agent re-emits the same write every turn, and `/compact` 403s resending
    /// the transcript). A path operand pointing AT `~/.ssh` still blocks, and the
    /// planted-canary tripwire still fires on file content.
    ContentArgs,
    /// Anywhere else (system prompt, chat text, tool definitions, tool
    /// results) → **no** rule checks except the canary tripwire (a planted
    /// canary has no legitimate use even in prose). This text is otherwise
    /// natural language bound for the trusted provider and is resent every
    /// turn; blocking on it merely mentioning a secret/card/path would wedge
    /// the session. Tool-call shapes found here promote their subtree to
    /// [`Scope::ToolArgs`] / [`Scope::ContentArgs`], which is where the
    /// actionable checks live.
    Prose,
    /// An already-adjudicated conversation turn → **no** rule checks (not
    /// even canaries — a settled leak must not wedge the session), and
    /// tool-call shapes do NOT promote. See [`walk_turn_array`].
    History,
}

/// Invariants shared across one scan walk, passed by reference so the
/// per-node parameters (`scope`, `tool`, `key`) stay light.
struct Ctx<'a> {
    rules: &'a Ruleset,
    /// Destination provider for the credential-misdirection check (#7);
    /// `Some` only via [`scan_request_for`].
    dest_provider: Option<&'a str>,
    /// Full-strict mode ([`scan`]): every leaf gets the complete check set and
    /// the key-aware suppressions (metadata-key / path-operand-key, below) are
    /// OFF, so MCP tool-definition inspection and the `rules test` playground
    /// keep scanning every field. The context-aware request/MCP scans set this
    /// `false` so a shell tool's `description` sibling or an editor tool's
    /// free-text content leaf is not command/path-matched (false-positive
    /// review, 2026-06-11).
    strict: bool,
}

/// Scan every string leaf with the full check set.
pub fn scan(value: &Value, rules: &Ruleset) -> Option<Violation> {
    let ctx = Ctx {
        rules,
        dest_provider: None,
        strict: true,
    };
    walk(value, &ctx, Scope::ToolArgs, None, None)
}

/// Context-aware scan for an LLM request body — see the module docs.
pub fn scan_request(value: &Value, rules: &Ruleset) -> Option<Violation> {
    let ctx = Ctx {
        rules,
        dest_provider: None,
        strict: false,
    };
    walk(value, &ctx, Scope::Prose, None, None)
}

/// Like [`scan_request`] but also knows the request's **destination provider**
/// (`"anthropic"` / `"openai"` / `"google"`), enabling the credential-
/// misdirection check (feature #7, opt-in via
/// `block_credential_misdirection`): a recognized provider credential inside a
/// tool-call argument whose provider differs from `dest_provider` is blocked.
/// When the flag is off this behaves exactly like [`scan_request`].
pub fn scan_request_for(value: &Value, rules: &Ruleset, dest_provider: &str) -> Option<Violation> {
    let ctx = Ctx {
        rules,
        dest_provider: Some(dest_provider),
        strict: false,
    };
    walk(value, &ctx, Scope::Prose, None, None)
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
    let ctx = Ctx {
        rules,
        dest_provider: None,
        strict: false,
    };
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
                if let Some(v) = walk(args, &ctx, scope, name, None) {
                    return Some(v);
                }
            }
        }
    }
    // The rest of the envelope is prose: no checks fire here. (The actionable
    // `tools/call` arguments were handled above.) Walked for completeness so a
    // future promotable shape inside `params` is still discovered.
    walk(value, &ctx, Scope::Prose, None, None)
}

/// Upper bound on bytes scanned from a raw (non-JSON) file-upload body
/// ([`scan_raw_upload`]). A multipart upload can be large; we inspect only a
/// bounded prefix to keep the hot path cheap, accepting that a secret buried
/// past the cap is missed (fail-open, like every other inspection limit).
pub const MAX_RAW_UPLOAD_SCAN: usize = 1024 * 1024;

/// If the decoded text of `body` is more than this fraction non-UTF-8 /
/// control bytes, treat it as binary and skip (return `None`). A genuine
/// file upload of an image or archive is unscannable as text, so scanning it
/// would only produce noise; fail open.
const BINARY_RATIO_THRESHOLD: f64 = 0.30;

/// Scan a **raw, non-JSON** request body (a multipart/form-data file upload to
/// a provider file endpoint) for exfiltration-prone content: built-in secret
/// patterns, DLP (card/SSN), and planted canaries. Returns the first violation
/// or `None`.
///
/// This is the one body inspection in the proxy that is deliberately NOT
/// tool-call-scoped, and that is correct here: a raw file upload has no
/// "prose vs tool-call" structure to scope by — the entire body IS the egress
/// payload the user is shipping to the provider, so the whole thing is the
/// action surface. (A JSON chat body, by contrast, is mostly resent
/// history/prose and must stay scoped — that path never reaches here.) Gated
/// by the caller on the existing `detect_egress` (`security.dlp`) opt-in and a
/// known file-upload route; command/path/mount checks do NOT run (there is no
/// command in a file body). Bounds: at most [`MAX_RAW_UPLOAD_SCAN`] bytes are
/// examined, and a body that is largely non-text (an image/archive) is treated
/// as unscannable and fails open.
pub fn scan_raw_upload(body: &[u8], rules: &Ruleset) -> Option<Violation> {
    if !rules.enabled || !rules.detect_egress {
        return None;
    }
    let slice = &body[..body.len().min(MAX_RAW_UPLOAD_SCAN)];
    // Lossy decode: a clearly-binary body yields many U+FFFD replacements.
    let text = String::from_utf8_lossy(slice);
    let replacements = text.chars().filter(|&c| c == '\u{FFFD}').count();
    let total = text.chars().count().max(1);
    if (replacements as f64 / total as f64) > BINARY_RATIO_THRESHOLD {
        // Unscannable as text — fail open (warn once is the caller's job; here
        // we just decline so a real image upload isn't garbage-matched).
        return None;
    }
    let location = MatchLocation::Body;
    // Canary tripwire first — a canary has no legitimate use in any payload.
    for canary in &rules.canaries {
        if canary.len() >= rules::MIN_CANARY_LEN && text.contains(canary.as_str()) {
            return Some(
                Violation::new(ViolationKind::Canary, "planted canary credential", location)
                    .with_preview(secrets::mask_match(canary)),
            );
        }
    }
    if rules.detect_secrets {
        if let Some((name, preview)) = secrets::first_match_masked(&text) {
            return Some(
                Violation::new(ViolationKind::Secret, name, location).with_preview(preview),
            );
        }
        if !rules.secret_patterns.is_empty() {
            if let Some((name, preview)) =
                secrets::first_match_in_masked(&text, &rules.secret_patterns)
            {
                return Some(
                    Violation::new(ViolationKind::Secret, name.to_string(), location)
                        .with_preview(preview),
                );
            }
        }
    }
    if let Some((name, preview)) = super::dlp::first_match_masked(&text) {
        return Some(Violation::new(ViolationKind::Dlp, name, location).with_preview(preview));
    }
    None
}

fn walk<'a>(
    value: &'a Value,
    ctx: &Ctx<'_>,
    scope: Scope,
    tool: Option<&'a str>,
    key: Option<&'a str>,
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
                            if let Some(violation) = walk_turn_array(turns, ctx) {
                                return Some(violation);
                            }
                            continue;
                        }
                    }
                }
                // Descending into a tool-call argument subtree both sets the
                // scope and captures the tool's name, so a block can say which
                // tool (`bash`, `write_file`, …) tripped it. The child's KEY
                // rides along so a leaf can be judged by what slot it fills —
                // a path operand vs. free-text content, a command vs. its
                // description (see check_string).
                let (child_scope, child_tool) = match scope {
                    Scope::ToolArgs => (Scope::ToolArgs, tool),
                    Scope::ContentArgs => (Scope::ContentArgs, tool),
                    Scope::Prose => match tool_arg_scope(k, map) {
                        Some((sc, name)) => (sc, name.or(tool)),
                        None => (Scope::Prose, tool),
                    },
                    Scope::History => (Scope::History, tool),
                };
                if let Some(violation) = walk(v, ctx, child_scope, child_tool, Some(k.as_str())) {
                    return Some(violation);
                }
            }
            None
        }
        Value::Array(arr) => {
            // A string inside an array inherits the array's key (e.g. each
            // element of a `command: [...]` argv list is still a command).
            for v in arr {
                if let Some(violation) = walk(v, ctx, scope, tool, key) {
                    return Some(violation);
                }
            }
            None
        }
        Value::String(s) => check_string(s, ctx, scope, tool, key),
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
fn walk_turn_array(turns: &[Value], ctx: &Ctx<'_>) -> Option<Violation> {
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
        // Tool name + leaf key are resolved deeper, on descent into the
        // tool-call subtree.
        if let Some(violation) = walk(turn, ctx, scope, None, None) {
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
/// shell-ish tool (its args are commands), [`Scope::ContentArgs`] for an
/// editor/content tool (its args are file content, S-H4), or [`Scope::Prose`]
/// for a sub-agent/prompt tool (its args are a natural-language instruction to
/// another agent, scanned like chat text). Unknown tool names default to strict
/// `ToolArgs` so an unrecognized tool keeps full coverage. The name (when
/// present) rides into the block message so a user knows which tool tripped the
/// firewall. Returns `None` if `key` isn't a tool-args slot.
fn tool_arg_scope<'a>(
    key: &str,
    obj: &'a serde_json::Map<String, Value>,
) -> Option<(Scope, Option<&'a str>)> {
    if !holds_tool_args(key, obj) {
        return None;
    }
    let name = tool_name(obj);
    // A recognized shell/exec tool keeps the strict command set. An editor tool
    // carries file *content*, and a search/fetch tool carries a *query* — both
    // get content scope (data + path-operand checks, no command checks): an
    // editor's free-text body or a grep's pattern can name `~/.ssh` or `rm -rf`
    // without it being an action, while a genuine path operand (the file being
    // written, the directory being searched) still blocks. A sub-agent/prompt
    // tool carries a natural-language *instruction* — semantically the user's
    // own prose — so it gets prose scope (no path/command/data checks); its
    // denied-path mentions are descriptions, and the spawned agent's OWN tool
    // calls are scanned independently. An unrecognized tool stays strict so
    // coverage never silently drops.
    let scope = if name.map(is_shell_tool).unwrap_or(false) {
        Scope::ToolArgs
    } else if name.map(is_editor_tool).unwrap_or(false) || name.map(is_search_tool).unwrap_or(false)
    {
        Scope::ContentArgs
    } else if name.map(is_prompt_tool).unwrap_or(false) {
        Scope::Prose
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

/// Does this tool name denote a read-only search/fetch tool — one whose primary
/// argument is a *query* (a pattern, a URL, a glob), not a command to run or
/// file content to write? Such a query routinely contains a denied path *as a
/// search string* (grepping the codebase FOR `~/.ssh`) or a dangerous command
/// *as text to find* — searching for a string is not executing or opening it.
/// Routed to [`Scope::ContentArgs`] so the query leaf gets no command/path
/// match (only a genuine path *operand* under a path key — e.g. the directory a
/// grep runs IN — is still checked), while secrets/canary/DLP still scan it (a
/// query must not carry a live credential). `is_shell_tool` is checked first by
/// the caller, so a tool that also runs commands (`search_and_exec`) stays
/// strict.
fn is_search_tool(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const SEARCH_MARKERS: &[&str] = &[
        "grep",
        "glob",
        "ripgrep",
        "websearch",
        "web_search",
        "webfetch",
        "web_fetch",
        "fetch_url",
        "read_url",
        "search",
        "find_files",
        "list_dir",
        "list_files",
        "codebase_search",
    ];
    SEARCH_MARKERS.iter().any(|m| n.contains(m))
}

/// Does this tool name denote a sub-agent / prompt-dispatch tool — one whose
/// argument is a natural-language instruction handed to another agent, not a
/// command, a path, or file content? Such a prompt routinely *names* sensitive
/// paths or commands while only *describing* work (a security-research prompt
/// that mentions `~/.ssh`, a task that says "leave /etc/passwd alone"), and it is
/// resent verbatim as the in-flight turn on every retry — so path/command checks
/// here 403 in a loop and wedge the session. It is therefore scoped as prose
/// (like the user's own chat text): no path/command/data checks. Nothing is lost
/// because the real file/command access happens in the spawned agent's OWN tool
/// calls, which the proxy scans independently. `is_shell_tool` is checked first
/// by the caller, so a shell tool that happens to contain one of these markers
/// (e.g. `agent_bash`) still gets the strict command set.
fn is_prompt_tool(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // Whole-name matches for the common launchers. The original substring form
    // (`contains("agent")`) wrongly downgraded any tool whose name merely
    // *contained* "agent"/"task" — e.g. `user_agent_fetch` — to prose, under-
    // scanning it. Match the dedicated launcher token, not an incidental
    // substring: an exact name, a `_agent`/`-agent` suffix, an `agent_`/`task_`/
    // `dispatch_` prefix, or `subagent` anywhere.
    const PROMPT_NAMES: &[&str] = &[
        "agent",
        "task",
        "subagent",
        "dispatch",
        "dispatch_agent",
        "oracle",
        "delegate",
    ];
    if PROMPT_NAMES.contains(&n.as_str()) {
        return true;
    }
    n.contains("subagent")
        || n.ends_with("_agent")
        || n.ends_with("-agent")
        || n.starts_with("agent_")
        || n.starts_with("agent-")
        || n.starts_with("task_")
        || n.starts_with("dispatch_")
}

fn check_string(
    s: &str,
    ctx: &Ctx<'_>,
    scope: Scope,
    tool: Option<&str>,
    key: Option<&str>,
) -> Option<Violation> {
    let rules = ctx.rules;
    let dest_provider = ctx.dest_provider;
    // Where this leaf sits — surfaced in the block message so a user can tell
    // a real action from the model quoting something (S-C3).
    let location = match scope {
        Scope::ToolArgs | Scope::ContentArgs => MatchLocation::ToolCall,
        Scope::Prose => MatchLocation::Body,
        Scope::History => MatchLocation::History,
    };

    // Canary tripwire — checked first and in every scope EXCEPT History. A
    // canary value has no legitimate use anywhere, so even a prose mention is
    // an exfiltration attempt worth stopping; but a canary sitting in settled
    // history is a leak that was already detected and adjudicated, and
    // re-blocking the resent transcript would wedge the session forever. The
    // tripwire's job — detection at the FIRST exfiltration attempt — is done.
    if scope != Scope::History && !rules.canaries.is_empty() {
        if let Some(v) = canary_match(s, rules, location, tool) {
            return Some(v);
        }
    }

    // Invisible-character handling (ToolArgs/ContentArgs only): a leaf dense
    // with suspicious zero-width/invisible chars is blocked as hidden content;
    // a leaf with a few is normalized (stripped) so split-token evasion can't
    // defeat the pattern checks below. Fast path: a pure-ASCII leaf cannot
    // contain them, so the common case costs one byte scan. Prose/History get
    // neither check — that text is natural language for the trusted provider.
    let deep = matches!(scope, Scope::ToolArgs | Scope::ContentArgs);
    let mut normalized: Option<String> = None;
    if deep && !s.is_ascii() {
        let inv = super::evasion::scan_invisible(s);
        if inv.suspicious >= super::evasion::INVISIBLE_THRESHOLD {
            return Some(
                Violation::new(
                    ViolationKind::Obfuscation,
                    format!("{} invisible characters", inv.suspicious),
                    location,
                )
                .with_tool(tool),
            );
        }
        if inv.total > 0 {
            normalized = Some(super::evasion::strip_invisible(s));
        }
    }
    // Below this point, all checks run on the normalized text (identical to
    // the original when no invisible chars were present). The forwarded
    // request itself is never modified.
    let s: &str = normalized.as_deref().unwrap_or(s);
    if normalized.is_some() {
        // Stripping may have rejoined a split canary — re-check.
        if let Some(v) = canary_match(s, rules, location, tool) {
            return Some(v);
        }
    }
    // Which checks run where:
    // - Command/destructive/exfil checks: ONLY shell-ish tool args — a command
    //   is only dangerous where it will be executed — and only on the operand
    //   leaf, not a metadata sibling (see `meta_key` below).
    // - Path/mount checks: shell tool args, plus genuine path *operands* of
    //   content/editor/search tools — `read_file {"path": "~/.ssh/id_rsa"}` or
    //   `write_file {"file_path": "~/.ssh/authorized_keys"}` must block even
    //   though those are not shells. The operand is a short, single-line value
    //   under a *path-valued key* (`path`, `file_path`, `notebook_path`, …); an
    //   editor's free-text body (`old_string`, `content`) or a search pattern is
    //   NOT a path operand, so a doc that mentions `~/.ssh` in its text passes
    //   (S-H4 / FP-review #2,#3) while a path argument pointing AT `~/.ssh`
    //   blocks.
    // - Data checks (secrets, DLP): the agent EGRESS surface only. They do NOT
    //   run on prose or settled history (system prompt, chat text, tool results,
    //   resent earlier turns) — that text is natural language bound for the
    //   trusted provider, resent verbatim every turn, so re-blocking it
    //   permanently WEDGES a session over a key-shaped token that is merely
    //   discussed or quoted (an innocent one-line question 403'd on every retry
    //   because a /compact summary mentioned an example AWS key). They also do
    //   NOT run on an editor tool's file-content BODY (#6): that content is
    //   written to a LOCAL file, not shipped off the machine — reading such a
    //   value never blocks, so writing a test fixture / `.env.example` /
    //   key-detection regex must not either (the second /compact wedge: a
    //   resent `Edit` carrying a fake key in its `new_string`). The exfiltration
    //   vectors that matter stay fully covered — a credential inside a shell
    //   command (ToolArgs), a search/fetch query or MCP app-tool argument
    //   (ContentArgs), or a raw file upload all still block. Where data checks
    //   do run, they run regardless of key, so a secret hidden in any field is
    //   caught.
    //
    // Key-aware suppression (false-positive review, 2026-06-11) is active ONLY
    // in the context-aware request/MCP scans (`ctx.strict == false`); the
    // full-strict `scan` (MCP tool-definition inspection, `rules test`) keeps
    // the original every-field behavior:
    //   #4 — a shell tool carries its command in `command`/`script`/argv; a
    //        sibling `description`/`explanation`/`reasoning` is prose ABOUT the
    //        command, not the command, so command-shaped checks skip a metadata-
    //        keyed leaf (a Bash call whose `description` names `~/.ssh` no longer
    //        403s). Data checks still run on it.
    //   #3 — an editor/content/search tool's path checks fire only on a leaf
    //        that IS a path operand (path-valued key + short single line), never
    //        on free-text content that merely mentions a path.
    //   #6 — an editor/file-write tool's content body gets NO data checks
    //        (`editor_content`, below); the file is local, not egress.
    let meta_key = !ctx.strict && key.map(is_metadata_key).unwrap_or(false);
    let command_set = scope == Scope::ToolArgs && !meta_key;
    // #6 — an editor/file-write tool's argument body is content bound for a
    // LOCAL file, not an egress payload, so the data checks (secrets, DLP,
    // misdirection) do NOT run on it: a test fixture, a `.env.example`, or a
    // key-detection regex must not 403, and blocking it wedges hands-off
    // sessions. The path *operand* (the file being written) is still checked
    // (`content_path`, below) and the canary tripwire still fires (above);
    // search/fetch queries and MCP app-tool args keep data checks (a query or
    // arg can carry a credential to a third party). Suppressed only in the
    // context-aware scans, never in full-strict `scan`.
    let editor_content =
        !ctx.strict && scope == Scope::ContentArgs && tool.map(is_editor_tool).unwrap_or(false);
    let scan_data = matches!(scope, Scope::ToolArgs | Scope::ContentArgs) && !editor_content;
    let content_path =
        scope == Scope::ContentArgs && key.map(is_path_key).unwrap_or(false) && path_shaped(s);
    let path_set = command_set || content_path;

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
    // Credential misdirection (feature #7, opt-in): a recognized provider
    // credential inside a tool-call argument whose provider differs from the
    // request's destination. Checked before the generic secret block so the
    // more specific message wins; only when the flag is on AND we know the
    // destination AND the providers actually differ. A matching-provider key
    // (e.g. an Anthropic key bound for Anthropic) is NOT misdirected and falls
    // through to the normal secret handling below. Scoped to tool-call args
    // (the action surface), like every other data check.
    if rules.block_credential_misdirection && scan_data {
        if let (Some(dest), Some((cred_provider, _name, preview))) =
            (dest_provider, secrets::first_provider_match_masked(s))
        {
            if cred_provider != dest {
                let label = format!("a {cred_provider} credential to the {dest} endpoint");
                return Some(
                    Violation::new(ViolationKind::Misdirection, label, location)
                        .with_tool(tool)
                        .with_preview(preview),
                );
            }
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
    // Decode-then-scan (ToolArgs/ContentArgs only), after the plaintext checks
    // came up clean: find base64/hex tokens, decode within strict CPU bounds,
    // and re-run the data + path checks on the decoded text so an encoded
    // secret/card/path can't slip past the plaintext patterns. Fast path: one
    // byte scan; leaves without a long encoded run pay nothing more.
    // Decode-then-scan re-runs the data + path checks on decoded base64/hex, so
    // it must honour the editor-content carve-out (#6) too — otherwise a base64
    // blob in a file the agent is writing would block while its plaintext form
    // passes. Encoded exfiltration through a LOCAL file write is not a vector;
    // the shell / search-fetch / MCP / raw-upload paths still decode-and-scan.
    if deep && !editor_content && super::evasion::has_encoded_run(s) {
        if let Some(v) = super::evasion::scan_encoded(s, rules, location, tool) {
            return Some(v);
        }
    }
    None
}

/// First configured canary value appearing as a substring of `s`, as a
/// [`ViolationKind::Canary`] violation. The matched label never carries the
/// canary itself — only a masked preview rides along, consistent with the
/// never-echo-secrets principle (a canary is fake, but training users to see
/// credential-shaped strings echoed back is the wrong habit).
fn canary_match(
    s: &str,
    rules: &Ruleset,
    location: MatchLocation,
    tool: Option<&str>,
) -> Option<Violation> {
    for canary in &rules.canaries {
        // Defense in depth: construction already filters short values
        // ([`rules::armed_canaries`]), but a hand-built Ruleset might not.
        if canary.len() >= rules::MIN_CANARY_LEN && s.contains(canary.as_str()) {
            return Some(
                Violation::new(ViolationKind::Canary, "planted canary credential", location)
                    .with_tool(tool)
                    .with_preview(secrets::mask_match(canary)),
            );
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

/// Does `key` name a filesystem *path operand* — the thing a tool opens, reads,
/// writes, or searches in — as opposed to free-text content, a note body, or a
/// search pattern? Used to scope a content/editor/search tool's path checks to
/// true path arguments (`path`, `file_path`, `notebook_path`, the `dir` a grep
/// runs in, …) so editing a doc whose text merely mentions `~/.ssh` does not
/// 403, while a path argument pointing AT `~/.ssh` still blocks (FP-review
/// #2,#3, 2026-06-11). Matched case-insensitively against a known set plus the
/// common `_path`/`_file`/`_dir` suffixes.
fn is_path_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const PATH_KEYS: &[&str] = &[
        "path",
        "filepath",
        "file_path",
        "file",
        "filename",
        "fname",
        "notebook_path",
        "notebookpath",
        "target_file",
        "targetfile",
        "target_path",
        "targetpath",
        "dir",
        "directory",
        "folder",
        "src",
        "source",
        "source_path",
        "dest",
        "destination",
        "dest_path",
        "output_path",
        "outputpath",
        "output_file",
        "out_file",
        "old_path",
        "new_path",
        "abs_path",
        "absolute_path",
        "relative_path",
        "cwd",
        "workdir",
        "working_directory",
        "pathname",
    ];
    PATH_KEYS.contains(&k.as_str())
        || k.ends_with("_path")
        || k.ends_with("_file")
        || k.ends_with("_dir")
        || k.ends_with("_directory")
}

/// Does `key` name an explanatory / metadata field — prose ABOUT a tool call,
/// not an operand of it (`description`, `explanation`, `reasoning`, …)? A shell
/// tool's command lives in its command field; a sibling description that merely
/// names a denied path or command is commentary (Claude Code's Bash tool, for
/// one, pairs `command` with a human-readable `description`), so the command-
/// shaped checks skip it (data checks still run). Suppressed only in the
/// context-aware scans, never in full-strict `scan` (FP-review #4, 2026-06-11).
fn is_metadata_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const META_KEYS: &[&str] = &[
        "description",
        "explanation",
        "comment",
        "reasoning",
        "thought",
        "rationale",
        "justification",
        "summary",
        "note",
        "notes",
        "purpose",
        "intent",
    ];
    META_KEYS.contains(&k.as_str())
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
