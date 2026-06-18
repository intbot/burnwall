//! Tier-2 cost tracking — scrape local session logs from AI coding tools
//! that do *not* run through the Burnwall proxy.
//!
//! The proxy + SQLite path is authoritative for traffic Burnwall actually
//! *enforced*. This module is the complementary read-only view: it parses
//! the JSONL session logs that tools like Claude Code and Codex CLI write
//! to disk, so `burnwall status` can show total cross-tool spend — not just
//! what happened to be proxied.
//!
//! ### Principles
//! - **Read-only.** Nothing here writes to SQLite. `burnwall status`
//!   scrapes on demand and prints the result in its own section; the proxy
//!   DB is never touched, so there is no double-counting and no dedup.
//! - **Metadata only.** We read token counts, model names, and timestamps.
//!   Prompt/response *content* is never read into Burnwall, matching the
//!   "never log prompt content" rule in CLAUDE.md.
//! - **Fail-open everywhere.** A tool that isn't installed, a missing log
//!   directory, a malformed line, an unknown model — none of these are
//!   errors. They just contribute nothing. A format mismatch yields *zero*
//!   entries, never wrong numbers.
//! - **Offline.** Pure local filesystem reads; no network.
//!
//! ### Supported tools
//! Claude Code, Codex, OpenCode, and Aider write per-turn token usage to
//! local files we can read accurately. Two tools are deliberately *not*
//! parsed: **Cursor** keeps per-request usage server-side (its local
//! `state.vscdb` has no reliable token counts), so any local total would be a
//! misleading lower bound; **Cline** stores per-request tokens inside a
//! double-encoded JSON string under per-editor storage roots, and its exact
//! field shape needs confirming against a real `ui_messages.json` before we
//! parse it — shipping it unverified would risk wrong numbers, which this
//! module must never do.

pub mod aider;
pub mod claude_code;
pub mod codex;
pub mod opencode;

use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, SystemTime};

use chrono::{DateTime, Local, NaiveDate, Utc};

use crate::pricing;
use crate::providers::TokenUsage;

/// One assistant turn extracted from a tool's local log file.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageEntry {
    /// Stable tool identifier, e.g. `"claude-code"` / `"codex"`.
    pub tool: &'static str,
    pub model: String,
    pub timestamp: DateTime<Utc>,
    pub usage: TokenUsage,
    /// Reasoning/thinking tokens spent this turn — a *subset* of
    /// `usage.output_tokens` already billed at the output rate, surfaced
    /// separately so the waste engine can re-attribute it. `0` when the tool
    /// doesn't report it (Claude Code's usage block has no separate count);
    /// populated from Codex's `last_token_usage.reasoning_output_tokens`.
    /// Never added to cost math — it is informational only.
    pub reasoning_tokens: u64,
    /// Session this turn belongs to, used to group multi-turn rules
    /// (mega-sessions, runaway-context-growth). `None` when the tool's log
    /// carries no session identity.
    pub session_id: Option<String>,
    /// Working directory the turn ran in, for the per-workspace cost
    /// dimension. `None` when the log doesn't record it.
    pub workspace: Option<String>,
    /// The model's context-window size in tokens, when the log reports it
    /// (Codex's `model_context_window`). Lets the saturation rule compare a
    /// prompt against the real limit instead of a hardcoded per-model map.
    pub context_window: Option<u64>,
}

/// Per-(tool, model) aggregate for a single date — one row of the
/// "Tracked via log files" section in `burnwall status`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScrapeBreakdown {
    pub tool: &'static str,
    pub model: String,
    pub usage: TokenUsage,
    /// Billed cost in USD. `0.0` when the model is unknown to the pricing
    /// table (fail-open — a pricing miss never breaks `status`).
    pub cost: f64,
    /// Number of assistant turns that rolled into this aggregate.
    pub turns: usize,
}

impl ScrapeBreakdown {
    /// Cache hit rate as a fraction in `[0.0, 1.0]` — cache reads over total
    /// prompt-side tokens. Mirrors [`crate::storage::ModelBreakdown`].
    pub fn cache_hit_rate(&self) -> f64 {
        let prompt = self.usage.input_tokens
            + self.usage.cache_creation_tokens
            + self.usage.cache_read_tokens;
        if prompt == 0 {
            0.0
        } else {
            self.usage.cache_read_tokens as f64 / prompt as f64
        }
    }
}

/// Which tools' logs to scrape, mirroring the per-tool `[tools]` config
/// switches. Lets callers disable an individual tool without a growing
/// positional argument list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tools {
    pub claude_code: bool,
    pub codex: bool,
    pub opencode: bool,
    pub aider: bool,
}

impl Tools {
    /// Every supported tool enabled — used by `collect_all` and tests.
    pub fn all() -> Self {
        Self {
            claude_code: true,
            codex: true,
            opencode: true,
            aider: true,
        }
    }
}

/// Collect usage entries from every supported tool's logs. Fail-open: a
/// tool with no log directory or unparseable logs contributes nothing.
pub fn collect_all() -> Vec<UsageEntry> {
    collect_selected(Tools::all())
}

/// [`collect_all`] with an mtime cutoff — see [`collect_selected_since`].
pub fn collect_all_since(cutoff: Option<SystemTime>) -> Vec<UsageEntry> {
    collect_selected_since(Tools::all(), cutoff)
}

/// Collect entries only from the selected tools — honors the per-tool
/// `[tools]` config switches so a disabled tool is never read.
pub fn collect_selected(tools: Tools) -> Vec<UsageEntry> {
    collect_selected_since(tools, None)
}

/// [`collect_selected`] with an optional mtime cutoff: log files whose
/// mtime predates `cutoff` by more than [`MTIME_SAFETY_MARGIN`] are skipped
/// without being read — a file untouched since before the window started
/// cannot contribute rows inside it. `None` reads everything (the previous
/// behavior).
pub fn collect_selected_since(tools: Tools, cutoff: Option<SystemTime>) -> Vec<UsageEntry> {
    let mut entries = Vec::new();
    if tools.claude_code {
        entries.extend(claude_code::collect_since(cutoff));
    }
    if tools.codex {
        entries.extend(codex::collect_since(cutoff));
    }
    if tools.opencode {
        entries.extend(opencode::collect_since(cutoff));
    }
    if tools.aider {
        entries.extend(aider::collect_since(cutoff));
    }
    entries
}

/// Scrape every supported tool's logs and aggregate the entries that fall
/// on `date` (a *local* `YYYY-MM-DD` string) by tool + model. Files whose
/// mtime predates `date` (minus the safety margin) are never read.
pub fn scrape_for_date(date: &str) -> Vec<ScrapeBreakdown> {
    aggregate(collect_all_since(cutoff_for_local_date(date)), date)
}

/// How far past a window-start cutoff a file's mtime may lag before the
/// file is skipped unread. One day absorbs clock skew, coarse filesystem
/// timestamps, and tools that buffer writes — a file untouched for longer
/// than this before the window start cannot hold entries inside the window.
pub const MTIME_SAFETY_MARGIN: StdDuration = StdDuration::from_secs(24 * 60 * 60);

/// Pure cutoff predicate: true when a file last modified at `mtime` cannot
/// contain entries at or after `cutoff` — i.e. the mtime predates the
/// window start by more than [`MTIME_SAFETY_MARGIN`].
pub fn mtime_is_stale(mtime: SystemTime, cutoff: SystemTime) -> bool {
    match cutoff.duration_since(mtime) {
        Ok(gap) => gap > MTIME_SAFETY_MARGIN,
        // mtime is at/after the cutoff — definitely fresh.
        Err(_) => false,
    }
}

/// The window-start instant for a local `YYYY-MM-DD` date string — local
/// midnight of that date. `None` when the string doesn't parse (fail-open:
/// no pruning rather than wrong pruning).
pub fn cutoff_for_local_date(date: &str) -> Option<SystemTime> {
    let day = NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    let midnight = day
        .and_hms_opt(0, 0, 0)?
        .and_local_timezone(Local)
        .earliest()?;
    Some(SystemTime::from(midnight))
}

/// True when `path`'s mtime says the file cannot contribute entries at or
/// after `cutoff`. An unreadable mtime keeps the file (fail-open — never
/// drop data over a metadata hiccup); `cutoff == None` keeps everything.
pub(crate) fn path_is_stale(path: &Path, cutoff: Option<SystemTime>) -> bool {
    let Some(cutoff) = cutoff else {
        return false;
    };
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => mtime_is_stale(mtime, cutoff),
        Err(_) => false,
    }
}

/// Stream `path` line by line through `f`, without slurping the whole file
/// into memory (Claude Code session files can run to 100MB+). Fail-open per
/// line: a non-UTF-8 line is skipped, matching the "skip unparseable lines"
/// policy; any other I/O error stops reading the file, keeping the lines
/// already seen.
pub(crate) fn for_each_line(path: &Path, mut f: impl FnMut(&str)) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    for line in std::io::BufReader::new(file).lines() {
        match line {
            Ok(line) => f(&line),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => break,
        }
    }
}

/// Pure aggregation step, split out so tests can feed synthetic entries.
/// Keeps only entries whose *local* date equals `date`, groups by tool +
/// model, sums token buckets, costs each group via the pricing table, and
/// sorts rows by cost descending (ties broken by tool then model).
///
/// Entry timestamps are stored in UTC but compared in local time so this
/// stays consistent with `burnwall status`, whose "today" is local.
pub fn aggregate(entries: Vec<UsageEntry>, date: &str) -> Vec<ScrapeBreakdown> {
    let mut groups: BTreeMap<(&'static str, String), (TokenUsage, usize)> = BTreeMap::new();
    for entry in entries {
        if entry
            .timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d")
            .to_string()
            != date
        {
            continue;
        }
        let slot = groups
            .entry((entry.tool, entry.model.clone()))
            .or_insert((TokenUsage::default(), 0));
        slot.0.input_tokens += entry.usage.input_tokens;
        slot.0.output_tokens += entry.usage.output_tokens;
        slot.0.cache_creation_tokens += entry.usage.cache_creation_tokens;
        slot.0.cache_read_tokens += entry.usage.cache_read_tokens;
        slot.1 += 1;
    }
    let mut rows: Vec<ScrapeBreakdown> = groups
        .into_iter()
        .map(|((tool, model), (usage, turns))| {
            let cost = pricing::calculate_cost(&model, &usage).unwrap_or(0.0);
            ScrapeBreakdown {
                tool,
                model,
                usage,
                cost,
                turns,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.cost
            .partial_cmp(&a.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.tool.cmp(b.tool))
            .then_with(|| a.model.cmp(&b.model))
    });
    rows
}

/// Sum of billed cost across scrape breakdown rows.
pub fn subtotal(rows: &[ScrapeBreakdown]) -> f64 {
    rows.iter().map(|r| r.cost).sum()
}

/// Recursively collect `*.jsonl` files under `root`. See
/// [`find_files_with_ext`].
pub(crate) fn find_jsonl_files(root: &Path, cutoff: Option<SystemTime>) -> Vec<PathBuf> {
    find_files_with_ext(root, "jsonl", cutoff)
}

/// Recursively collect files with extension `ext` under `root`, pruning
/// files whose mtime predates `cutoff` by more than the safety margin (see
/// [`mtime_is_stale`]; `None` keeps everything). Returns an empty vec if
/// `root` does not exist or cannot be read; unreadable sub-entries are
/// skipped, and a file whose mtime can't be read is kept (fail-open).
pub(crate) fn find_files_with_ext(
    root: &Path,
    ext: &str,
    cutoff: Option<SystemTime>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some(ext)
            {
                if let Some(cutoff) = cutoff {
                    if let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) {
                        if mtime_is_stale(mtime, cutoff) {
                            continue;
                        }
                    }
                }
                out.push(path);
            }
        }
    }
    out
}
