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

pub mod claude_code;
pub mod codex;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

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

/// Collect usage entries from every supported tool's logs. Fail-open: a
/// tool with no log directory or unparseable logs contributes nothing.
pub fn collect_all() -> Vec<UsageEntry> {
    let mut entries = Vec::new();
    entries.extend(claude_code::collect());
    entries.extend(codex::collect());
    entries
}

/// Scrape every supported tool's logs and aggregate the entries that fall
/// on `date` (a UTC `YYYY-MM-DD` string) by tool + model.
pub fn scrape_for_date(date: &str) -> Vec<ScrapeBreakdown> {
    aggregate(collect_all(), date)
}

/// Pure aggregation step, split out so tests can feed synthetic entries.
/// Keeps only entries whose UTC date equals `date`, groups by tool + model,
/// sums token buckets, costs each group via the pricing table, and sorts
/// rows by cost descending (ties broken by tool then model).
pub fn aggregate(entries: Vec<UsageEntry>, date: &str) -> Vec<ScrapeBreakdown> {
    let mut groups: BTreeMap<(&'static str, String), (TokenUsage, usize)> = BTreeMap::new();
    for entry in entries {
        if entry.timestamp.format("%Y-%m-%d").to_string() != date {
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

/// Recursively collect `*.jsonl` files under `root`, newest paths last.
/// Returns an empty vec if `root` does not exist or cannot be read;
/// unreadable sub-entries are skipped (fail-open).
pub(crate) fn find_jsonl_files(root: &Path) -> Vec<PathBuf> {
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
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("jsonl")
            {
                out.push(path);
            }
        }
    }
    out
}
