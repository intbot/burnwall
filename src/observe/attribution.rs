//! Cost-per-PR / per-task attribution (v0.9.1).
//!
//! Buckets local cross-tool session-log spend into the *active window of the
//! current git branch* — an approximate "what did this branch / PR cost me?".
//! Reads git metadata (branch, commit timestamps) + session logs only; never
//! reads prompt content. **Approximate:** session logs are time-bucketed, so a
//! session that spans a branch switch is attributed purely by timestamp.

use std::process::Command;

use chrono::{DateTime, Duration, Utc};

use crate::logscrape::UsageEntry;
use crate::pricing;

/// Per-(tool, model) cost within the attributed window.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelCost {
    pub tool: String,
    pub model: String,
    pub cost_usd: f64,
    pub turns: usize,
}

/// Attributed spend for a window.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribution {
    pub total_cost_usd: f64,
    pub turns: usize,
    pub by_model: Vec<ModelCost>,
}

/// Best-effort git context for the current branch (every field optional).
#[derive(Debug, Clone)]
pub struct GitContext {
    pub repo_root: Option<String>,
    pub branch: Option<String>,
    /// Window start: the oldest commit on `base..HEAD`, else the merge-base
    /// commit time, else `now - fallback_days`.
    pub since: Option<DateTime<Utc>>,
    /// True when the window came from a fallback (no forward branch commits) —
    /// attribution is rougher than usual.
    pub approximate: bool,
}

fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Resolve git context for `base` (e.g. `"main"`), falling back to a
/// `fallback_days` window when branch commit times aren't available.
pub fn git_context(base: &str, fallback_days: i64) -> GitContext {
    let repo_root = run_git(&["rev-parse", "--show-toplevel"]);
    let branch = run_git(&["rev-parse", "--abbrev-ref", "HEAD"]);

    let mut approximate = false;
    let mut since: Option<DateTime<Utc>> = None;

    if repo_root.is_some() {
        // Oldest commit time on base..HEAD = when this branch diverged forward.
        let range = format!("{base}..HEAD");
        if let Some(log) = run_git(&["log", &range, "--format=%ct"]) {
            if let Some(secs) = log
                .lines()
                .last()
                .and_then(|l| l.trim().parse::<i64>().ok())
            {
                since = DateTime::from_timestamp(secs, 0);
            }
        }
        // Fall back to the merge-base commit time.
        if since.is_none() {
            if let Some(secs) = run_git(&["merge-base", base, "HEAD"])
                .and_then(|mb| run_git(&["log", "-1", "--format=%ct", &mb]))
                .and_then(|s| s.trim().parse::<i64>().ok())
            {
                since = DateTime::from_timestamp(secs, 0);
                approximate = true;
            }
        }
    }

    if since.is_none() {
        since = Some(Utc::now() - Duration::days(fallback_days.max(1)));
        approximate = true;
    }

    GitContext {
        repo_root,
        branch,
        since,
        approximate,
    }
}

/// Attribute session-log entries to a repo window. **Pure** — no I/O. An entry
/// counts when its `workspace` is under `repo_root` (or `repo_root` is `None`)
/// and its timestamp is at/after `since` (or `since` is `None`).
pub fn attribute(
    entries: &[UsageEntry],
    repo_root: Option<&str>,
    since: Option<DateTime<Utc>>,
) -> Attribution {
    use std::collections::BTreeMap;

    let mut map: BTreeMap<(String, String), (f64, usize)> = BTreeMap::new();
    let mut total = 0.0;
    let mut turns = 0;

    for e in entries {
        let in_repo = match (repo_root, e.workspace.as_deref()) {
            (Some(root), Some(ws)) => path_under(ws, root),
            (None, _) => true,
            (Some(_), None) => false,
        };
        let in_window = since.is_none_or(|s| e.timestamp >= s);
        if !(in_repo && in_window) {
            continue;
        }
        let cost = pricing::calculate_cost(&e.model, &e.usage).unwrap_or(0.0);
        let slot = map
            .entry((e.tool.to_string(), e.model.clone()))
            .or_insert((0.0, 0));
        slot.0 += cost;
        slot.1 += 1;
        total += cost;
        turns += 1;
    }

    let mut by_model: Vec<ModelCost> = map
        .into_iter()
        .map(|((tool, model), (cost_usd, turns))| ModelCost {
            tool,
            model,
            cost_usd,
            turns,
        })
        .collect();
    by_model.sort_by(|a, b| {
        b.cost_usd
            .partial_cmp(&a.cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Attribution {
        total_cost_usd: total + 0.0, // coerce -0.0 → +0.0 for empty windows
        turns,
        by_model,
    }
}

/// Heuristic "is `path` inside `root`" — normalizes `\`→`/`, trims trailing
/// slashes, and lower-cases (Windows paths are case-insensitive; on Unix this
/// is a best-effort approximation, documented as such).
fn path_under(path: &str, root: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_end_matches('/').to_lowercase();
    let p = norm(path);
    let r = norm(root);
    p == r || p.starts_with(&format!("{r}/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::TokenUsage;

    fn entry(tool: &'static str, model: &str, ws: Option<&str>, ts: DateTime<Utc>) -> UsageEntry {
        UsageEntry {
            tool,
            model: model.to_string(),
            timestamp: ts,
            usage: TokenUsage {
                input_tokens: 1000,
                output_tokens: 500,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
            },
            reasoning_tokens: 0,
            session_id: None,
            workspace: ws.map(str::to_string),
            context_window: None,
        }
    }

    #[test]
    fn filters_by_repo_and_window() {
        let now = Utc::now();
        let old = now - Duration::days(10);
        let since = now - Duration::days(3);
        let entries = vec![
            entry("claude-code", "claude-opus-4-7", Some("/repo/app/src"), now), // in repo + window
            entry("codex", "gpt-5.5", Some("/other/proj"), now),                 // wrong repo
            entry("claude-code", "claude-opus-4-7", Some("/repo/app"), old),     // too old
        ];
        let attr = attribute(&entries, Some("/repo/app"), Some(since));
        assert_eq!(attr.turns, 1);
        assert!(attr.total_cost_usd > 0.0);
        assert_eq!(attr.by_model.len(), 1);
        assert_eq!(attr.by_model[0].model, "claude-opus-4-7");
    }

    #[test]
    fn no_repo_root_counts_all_in_window() {
        let now = Utc::now();
        let entries = vec![
            entry("claude-code", "claude-opus-4-7", Some("/a"), now),
            entry("codex", "gpt-5.5", None, now),
        ];
        let attr = attribute(&entries, None, Some(now - Duration::days(1)));
        assert_eq!(attr.turns, 2);
    }

    #[test]
    fn empty_window_is_zero_not_negative_zero() {
        let attr = attribute(&[], Some("/repo"), Some(Utc::now()));
        assert_eq!(attr.turns, 0);
        assert_eq!(attr.total_cost_usd, 0.0);
        assert!(attr.total_cost_usd.is_sign_positive());
    }

    #[test]
    fn path_under_handles_separators_and_nesting() {
        assert!(path_under("/repo/app/src", "/repo/app"));
        assert!(path_under("C:\\Code\\burnwall\\src", "C:/Code/burnwall"));
        assert!(path_under("/repo/app", "/repo/app/"));
        assert!(!path_under("/repo/application", "/repo/app")); // prefix, not a child
        assert!(!path_under("/other", "/repo/app"));
    }
}
