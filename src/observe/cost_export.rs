//! Per-repo / per-session cost CSV export (v0.9).
//!
//! Emits a clean CSV of cross-tool spend attributed *per git repo* **and** *per
//! session*, from the read-only local session-log scrape ([`UsageEntry`]).
//!
//! ### Concurrency-correct attribution
//! Each `UsageEntry` already carries its own `workspace` (which repo the turn
//! ran in) and `session_id`. Rows are grouped by the tuple
//! `(local-date, repo, session, model)` derived *from the entry itself* — never
//! by wall-clock bucket. So when several projects or sessions interleave in
//! time inside the export window, every turn lands in the right repo+session
//! bucket regardless of what ran immediately before or after it.
//!
//! Pure + metadata-only: no I/O, no network, no prompt content. The CLI
//! (`burnwall cost-per-pr --export-csv`) does the log scrape and feeds the
//! entries in; everything here is deterministic and unit-testable.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use chrono::Local;

use crate::logscrape::UsageEntry;
use crate::pricing;
use crate::providers::TokenUsage;

/// One CSV row: a single `(date, repo, session, model)` aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct CsvRow {
    /// Local calendar date (`YYYY-MM-DD`) the turns ran on.
    pub date: String,
    /// Repository the turns ran in. The entry's `workspace`, mapped to the
    /// repo it sits under when a `repo_roots` hint is supplied, else the raw
    /// workspace, else `"(unknown)"`.
    pub repo: String,
    /// Session identifier, or `"(none)"` when the tool's log carried none.
    pub session: String,
    pub model: String,
    pub requests: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub cost_usd: f64,
}

/// Build deterministically-ordered CSV rows from log-scrape entries.
///
/// `repo_roots` is an optional set of known repo root paths: when a workspace
/// sits under one of them, that root becomes the row's `repo` (so nested
/// sub-directories of one repo collapse to a single repo bucket). When empty,
/// or no root matches, the raw workspace string is used as the repo.
///
/// Grouping key is `(date, repo, session, model)` taken from each entry, so
/// interleaved repos/sessions are attributed per-turn, never by time window.
/// Output is sorted by that key (date, then repo, then session, then model),
/// giving stable, diffable CSV.
pub fn rows_from_entries(entries: &[UsageEntry], repo_roots: &[String]) -> Vec<CsvRow> {
    // Accumulator keyed by the attribution tuple. Token buckets + cost + count
    // accumulate per group; the BTreeMap gives us deterministic ordering for
    // free (lexicographic over the tuple).
    let mut map: BTreeMap<(String, String, String, String), Acc> = BTreeMap::new();

    for e in entries {
        let date = e
            .timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d")
            .to_string();
        let repo = repo_for(e.workspace.as_deref(), repo_roots);
        let session = e.session_id.clone().unwrap_or_else(|| "(none)".to_string());
        let model = e.model.clone();

        let acc = map.entry((date, repo, session, model)).or_default();
        acc.usage.input_tokens += e.usage.input_tokens;
        acc.usage.output_tokens += e.usage.output_tokens;
        acc.usage.cache_creation_tokens += e.usage.cache_creation_tokens;
        acc.usage.cache_read_tokens += e.usage.cache_read_tokens;
        acc.cost += pricing::calculate_cost(&e.model, &e.usage).unwrap_or(0.0);
        acc.requests += 1;
    }

    map.into_iter()
        .map(|((date, repo, session, model), acc)| CsvRow {
            date,
            repo,
            session,
            model,
            requests: acc.requests,
            input_tokens: acc.usage.input_tokens,
            output_tokens: acc.usage.output_tokens,
            cache_creation_tokens: acc.usage.cache_creation_tokens,
            cache_read_tokens: acc.usage.cache_read_tokens,
            // `+ 0.0` coerces a `-0.0` sum to `+0.0`.
            cost_usd: acc.cost + 0.0,
        })
        .collect()
}

#[derive(Default)]
struct Acc {
    usage: TokenUsage,
    cost: f64,
    requests: usize,
}

/// Map a workspace path to the repo bucket it belongs to.
///
/// If any `repo_roots` entry is a prefix of the workspace (path-component
/// aware, separator- and case-normalized like
/// [`crate::observe::attribution`]), the *longest* matching root wins so that
/// nested repos are not swallowed by an ancestor. Otherwise the raw workspace
/// is the repo; a missing workspace is `"(unknown)"`.
fn repo_for(workspace: Option<&str>, repo_roots: &[String]) -> String {
    let Some(ws) = workspace else {
        return "(unknown)".to_string();
    };
    let mut best: Option<&String> = None;
    for root in repo_roots {
        if path_under(ws, root) && best.is_none_or(|b| root.len() > b.len()) {
            best = Some(root);
        }
    }
    best.cloned().unwrap_or_else(|| ws.to_string())
}

/// Heuristic "is `path` inside `root`" — normalizes `\`→`/`, trims trailing
/// slashes, lower-cases (Windows is case-insensitive; on Unix this is a
/// documented best-effort approximation), and requires a path-component
/// boundary so `/repo/app` does not match `/repo/application`.
fn path_under(path: &str, root: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_end_matches('/').to_lowercase();
    let p = norm(path);
    let r = norm(root);
    p == r || p.starts_with(&format!("{r}/"))
}

/// Write `rows` as RFC 4180 CSV to `w`, including the header line.
pub fn write_csv(w: &mut impl Write, rows: &[CsvRow]) -> std::io::Result<()> {
    writeln!(
        w,
        "date,repo,session,model,requests,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,cost_usd"
    )?;
    for r in rows {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{:.6}",
            csv_field(&r.date),
            csv_field(&r.repo),
            csv_field(&r.session),
            csv_field(&r.model),
            r.requests,
            r.input_tokens,
            r.output_tokens,
            r.cache_creation_tokens,
            r.cache_read_tokens,
            r.cost_usd,
        )?;
    }
    Ok(())
}

/// Serialize one CSV field per RFC 4180: a field containing a comma, double
/// quote, CR, or LF is wrapped in double quotes with embedded quotes doubled.
/// Plain fields pass through unchanged.
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Render `rows` as a CSV string. Convenience over [`write_csv`] for callers
/// that want a buffer (e.g. writing to `--out <path>`).
pub fn to_csv_string(rows: &[CsvRow]) -> String {
    let mut buf = Vec::new();
    // Writing to a Vec<u8> is infallible.
    let _ = write_csv(&mut buf, rows);
    String::from_utf8(buf).unwrap_or_default()
}

/// Whether `path` looks like a usable filesystem path for `--out`. Purely a
/// guard so an empty `--out ""` is rejected before we try to write.
pub fn is_writable_target(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    fn entry(
        model: &str,
        ws: Option<&str>,
        session: Option<&str>,
        ts: DateTime<Utc>,
        input: u64,
        output: u64,
    ) -> UsageEntry {
        UsageEntry {
            tool: "claude-code",
            model: model.to_string(),
            timestamp: ts,
            usage: TokenUsage {
                input_tokens: input,
                output_tokens: output,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
            },
            reasoning_tokens: 0,
            session_id: session.map(str::to_string),
            workspace: ws.map(str::to_string),
            context_window: None,
        }
    }

    #[test]
    fn interleaved_repos_and_sessions_attribute_per_entry() {
        // Two repos + two sessions interleaved in time within the same minute.
        let t = |sec: u32| Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, sec).unwrap();
        let entries = vec![
            entry("m", Some("/a/proj"), Some("s1"), t(0), 100, 10),
            entry("m", Some("/b/proj"), Some("s2"), t(1), 200, 20),
            entry("m", Some("/a/proj"), Some("s1"), t(2), 100, 10), // same group as #0
            entry("m", Some("/b/proj"), Some("s3"), t(3), 50, 5),   // diff session, same repo
        ];
        let rows = rows_from_entries(&entries, &[]);
        // Groups: (a/proj,s1), (b/proj,s2), (b/proj,s3) => 3 rows.
        assert_eq!(rows.len(), 3);
        let a = rows
            .iter()
            .find(|r| r.repo == "/a/proj" && r.session == "s1")
            .unwrap();
        assert_eq!(a.requests, 2);
        assert_eq!(a.input_tokens, 200);
        assert_eq!(a.output_tokens, 20);
        // b/proj is split across two sessions, never merged by time window.
        assert!(
            rows.iter()
                .any(|r| r.repo == "/b/proj" && r.session == "s2")
        );
        assert!(
            rows.iter()
                .any(|r| r.repo == "/b/proj" && r.session == "s3")
        );
    }

    #[test]
    fn deterministic_ordering_by_tuple() {
        let t = Utc.with_ymd_and_hms(2026, 6, 11, 9, 0, 0).unwrap();
        let entries = vec![
            entry("z-model", Some("/b"), Some("s2"), t, 1, 1),
            entry("a-model", Some("/a"), Some("s1"), t, 1, 1),
            entry("a-model", Some("/a"), Some("s1"), t, 1, 1),
        ];
        let rows = rows_from_entries(&entries, &[]);
        // Sorted by (date, repo, session, model): /a before /b.
        assert_eq!(rows[0].repo, "/a");
        assert_eq!(rows.last().unwrap().repo, "/b");
        // Stable across re-runs.
        assert_eq!(rows, rows_from_entries(&entries, &[]));
    }

    #[test]
    fn repo_roots_collapse_nested_workspaces() {
        let t = Utc.with_ymd_and_hms(2026, 6, 11, 9, 0, 0).unwrap();
        let entries = vec![
            entry("m", Some("/repo/app/src"), Some("s1"), t, 1, 1),
            entry("m", Some("/repo/app/tests"), Some("s1"), t, 1, 1),
        ];
        let rows = rows_from_entries(&entries, &["/repo/app".to_string()]);
        // Both nested dirs collapse to the one repo root + session => 1 row.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].repo, "/repo/app");
        assert_eq!(rows[0].requests, 2);
    }

    #[test]
    fn longest_repo_root_wins() {
        assert_eq!(
            repo_for(
                Some("/repo/app/nested/src"),
                &["/repo".to_string(), "/repo/app/nested".to_string()]
            ),
            "/repo/app/nested"
        );
    }

    #[test]
    fn missing_and_unmatched_workspace() {
        assert_eq!(repo_for(None, &[]), "(unknown)");
        assert_eq!(repo_for(Some("/x/y"), &["/z".to_string()]), "/x/y");
    }

    #[test]
    fn missing_session_is_none_label() {
        let t = Utc.with_ymd_and_hms(2026, 6, 11, 9, 0, 0).unwrap();
        let rows = rows_from_entries(&[entry("m", Some("/a"), None, t, 1, 1)], &[]);
        assert_eq!(rows[0].session, "(none)");
    }

    #[test]
    fn csv_quoting_is_rfc4180_safe() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("he said \"hi\""), "\"he said \"\"hi\"\"\"");
        assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_output_has_header_and_quotes_repo_with_comma() {
        let t = Utc.with_ymd_and_hms(2026, 6, 11, 9, 0, 0).unwrap();
        let rows = rows_from_entries(
            &[entry("gpt", Some("/odd,name"), Some("s1"), t, 100, 50)],
            &[],
        );
        let csv = to_csv_string(&rows);
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "date,repo,session,model,requests,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,cost_usd"
        );
        let row = lines.next().unwrap();
        assert!(row.contains("\"/odd,name\""), "comma'd repo is quoted");
        assert!(row.contains("2026-06-11"));
    }

    #[test]
    fn empty_entries_yield_header_only() {
        let csv = to_csv_string(&[]);
        assert_eq!(csv.lines().count(), 1, "header line only");
    }
}
