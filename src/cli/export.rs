//! `burnwall export --format csv|json` — a clean copy of *your own* cost/usage
//! data, for a spreadsheet, an analysis, a backup, or a machine migration.
//!
//! This is **data ownership, not a support channel**: the rows stay on your
//! machine. (For a redacted bundle to *share* when something is broken, that's
//! `burnwall doctor --export`, which masks paths and aggregates the timeline.)
//!
//! Rows are per `(local date, provider, model)` aggregates — token buckets,
//! request count, cost, and cache-hit rate — the most useful spreadsheet shape
//! and small enough to diff. Distinct from `observe::cost_export`, which emits
//! git-repo/session-attributed rows from the cross-tool log scrape.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, ValueEnum};

use crate::storage::{ModelBreakdown, Storage};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Csv,
    Json,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Csv)]
    pub format: Format,
    /// How many days back to include (local calendar days, default 30).
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Write to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// One exported aggregate row.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportRow {
    pub date: String,
    pub provider: String,
    pub model: String,
    pub requests: i64,
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub cache_hit_rate: f64,
}

pub fn run_cmd(args: ExportArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);

    // Walk local calendar days newest-first → oldest, reading each day's
    // per-model breakdown. Local dates match how `status` defines "today".
    let days = args.days.max(1);
    let today = chrono::Local::now().date_naive();
    let mut per_day: Vec<(String, Vec<ModelBreakdown>)> = Vec::new();
    for back in 0..days {
        let date = today - chrono::Duration::days(back);
        let key = date.format("%Y-%m-%d").to_string();
        let rows = storage.breakdown_for_date(&key)?;
        if !rows.is_empty() {
            per_day.push((key, rows));
        }
    }
    let rows = build_rows(per_day);

    let payload = match args.format {
        Format::Csv => rows_to_csv(&rows),
        Format::Json => serde_json::to_string_pretty(&rows_to_json(&rows)).unwrap(),
    };

    match args.out {
        Some(path) => {
            std::fs::write(&path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            // Friendly confirmation on stderr so stdout stays pipe-clean even
            // with --out unset elsewhere; here we wrote a file, so eprintln.
            eprintln!(
                "Wrote {} row(s) to {} — your data, stays on your machine.",
                rows.len(),
                path.display()
            );
        }
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(payload.as_bytes())?;
            if !payload.ends_with('\n') {
                writeln!(out)?;
            }
        }
    }
    Ok(())
}

/// Flatten per-day breakdowns into a deterministically-ordered row list
/// (date desc, then provider, then model). Pure — unit-tested.
pub fn build_rows(per_day: Vec<(String, Vec<ModelBreakdown>)>) -> Vec<ExportRow> {
    let mut rows: Vec<ExportRow> = Vec::new();
    for (date, breakdown) in per_day {
        for b in breakdown {
            rows.push(ExportRow {
                date: date.clone(),
                provider: b.provider.clone(),
                model: b.model.clone(),
                requests: b.requests,
                input_tokens: b.input_tokens,
                cache_creation_tokens: b.cache_creation_tokens,
                cache_read_tokens: b.cache_read_tokens,
                output_tokens: b.output_tokens,
                cost_usd: b.cost,
                cache_hit_rate: b.cache_hit_rate(),
            });
        }
    }
    rows.sort_by(|a, b| {
        b.date
            .cmp(&a.date)
            .then(a.provider.cmp(&b.provider))
            .then(a.model.cmp(&b.model))
    });
    rows
}

const CSV_HEADER: &str = "date,provider,model,requests,input_tokens,cache_creation_tokens,cache_read_tokens,output_tokens,cost_usd,cache_hit_rate";

/// RFC 4180 CSV. Numeric fields never need quoting; the string fields are
/// escaped defensively in case a model name ever carries a comma/quote.
pub fn rows_to_csv(rows: &[ExportRow]) -> String {
    let mut s = String::new();
    s.push_str(CSV_HEADER);
    s.push('\n');
    for r in rows {
        s.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.6},{:.4}\n",
            csv_field(&r.date),
            csv_field(&r.provider),
            csv_field(&r.model),
            r.requests,
            r.input_tokens,
            r.cache_creation_tokens,
            r.cache_read_tokens,
            r.output_tokens,
            r.cost_usd,
            r.cache_hit_rate,
        ));
    }
    s
}

pub fn rows_to_json(rows: &[ExportRow]) -> serde_json::Value {
    use serde_json::json;
    json!({
        "rows": rows.iter().map(|r| json!({
            "date": r.date,
            "provider": r.provider,
            "model": r.model,
            "requests": r.requests,
            "input_tokens": r.input_tokens,
            "cache_creation_tokens": r.cache_creation_tokens,
            "cache_read_tokens": r.cache_read_tokens,
            "output_tokens": r.output_tokens,
            "cost_usd": r.cost_usd,
            "cache_hit_rate": r.cache_hit_rate,
        })).collect::<Vec<_>>(),
    })
}

/// RFC 4180 field escaping: wrap in quotes and double any embedded quotes when
/// the value contains a comma, quote, or newline.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(provider: &str, model: &str, cost: f64, requests: i64) -> ModelBreakdown {
        ModelBreakdown {
            provider: provider.into(),
            model: model.into(),
            cost,
            requests,
            input_tokens: 1000,
            cache_creation_tokens: 0,
            cache_read_tokens: 3000,
            output_tokens: 200,
        }
    }

    #[test]
    fn rows_are_sorted_date_desc_then_provider_model() {
        let per_day = vec![
            (
                "2026-06-10".to_string(),
                vec![mb("openai", "gpt-5.5", 0.04, 1)],
            ),
            (
                "2026-06-11".to_string(),
                vec![
                    mb("anthropic", "claude-opus-4-7", 0.10, 2),
                    mb("anthropic", "claude-haiku-4-5", 0.01, 5),
                ],
            ),
        ];
        let rows = build_rows(per_day);
        // Newest date first; within a date, provider then model ascending.
        assert_eq!(rows[0].date, "2026-06-11");
        assert_eq!(rows[0].model, "claude-haiku-4-5");
        assert_eq!(rows[1].model, "claude-opus-4-7");
        assert_eq!(rows[2].date, "2026-06-10");
    }

    #[test]
    fn csv_has_header_and_one_line_per_row() {
        let rows = build_rows(vec![(
            "2026-06-11".to_string(),
            vec![mb("anthropic", "claude-opus-4-7", 0.10, 2)],
        )]);
        let csv = rows_to_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("date,provider,model,requests"));
        assert_eq!(lines.len(), 2);
        // cache_hit_rate = 3000 / (1000+0+3000) = 0.75.
        assert!(lines[1].ends_with("0.7500"));
        // Deterministic.
        assert_eq!(csv, rows_to_csv(&rows));
    }

    #[test]
    fn csv_escapes_commas_in_string_fields() {
        let mut rows = build_rows(vec![(
            "2026-06-11".to_string(),
            vec![mb("anthropic", "weird,model", 0.10, 1)],
        )]);
        rows[0].model = "weird,model".to_string();
        let csv = rows_to_csv(&rows);
        assert!(csv.contains("\"weird,model\""));
    }

    #[test]
    fn json_shape_roundtrips_counts() {
        let rows = build_rows(vec![(
            "2026-06-11".to_string(),
            vec![mb("anthropic", "claude-opus-4-7", 0.10, 2)],
        )]);
        let v = rows_to_json(&rows);
        assert_eq!(v["rows"].as_array().unwrap().len(), 1);
        assert_eq!(v["rows"][0]["requests"], 2);
        assert_eq!(v["rows"][0]["provider"], "anthropic");
    }
}
