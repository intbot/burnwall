//! `burnwall accuracy` — real on-the-wire cost vs a naive token-tally estimate.
//!
//! Burnwall prices every call from the provider's *returned* token usage on the
//! response path, cache-aware: cached reads and cache-creation tokens are each
//! billed at their own rate. A naive token tally — every prompt token charged
//! at the sticker input rate — is the shortcut a log-only estimator takes when
//! it ignores the cache token classes. For cache-heavy workloads (a coding
//! agent re-sending a large stable prefix) that tally massively over-states the
//! real bill. This command contrasts the two over a window so the gap that
//! cache-aware, on-wire accounting captures is visible.
//!
//! Framing is deliberately precise: the "estimate" is *the naive non-cache-aware
//! method*, clearly labelled — not a claim about any specific other tool.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};
use crate::term::{Card, Color, Styler, fill_bar, render_cards};

#[derive(Args, Debug)]
pub struct AccuracyArgs {
    /// Day window to analyse (default 30). Alias `-n`.
    #[arg(long, short = 'n', default_value_t = 30)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

/// One model's real (on-wire, cache-aware) cost vs the naive tally.
struct ModelAccuracy {
    provider: String,
    model: String,
    real_usd: f64,
    naive_usd: f64,
}

impl ModelAccuracy {
    /// Dollars the naive tally over-states (≥ 0 for any well-formed rate card,
    /// since cached reads cost no more than base input).
    fn overstated_usd(&self) -> f64 {
        (self.naive_usd - self.real_usd).max(0.0)
    }

    /// Over-statement as a percent of the real cost, or `None` when real is 0.
    fn overstated_pct(&self) -> Option<f64> {
        if self.real_usd <= 0.0 {
            return None;
        }
        Some(self.overstated_usd() / self.real_usd * 100.0)
    }
}

/// The full report: per-model rows (over-statement first) plus totals.
struct AccuracyReport {
    days: i64,
    by_model: Vec<ModelAccuracy>,
    total_real: f64,
    total_naive: f64,
}

impl AccuracyReport {
    /// Pure: build the report from proxied per-model aggregates. Unpriced models
    /// contribute no drift (naive == real), so a missing rate card never
    /// fabricates an over-statement.
    fn from_breakdown(days: i64, rows: &[ModelBreakdown]) -> Self {
        let mut by_model: Vec<ModelAccuracy> = rows
            .iter()
            .map(|r| {
                let usage = TokenUsage {
                    input_tokens: r.input_tokens,
                    output_tokens: r.output_tokens,
                    cache_creation_tokens: r.cache_creation_tokens,
                    cache_read_tokens: r.cache_read_tokens,
                };
                let naive = pricing::get_pricing(&r.model)
                    .map(|p| pricing::cost_without_cache(&usage, p))
                    .unwrap_or(r.cost);
                ModelAccuracy {
                    provider: r.provider.clone(),
                    model: r.model.clone(),
                    real_usd: r.cost,
                    naive_usd: naive,
                }
            })
            .collect();
        // Biggest over-statement first — that's where cache accounting matters.
        by_model.sort_by(|a, b| {
            b.overstated_usd()
                .partial_cmp(&a.overstated_usd())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let total_real = by_model.iter().map(|m| m.real_usd).sum();
        let total_naive = by_model.iter().map(|m| m.naive_usd).sum();
        Self {
            days,
            by_model,
            total_real,
            total_naive,
        }
    }

    fn overstated_usd(&self) -> f64 {
        (self.total_naive - self.total_real).max(0.0)
    }

    fn overstated_pct(&self) -> Option<f64> {
        if self.total_real <= 0.0 {
            return None;
        }
        Some(self.overstated_usd() / self.total_real * 100.0)
    }
}

pub fn run_cmd(args: AccuracyArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);
    let storage = Storage::open_default().context("opening storage")?;
    let rows = storage.breakdown_since_days(days)?;
    let report = AccuracyReport::from_breakdown(days, &rows);

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, &report)?;
    } else {
        write_table(&mut out, &report)?;
    }
    Ok(())
}

fn write_table(w: &mut impl Write, r: &AccuracyReport) -> std::io::Result<()> {
    let sty = Styler::stdout();
    writeln!(
        w,
        "🔥 {} · Cost accuracy · last {} day{}",
        sty.bold("Burnwall"),
        r.days,
        if r.days == 1 { "" } else { "s" }
    )?;
    writeln!(w)?;

    if r.by_model.is_empty() || r.total_real <= 0.0 {
        writeln!(w, "  (no proxied spend in this window)")?;
        return Ok(());
    }

    let pct = r.overstated_pct().unwrap_or(0.0);
    let cards = [
        Card::new("On-wire", &format!("${:.2}", r.total_real), "cache-aware")
            .with_value_color(Color::Green),
        Card::new(
            "Naive tally",
            &format!("${:.2}", r.total_naive),
            "sticker rate",
        )
        .with_value_color(Color::Yellow),
        Card::new(
            "Overstated",
            &format!("{:.0}%", pct),
            &format!("+${:.2}", r.overstated_usd()),
        )
        .with_value_color(Color::Orange)
        .with_sub_color(Color::Orange),
    ];
    writeln!(w, "{}", render_cards(&cards, 13, 2, &sty))?;
    writeln!(w)?;

    writeln!(
        w,
        "  Burnwall prices each call from the provider's returned usage on the wire,"
    )?;
    writeln!(
        w,
        "  cache-aware. A naive tally bills every prompt token at the sticker input"
    )?;
    writeln!(
        w,
        "  rate — the shortcut a log-only estimator takes when it ignores cache reads."
    )?;
    writeln!(w)?;

    writeln!(
        w,
        "  {:<30}  {:>10}  {:>10}  {:>11}  Gap",
        "Provider / Model", "On-wire", "Naive", "Overstated"
    )?;
    writeln!(w, "  {}", "─".repeat(79))?;
    for m in &r.by_model {
        let label = format!("{}/{}", m.provider, m.model);
        // Share the over-statement against the largest one, so the bar reads as
        // "where the cache-accounting gap concentrates".
        let gap_pct = m.overstated_pct().unwrap_or(0.0).min(100.0);
        writeln!(
            w,
            "  {:<30}  ${:>9.2}  ${:>9.2}  ${:>10.2}  {} {}",
            truncate(&label, 30),
            m.real_usd,
            m.naive_usd,
            m.overstated_usd(),
            sty.paint(&fill_bar(gap_pct, 8), Color::Orange),
            match m.overstated_pct() {
                Some(p) => format!("{p:>3.0}%"),
                None => "  –".to_string(),
            },
        )?;
    }
    Ok(())
}

fn write_json(w: &mut impl Write, r: &AccuracyReport) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "days": r.days,
        "on_wire_usd": r.total_real,
        "naive_tally_usd": r.total_naive,
        "overstated_usd": r.overstated_usd(),
        "overstated_pct": r.overstated_pct(),
        "by_model": r.by_model.iter().map(|m| json!({
            "provider": m.provider,
            "model": m.model,
            "on_wire_usd": m.real_usd,
            "naive_tally_usd": m.naive_usd,
            "overstated_usd": m.overstated_usd(),
            "overstated_pct": m.overstated_pct(),
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ModelBreakdown;

    fn row(model: &str, cost: f64, input: u64, cache_read: u64, output: u64) -> ModelBreakdown {
        ModelBreakdown {
            provider: "anthropic".to_string(),
            model: model.to_string(),
            cost,
            requests: 1,
            input_tokens: input,
            cache_creation_tokens: 0,
            cache_read_tokens: cache_read,
            output_tokens: output,
        }
    }

    #[test]
    fn cache_heavy_row_is_overstated_by_the_naive_tally() {
        // A real Anthropic model with a big cached-read prefix: the naive tally
        // (all prompt tokens at input rate) must exceed the cache-aware cost.
        let model = "claude-sonnet-4-6";
        // Sanity: the model is priced, else the test asserts nothing meaningful.
        assert!(pricing::get_pricing(model).is_some());
        let rows = [row(model, 0.10, 1_000, 100_000, 2_000)];
        let r = AccuracyReport::from_breakdown(30, &rows);
        assert!(
            r.total_naive > r.total_real,
            "naive {} should exceed real {}",
            r.total_naive,
            r.total_real
        );
        assert!(r.overstated_usd() > 0.0);
        assert!(r.overstated_pct().unwrap() > 0.0);
    }

    #[test]
    fn no_cache_means_no_overstatement() {
        // With zero cached tokens, the naive tally equals the real cost.
        let rows = [row("claude-sonnet-4-6", 0.05, 5_000, 0, 1_000)];
        let r = AccuracyReport::from_breakdown(7, &rows);
        assert!(
            (r.overstated_usd()).abs() < 1e-9,
            "no cache → no gap, got {}",
            r.overstated_usd()
        );
    }

    #[test]
    fn unpriced_model_contributes_no_drift() {
        // A model with no rate card must not fabricate an over-statement.
        let rows = [row("totally-unknown-model-xyz", 0.0, 1_000, 50_000, 500)];
        let r = AccuracyReport::from_breakdown(30, &rows);
        assert_eq!(r.overstated_usd(), 0.0);
        assert!(r.overstated_pct().is_none());
    }

    #[test]
    fn rows_sort_by_overstatement_desc() {
        let rows = [
            row("claude-sonnet-4-6", 0.05, 5_000, 0, 1_000), // no gap
            row("claude-sonnet-4-6", 0.10, 1_000, 200_000, 2_000), // big gap
        ];
        let r = AccuracyReport::from_breakdown(30, &rows);
        assert!(
            r.by_model[0].overstated_usd() >= r.by_model[1].overstated_usd(),
            "biggest gap must sort first"
        );
    }
}
