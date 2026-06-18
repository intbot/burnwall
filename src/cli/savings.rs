//! `burnwall savings` — your own *measured* cost-savings report.
//!
//! The honest ROI surface: instead of a marketing percentage, this shows the
//! dollars **you actually recovered** through prompt caching over a window,
//! computed from your real token buckets at the provider's published cache-read
//! vs. base-input rates. It also flags where caching is **underused** so the
//! recoverable opportunity is visible — without inventing a number we can't
//! measure.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};

#[derive(Args, Debug)]
pub struct SavingsArgs {
    /// How many days back to include (default 30).
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: SavingsArgs) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let rows = storage.breakdown_since_days(args.days)?;
    let report = Report::from_rows(&rows);
    let mut out = std::io::stdout().lock();

    if args.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report.to_json())?)?;
        return Ok(());
    }

    writeln!(out, "💰 Savings & cost (last {} days)", args.days)?;
    writeln!(out)?;
    if report.real_spend == 0.0 {
        writeln!(out, "   No proxied spend yet in this window.")?;
        return Ok(());
    }
    writeln!(out, "   Real spend:             ${:.2}", report.real_spend)?;
    writeln!(
        out,
        "   Without caching:        ${:.2}   (what you'd pay with no cache reads)",
        report.without_cache
    )?;
    writeln!(
        out,
        "   Cache savings captured: ${:.2}   ({:.0}% off)",
        report.captured,
        report.captured_pct()
    )?;
    writeln!(out)?;

    if report.opportunities.is_empty() {
        writeln!(
            out,
            "   ✓ No major caching opportunities — cache use looks healthy."
        )?;
    } else {
        writeln!(out, "   Opportunity — models underusing cache:")?;
        for o in &report.opportunities {
            writeln!(
                out,
                "     {:<28} cache-read {:>3.0}%   ${:.2} spent",
                format!("{}/{}", o.provider, o.model),
                o.cache_read_pct,
                o.cost
            )?;
        }
        writeln!(
            out,
            "   Enabling prompt caching on these can cut input cost up to 90% on the cached portion."
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "   (Captured savings are your own measured numbers — cache-read vs base-input rates.)"
    )?;
    Ok(())
}

struct Opportunity {
    provider: String,
    model: String,
    cache_read_pct: f64,
    cost: f64,
}

struct Report {
    real_spend: f64,
    without_cache: f64,
    captured: f64,
    opportunities: Vec<Opportunity>,
}

impl Report {
    fn from_rows(rows: &[ModelBreakdown]) -> Report {
        let mut real_spend = 0.0;
        let mut without_cache = 0.0;
        let mut opportunities = Vec::new();

        for r in rows {
            let usage = row_usage(r);
            // Only models with a known rate card contribute to the measured math.
            if let Some(p) = pricing::get_pricing(&r.model) {
                real_spend += pricing::cost(&usage, p);
                without_cache += pricing::cost_without_cache(&usage, p);
            }
            // Opportunity: meaningful spend but low cache-read share of the
            // prompt. Conservative thresholds so we don't nag on small/healthy
            // usage.
            let prompt = r.input_tokens + r.cache_creation_tokens + r.cache_read_tokens;
            if prompt > 0 && r.cost >= 0.50 {
                let cache_read_pct = (r.cache_read_tokens as f64 / prompt as f64) * 100.0;
                if cache_read_pct < 30.0 {
                    opportunities.push(Opportunity {
                        provider: r.provider.clone(),
                        model: r.model.clone(),
                        cache_read_pct,
                        cost: r.cost,
                    });
                }
            }
        }
        // Biggest spend first.
        opportunities.sort_by(|a, b| b.cost.total_cmp(&a.cost));

        let captured = (without_cache - real_spend).max(0.0);
        Report {
            real_spend,
            without_cache,
            captured,
            opportunities,
        }
    }

    fn captured_pct(&self) -> f64 {
        if self.without_cache > 0.0 {
            (self.captured / self.without_cache) * 100.0
        } else {
            0.0
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "real_spend_usd": self.real_spend,
            "without_cache_usd": self.without_cache,
            "cache_savings_captured_usd": self.captured,
            "cache_savings_captured_pct": self.captured_pct(),
            "opportunities": self.opportunities.iter().map(|o| serde_json::json!({
                "provider": o.provider,
                "model": o.model,
                "cache_read_pct": o.cache_read_pct,
                "cost_usd": o.cost,
            })).collect::<Vec<_>>(),
        })
    }
}

fn row_usage(r: &ModelBreakdown) -> TokenUsage {
    TokenUsage {
        input_tokens: r.input_tokens,
        output_tokens: r.output_tokens,
        cache_creation_tokens: r.cache_creation_tokens,
        cache_read_tokens: r.cache_read_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        model: &str,
        input: u64,
        cache_create: u64,
        cache_read: u64,
        output: u64,
        cost: f64,
    ) -> ModelBreakdown {
        ModelBreakdown {
            provider: "anthropic".to_string(),
            model: model.to_string(),
            cost,
            requests: 1,
            input_tokens: input,
            cache_creation_tokens: cache_create,
            cache_read_tokens: cache_read,
            output_tokens: output,
        }
    }

    #[test]
    fn captured_savings_is_without_minus_real_and_nonnegative() {
        // Heavy cache reads → real spend well below the no-cache hypothetical.
        let rows = vec![row("claude-sonnet-4-6", 512, 8192, 45056, 28, 0.0)];
        let report = Report::from_rows(&rows);
        assert!(report.without_cache > report.real_spend);
        assert!(report.captured > 0.0);
        assert!(report.captured_pct() > 0.0);
    }

    #[test]
    fn flags_low_cache_use_opportunity() {
        // High spend, zero cache reads → flagged as an opportunity.
        let rows = vec![row("claude-sonnet-4-6", 1_000_000, 0, 0, 1000, 3.0)];
        let report = Report::from_rows(&rows);
        assert_eq!(report.opportunities.len(), 1);
        assert!(report.opportunities[0].cache_read_pct < 1.0);
    }

    #[test]
    fn healthy_cache_use_is_not_flagged() {
        // Mostly cache reads → no opportunity nag.
        let rows = vec![row("claude-sonnet-4-6", 500, 1000, 45000, 100, 2.0)];
        let report = Report::from_rows(&rows);
        assert!(report.opportunities.is_empty());
    }

    #[test]
    fn small_spend_is_not_nagged() {
        // Below the $0.50 floor → ignored even with zero cache.
        let rows = vec![row("claude-sonnet-4-6", 10_000, 0, 0, 100, 0.03)];
        let report = Report::from_rows(&rows);
        assert!(report.opportunities.is_empty());
    }

    #[test]
    fn empty_is_zeroed() {
        let report = Report::from_rows(&[]);
        assert_eq!(report.real_spend, 0.0);
        assert_eq!(report.captured, 0.0);
    }
}
