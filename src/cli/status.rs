//! `burnwall status` — today's spend summary.
//!
//! Format follows SPEC.md §"burnwall status".

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::budget::BudgetTracker;
use crate::config;
use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: StatusArgs) -> anyhow::Result<()> {
    let cfg_path = config::default_path()?;
    let config = config::load_or_default(&cfg_path).context("loading config")?;

    let storage = Arc::new(Storage::open_default()?);
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let breakdown = storage.breakdown_for_date(&today)?;
    let total_requests = storage.request_count_for_date(&today)?;
    let blocked_count = storage.blocked_count_for_date(&today)?;
    let security_events = storage.security_event_count_for_date(&today)?;
    let today_cost = storage.total_cost_for_date(&today)?;

    let cache_savings_total: f64 = breakdown.iter().map(model_cache_savings).sum();
    let cost_without_cache_total: f64 = breakdown.iter().map(model_cost_without_cache).sum();

    let budget = BudgetTracker::new((&config.budget).into());
    budget.hydrate_for_date(&storage, &today)?;

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(
            &mut out,
            &today,
            &breakdown,
            total_requests,
            blocked_count,
            security_events,
            today_cost,
            &budget,
            cache_savings_total,
            cost_without_cache_total,
        )?;
    } else {
        write_table(
            &mut out,
            &today,
            &breakdown,
            total_requests,
            blocked_count,
            security_events,
            today_cost,
            &budget,
            cache_savings_total,
            cost_without_cache_total,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_table(
    w: &mut impl Write,
    date: &str,
    breakdown: &[ModelBreakdown],
    total_requests: i64,
    blocked: i64,
    security_events: i64,
    today_cost: f64,
    budget: &BudgetTracker,
    cache_savings: f64,
    cost_without_cache: f64,
) -> std::io::Result<()> {
    writeln!(w, "📊 Today (UTC {})", date)?;
    writeln!(
        w,
        "   Total: ${:.2} across {} request{}",
        today_cost,
        total_requests,
        if total_requests == 1 { "" } else { "s" }
    )?;
    writeln!(w)?;

    if breakdown.is_empty() {
        writeln!(w, "   (no requests yet)")?;
    } else {
        writeln!(
            w,
            "   {:<32}  {:>8}  {:>8}  {:>9}",
            "Provider / Model", "Cost", "Requests", "Cache Hit"
        )?;
        writeln!(w, "   {}", "─".repeat(63))?;
        for row in breakdown {
            let label = format!("{}/{}", row.provider, row.model);
            writeln!(
                w,
                "   {:<32}  ${:>7.2}  {:>8}  {:>8.0}%",
                truncate(&label, 32),
                row.cost,
                row.requests,
                row.cache_hit_rate() * 100.0
            )?;
        }
    }
    writeln!(w)?;

    let bcfg = budget.config();
    if bcfg.daily_usd > 0.0 {
        let pct = (today_cost / bcfg.daily_usd) * 100.0;
        writeln!(
            w,
            "   💰 Budget: ${:.2} / ${:.2} ({:.1}%)",
            today_cost, bcfg.daily_usd, pct
        )?;
    } else {
        writeln!(
            w,
            "   💰 Budget: ${:.2} (no daily limit configured)",
            today_cost
        )?;
    }
    writeln!(
        w,
        "   🛡️  Security: {} blocked attempt{}",
        security_events,
        if security_events == 1 { "" } else { "s" }
    )?;
    if blocked > security_events {
        writeln!(w, "   🚫 Blocked requests (any reason): {}", blocked)?;
    }
    writeln!(w)?;
    if cache_savings > 0.0 {
        writeln!(w, "   Cache savings today: ${:.2}", cache_savings)?;
        writeln!(
            w,
            "   (without caching, today would have cost ${:.2})",
            cost_without_cache
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_json(
    w: &mut impl Write,
    date: &str,
    breakdown: &[ModelBreakdown],
    total_requests: i64,
    blocked: i64,
    security_events: i64,
    today_cost: f64,
    budget: &BudgetTracker,
    cache_savings: f64,
    cost_without_cache: f64,
) -> std::io::Result<()> {
    use serde_json::json;
    let bcfg = budget.config();
    let value = json!({
        "date": date,
        "total_cost_usd": today_cost,
        "total_requests": total_requests,
        "blocked_requests": blocked,
        "security_events": security_events,
        "cache_savings_usd": cache_savings,
        "cost_without_cache_usd": cost_without_cache,
        "budget": {
            "daily_limit_usd": bcfg.daily_usd,
            "spent_today_usd": today_cost,
        },
        "breakdown": breakdown.iter().map(|r| json!({
            "provider": r.provider,
            "model": r.model,
            "cost_usd": r.cost,
            "requests": r.requests,
            "input_tokens": r.input_tokens,
            "cache_creation_tokens": r.cache_creation_tokens,
            "cache_read_tokens": r.cache_read_tokens,
            "output_tokens": r.output_tokens,
            "cache_hit_rate": r.cache_hit_rate(),
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())?;
    Ok(())
}

/// Build a one-row `TokenUsage` from a breakdown and reuse the pricing
/// helpers so the table matches the per-row math used by the proxy.
fn row_usage(row: &ModelBreakdown) -> TokenUsage {
    TokenUsage {
        input_tokens: row.input_tokens,
        output_tokens: row.output_tokens,
        cache_creation_tokens: row.cache_creation_tokens,
        cache_read_tokens: row.cache_read_tokens,
    }
}

fn model_cache_savings(row: &ModelBreakdown) -> f64 {
    pricing::get_pricing(&row.model)
        .map(|p| pricing::cache_savings(&row_usage(row), p))
        .unwrap_or(0.0)
}

fn model_cost_without_cache(row: &ModelBreakdown) -> f64 {
    pricing::get_pricing(&row.model)
        .map(|p| pricing::cost_without_cache(&row_usage(row), p))
        .unwrap_or(0.0)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
