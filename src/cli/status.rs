//! `burnwall status` — today's spend summary.
//!
//! Format follows SPEC.md §"burnwall status".

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::budget::BudgetTracker;
use crate::config;
use crate::logscrape::{self, ScrapeBreakdown};
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
    let pricing_age = pricing::pricing_age_days(chrono::Utc::now().date_naive());

    let cache_savings_total: f64 = breakdown.iter().map(model_cache_savings).sum();
    let cost_without_cache_total: f64 = breakdown.iter().map(model_cost_without_cache).sum();

    // Tier-2: scrape local tool session logs for cross-tool spend that did
    // not go through the proxy. `None` when disabled; `Some([])` when
    // enabled but no Claude Code / Codex activity today.
    let log_scrape = if config.log_scrape.enabled {
        Some(logscrape::scrape_for_date(&today))
    } else {
        None
    };

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
            pricing_age,
            log_scrape.as_deref(),
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
            pricing_age,
            log_scrape.as_deref(),
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
    pricing_age_days: Option<i64>,
    log_scrape: Option<&[ScrapeBreakdown]>,
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

    if let Some(rows) = log_scrape {
        writeln!(w, "   Tracked via log files (not proxied)")?;
        if rows.is_empty() {
            writeln!(w, "   (no Claude Code or Codex activity today)")?;
        } else {
            writeln!(
                w,
                "   {:<32}  {:>8}  {:>8}  {:>9}",
                "Tool / Model", "Cost", "Turns", "Cache Hit"
            )?;
            writeln!(w, "   {}", "─".repeat(63))?;
            for row in rows {
                let label = format!("{}/{}", row.tool, row.model);
                writeln!(
                    w,
                    "   {:<32}  ${:>7.2}  {:>8}  {:>8.0}%",
                    truncate(&label, 32),
                    row.cost,
                    row.turns,
                    row.cache_hit_rate() * 100.0
                )?;
            }
            let log_subtotal = logscrape::subtotal(rows);
            writeln!(w, "   {}", "─".repeat(63))?;
            writeln!(w, "   Log-file subtotal: ${:.2}", log_subtotal)?;
            writeln!(w)?;
            writeln!(
                w,
                "   Combined today (proxied + log files): ${:.2}",
                today_cost + log_subtotal
            )?;
        }
        writeln!(w)?;
    }

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
    if let Some(age) = pricing_age_days {
        if age > 30 {
            writeln!(w)?;
            writeln!(
                w,
                "   ⚠️  Pricing data is {} days old (>30). Update Burnwall or override via ~/.burnwall/pricing.toml.",
                age
            )?;
        }
    }
    writeln!(w)?;
    writeln!(
        w,
        "   ℹ️  Scope: Burnwall guards LLM API traffic. MCP tool calls flow through unfiltered."
    )?;
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
    pricing_age_days: Option<i64>,
    log_scrape: Option<&[ScrapeBreakdown]>,
) -> std::io::Result<()> {
    use serde_json::json;
    let bcfg = budget.config();
    let log_subtotal = log_scrape.map(logscrape::subtotal).unwrap_or(0.0);
    let value = json!({
        "date": date,
        "total_cost_usd": today_cost,
        "total_requests": total_requests,
        "blocked_requests": blocked,
        "security_events": security_events,
        "cache_savings_usd": cache_savings,
        "cost_without_cache_usd": cost_without_cache,
        "pricing_age_days": pricing_age_days,
        "pricing_stale": pricing_age_days.map(|d| d > 30).unwrap_or(false),
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
        // `null` when log scraping is disabled; otherwise the per-tool/model
        // rows plus their subtotal. Read-only — not part of the proxy DB.
        "log_scrape": log_scrape.map(|rows| json!({
            "rows": rows.iter().map(|r| json!({
                "tool": r.tool,
                "model": r.model,
                "cost_usd": r.cost,
                "turns": r.turns,
                "input_tokens": r.usage.input_tokens,
                "cache_creation_tokens": r.usage.cache_creation_tokens,
                "cache_read_tokens": r.usage.cache_read_tokens,
                "output_tokens": r.usage.output_tokens,
                "cache_hit_rate": r.cache_hit_rate(),
            })).collect::<Vec<_>>(),
            "subtotal_usd": logscrape::subtotal(rows),
        })),
        "combined_total_usd": today_cost + log_subtotal,
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
