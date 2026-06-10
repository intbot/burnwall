//! `burnwall status` — today's spend summary.
//!
//! Format follows SPEC.md §"burnwall status".

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::budget::BudgetTracker;
use crate::config;
#[cfg(feature = "logscrape")]
use crate::logscrape::{self, ScrapeBreakdown};
use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};
use crate::term::Styler;

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
    // "Today" is the user's local calendar day — storage queries match
    // timestamps in local time (see `storage::repository`).
    let now_local = chrono::Local::now();
    let today = now_local.format("%Y-%m-%d").to_string();

    let breakdown = storage.breakdown_for_date(&today)?;
    let total_requests = storage.request_count_for_date(&today)?;
    let blocked_count = storage.blocked_count_for_date(&today)?;
    let security_events = storage.security_event_count_for_date(&today)?;
    let today_cost = storage.total_cost_for_date(&today)?;
    let pricing_age = pricing::pricing_age_days(now_local.date_naive());
    let projected_savings = storage.cache_projection_for_date(&today)?;
    let mcp_events_today = storage.mcp_event_count_for_date(&today)?;

    let cache_savings_total: f64 = breakdown.iter().map(model_cache_savings).sum();
    let cost_without_cache_total: f64 = breakdown.iter().map(model_cost_without_cache).sum();

    // Tier-2: scrape local tool session logs for cross-tool spend that did
    // not go through the proxy (optional `logscrape` feature). `None` when
    // disabled; `Some([])` when enabled but no activity today. The 7-day
    // avoidable-spend teaser is additionally gated behind the `waste` feature.
    // When both are compiled out, `status` shows only proxied numbers.
    #[cfg(feature = "logscrape")]
    let (log_scrape, waste_per_day) = collect_logscrape_and_waste(&config, now_local, &today);
    #[cfg(not(feature = "logscrape"))]
    let waste_per_day: f64 = 0.0;

    let budget = BudgetTracker::new((&config.budget).into());
    budget.hydrate_for_date(&storage, &today)?;

    // Coverage: which installed tools actually route through the proxy. Surfaces
    // silent non-coverage (e.g. ChatGPT-login Codex bypasses entirely).
    let coverage = crate::coverage::assess(&storage, chrono::Utc::now().timestamp());

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
            #[cfg(feature = "logscrape")]
            log_scrape.as_deref(),
            projected_savings,
            mcp_events_today,
            waste_per_day,
            &coverage,
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
            #[cfg(feature = "logscrape")]
            log_scrape.as_deref(),
            projected_savings,
            mcp_events_today,
            waste_per_day,
        )?;
        // Per-session / swarm breakdown — only shown when the opt-in
        // `x-burnwall-session` header is in use, so it never clutters the
        // common case.
        if let Ok(sessions) = storage.session_costs_for_date(&today) {
            if !sessions.is_empty() {
                writeln!(out)?;
                writeln!(out, "   By session (x-burnwall-session):")?;
                for (sid, cost, n) in sessions.iter().take(8) {
                    writeln!(out, "     {:<28} ${:.2}  ({} req)", truncate(sid, 28), cost, n)?;
                }
            }
        }

        // Self-test heartbeat: make it unmistakable whether protection is live,
        // so a passive proxy never leaves the user wondering "is it even doing
        // anything?" (a common reason such tools get distrusted / disabled).
        let sty = Styler::stdout();
        writeln!(out)?;
        match super::daemon::running_pid().ok().flatten() {
            Some(pid) => writeln!(
                out,
                "   {} proxy running (pid {pid}); every request is scanned.",
                sty.green("🟢 Protection active —")
            )?,
            None => writeln!(
                out,
                "   {} start it with `burnwall start` (rules apply only while it runs).",
                sty.yellow("⚪ Proxy not running —")
            )?,
        }

        // Routing health for *this* shell: even with the proxy up, traffic only
        // reaches it if the tool's base URL points here. Reading the env that
        // `burnwall status` runs in catches the silent "running but unrouted"
        // gap (the common Windows case: routed in PowerShell, not in bash).
        write_routing(&mut out, &sty)?;

        write_coverage(&mut out, &coverage, &sty)?;
    }
    Ok(())
}

/// Per-tool coverage readout: who's actually behind the firewall. Only shown
/// when at least one supported tool is installed, so it stays out of the way on
/// machines with none. The point is to make *non*-coverage visible — a
/// ChatGPT-login Codex user must not be left assuming protection they don't have.
fn write_coverage(
    w: &mut impl Write,
    coverage: &[crate::coverage::ToolCoverage],
    sty: &Styler,
) -> std::io::Result<()> {
    if coverage.is_empty() {
        return Ok(());
    }
    writeln!(w)?;
    writeln!(w, "   Coverage (tools that route through Burnwall):")?;
    for tc in coverage {
        // Colour the verdict by severity so a not-protected tool stands out.
        let summary = match &tc.state {
            crate::coverage::CoverageState::Protected { .. } => sty.green(&tc.state.summary()),
            crate::coverage::CoverageState::InstalledNotSeen => sty.yellow(&tc.state.summary()),
            crate::coverage::CoverageState::Bypasses { .. } => sty.red(&tc.state.summary()),
        };
        writeln!(w, "     {:<14} {}", tc.label, summary)?;
    }
    if coverage
        .iter()
        .any(|c| matches!(c.state, crate::coverage::CoverageState::Bypasses { .. }))
    {
        writeln!(
            w,
            "   ℹ️  Burnwall only protects traffic that flows through it; subscription-backend\n      traffic (e.g. ChatGPT-login Codex) bypasses any no-MITM proxy."
        )?;
    }
    Ok(())
}

/// Cross-tool "today" without double counting (X4). A tool routed through the
/// proxy is recorded twice — once in the proxy DB and once in its own session
/// log — so summing the two buckets read ~2× reality for the recommended
/// setup. We exclude a log row when its tool's provider demonstrably had
/// proxied traffic today (claude-code → anthropic, codex → openai); tools with
/// ambiguous providers (aider, opencode) stay included, which can only
/// over-count, never hide spend. True per-turn dedup needs message-id matching
/// and is tracked separately.
#[cfg(feature = "logscrape")]
fn combined_today(
    today_cost: f64,
    log_rows: &[crate::logscrape::ScrapeBreakdown],
    breakdown: &[ModelBreakdown],
) -> f64 {
    let proxied_provider = |p: &str| breakdown.iter().any(|b| b.provider == p && b.cost > 0.0);
    let unproxied_logs: f64 = log_rows
        .iter()
        .filter(|r| match r.tool {
            "claude-code" => !proxied_provider("anthropic"),
            "codex" => !proxied_provider("openai"),
            _ => true,
        })
        .map(|r| r.cost)
        .sum();
    today_cost + unproxied_logs
}

/// Routing readout for the shell `burnwall status` runs in: is the AI tool you'd
/// launch here actually pointed at the proxy? Catches the "proxy up but traffic
/// goes direct" gap that leaves a user unprotected without any error.
fn write_routing(w: &mut impl Write, sty: &Styler) -> std::io::Result<()> {
    use crate::cli::routing::{current_routing, EnvRouting};
    match current_routing("anthropic") {
        EnvRouting::Proxied => {
            // Routed per the env — but cross-check the proxy is actually
            // answering (U-C1): "routed at a dead port" means every AI tool in
            // this shell fails with connection-refused, and a green line here
            // would half-reassure the user into blaming the provider.
            let alive = std::env::var("ANTHROPIC_BASE_URL")
                .ok()
                .and_then(|u| crate::cli::routing::proxy_alive_for_url(&u));
            if alive == Some(false) {
                writeln!(
                    w,
                    "   {} this shell routes to the proxy, but nothing answers on that port.",
                    sty.red("⛔ Routed to a DEAD proxy —")
                )?;
                writeln!(
                    w,
                    "      Every AI tool launched from this shell will fail to connect."
                )?;
                return writeln!(
                    w,
                    "      Fix:  {}   (or `burnwall stop` to pause routing and go direct)",
                    sty.bold("burnwall start")
                );
            }
            writeln!(
                w,
                "   {} this shell points Anthropic traffic at the proxy.",
                sty.green("🟢 Routed —")
            )
        }
        EnvRouting::Direct => {
            writeln!(
                w,
                "   {} ANTHROPIC_BASE_URL is not set to the proxy in this shell.",
                sty.orange("⚠  Not routed —")
            )?;
            writeln!(
                w,
                "      Traffic goes straight to the provider: no security scan, no cost capture."
            )?;
            // Routing paused by `burnwall stop` resumes on `start`; anything
            // else needs an explicit enable.
            let paused = crate::cli::init::Shell::detect()
                .map(|s| {
                    crate::cli::routing::env_file_state(s)
                        == Some(crate::cli::routing::EnvFileState::Paused)
                })
                .unwrap_or(false);
            if paused {
                writeln!(
                    w,
                    "      Fix:  {}   (routing is paused while the proxy is stopped)",
                    sty.bold("burnwall start")
                )
            } else {
                writeln!(
                    w,
                    "      Fix:  {}   (then restart your AI tool)",
                    sty.bold("burnwall enable-routing")
                )
            }
        }
        EnvRouting::Bypassed => writeln!(
            w,
            "   {} BURNWALL_BYPASS is set — the proxy relays without scanning.",
            sty.yellow("⚠  Bypass active —")
        ),
    }
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
    #[cfg(feature = "logscrape")] log_scrape: Option<&[ScrapeBreakdown]>,
    projected_savings: f64,
    mcp_events: i64,
    waste_per_day: f64,
) -> std::io::Result<()> {
    writeln!(w, "📊 Today ({})", date)?;
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

    #[cfg(feature = "logscrape")]
    if let Some(rows) = log_scrape {
        writeln!(w, "   Tracked via local session logs")?;
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
            // X4: a proxied tool's traffic shows up in BOTH buckets (a proxy DB
            // row and a session-log row), so a naive proxied+logs sum read ~2×
            // reality for exactly the recommended setup. Exclude the log rows
            // of tools whose provider demonstrably flowed through the proxy
            // today; the remainder is the genuinely unproxied add-on.
            let combined = combined_today(today_cost, rows, breakdown);
            if (combined - (today_cost + log_subtotal)).abs() > 0.005 {
                writeln!(
                    w,
                    "   Combined today: ${:.2}  (proxied + unproxied logs; overlapping tool logs excluded)",
                    combined
                )?;
            } else {
                writeln!(w, "   Combined today (proxied + log files): ${:.2}", combined)?;
            }
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
        // Soft alert (v0.9.1): a non-blocking heads-up once spend crosses the
        // configured warn threshold but is still under the hard daily limit.
        if bcfg.warn_percent > 0 && pct >= bcfg.warn_percent as f64 && pct < 100.0 {
            writeln!(
                w,
                "   ⚠️  Soft alert: {:.0}% of today's budget used (warns at {}%).",
                pct, bcfg.warn_percent
            )?;
        }
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
    if projected_savings > 0.0 {
        writeln!(
            w,
            "   💡 Cache injection (off): est. ${:.2} foregone today",
            projected_savings
        )?;
        writeln!(
            w,
            "      Enable with `burnwall config set proxy.cache_injection true`."
        )?;
    }
    if waste_per_day >= 0.01 {
        writeln!(
            w,
            "   💡 ~${:.2}/day of avoidable spend — run `burnwall waste`",
            waste_per_day
        )?;
    }
    if let Some(age) = pricing_age_days {
        if age > 30 {
            writeln!(w)?;
            writeln!(
                w,
                "   ⚠️  Pricing data is {} days old (>30). Update Burnwall, or override prices locally with `burnwall pricing path --init`.",
                age
            )?;
        }
    }
    let override_count = crate::pricing::overrides::count();
    if override_count > 0 {
        writeln!(w)?;
        writeln!(
            w,
            "   💲 {} local price override(s) active (burnwall pricing list).",
            override_count
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "   ℹ️  Scope: Burnwall guards LLM API traffic. MCP tool calls flow through unfiltered."
    )?;
    if mcp_events > 0 {
        writeln!(
            w,
            "      MCP tools/call recorded by `mcp-watch`: {} today",
            mcp_events
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
    pricing_age_days: Option<i64>,
    #[cfg(feature = "logscrape")] log_scrape: Option<&[ScrapeBreakdown]>,
    projected_savings: f64,
    mcp_events: i64,
    waste_per_day: f64,
    coverage: &[crate::coverage::ToolCoverage],
) -> std::io::Result<()> {
    use serde_json::json;
    let bcfg = budget.config();

    // `log_scrape` JSON — `null` when the feature is off or scraping is
    // disabled; otherwise the per-tool/model rows plus subtotal.
    #[cfg(feature = "logscrape")]
    let log_scrape_json = log_scrape.map(|rows| {
        json!({
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
        })
    });
    #[cfg(not(feature = "logscrape"))]
    let log_scrape_json = Option::<serde_json::Value>::None;

    // Subscription-plan limit headroom, per provider, for the status bar / IDE
    // extension. `null` when no fresh snapshot exists (API user, or the proxy
    // hasn't captured a `unified-*` response). Reset is emitted as seconds-from-
    // now so the consumer needn't know the capture time.
    let plan_json = {
        let now = chrono::Utc::now().timestamp();
        let providers: Vec<_> = crate::plan::read_all()
            .into_iter()
            .filter(|s| !s.is_stale(now, 12 * 3600))
            .map(|s| {
                json!({
                    "provider": s.provider,
                    "status": s.status,
                    "windows": s.windows.iter().map(|w| json!({
                        "label": w.label,
                        "utilization": w.utilization,
                        "reset_in_secs": (w.reset - now).max(0),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        if providers.is_empty() {
            serde_json::Value::Null
        } else {
            json!({ "providers": providers })
        }
    };

    // Routing health for the shell this ran in, so an editor/extension can warn
    // when the tool it launches would bypass the proxy. `proxied` / `direct` /
    // `bypassed`.
    let env_routing = match crate::cli::routing::current_routing("anthropic") {
        crate::cli::routing::EnvRouting::Proxied => "proxied",
        crate::cli::routing::EnvRouting::Direct => "direct",
        crate::cli::routing::EnvRouting::Bypassed => "bypassed",
    };
    // Liveness, not just a PID file: lets the extension flag "routed but the
    // proxy is dead" (U-C1) instead of showing green over connection-refused.
    let proxy_running = super::daemon::running_pid().ok().flatten().is_some();

    // De-duplicated cross-tool total (X4): excludes log rows of tools whose
    // provider flowed through the proxy today, so proxied Claude Code isn't
    // counted twice in the headline figure.
    #[cfg(feature = "logscrape")]
    let combined_total = log_scrape
        .map(|rows| combined_today(today_cost, rows, breakdown))
        .unwrap_or(today_cost);
    #[cfg(not(feature = "logscrape"))]
    let combined_total = today_cost;

    let value = json!({
        "date": date,
        "env_routing": env_routing,
        "proxy_running": proxy_running,
        "total_cost_usd": today_cost,
        "total_requests": total_requests,
        "blocked_requests": blocked,
        "security_events": security_events,
        "cache_savings_usd": cache_savings,
        "cost_without_cache_usd": cost_without_cache,
        "projected_cache_savings_usd": projected_savings,
        "avoidable_per_day_usd": waste_per_day,
        "mcp_events_today": mcp_events,
        "pricing_age_days": pricing_age_days,
        "pricing_stale": pricing_age_days.map(|d| d > 30).unwrap_or(false),
        "pricing_override_count": crate::pricing::overrides::count(),
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
        // `null` when log scraping is disabled or compiled out; otherwise the
        // per-tool/model rows plus their subtotal. Read-only — not the proxy DB.
        "log_scrape": log_scrape_json,
        "combined_total_usd": combined_total,
        // Per-provider subscription limit headroom; `null` for API-only usage.
        "plan": plan_json,
        // Per-tool coverage: which installed tools route through the proxy,
        // which are unseen, and which bypass it entirely (e.g. ChatGPT-login
        // Codex). Lets the IDE extension show who's actually protected.
        "coverage": coverage.iter().map(|c| {
            let mut obj = json!({
                "tool": c.label,
                "binary": c.binary,
                "state": c.state.kind(),
            });
            match &c.state {
                crate::coverage::CoverageState::Protected { since_secs } => {
                    obj["seen_secs_ago"] = json!(since_secs);
                }
                crate::coverage::CoverageState::Bypasses { reason } => {
                    obj["reason"] = json!(reason);
                }
                crate::coverage::CoverageState::InstalledNotSeen => {}
            }
            obj
        }).collect::<Vec<_>>(),
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

/// Collect today's cross-tool log-scrape rows plus the 7-day avoidable-spend
/// teaser. Returns `(None, 0.0)` when scraping is disabled; the waste teaser is
/// additionally gated behind the `waste` feature (returns 0.0 when compiled out).
#[cfg(feature = "logscrape")]
fn collect_logscrape_and_waste(
    config: &config::Config,
    now_local: chrono::DateTime<chrono::Local>,
    today: &str,
) -> (Option<Vec<ScrapeBreakdown>>, f64) {
    if !config.any_scrape_enabled() {
        return (None, 0.0);
    }
    let all = logscrape::collect_selected(config.scrape_tools());
    let today_rows = logscrape::aggregate(all.clone(), today);

    #[cfg(feature = "waste")]
    let per_day = if config.waste.enabled {
        let cutoff = (now_local - chrono::Duration::days(6)).date_naive();
        let recent: Vec<_> = all
            .into_iter()
            .filter(|e| e.timestamp.with_timezone(&chrono::Local).date_naive() >= cutoff)
            .collect();
        let findings = crate::waste::analyze(&recent);
        crate::waste::capped_waste_usd(&findings, &recent) / 7.0
    } else {
        0.0
    };
    #[cfg(not(feature = "waste"))]
    let per_day = {
        let _ = now_local; // only used by the waste teaser
        0.0
    };

    (Some(today_rows), per_day)
}
