//! `burnwall status` — today's spend summary.
//!
//! Format follows SPEC.md §"burnwall status".

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::budget::BudgetTracker;
use crate::cli::nudge::{self, NudgeState};
use crate::config;
#[cfg(feature = "logscrape")]
use crate::logscrape::{self, ScrapeBreakdown};
use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};
use crate::term::{
    Card, Color, Styler, Trend, delta_chip_count, delta_chip_pct, fill_bar, gauge_hue,
    render_cards, sparkline,
};

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
    // Enforcement blocks vs advisory alerts — one conflated count rendered as
    // "blocked" overstated interventions ~50× on an alert-heavy day.
    let (security_blocked, security_alerts) =
        partition_security_counts(&storage.security_event_type_counts_for_date(&today)?);
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

    // Delta-vs-yesterday baselines for the stat-card chips, and a 7-day spend
    // series for the trend sparkline. Both are best-effort: a query hiccup or a
    // first-day-of-use empty baseline just means the chip/sparkline is omitted.
    let yesterday = (now_local - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let prev = compute_prev_day(&storage, &yesterday);
    let spend_spark = spend_series(&storage, now_local, 7);

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
            security_blocked,
            security_alerts,
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
            prev,
            &spend_spark,
        )?;
    } else {
        write_table(
            &mut out,
            &today,
            &breakdown,
            total_requests,
            blocked_count,
            security_blocked,
            security_alerts,
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
            prev,
            &spend_spark,
        )?;
        // Per-session / swarm breakdown — only shown when the opt-in
        // `x-burnwall-session` header is in use, so it never clutters the
        // common case.
        if let Ok(sessions) = storage.session_costs_for_date(&today) {
            if !sessions.is_empty() {
                writeln!(out)?;
                writeln!(out, "   By session (x-burnwall-session):")?;
                for (sid, cost, n) in sessions.iter().take(8) {
                    writeln!(
                        out,
                        "     {:<28} ${:.2}  ({} req)",
                        truncate(sid, 28),
                        cost,
                        n
                    )?;
                }
            }
        }

        // Self-test heartbeat: make it unmistakable whether protection is live,
        // so a passive proxy never leaves the user wondering "is it even doing
        // anything?" (a common reason such tools get distrusted / disabled).
        let sty = Styler::stdout();
        writeln!(out)?;
        let pause = crate::bypass::read(chrono::Utc::now().timestamp());
        match (super::daemon::running_pid().ok().flatten(), pause) {
            // A pause overrides the green heartbeat: a paused proxy *looks*
            // protective (process up, port answering) while checking nothing.
            (Some(pid), crate::bypass::Bypass::Paused { resumes_in_secs }) => {
                writeln!(
                    out,
                    "   {} proxy (pid {pid}) is relaying ALL traffic unchecked.",
                    sty.yellow("⏸  Protection PAUSED —")
                )?;
                writeln!(
                    out,
                    "      Auto-resumes in {}. Resume now:  burnwall resume",
                    crate::ribbon::human_duration(resumes_in_secs)
                )?;
            }
            (Some(pid), crate::bypass::Bypass::AllowOnce { .. }) => {
                writeln!(
                    out,
                    "   {} the next request relays unchecked (then protection restores). Disarm:  burnwall resume",
                    sty.yellow("⏸  Allow-once armed —")
                )?;
                writeln!(
                    out,
                    "   {} proxy running (pid {pid}).",
                    sty.green("🟢 Protection active —")
                )?;
            }
            (Some(pid), crate::bypass::Bypass::Draining) => {
                writeln!(
                    out,
                    "   {} proxy (pid {pid}) is relaying unchecked after `burnwall stop` — it retires once traffic goes idle.",
                    sty.yellow("⏹  Protection STOPPED (draining) —")
                )?;
                writeln!(
                    out,
                    "      Already-running tools keep working. Turn protection back on:  burnwall start"
                )?;
            }
            (Some(pid), crate::bypass::Bypass::None) => writeln!(
                out,
                "   {} proxy running (pid {pid}); every request is scanned.",
                sty.green("🟢 Protection active —")
            )?,
            (None, _) => writeln!(
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

        // Editor integration: nudge when Claude Code is in use but its Burnwall
        // status line was never wired (a fresh install, or a prior `uninstall`
        // that stripped it — `start`/`upgrade` never re-add it). Silent for
        // non-Claude-Code users and for a user's own custom status line.
        write_statusline_hint(&mut out, &sty)?;

        // Contextual usage nudge (v0.11): at most one data-driven line, gated
        // to once/day. Drawn from the user's own data; quiet when there's no
        // real finding. Never on the glanceable status line.
        let _ = maybe_emit_nudge(&mut out, &storage, budget.config().daily_usd, &today);
    }
    Ok(())
}

/// Append at most one data-driven nudge, once per local day. The gate + finding
/// rotation live in the `meta` table (`nudge_last_date` / `nudge_last_kind`);
/// the finding selection is the pure [`nudge::select`]. Best-effort: any
/// storage hiccup just means no nudge this run.
fn maybe_emit_nudge(
    out: &mut impl Write,
    storage: &Storage,
    daily_budget_usd: f64,
    today: &str,
) -> std::io::Result<()> {
    // Already nudged today → stay quiet.
    if storage
        .meta_get("nudge_last_date")
        .ok()
        .flatten()
        .as_deref()
        == Some(today)
    {
        return Ok(());
    }

    const WINDOW_DAYS: i64 = 7;
    let win = storage
        .breakdown_since_days(WINDOW_DAYS)
        .unwrap_or_default();
    let prompt_tokens: u64 = win
        .iter()
        .map(|b| b.input_tokens + b.cache_creation_tokens + b.cache_read_tokens)
        .sum();
    let cache_read: u64 = win.iter().map(|b| b.cache_read_tokens).sum();
    let cache_hit_rate = if prompt_tokens == 0 {
        0.0
    } else {
        cache_read as f64 / prompt_tokens as f64
    };
    // Same block/alert partition as the headline security line — the receipt
    // must not claim alert rows as blocked requests.
    let (blocked_window, alerts_window) = storage
        .security_events_since_days(WINDOW_DAYS)
        .map(|v| {
            v.iter().fold((0i64, 0i64), |(b, a), e| {
                if crate::security::catalog::is_advisory(&e.event_type) {
                    (b, a + 1)
                } else {
                    (b + 1, a)
                }
            })
        })
        .unwrap_or((0, 0));
    let state = NudgeState {
        daily_budget_usd,
        has_spend: win.iter().any(|b| b.cost > 0.0),
        cache_hit_rate,
        prompt_tokens,
        security_blocked_window: blocked_window,
        security_alerts_window: alerts_window,
        window_days: WINDOW_DAYS,
    };

    let last_kind = storage.meta_get("nudge_last_kind").ok().flatten();
    if let Some(n) = nudge::select(&state, last_kind.as_deref()) {
        writeln!(out)?;
        writeln!(out, "   👉 {}", n.message)?;
        // Record so we don't repeat today, and so tomorrow rotates onward.
        let _ = storage.meta_set("nudge_last_date", today);
        let _ = storage.meta_set("nudge_last_kind", n.kind);
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
    use crate::cli::routing::{EnvRouting, current_routing};
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
                    "      AI tools already running here will fail to connect (ConnectionRefused)."
                )?;
                writeln!(
                    w,
                    "      Fix:  {}   (revive the proxy — running tools recover instantly)",
                    sty.bold("burnwall start")
                )?;
                return writeln!(
                    w,
                    "            {}  (go direct instead, then restart already-open AI tools)",
                    sty.bold("burnwall recover")
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

/// Nudge when Claude Code is installed but its Burnwall status line isn't wired.
/// The ribbon is set up by `burnwall init`, never by `start`/`upgrade`, so a
/// fresh install or a prior `uninstall` leaves it off with nothing to say so —
/// this is that missing signal. Quiet for non-Claude-Code users (`NoClaudeCode`)
/// and for a user's own custom status line (`Foreign`).
fn write_statusline_hint(w: &mut impl Write, sty: &Styler) -> std::io::Result<()> {
    use crate::cli::claude_settings::{StatuslineState, statusline_state_default};
    if statusline_state_default() == StatuslineState::Missing {
        writeln!(w)?;
        writeln!(
            w,
            "   {} Claude Code is set up here, but its Burnwall status line isn't wired.",
            sty.orange("ℹ  No status line —")
        )?;
        writeln!(
            w,
            "      Show live cost + protection in the editor:  {}",
            sty.bold("burnwall init --apply")
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
    security_blocked: i64,
    security_alerts: i64,
    today_cost: f64,
    budget: &BudgetTracker,
    cache_savings: f64,
    cost_without_cache: f64,
    pricing_age_days: Option<i64>,
    #[cfg(feature = "logscrape")] log_scrape: Option<&[ScrapeBreakdown]>,
    projected_savings: f64,
    mcp_events: i64,
    waste_per_day: f64,
    prev: PrevDay,
    spend_spark: &[f64],
) -> std::io::Result<()> {
    let sty = Styler::stdout();
    let pretty = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map(|d| d.format("%a %b %d").to_string())
        .unwrap_or_else(|_| date.to_string());
    writeln!(w, "🔥 {} · Today ({})", sty.bold("Burnwall"), pretty)?;
    writeln!(w)?;

    // Aggregate cache-hit rate across today's models, for the Cache tile —
    // cache reads as a share of all prompt-side tokens (input + creation + read).
    let (mut cache_read, mut prompt_total) = (0u64, 0u64);
    for b in breakdown {
        cache_read += b.cache_read_tokens;
        prompt_total += b.input_tokens + b.cache_creation_tokens + b.cache_read_tokens;
    }
    let cache_hit = if prompt_total > 0 {
        cache_read as f64 / prompt_total as f64 * 100.0
    } else {
        0.0
    };

    let bcfg = budget.config();
    // A subscriber's dollar figure is notional (what metered API would have
    // cost), and on a flat-rate plan the cap isn't enforced — so a "120% of
    // budget" tile would be misleading. The Budget tile shows "notional" in that
    // case; the explanatory line is printed further down. (`freshest_any` is
    // `Some` once any plan window was ever captured — the subscription tell.)
    let subscriber = crate::plan::freshest_any().is_some();

    // Headline stat tiles (Variant 1 — native cards): the glanceable four, each
    // carrying a delta-vs-yesterday chip when there's a baseline to compare to.
    let mut cards = vec![
        Card::new(
            "Spend",
            &format!("${:.2}", today_cost),
            &format!("{} req", total_requests),
        )
        .with_delta(delta_chip_pct(today_cost, prev.cost, Trend::HigherWorse)),
    ];
    cards.push(if subscriber && !bcfg.enforce_on_plan {
        Card::new("Budget", "notional", "not billed").with_value_color(Color::Yellow)
    } else if bcfg.daily_usd > 0.0 {
        let pct = (today_cost / bcfg.daily_usd) * 100.0;
        Card::new("Budget", &format!("{:.0}%", pct), &fill_bar(pct, 8))
            .with_value_color(gauge_hue(pct))
            .with_sub_color(gauge_hue(pct))
    } else {
        Card::new("Budget", "no cap", &format!("${:.2}", today_cost))
    });
    cards.push(
        Card::new(
            "Cache",
            &format!("{:.0}%", cache_hit),
            &fill_bar(cache_hit, 8),
        )
        .with_value_color(Color::Green)
        .with_sub_color(Color::Green)
        .with_delta(delta_chip_pct(
            cache_hit,
            prev.cache_hit_pct,
            Trend::HigherBetter,
        )),
    );
    cards.push({
        let sub = if security_alerts > 0 {
            format!(
                "{} alert{}",
                security_alerts,
                if security_alerts == 1 { "" } else { "s" }
            )
        } else {
            "0 alerts".to_string()
        };
        Card::new("Blocked", &security_blocked.to_string(), &sub)
            .with_value_color(if security_blocked > 0 {
                Color::Red
            } else {
                Color::Green
            })
            .with_delta(delta_chip_count(
                security_blocked,
                prev.blocked,
                Trend::HigherWorse,
            ))
    });
    writeln!(w, "{}", render_cards(&cards, 11, 2, &sty))?;
    writeln!(w)?;

    // 7-day spend trend sparkline — context for whether today is high or low for
    // the week. Quiet when the whole week was idle.
    if spend_spark.iter().any(|&v| v > 0.0) {
        let lo = spend_spark.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = spend_spark
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        writeln!(
            w,
            "  {} {}  ${:.2}–${:.2}",
            sty.bold("7-day spend"),
            sty.paint(&sparkline(spend_spark), Color::Cyan),
            lo,
            hi
        )?;
        writeln!(w)?;
    }

    writeln!(w, "  {}", sty.bold("Cost by model"))?;
    if breakdown.is_empty() {
        writeln!(w, "  (no requests yet)")?;
    } else {
        // Share-of-spend bar per row, so the dominant model is visible at a
        // glance instead of having to compare dollar figures by eye.
        let model_total: f64 = breakdown.iter().map(|r| r.cost).sum();
        writeln!(
            w,
            "  {:<32}  {:>8}  {:>8}  {:>9}  Share",
            "Provider / Model", "Cost", "Requests", "Cache Hit"
        )?;
        writeln!(w, "  {}", "─".repeat(79))?;
        for row in breakdown {
            let label = format!("{}/{}", row.provider, row.model);
            let share = if model_total > 0.0 {
                row.cost / model_total * 100.0
            } else {
                0.0
            };
            writeln!(
                w,
                "  {:<32}  ${:>7.2}  {:>8}  {:>8.0}%  {} {:>3.0}%",
                truncate(&label, 32),
                row.cost,
                row.requests,
                row.cache_hit_rate() * 100.0,
                sty.paint(&fill_bar(share, 8), Color::Cyan),
                share,
            )?;
        }
    }
    writeln!(w)?;

    #[cfg(feature = "logscrape")]
    if let Some(rows) = log_scrape {
        writeln!(w, "  {}", sty.bold("Tracked via local session logs"))?;
        if rows.is_empty() {
            writeln!(w, "  (no Claude Code or Codex activity today)")?;
        } else {
            writeln!(
                w,
                "  {:<32}  {:>8}  {:>8}  {:>9}",
                "Tool / Model", "Cost", "Turns", "Cache Hit"
            )?;
            writeln!(w, "  {}", "─".repeat(63))?;
            for row in rows {
                let label = format!("{}/{}", row.tool, row.model);
                writeln!(
                    w,
                    "  {:<32}  ${:>7.2}  {:>8}  {:>8.0}%",
                    truncate(&label, 32),
                    row.cost,
                    row.turns,
                    row.cache_hit_rate() * 100.0
                )?;
            }
            let log_subtotal = logscrape::subtotal(rows);
            writeln!(w, "  {}", "─".repeat(63))?;
            writeln!(w, "  Log-file subtotal: ${:.2}", log_subtotal)?;
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
                    "  Combined today: ${:.2}  (proxied + unproxied logs; overlapping tool logs excluded)",
                    combined
                )?;
            } else {
                writeln!(
                    w,
                    "  Combined today (proxied + log files): ${:.2}",
                    combined
                )?;
            }
        }
        writeln!(w)?;
    }

    // Budget nuance the tile can't carry: the notional-spend caveat for a
    // flat-rate subscriber, or a soft alert when an API user crosses the warn
    // threshold (the tile shows the percentage; this explains it).
    if subscriber && !bcfg.enforce_on_plan {
        writeln!(
            w,
            "  💰 Notional spend ${:.2} today — flat-rate subscription (not billed; the daily cap isn't enforced on plan traffic).",
            today_cost
        )?;
    } else if bcfg.daily_usd > 0.0 {
        let pct = (today_cost / bcfg.daily_usd) * 100.0;
        // Soft alert (v0.9.1): a non-blocking heads-up once spend crosses the
        // configured warn threshold but is still under the hard daily limit.
        if bcfg.warn_percent > 0 && pct >= bcfg.warn_percent as f64 && pct < 100.0 {
            writeln!(
                w,
                "  ⚠️  Soft alert: {:.0}% of today's ${:.2} budget used (warns at {}%).",
                pct, bcfg.daily_usd, bcfg.warn_percent
            )?;
        }
    }
    // Burn-rate speedometer (#2): today's average spend per hour over the local
    // day so far, with the hourly brake's status. Always shown; never blocks.
    // (The live short-window spike alert runs in the proxy hot path; here we
    // show the steady-state rate computed from recorded spend.)
    let burn = burn_rate_today(today_cost);
    if burn > 0.0 {
        if bcfg.per_hour_usd > 0.0 {
            writeln!(
                w,
                "  🏎️  Burn rate ~${:.2}/hr today (hourly brake at ${:.2}/hr).",
                burn, bcfg.per_hour_usd
            )?;
        } else {
            writeln!(
                w,
                "  🏎️  Burn rate ~${:.2}/hr today (no hourly brake — set budget.per_hour to arm it).",
                burn
            )?;
        }
    }
    // The Blocked tile carries the counts; this line keeps the block/alert split
    // honest (an advisory alert is never called a block) and points at the
    // drill-down command on an alert-heavy day.
    writeln!(w, "  {}", security_line(security_blocked, security_alerts))?;
    // `blocked` counts every stopped request regardless of reason (security,
    // budget cap, loop detector). Surface it when it exceeds the security
    // blocks — the difference is budget/loop interventions.
    if blocked > security_blocked {
        writeln!(w, "  🚫 Requests stopped (incl. budget/loop): {}", blocked)?;
    }
    if cache_savings > 0.0 {
        writeln!(
            w,
            "  💚 Cache saved ${:.2} today (≈ ${:.2} without caching).",
            cache_savings, cost_without_cache
        )?;
    }
    if projected_savings > 0.0 {
        writeln!(
            w,
            "  💡 Cache injection (off): est. ${:.2} foregone today — enable with `burnwall config set proxy.cache_injection true`.",
            projected_savings
        )?;
    }
    if waste_per_day >= 0.01 {
        writeln!(
            w,
            "  💡 ~${:.2}/day of avoidable spend — run `burnwall waste`.",
            waste_per_day
        )?;
    }
    if let Some(age) = pricing_age_days {
        if age > 30 {
            writeln!(
                w,
                "  ⚠️  Pricing data is {} days old (>30). Update Burnwall, or override prices locally with `burnwall pricing path --init`.",
                age
            )?;
        }
    }
    let override_count = crate::pricing::overrides::count();
    if override_count > 0 {
        writeln!(
            w,
            "  💲 {} local price override(s) active (`burnwall pricing list`).",
            override_count
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "  ℹ️  Scope: Burnwall guards LLM API traffic. MCP tool calls flow through unfiltered."
    )?;
    if mcp_events > 0 {
        writeln!(
            w,
            "     MCP tools/call recorded by `mcp-watch`: {} today",
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
    security_blocked: i64,
    security_alerts: i64,
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
    prev: PrevDay,
    spend_spark: &[f64],
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

    // Runtime pause (`burnwall pause`): the editor extension must be able to
    // warn that a green-looking proxy is currently checking nothing.
    let bypass_now = crate::bypass::read(chrono::Utc::now().timestamp());
    let (protection_paused, pause_resumes_in_secs) = match bypass_now {
        crate::bypass::Bypass::Paused { resumes_in_secs } => (true, Some(resumes_in_secs)),
        _ => (false, None),
    };
    // Soft `burnwall stop` left the proxy up as a pass-through (relay-only),
    // retiring when idle — surfaces should show it as stopped, not green.
    let protection_draining = matches!(bypass_now, crate::bypass::Bypass::Draining);

    // Claude Code editor-integration state for the IDE extension / scripts:
    // `wired`, `missing` (Claude Code present but the ribbon isn't set up —
    // run `burnwall init`), `foreign` (a custom status line), or `none`.
    let claude_statusline = crate::cli::claude_settings::statusline_state_default().tag();

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
        "protection_paused": protection_paused,
        "pause_resumes_in_secs": pause_resumes_in_secs,
        "protection_draining": protection_draining,
        "claude_statusline": claude_statusline,
        "total_cost_usd": today_cost,
        "total_requests": total_requests,
        "blocked_requests": blocked,
        // Total kept for compatibility; the split is what surfaces should use.
        "security_events": security_blocked + security_alerts,
        "security_blocked": security_blocked,
        "security_alerts": security_alerts,
        "cache_savings_usd": cache_savings,
        "cost_without_cache_usd": cost_without_cache,
        "projected_cache_savings_usd": projected_savings,
        "avoidable_per_day_usd": waste_per_day,
        // Dense 7-day spend series (oldest → newest, zero-filled) for the panel's
        // static SVG trend chart, and yesterday's baselines for its delta chips.
        "spend_series": spend_spark,
        "previous_day": {
            "cost_usd": prev.cost,
            "cache_hit_pct": prev.cache_hit_pct,
            "blocked": prev.blocked,
        },
        "mcp_events_today": mcp_events,
        "pricing_age_days": pricing_age_days,
        "pricing_stale": pricing_age_days.map(|d| d > 30).unwrap_or(false),
        "pricing_override_count": crate::pricing::overrides::count(),
        "budget": {
            "daily_limit_usd": bcfg.daily_usd,
            "spent_today_usd": today_cost,
            // Burn-rate speedometer (#2): today's average $/hour and the hourly
            // brake ceiling (0 = brake off). Lets the IDE extension show a live
            // speedometer next to the daily budget.
            "burn_rate_per_hour_usd": burn_rate_today(today_cost),
            "hourly_limit_usd": bcfg.per_hour_usd,
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

/// Yesterday's headline metrics, the baseline for the stat-card delta chips.
/// Defaults to zeros when there was no activity yesterday — the `delta_chip_*`
/// helpers then return `None` (no chip) against the zero baseline.
#[derive(Default, Clone, Copy)]
pub(crate) struct PrevDay {
    cost: f64,
    cache_hit_pct: f64,
    blocked: i64,
}

/// Compute [`PrevDay`] for a local date string. Best-effort: any storage error
/// degrades to a zero field, never a failed `status`.
fn compute_prev_day(storage: &Storage, date: &str) -> PrevDay {
    let cost = storage.total_cost_for_date(date).unwrap_or(0.0);
    let (cache_read, prompt_total) = storage
        .breakdown_for_date(date)
        .map(|rows| {
            rows.iter().fold((0u64, 0u64), |(cr, pt), b| {
                (
                    cr + b.cache_read_tokens,
                    pt + b.input_tokens + b.cache_creation_tokens + b.cache_read_tokens,
                )
            })
        })
        .unwrap_or((0, 0));
    let cache_hit_pct = if prompt_total > 0 {
        cache_read as f64 / prompt_total as f64 * 100.0
    } else {
        0.0
    };
    let blocked = storage
        .security_event_type_counts_for_date(date)
        .map(|c| partition_security_counts(&c).0)
        .unwrap_or(0);
    PrevDay {
        cost,
        cache_hit_pct,
        blocked,
    }
}

/// A dense `len`-day spend series ending today (oldest → newest, one entry per
/// local day, zero-filled for idle days). Powers the status sparkline and the
/// panel's SVG chart. Best-effort: an error yields an all-zero series.
fn spend_series(
    storage: &Storage,
    now_local: chrono::DateTime<chrono::Local>,
    len: i64,
) -> Vec<f64> {
    let by_date: std::collections::HashMap<String, f64> = storage
        .daily_totals(len)
        .unwrap_or_default()
        .into_iter()
        .map(|t| (t.date, t.total_cost))
        .collect();
    (0..len)
        .rev()
        .map(|i| {
            let d = (now_local - chrono::Duration::days(i))
                .format("%Y-%m-%d")
                .to_string();
            by_date.get(&d).copied().unwrap_or(0.0)
        })
        .collect()
}

/// Today's average spend per hour over the local day so far — the steady-state
/// burn-rate speedometer (#2). `today_cost` divided by the local-day hours
/// elapsed (floored at a few minutes so the small hours after midnight don't
/// produce a wild per-hour figure from a single early request). `0.0` when
/// nothing has been spent yet.
fn burn_rate_today(today_cost: f64) -> f64 {
    if today_cost <= 0.0 {
        return 0.0;
    }
    use chrono::Timelike;
    let secs = chrono::Local::now().num_seconds_from_midnight() as f64;
    // Floor at 5 minutes of elapsed time to avoid a huge extrapolation right
    // after midnight.
    let hours = (secs / 3600.0).max(5.0 / 60.0);
    today_cost / hours
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

/// Partition per-`event_type` counts into `(enforcement blocks, advisory
/// alerts)` using the security catalog's classification.
fn partition_security_counts(counts: &[(String, i64)]) -> (i64, i64) {
    counts.iter().fold((0, 0), |(b, a), (et, n)| {
        if crate::security::catalog::is_advisory(et) {
            (b, a + n)
        } else {
            (b + n, a)
        }
    })
}

/// The one-line security summary, blocks and alerts named separately so an
/// informational alert is never presented as a blocked request.
fn security_line(blocked: i64, alerts: i64) -> String {
    let s = |n: i64| if n == 1 { "" } else { "s" };
    match (blocked, alerts) {
        (0, 0) => "🛡️  Security: no events today".to_string(),
        (b, 0) => format!("🛡️  Security: {b} request{} blocked", s(b)),
        (0, a) => format!(
            "🛡️  Security: {a} alert{} (nothing blocked) — `burnwall security --summary`",
            s(a)
        ),
        (b, a) => format!(
            "🛡️  Security: {b} request{} blocked · {a} alert{} — `burnwall security --summary`",
            s(b),
            s(a)
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(&str, i64)]) -> Vec<(String, i64)> {
        pairs.iter().map(|(t, n)| (t.to_string(), *n)).collect()
    }

    #[test]
    fn partition_separates_blocks_from_alerts() {
        // The user-reported day: 3 real blocks drowned in 153 drip alerts.
        let (b, a) = partition_security_counts(&counts(&[
            ("slow_drip_alert", 153),
            ("path_blocked", 2),
            ("secret_detected", 1),
        ]));
        assert_eq!((b, a), (3, 153));
        // Unknown (pack-authored) types count as enforcement.
        let (b, a) = partition_security_counts(&counts(&[("pack_rule_x", 2)]));
        assert_eq!((b, a), (2, 0));
        assert_eq!(partition_security_counts(&[]), (0, 0));
    }

    #[test]
    fn security_line_never_calls_an_alert_a_block() {
        assert_eq!(security_line(0, 0), "🛡️  Security: no events today");
        assert_eq!(security_line(1, 0), "🛡️  Security: 1 request blocked");
        assert_eq!(security_line(3, 0), "🛡️  Security: 3 requests blocked");
        let alerts_only = security_line(0, 153);
        assert!(alerts_only.contains("153 alerts"), "got: {alerts_only}");
        assert!(
            alerts_only.contains("nothing blocked"),
            "alert-only day must say so explicitly: {alerts_only}"
        );
        let mixed = security_line(3, 153);
        assert!(mixed.contains("3 requests blocked"), "got: {mixed}");
        assert!(mixed.contains("153 alerts"), "got: {mixed}");
        assert!(
            !mixed.contains("156"),
            "the conflated total must never render: {mixed}"
        );
    }
}
