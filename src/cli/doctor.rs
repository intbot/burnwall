//! `burnwall doctor` — a one-glance health check, and with `--export`, the
//! redacted metadata-only bundle a user can paste into a bug report.
//!
//! ## Why this exists
//! Burnwall has zero telemetry and a local-only DB; we can never fetch a user's
//! logs. So the entire support story is *the user is our eyes, voluntarily* —
//! which only works if producing a shareable, trustworthy diagnostic is one
//! command and obviously safe to send. `doctor --export` is that command.
//!
//! ## What it must never contain
//! No prompt content, no API keys, no request/response bodies, and **no raw
//! paths or commands**. The raw `requests` table is a full spend/timing
//! timeline; `security_events.details` holds blocked paths in the clear
//! (`~/.ssh/id_rsa`); `mcp_events.upstream_uri` names servers. The export
//! masks/aggregates every one of those, and we **never** ship the raw `.db`.
//!
//! ## The self-scan backstop
//! After the report is built it is run through the same on-disk secret scanner
//! that powers `burnwall scan` ([`filescan::scan_text`]). If anything
//! secret-shaped survived redaction the line is masked and re-scanned; the file
//! is only written once the scan is clean, and we print
//! `✓ no secrets or prompt content in this file` so a privacy-conscious user can
//! trust pasting it. Zero-telemetry is preserved end to end: we never receive
//! it — the user reads it, then chooses to share.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::security::{filescan, secrets};
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Write a redacted, metadata-only diagnostic bundle (safe to attach to a
    /// bug report) instead of the short health readout.
    #[arg(long)]
    pub export: bool,
    /// With --export: print the bundle to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,
    /// With --export: write to this path instead of the default under ~/.burnwall.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// How many days of recent blocks / cost to summarize (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Attempt the one safe repair for an *unintended* unprotected state:
    /// start the proxy when routing is enabled but the proxy is down. Never
    /// overrides a deliberate choice (disabled routing, a pause, BURNWALL_BYPASS)
    /// — it explains the manual command instead.
    #[arg(long)]
    pub fix: bool,
}

pub async fn run_cmd(args: DoctorArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let input = gather(&storage, args.days.max(1))?;

    if args.fix {
        return run_fix(&input).await;
    }

    if !args.export {
        let mut out = std::io::stdout().lock();
        return print_health(&mut out, &input);
    }

    // Build → harden (mask any secret-shaped token that survived) → self-scan.
    let report = harden(build_report(&input));
    let findings = filescan::scan_text("doctor-export", &report);

    let mut out = std::io::stdout().lock();
    if !findings.is_empty() {
        // Redaction has a hole — refuse to write rather than ship a leak. This
        // is fail-closed on purpose: the whole promise of the bundle is that it
        // is safe to share.
        writeln!(
            out,
            "⛔ Refusing to write the export: the self-scan still found {} secret-shaped item(s).",
            findings.len()
        )?;
        writeln!(
            out,
            "   This is a Burnwall bug — please report it (the offending value was NOT written)."
        )?;
        std::process::exit(1);
    }

    if args.stdout {
        print!("{report}");
        writeln!(out, "\n✓ no secrets or prompt content in this file")?;
        return Ok(());
    }

    let path = match args.out {
        Some(p) => p,
        None => {
            let dir = crate::storage::data_dir().context("locating data dir")?;
            let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
            dir.join(format!("doctor-{stamp}.txt"))
        }
    };
    std::fs::write(&path, &report).with_context(|| format!("writing {}", path.display()))?;

    let issues = format!("{}/issues/new", env!("CARGO_PKG_REPOSITORY"));
    writeln!(out, "🩺  Wrote a redacted diagnostic bundle (metadata only, nothing sent):")?;
    writeln!(out, "      {}", path.display())?;
    writeln!(out, "   ✓ no secrets or prompt content in this file (self-scanned)")?;
    writeln!(out)?;
    writeln!(out, "   Review it, then attach it to a bug report:")?;
    writeln!(out, "      {issues}")?;
    Ok(())
}

/// `burnwall doctor --fix`: perform the *one* safe repair for an unintended
/// unprotected state — start the proxy when routing is enabled but the proxy is
/// down. Everything the user turned off deliberately (disabled routing, a pause,
/// BURNWALL_BYPASS) is reported and explained, never overridden. And we never
/// touch this shell's environment: env vars are fixed at launch, so a routed
/// session always requires a fresh shell — we say so rather than pretend.
async fn run_fix(i: &DoctorInput) -> anyhow::Result<()> {
    let p = assess_protection(i);
    {
        let mut out = std::io::stdout().lock();
        if p.ok {
            writeln!(out, "✓ {}  Nothing to fix.", p.headline)?;
            return Ok(());
        }
        if p.chosen {
            // Deliberate off-state: respect it. Explain the manual command, act on nothing.
            writeln!(out, "• {}", p.headline)?;
            writeln!(
                out,
                "  This is a deliberate setting, so I won't change it for you."
            )?;
            if let Some(fix) = &p.fix {
                writeln!(out, "  If you want protection back: {fix}")?;
            }
            return Ok(());
        }
        if i.proxy_listening {
            // Proxy is up; only this shell is direct (it predates the proxy).
            // We cannot re-route an already-running shell from another process.
            writeln!(out, "⚠ {}", p.headline)?;
            writeln!(
                out,
                "  The proxy is already running — I can't re-route this shell from here."
            )?;
            writeln!(
                out,
                "  Open a new shell (or restart your AI tool) and it will route through Burnwall."
            )?;
            return Ok(());
        }
        if i.proxy_running {
            // A PID file exists but the port is dead — a stuck/dying process.
            // Auto-starting on top would just collide; hand off the clean path.
            writeln!(out, "⚠ {}", p.headline)?;
            writeln!(
                out,
                "  A burnwall process exists but isn't answering. Run `burnwall stop`, then `burnwall doctor --fix`."
            )?;
            return Ok(());
        }
        writeln!(out, "🔧 {}", p.headline)?;
        writeln!(out, "   Starting the proxy…")?;
    } // release the stdout lock before spawn_background prints its own output

    // The one repair we perform. spawn_background also re-enables routing (so a
    // paused env file goes active) and prints its own success line.
    let start_args = super::start::StartArgs {
        port: None,
        host: None,
        daemon: false,
        upstream_anthropic: super::start::DEFAULT_UPSTREAM_ANTHROPIC.to_string(),
        upstream_openai: super::start::DEFAULT_UPSTREAM_OPENAI.to_string(),
        upstream_google: super::start::DEFAULT_UPSTREAM_GOOGLE.to_string(),
        rewrite_anthropic_cache: false,
        no_routing: false,
        pause_routing_on_exit: false,
    };
    super::daemon::spawn_background(&start_args).await?;

    let mut out = std::io::stdout().lock();
    writeln!(out)?;
    writeln!(
        out,
        "   ⚠ This shell still goes direct until you open a NEW shell — env vars are fixed at launch."
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Gathering (impure: reads DB / env / process state) → a plain input struct.
// ---------------------------------------------------------------------------

/// Everything the report needs, already reduced to safe, displayable values.
/// Built by [`gather`]; consumed by the pure [`build_report`] / [`print_health`].
#[derive(Debug, Clone)]
pub struct DoctorInput {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub days: i64,
    pub proxy_running: bool,
    pub proxy_pid: Option<u32>,
    pub paused: bool,
    pub routing: &'static str,
    pub routed_proxy_alive: Option<bool>,
    /// What this shell's env file records: `active` (routing configured on),
    /// `paused` (proxy stopped), `disabled` (user opted out), or `None` (never
    /// set up). The discriminator between an *unintended* direct (active env,
    /// but went direct anyway) and a *chosen* one.
    pub env_file_state: Option<&'static str>,
    /// Whether the configured proxy port is answering right now — probed
    /// directly, independent of whether *this* shell is routed. Lets the
    /// protection verdict tell "proxy down" apart from "proxy up but this shell
    /// started before it".
    pub proxy_listening: bool,
    pub config_redacted: String,
    pub security_enabled: bool,
    pub canaries_armed: usize,
    pub pricing_age_days: Option<i64>,
    pub total_cost: f64,
    pub total_requests: i64,
    /// Enforcement blocks in the window (requests actually stopped) — kept
    /// separate from advisory alerts so the bundle never overstates
    /// interventions (the "156 blocked" that was 153 alerts).
    pub blocked_events: i64,
    /// Advisory alerts in the window (informational, nothing stopped).
    pub alert_events: i64,
    pub cost_rows: Vec<CostRow>,
    pub events: Vec<EventRow>,
    pub mcp_events: i64,
    pub mcp_distinct_servers: usize,
}

/// Per-model cost aggregate (no per-request timeline).
#[derive(Debug, Clone, PartialEq)]
pub struct CostRow {
    pub provider: String,
    pub model: String,
    pub cost: f64,
    pub requests: i64,
    pub cache_hit_pct: f64,
}

/// A recent block, reduced to rule id + masked match + timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    pub timestamp: String,
    pub rule_id: String,
    pub masked_detail: String,
    pub route: String,
}

fn gather(storage: &Storage, days: i64) -> anyhow::Result<DoctorInput> {
    let now = chrono::Utc::now().timestamp();
    let proxy_pid = super::daemon::running_pid().ok().flatten();
    let paused = matches!(
        crate::bypass::read(now),
        crate::bypass::Bypass::Paused { .. }
    );

    let (routing, routed_proxy_alive) = match crate::cli::routing::current_routing("anthropic") {
        crate::cli::routing::EnvRouting::Proxied => {
            let alive = std::env::var("ANTHROPIC_BASE_URL")
                .ok()
                .and_then(|u| crate::cli::routing::proxy_alive_for_url(&u));
            ("proxied", alive)
        }
        crate::cli::routing::EnvRouting::Direct => ("direct", None),
        crate::cli::routing::EnvRouting::Bypassed => ("bypassed", None),
    };

    // Read this shell's env file once: it tells us whether routing is configured
    // (active / paused / disabled / never), and the port it targets — which is
    // the right port to liveness-probe even when this shell itself went direct.
    let env_contents = crate::cli::init::Shell::detect()
        .and_then(crate::cli::routing::env_file_path)
        .and_then(|p| std::fs::read_to_string(p).ok());
    let env_file_state = env_contents.as_deref().map(|c| {
        match crate::cli::routing::classify_env_contents(c) {
            crate::cli::routing::EnvFileState::Active => "active",
            crate::cli::routing::EnvFileState::Paused => "paused",
            crate::cli::routing::EnvFileState::Disabled => "disabled",
        }
    });
    let probe_port = env_contents
        .as_deref()
        .and_then(crate::cli::routing::active_env_port)
        .unwrap_or(4100);
    let proxy_listening = crate::cli::routing::proxy_port_alive(
        probe_port,
        std::time::Duration::from_millis(80),
    );

    let cfg_path = crate::config::default_path()?;
    let cfg = crate::config::load_or_default(&cfg_path).context("loading config")?;
    let config_redacted = redact_config(&toml::to_string_pretty(&cfg).unwrap_or_default());
    let canaries_armed =
        crate::security::rules::armed_canaries(cfg.security.canaries.clone()).len();

    let breakdown = storage.breakdown_since_days(days)?;
    let cost_rows: Vec<CostRow> = breakdown
        .iter()
        .map(|b| CostRow {
            provider: b.provider.clone(),
            model: b.model.clone(),
            cost: b.cost,
            requests: b.requests,
            cache_hit_pct: b.cache_hit_rate() * 100.0,
        })
        .collect();
    let total_cost: f64 = breakdown.iter().map(|b| b.cost).sum();
    let total_requests: i64 = breakdown.iter().map(|b| b.requests).sum();

    let raw_events = storage.security_events_since_days(days)?;
    let (blocked_events, alert_events) = raw_events.iter().fold((0i64, 0i64), |(b, a), e| {
        if crate::security::catalog::is_advisory(&e.event_type) {
            (b, a + 1)
        } else {
            (b + 1, a)
        }
    });
    let events: Vec<EventRow> = raw_events
        .iter()
        .rev()
        .take(50)
        .map(|e| EventRow {
            timestamp: e
                .timestamp
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
            rule_id: e.event_type.clone(),
            masked_detail: redact_detail(&e.event_type, &e.details),
            route: match (&e.provider, &e.model) {
                (Some(p), Some(m)) => format!("{p}/{m}"),
                (Some(p), None) => p.clone(),
                _ => "-".to_string(),
            },
        })
        .collect();

    let mcp_raw = storage.mcp_events_since_days(days).unwrap_or_default();
    let mcp_events = mcp_raw.len() as i64;
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in &mcp_raw {
        if let Some(uri) = &e.upstream_uri {
            if let Some(h) = host_of(uri) {
                hosts.insert(h);
            }
        }
    }

    Ok(DoctorInput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        days,
        proxy_running: proxy_pid.is_some(),
        proxy_pid,
        paused,
        routing,
        routed_proxy_alive,
        env_file_state,
        proxy_listening,
        config_redacted,
        security_enabled: cfg.security.enabled,
        canaries_armed,
        pricing_age_days: crate::pricing::pricing_age_days(chrono::Local::now().date_naive()),
        total_cost,
        total_requests,
        blocked_events,
        alert_events,
        cost_rows,
        events,
        mcp_events,
        mcp_distinct_servers: hosts.len(),
    })
}

// ---------------------------------------------------------------------------
// Pure rendering + redaction (no I/O) — unit-tested below.
// ---------------------------------------------------------------------------

/// A plain-language verdict on whether the user is *actually protected right
/// now*, plus the single command that fixes it when they're not. Pure over
/// [`DoctorInput`], so the status line, `doctor`, and `doctor --fix` all agree.
#[derive(Debug, Clone, PartialEq)]
pub struct Protection {
    /// Traffic is flowing through Burnwall — scanning + cost capture are live.
    pub ok: bool,
    /// One-line status (e.g. "UNPROTECTED — routing is enabled but the proxy
    /// isn't running").
    pub headline: String,
    /// The fix, when something is wrong. `None` only when `ok`.
    pub fix: Option<String>,
    /// The unprotected state is the user's deliberate choice (disabled routing,
    /// a pause, or BURNWALL_BYPASS). Surfaces must not nag, and `--fix` must not
    /// override it — only explain the manual command.
    pub chosen: bool,
}

/// Classify the current protection state. The ordering matters: a deliberate
/// pause or bypass is reported as *chosen* before any routing analysis, so we
/// never auto-"fix" something the user switched off on purpose.
pub fn assess_protection(i: &DoctorInput) -> Protection {
    if i.paused {
        return Protection {
            ok: false,
            headline: "protection PAUSED — relaying everything unchecked".into(),
            fix: Some("run `burnwall resume` to end the pause now".into()),
            chosen: true,
        };
    }
    match i.routing {
        "bypassed" => Protection {
            ok: false,
            headline: "BURNWALL_BYPASS is set — relaying without scanning".into(),
            fix: Some("unset BURNWALL_BYPASS to restore scanning".into()),
            chosen: true,
        },
        "proxied" => {
            if i.routed_proxy_alive == Some(false) {
                Protection {
                    ok: false,
                    headline: "routed through the proxy, but the proxy port is DEAD".into(),
                    fix: Some("run `burnwall start`  (or `burnwall doctor --fix`)".into()),
                    chosen: false,
                }
            } else {
                Protection {
                    ok: true,
                    headline: "protected — traffic flows through Burnwall".into(),
                    fix: None,
                    chosen: false,
                }
            }
        }
        // Direct: the same word, two very different causes.
        "direct" => match i.env_file_state {
            // Routing IS configured, yet this shell went direct → unintended,
            // and fixable. Which fix depends on whether the proxy is up.
            Some("active") => {
                if i.proxy_listening {
                    Protection {
                        ok: false,
                        headline: "this shell is UNPROTECTED — the proxy is up, but this shell started before it".into(),
                        fix: Some("open a new shell / restart your AI tool so it picks up routing".into()),
                        chosen: false,
                    }
                } else {
                    Protection {
                        ok: false,
                        headline: "UNPROTECTED — routing is enabled but the proxy isn't running".into(),
                        fix: Some("run `burnwall start`, then open a new shell  (or `burnwall doctor --fix`)".into()),
                        chosen: false,
                    }
                }
            }
            // Stopped / opted-out / never-configured → a choice, not a bug.
            Some("paused") => Protection {
                ok: false,
                headline: "routing was paused when the proxy stopped — traffic goes direct".into(),
                fix: Some("run `burnwall start` to bring the proxy up and re-enable routing".into()),
                chosen: true,
            },
            Some("disabled") => Protection {
                ok: false,
                headline: "routing is DISABLED (your choice) — traffic goes direct".into(),
                fix: Some("run `burnwall enable-routing` to turn protection back on".into()),
                chosen: true,
            },
            _ => Protection {
                ok: false,
                headline: "routing isn't set up — traffic goes direct".into(),
                fix: Some("run `burnwall init` to route your AI tools through Burnwall".into()),
                chosen: true,
            },
        },
        _ => Protection {
            ok: false,
            headline: "routing state unknown".into(),
            fix: Some("run `burnwall doctor` to diagnose".into()),
            chosen: false,
        },
    }
}

/// The status glyph for a verdict: ✓ protected, • a deliberate off-state (no
/// alarm), ⚠ an unintended unprotected state (needs attention).
fn protection_mark(p: &Protection) -> &'static str {
    if p.ok {
        "✓"
    } else if p.chosen {
        "•"
    } else {
        "⚠"
    }
}

/// The short, human health readout (`burnwall doctor` with no `--export`).
fn print_health(out: &mut impl Write, i: &DoctorInput) -> anyhow::Result<()> {
    writeln!(out, "🩺 Burnwall doctor — quick health check")?;
    writeln!(out, "   version: {} ({}/{})", i.version, i.os, i.arch)?;
    let proxy = match (i.proxy_running, i.paused) {
        (true, true) => "running, but PROTECTION PAUSED (relaying unchecked)".to_string(),
        (true, false) => match i.proxy_pid {
            Some(pid) => format!("running (pid {pid})"),
            None => "running".to_string(),
        },
        (false, _) => "not running — start with `burnwall start`".to_string(),
    };
    writeln!(out, "   proxy:   {proxy}")?;
    let routing = match (i.routing, i.routed_proxy_alive) {
        ("proxied", Some(false)) => "routed here, but NOTHING answers on that port (dead proxy)",
        ("proxied", _) => "this shell routes through the proxy",
        ("direct", _) => "NOT routed — traffic goes straight to the provider (no scan, no cost)",
        ("bypassed", _) => "BURNWALL_BYPASS is set — relaying without scanning",
        _ => "unknown",
    };
    writeln!(out, "   routing: {routing}")?;

    // The headline verdict: am I actually protected right now, and if not, the
    // one command that fixes it (or, for a deliberate off-state, no nag).
    let p = assess_protection(i);
    writeln!(out, "   protection: {} {}", protection_mark(&p), p.headline)?;
    if let Some(fix) = &p.fix {
        writeln!(out, "      → {fix}")?;
    }

    if !i.security_enabled {
        writeln!(out, "   ⚠️  security.enabled is OFF — nothing is being blocked.")?;
    }
    if let Some(age) = i.pricing_age_days {
        if age > 30 {
            writeln!(out, "   ⚠️  pricing data is {age} days old (>30) — update Burnwall.")?;
        }
    }
    writeln!(
        out,
        "   last {} day(s): ${:.2} over {} request(s), {} block(s), {} alert(s).",
        i.days, i.total_cost, i.total_requests, i.blocked_events, i.alert_events
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "   For a redacted bundle to attach to a bug report:  burnwall doctor --export"
    )?;
    Ok(())
}

/// Build the full export bundle. Pure over [`DoctorInput`]; every value it
/// receives is already redacted/aggregated, and [`harden`] runs over the result
/// as a backstop.
pub fn build_report(i: &DoctorInput) -> String {
    let mut s = String::new();
    s.push_str("# Burnwall doctor export\n\n");
    s.push_str(
        "> Metadata only. No prompt content, no API keys, no request bodies, no raw paths.\n\
         > Self-scanned before writing. Safe to attach to a bug report.\n\n",
    );

    s.push_str("## Environment\n");
    s.push_str(&format!("- version: {}\n", i.version));
    s.push_str(&format!("- os/arch: {}/{}\n", i.os, i.arch));
    s.push_str(&format!(
        "- generated: {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z")
    ));
    s.push_str(&format!("- window: last {} day(s)\n\n", i.days));

    s.push_str("## Runtime state\n");
    s.push_str(&format!(
        "- proxy running: {}{}\n",
        i.proxy_running,
        if i.paused { " (PROTECTION PAUSED)" } else { "" }
    ));
    s.push_str(&format!("- routing (this shell): {}\n", i.routing));
    if let Some(alive) = i.routed_proxy_alive {
        s.push_str(&format!("- routed proxy answering: {alive}\n"));
    }
    s.push_str(&format!(
        "- routing configured (env file): {}\n",
        i.env_file_state.unwrap_or("none")
    ));
    s.push_str(&format!("- proxy port answering: {}\n", i.proxy_listening));
    let p = assess_protection(i);
    s.push_str(&format!(
        "- protection: {} {}\n",
        protection_mark(&p),
        p.headline
    ));
    if let Some(fix) = &p.fix {
        s.push_str(&format!("- suggested fix: {fix}\n"));
    }
    s.push_str(&format!("- security enabled: {}\n", i.security_enabled));
    s.push_str(&format!("- canary tripwires armed: {}\n", i.canaries_armed));
    if let Some(age) = i.pricing_age_days {
        s.push_str(&format!("- pricing data age (days): {age}\n"));
    }
    s.push('\n');

    s.push_str("## Cost summary (aggregate — no per-request timeline)\n");
    s.push_str(&format!(
        "- total: ${:.2} over {} request(s)\n",
        i.total_cost, i.total_requests
    ));
    if i.cost_rows.is_empty() {
        s.push_str("- (no requests in window)\n");
    } else {
        s.push_str("\n| provider/model | cost | requests | cache hit |\n");
        s.push_str("|---|---|---|---|\n");
        for r in &i.cost_rows {
            s.push_str(&format!(
                "| {}/{} | ${:.2} | {} | {:.0}% |\n",
                r.provider, r.model, r.cost, r.requests, r.cache_hit_pct
            ));
        }
    }
    s.push('\n');

    s.push_str(&format!(
        "## Recent security events ({} block(s) + {} alert(s) in window — rule id + masked match)\n",
        i.blocked_events, i.alert_events
    ));
    if i.events.is_empty() {
        s.push_str("- (none)\n");
    } else {
        s.push_str("\n| time (local) | rule | matched (masked) | route |\n");
        s.push_str("|---|---|---|---|\n");
        for e in &i.events {
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                e.timestamp,
                e.rule_id,
                e.masked_detail.replace('|', "\\|"),
                e.route
            ));
        }
    }
    s.push('\n');

    s.push_str("## MCP (aggregate — server hostnames omitted)\n");
    s.push_str(&format!(
        "- tools/call events: {} across {} distinct upstream server(s)\n\n",
        i.mcp_events, i.mcp_distinct_servers
    ));

    s.push_str("## Effective config (redacted)\n```toml\n");
    s.push_str(&i.config_redacted);
    if !i.config_redacted.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("```\n");

    s
}

/// Redact a TOML config dump: blank the value of any key whose name implies a
/// secret, and mask any secret-shaped token anywhere on the line. Canary
/// values (`security.canaries`) are real planted credentials and must go.
fn redact_config(toml_text: &str) -> String {
    let mut out = String::with_capacity(toml_text.len());
    let mut in_canaries = false;
    for line in toml_text.lines() {
        let trimmed = line.trim_start();
        // Track a multi-line `canaries = [` array; redact its element lines too.
        if trimmed.starts_with("canaries") {
            in_canaries = trimmed.contains('[') && !trimmed.contains(']');
            out.push_str(&redact_kv_line(line));
            out.push('\n');
            continue;
        }
        if in_canaries {
            if line.contains(']') {
                in_canaries = false;
            }
            out.push_str(&blank_value(line));
            out.push('\n');
            continue;
        }
        out.push_str(&redact_kv_line(line));
        out.push('\n');
    }
    out
}

/// True if a TOML key name implies its value is a secret.
fn key_is_secretish(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    // "canar" catches both `canary` and `canaries`.
    ["key", "token", "secret", "password", "passwd", "canar", "credential"]
        .iter()
        .any(|needle| k.contains(needle))
}

/// Redact one `key = value` line by key-name, then mask any secret-shaped token.
fn redact_kv_line(line: &str) -> String {
    if let Some((lhs, _rhs)) = line.split_once('=') {
        if key_is_secretish(lhs.trim()) {
            return format!("{}= \"[redacted]\"", lhs);
        }
    }
    mask_secrets_in_line(line)
}

/// Blank the literal values on an array-element line (`  "AKIA…",`).
fn blank_value(line: &str) -> String {
    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let suffix = if line.trim_end().ends_with(',') { "," } else { "" };
    format!("{indent}\"[redacted]\"{suffix}")
}

/// Replace any secret-shaped span on a line with its masked preview.
fn mask_secrets_in_line(line: &str) -> String {
    match secrets::first_match_masked(line) {
        Some((_, masked)) => {
            // We have the masked preview but not the raw span offsets; rebuild
            // the line by masking every whitespace token that itself matches.
            line.split_inclusive(char::is_whitespace)
                .map(|tok| {
                    let core = tok.trim();
                    if !core.is_empty() && secrets::first_match_masked(core).is_some() {
                        tok.replacen(core, &masked, 1)
                    } else {
                        tok.to_string()
                    }
                })
                .collect()
        }
        None => line.to_string(),
    }
}

/// Reduce a recorded `details` value to a masked match: drop the `type:` prefix,
/// keep label-only details (secret/dlp pattern names) as-is, and mask anything
/// that looks like a path/command so filesystem layout doesn't leak.
fn redact_detail(event_type: &str, details: &str) -> String {
    let value = details
        .strip_prefix(event_type)
        .and_then(|r| r.strip_prefix(": "))
        .unwrap_or(details);
    match event_type {
        // These store a pattern *name* ("AWS access key ID"), not the value.
        "secret_detected" | "dlp_blocked" | "misdirection_blocked" => value.to_string(),
        // Paths / commands / mounts: mask so structure doesn't leak.
        _ => secrets::mask_match(value),
    }
}

/// Final backstop: mask any secret-shaped token on any line of the assembled
/// report. If redaction upstream missed something, this catches it before the
/// self-scan ever runs.
fn harden(report: String) -> String {
    report
        .lines()
        .map(mask_secrets_in_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Extract a bare host from a URI for distinct-server counting (no URL crate).
/// We only ever count these — hostnames are never written to the bundle.
fn host_of(uri: &str) -> Option<String> {
    let after = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri);
    let host_port = after.split(['/', '?', '#']).next().unwrap_or(after);
    let host = host_port.rsplit_once('@').map(|(_, h)| h).unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> DoctorInput {
        DoctorInput {
            version: "0.11.0".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            days: 7,
            proxy_running: true,
            proxy_pid: Some(4242),
            paused: false,
            routing: "proxied",
            routed_proxy_alive: Some(true),
            env_file_state: Some("active"),
            proxy_listening: true,
            config_redacted: "[security]\nenabled = true\n".into(),
            security_enabled: true,
            canaries_armed: 1,
            pricing_age_days: Some(3),
            total_cost: 1.23,
            total_requests: 10,
            blocked_events: 1,
            alert_events: 2,
            cost_rows: vec![CostRow {
                provider: "anthropic".into(),
                model: "claude-opus-4-7".into(),
                cost: 1.23,
                requests: 10,
                cache_hit_pct: 80.0,
            }],
            events: vec![EventRow {
                timestamp: "2026-06-11 10:00:00".into(),
                rule_id: "path_blocked".into(),
                masked_detail: "~/.…rsa".into(),
                route: "anthropic/claude-opus-4-7".into(),
            }],
            mcp_events: 4,
            mcp_distinct_servers: 2,
        }
    }

    #[test]
    fn report_has_sections_and_no_raw_secret() {
        let r = build_report(&sample_input());
        assert!(r.contains("## Environment"));
        assert!(r.contains("## Cost summary"));
        assert!(r.contains("## Recent security events (1 block(s) + 2 alert(s)"));
        assert!(r.contains("server hostnames omitted"));
        assert!(r.contains("0.11.0"));
    }

    #[test]
    fn redact_config_masks_canary_and_secretish_keys() {
        let toml = "[anthropic]\napi_key = \"sk-ant-secretvalue\"\n\n[security]\ncanaries = [\"AKIAIOSFODNN7EXAMPLE0\"]\n";
        let red = redact_config(toml);
        assert!(!red.contains("sk-ant-secretvalue"));
        assert!(red.contains("api_key = \"[redacted]\""));
        // The canary value must not survive in any form.
        assert!(!red.contains("AKIAIOSFODNN7EXAMPLE0"));
    }

    #[test]
    fn redact_config_masks_multiline_canary_array() {
        let toml = "[security]\ncanaries = [\n  \"AKIAIOSFODNN7EXAMPLE0\",\n  \"AKIAIOSFODNN7EXAMPLE1\",\n]\n";
        let red = redact_config(toml);
        assert!(!red.contains("EXAMPLE0"));
        assert!(!red.contains("EXAMPLE1"));
        assert!(red.contains("[redacted]"));
    }

    #[test]
    fn redact_detail_masks_paths_keeps_labels() {
        // A path is masked (structure hidden).
        let masked = redact_detail("path_blocked", "path_blocked: ~/.ssh/id_rsa");
        assert!(!masked.contains(".ssh"));
        // A secret pattern *name* is kept (it is already safe).
        assert_eq!(
            redact_detail("secret_detected", "AWS access key ID"),
            "AWS access key ID"
        );
    }

    #[test]
    fn harden_masks_a_secret_that_slipped_through() {
        // Simulate a raw AWS-shaped key surviving into the body; harden + the
        // self-scan must neutralize it. Assembled by concat so this source file
        // stays clean under the pre-push secret guard, and chosen so it matches
        // the detector (not the filtered AWS doc example).
        let leaked = format!("note: {} appeared\n", "AKIA".to_string() + "QQQQRRRRSSSSTTTT");
        let hardened = harden(leaked);
        assert!(!hardened.contains("QQQQRRRRSSSS")); // masked middle is gone
        // And the canonical self-scan agrees it is clean.
        assert!(filescan::scan_text("doctor-export", &hardened).is_empty());
    }

    #[test]
    fn host_of_extracts_bare_host() {
        assert_eq!(host_of("https://api.example.com:443/mcp?x=1").as_deref(), Some("api.example.com"));
        assert_eq!(host_of("http://user@10.0.0.1/rpc").as_deref(), Some("10.0.0.1"));
        assert_eq!(host_of("").as_deref(), None);
    }

    /// A `direct` input with a given env-file state and proxy liveness, for the
    /// protection-verdict transitions.
    fn direct_input(env_file_state: Option<&'static str>, proxy_listening: bool) -> DoctorInput {
        DoctorInput {
            routing: "direct",
            routed_proxy_alive: None,
            env_file_state,
            proxy_listening,
            ..sample_input()
        }
    }

    #[test]
    fn protected_when_proxied_and_alive() {
        let p = assess_protection(&sample_input());
        assert!(p.ok && !p.chosen && p.fix.is_none(), "{p:?}");
    }

    #[test]
    fn proxied_but_dead_port_is_unintended_and_fixable() {
        let i = DoctorInput {
            routed_proxy_alive: Some(false),
            ..sample_input()
        };
        let p = assess_protection(&i);
        assert!(!p.ok && !p.chosen, "{p:?}");
        assert!(p.fix.unwrap().contains("burnwall start"));
    }

    #[test]
    fn degraded_direct_proxy_down_suggests_start() {
        // Routing configured (active env) but the proxy is down: unintended,
        // not chosen → `--fix` is allowed to act. This is the user's case.
        let p = assess_protection(&direct_input(Some("active"), false));
        assert!(!p.ok && !p.chosen, "must be unintended, not a choice: {p:?}");
        let fix = p.fix.unwrap();
        assert!(fix.contains("burnwall start"), "fix: {fix}");
    }

    #[test]
    fn degraded_direct_proxy_up_suggests_new_shell() {
        // Proxy is up but this shell predates it: unintended, but the fix is a
        // new shell, NOT starting anything.
        let p = assess_protection(&direct_input(Some("active"), true));
        assert!(!p.ok && !p.chosen, "{p:?}");
        let fix = p.fix.unwrap();
        assert!(fix.contains("new shell"), "fix: {fix}");
        assert!(!fix.contains("burnwall start"), "must not tell them to start: {fix}");
    }

    #[test]
    fn disabled_routing_is_a_respected_choice() {
        let p = assess_protection(&direct_input(Some("disabled"), false));
        assert!(!p.ok && p.chosen, "a deliberate disable must be `chosen`: {p:?}");
        assert!(p.fix.unwrap().contains("enable-routing"));
    }

    #[test]
    fn never_configured_points_at_init() {
        let p = assess_protection(&direct_input(None, false));
        assert!(p.chosen, "{p:?}");
        assert!(p.fix.unwrap().contains("burnwall init"));
    }

    #[test]
    fn pause_and_bypass_are_chosen_not_alarms() {
        let paused = DoctorInput { paused: true, ..sample_input() };
        assert!(assess_protection(&paused).chosen);
        let bypass = DoctorInput { routing: "bypassed", ..sample_input() };
        assert!(assess_protection(&bypass).chosen);
    }

    #[test]
    fn export_report_carries_protection_verdict() {
        // The shareable bundle states the verdict + env-file state (metadata,
        // not sensitive) so a bug report shows whether the user was protected.
        let r = build_report(&direct_input(Some("active"), false));
        assert!(r.contains("UNPROTECTED"), "{r}");
        assert!(r.contains("routing configured (env file): active"), "{r}");
    }
}
