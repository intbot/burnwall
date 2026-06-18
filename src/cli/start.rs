//! `burnwall start` — boot the proxy. Reads `~/.burnwall/config.toml` for
//! budget, security, and proxy bind values; CLI flags override individual
//! fields when present.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use super::daemon;
use crate::budget::{BudgetTracker, LoopDetector};
use crate::config;
use crate::proxy::{AppState, serve_with_shutdown};
use crate::security::SecurityEngine;
use crate::storage::Storage;

/// Built-in provider endpoints. A CLI `--upstream-*` flag that differs from
/// these wins; otherwise a non-empty `[upstreams]` config value applies; the
/// built-in is the fallback. Lets Burnwall chain in front of another local
/// gateway or a corporate egress proxy without losing scanning or tracking.
pub const DEFAULT_UPSTREAM_ANTHROPIC: &str = "https://api.anthropic.com";
pub const DEFAULT_UPSTREAM_OPENAI: &str = "https://api.openai.com";
pub const DEFAULT_UPSTREAM_GOOGLE: &str = "https://generativelanguage.googleapis.com";

#[derive(Args, Debug)]
pub struct StartArgs {
    /// TCP port to listen on. Overrides `proxy.port` from config.
    #[arg(long)]
    pub port: Option<u16>,
    /// Address to bind on. Overrides `proxy.host` from config.
    #[arg(long)]
    pub host: Option<String>,
    /// Run in the background, detached from the terminal. The PID is
    /// written to `<data dir>/burnwall.pid`; stop it with `burnwall stop`.
    #[arg(long)]
    pub daemon: bool,
    /// Override the Anthropic upstream URL (beats `upstreams.anthropic`).
    #[arg(long, default_value = DEFAULT_UPSTREAM_ANTHROPIC)]
    pub upstream_anthropic: String,
    /// Override the OpenAI upstream URL (beats `upstreams.openai`).
    #[arg(long, default_value = DEFAULT_UPSTREAM_OPENAI)]
    pub upstream_openai: String,
    /// Override the Google Gemini upstream URL (beats `upstreams.google`).
    #[arg(long, default_value = DEFAULT_UPSTREAM_GOOGLE)]
    pub upstream_google: String,
    /// Auto-inject Anthropic `cache_control` markers on outbound requests.
    /// Overrides `proxy.cache_injection` from config when present.
    #[arg(long)]
    pub rewrite_anthropic_cache: bool,
    /// Leave shell routing untouched: don't re-enable it once the proxy is
    /// up, and don't pause it when the proxy exits.
    #[arg(long)]
    pub no_routing: bool,
    /// (internal) Pause routing when this process exits even under
    /// `--no-routing`. Injected by the daemon launcher so a gracefully-exiting
    /// background child doesn't strand Active env files at a dead port.
    #[arg(long, hide = true)]
    pub pause_routing_on_exit: bool,
    /// Don't spawn the guard watchdog alongside the daemon. By default
    /// `--daemon` also starts `burnwall guard`, which auto-pauses routing if
    /// the proxy dies silently (e.g. an antivirus quarantine) so new shells go
    /// direct instead of stranding at a dead port.
    #[arg(long)]
    pub no_guard: bool,
}

pub async fn run_cmd(args: StartArgs) -> anyhow::Result<()> {
    // Diagnose an unclean prior exit (crash / forced kill / antivirus
    // quarantine) BEFORE anything cleans up the stale PID file. The usual
    // cause on Windows is Defender quarantining the unsigned binary, which
    // silently kills the daemon and strands every routed shell on a dead
    // port — naming it turns a baffling `ConnectionRefused` into a fix. Read
    // once here so the daemon launcher surfaces it on the user's terminal
    // (the detached child logs to a file nobody is watching).
    let prior_exit = daemon::take_prior_exit_status();

    if args.daemon {
        if let daemon::PriorExit::Abnormal { consecutive } = prior_exit {
            for line in unclean_prior_exit_lines(consecutive) {
                println!("{line}");
            }
        }
        return daemon::spawn_background(&args).await;
    }

    let cfg_path = config::default_path()?;
    let user_config = config::load_or_default(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

    // The daemon child (marked by --pause-routing-on-exit) runs with stdio
    // detached, so stdout logging goes nowhere — a crashed daemon used to be
    // undiagnosable, and `logging.file` was a dead config key (L-H2). Route
    // its tracing to the configured log file; foreground keeps stdout.
    let log_file = if args.pause_routing_on_exit {
        resolved_log_path(&user_config.logging)
    } else {
        None
    };
    init_tracing(log_file, &user_config.logging.level);
    install_panic_hook();
    tracing::info!("panic capture armed — a crash in any background task will be logged here");

    // Foreground start (a user running `burnwall start` directly — the daemon
    // CHILD sees `Clean` here because the launcher already consumed the
    // signal): surface the unclean prior exit both on stdout and through
    // tracing so it lands in the log too.
    if let daemon::PriorExit::Abnormal { consecutive } = prior_exit {
        for line in unclean_prior_exit_lines(consecutive) {
            println!("{line}");
        }
        tracing::warn!("previous run exited uncleanly ({consecutive} in a row)");
    }

    // Refuse to start a second proxy on top of a running one — `bind` below
    // is the real backstop, but this gives a clearer message in the common
    // case (and cleans up a stale PID file from a previous crashed run). A
    // proxy that is only DRAINING (a soft `burnwall stop` left it up as a
    // pass-through) is retired here so `stop` → `start` re-arms protection.
    if let Some(pid) = daemon::protecting_proxy_blocking_start()? {
        anyhow::bail!(
            "Burnwall is already running (PID {pid}). Use `burnwall stop` to stop it first."
        );
    }
    // A fresh start means protection is ON: clear any stale bypass (the drain
    // left by a proxy we just retired, or an orphaned pause) so the new daemon
    // never boots straight into relay-only mode with protection silently off.
    let _ = crate::bypass::clear();

    let storage = Arc::new(Storage::open_default().context("opening default storage")?);

    let mut ruleset: crate::security::Ruleset = (&user_config.security).into();
    let mut budget_cfg: crate::budget::BudgetConfig = (&user_config.budget).into();

    // Enabled official rule packs (v0.6): bundled, inherently-trusted packs the
    // user turned on with `burnwall rules install`. Each only EXTENDS the deny
    // lists (invariant I2). Applied before the project profile.
    for id in &user_config.rules.enabled {
        match crate::security::packs::load_official(id) {
            Some(pack) => pack.apply_to_ruleset(&mut ruleset),
            None => {
                tracing::warn!("configured rule pack '{id}' is not a known official pack; skipping")
            }
        }
    }

    // Approved third-party rule packs (v0.6): files under `<data dir>/rules/`,
    // applied ONLY when the file's current SHA-256 matches the pinned approval
    // (invariant I6). An edited or unapproved pack is skipped with a warning —
    // never silently trusted. `burnwall rules add` installs + pins them.
    apply_third_party_packs(&storage, &mut ruleset);

    // Per-project profile: discover a `.burnwall.yaml` by walking up from the
    // working directory and layer its rules onto the global config. deny_paths
    // extend the denylist, allow_paths add exceptions, and budget.daily_max_usd
    // can only tighten the daily limit. See `config::project`.
    let project_profile = match std::env::current_dir() {
        Ok(cwd) => config::project::discover_and_load(&cwd)
            .context("loading per-project .burnwall.yaml")?,
        Err(e) => {
            tracing::warn!("could not determine working directory: {e}");
            None
        }
    };
    if let Some((_, profile)) = &project_profile {
        profile.apply_to_ruleset(&mut ruleset);
        profile.apply_to_budget(&mut budget_cfg);
    }

    let security = Arc::new(SecurityEngine::new(ruleset));
    let budget = Arc::new(BudgetTracker::new(budget_cfg));
    let loop_detector = Arc::new(LoopDetector::new((&user_config.loop_detection).into()));

    // Hydrate from the user's local "today" — storage queries match
    // timestamps in local time, so the budget counter restarts on the
    // local day boundary, not UTC midnight.
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    budget
        .hydrate_for_date(&storage, &today)
        .context("hydrating today's spend")?;
    let this_month = chrono::Local::now().format("%Y-%m").to_string();
    budget
        .hydrate_for_month(&storage, &this_month)
        .context("hydrating this month's spend")?;

    let port = args.port.unwrap_or(user_config.proxy.port);
    let host_str = args
        .host
        .clone()
        .unwrap_or_else(|| user_config.proxy.host.clone());

    let cache_injection = args.rewrite_anthropic_cache || user_config.proxy.cache_injection;

    // Gateway chaining (#9): resolve each provider's effective upstream —
    // explicit CLI flag, else `[upstreams]` config, else the provider's own
    // API. Resolved in place so the banner and AppState agree on the truth.
    let mut args = args;
    args.upstream_anthropic = resolve_upstream(
        &args.upstream_anthropic,
        DEFAULT_UPSTREAM_ANTHROPIC,
        &user_config.upstreams.anthropic,
    );
    args.upstream_openai = resolve_upstream(
        &args.upstream_openai,
        DEFAULT_UPSTREAM_OPENAI,
        &user_config.upstreams.openai,
    );
    args.upstream_google = resolve_upstream(
        &args.upstream_google,
        DEFAULT_UPSTREAM_GOOGLE,
        &user_config.upstreams.google,
    );

    // Resilience: same-model endpoint failover + circuit breaking. Disabled
    // unless `[resilience]` is configured.
    let resilience = Arc::new(user_config.resilience.to_runtime());

    // OTel GenAI spans: opt-in, file-only (no network). Default path lives
    // under the data dir. A failure to open the file is non-fatal — we warn
    // and run without span emission rather than refusing to start.
    #[cfg(feature = "observe")]
    let otel = if user_config.observability.otel_spans {
        let path = if user_config.observability.otel_file.trim().is_empty() {
            crate::storage::data_dir()
                .map(|d| d.join("otel-spans.jsonl"))
                .unwrap_or_else(|_| std::path::PathBuf::from("otel-spans.jsonl"))
        } else {
            std::path::PathBuf::from(&user_config.observability.otel_file)
        };
        match crate::observe::otel::SpanWriter::open(&path) {
            Ok(w) => Some(Arc::new(w)),
            Err(e) => {
                tracing::warn!("could not open OTel span file {}: {e}", path.display());
                None
            }
        }
    } else {
        None
    };

    print_banner(
        &host_str,
        port,
        &args,
        &storage,
        &security,
        &budget,
        project_profile.as_ref(),
        &user_config.rules.enabled,
        cache_injection,
        &resilience,
        #[cfg(feature = "observe")]
        otel.as_deref(),
    );

    let state = AppState {
        upstream_anthropic: args.upstream_anthropic.clone(),
        upstream_openai: args.upstream_openai.clone(),
        upstream_google: args.upstream_google.clone(),
        http_client: crate::proxy::build_http_client(),
        security,
        budget,
        loop_detector,
        storage,
        cache_injection,
        trim_tool_output: user_config.proxy.trim_tool_output,
        paranoid: user_config.security.paranoid,
        warn_response_exfil: user_config.security.warn_response_exfil,
        resilience,
        #[cfg(feature = "observe")]
        otel,
        // Live escape hatch: `burnwall pause` / `allow-once` write this file;
        // the handler checks it per request. Resolved once, here.
        pause_path: crate::bypass::default_path(),
        last_activity: Arc::new(std::sync::atomic::AtomicI64::new(
            chrono::Utc::now().timestamp(),
        )),
    };

    let host: IpAddr = host_str
        .parse()
        .with_context(|| format!("invalid host: {}", host_str))?;
    let addr = SocketAddr::new(host, port);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr} — is the port already in use?"))?;

    // Record our PID so `burnwall stop` (and a second `start`) can find us.
    // Removed on graceful shutdown; `stop` and `running_pid` clean it up if
    // we are killed without the chance to.
    daemon::write_pid_file(std::process::id())?;

    // Routing follows the proxy lifecycle: resume it now that the port is
    // actually bound (never before — routing at a dead port is the failure
    // mode this exists to prevent), pause it again on the way out so a
    // Ctrl-C'd foreground proxy doesn't strand new shells either.
    if !args.no_routing {
        resume_and_report(&format!("http://localhost:{port}"));
    }

    let state = Arc::new(state);
    // Idle-retire monitor: when a soft `burnwall stop` flips us into drain
    // (relay-only) mode, wind the process down once traffic goes idle so the
    // port frees on its own — without ever cutting an in-use tool. A no-op
    // until/unless drain is entered.
    spawn_idle_retire_monitor(state.clone());
    let result = serve_with_shutdown(listener, state, daemon::shutdown_signal()).await;
    daemon::remove_pid_file().ok();
    // We reached the end of `serve` on our own terms (signal / shutdown file),
    // so this run is exiting cleanly — clear the unclean-exit escalation.
    daemon::note_clean_exit();
    if !args.no_routing || args.pause_routing_on_exit {
        super::stop::pause_and_report();
    }
    result.context("proxy serve")?;
    Ok(())
}

/// Seconds a drain relay (from a soft `burnwall stop`) may sit idle before it
/// retires itself and frees the port. Long enough to bridge a tool between
/// requests, short enough that a stopped proxy doesn't linger.
const DRAIN_IDLE_RETIRE_SECS: i64 = 60;

/// Watchdog for the drain relay a soft `burnwall stop` leaves behind: while
/// drain is active and no real request has arrived for [`DRAIN_IDLE_RETIRE_SECS`],
/// ask the proxy to shut down (via the same shutdown file `stop` uses) so the
/// port frees itself. A no-op while protection is on — it only ever fires once
/// drain has been entered, and only after traffic has actually gone quiet.
fn spawn_idle_retire_monitor(state: Arc<AppState>) {
    const POLL: std::time::Duration = std::time::Duration::from_secs(5);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL).await;
            let now = chrono::Utc::now().timestamp();
            let draining = crate::bypass::is_draining(now);
            let last = state
                .last_activity
                .load(std::sync::atomic::Ordering::Relaxed);
            if drain_should_retire(draining, now, last, DRAIN_IDLE_RETIRE_SECS) {
                tracing::info!(
                    "drain idle for {}s — retiring the proxy so the port frees",
                    now - last
                );
                if let Ok(path) = daemon::shutdown_file_path() {
                    let _ = std::fs::write(&path, "idle-retire after soft stop");
                }
                return;
            }
        }
    });
}

/// Pure decision for the idle-retire monitor: a drain relay retires only while
/// drain is actually in effect AND no real request has arrived for `idle_secs`.
/// Split out so the timing logic is unit-testable without a clock or a socket.
fn drain_should_retire(is_draining: bool, now: i64, last_activity: i64, idle_secs: i64) -> bool {
    is_draining && now - last_activity >= idle_secs
}

/// Lines explaining an unclean prior exit, with platform-specific antivirus
/// guidance. Escalates wording once it has happened repeatedly — a single
/// occurrence is often a reboot; a streak is almost always AV quarantining
/// the unsigned binary. Returned as lines so the daemon launcher can print
/// them to the terminal and the foreground path can log them.
fn unclean_prior_exit_lines(consecutive: u32) -> Vec<String> {
    let mut out = Vec::new();
    if consecutive >= 2 {
        out.push(format!(
            "⚠️  Burnwall has failed to shut down cleanly {consecutive} times in a row."
        ));
        out.push(
            "    This is almost always an antivirus quarantining the (unsigned) binary."
                .to_string(),
        );
    } else {
        out.push(
            "⚠️  Burnwall did not shut down cleanly last time (crash, forced kill, antivirus, or an unclean reboot)."
                .to_string(),
        );
    }
    #[cfg(windows)]
    {
        out.push(
            "    If it keeps happening, exclude Burnwall in an elevated PowerShell:".to_string(),
        );
        out.push(
            "      Add-MpPreference -ExclusionPath \"$env:USERPROFILE\\.burnwall\"".to_string(),
        );
    }
    #[cfg(not(windows))]
    {
        out.push(
            "    If it keeps happening, an antivirus or the OOM killer may be terminating it; check your security tool's quarantine/logs."
                .to_string(),
        );
    }
    out.push("    Recover stranded shells with:  burnwall recover".to_string());
    out
}

/// Re-enable shell routing now that the proxy is serving, honoring an
/// explicit `disable-routing`, and say what happened. Failures are warnings —
/// routing is a convenience layer and must never stop the proxy.
/// Also called by the `--daemon` launcher once the child reports ready.
pub(crate) fn resume_and_report(proxy_url: &str) {
    use super::routing::ResumeAction;

    let outcomes = match super::routing::resume_routing(proxy_url) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("could not re-enable shell routing: {e}");
            return;
        }
    };
    let sty = crate::term::Styler::stdout();
    if outcomes.is_empty() {
        println!(
            "   Routing:  no shell configured — run `burnwall init` (or `burnwall enable-routing`) to route AI tools here."
        );
        return;
    }
    let labels = |action: ResumeAction| -> Vec<&str> {
        outcomes
            .iter()
            .filter(|o| o.action == action)
            .map(|o| o.shell.label())
            .collect()
    };
    let resumed = labels(ResumeAction::Resumed);
    if !resumed.is_empty() {
        println!(
            "   Routing:  {} for {} — new shells route through the proxy",
            sty.green("re-enabled"),
            resumed.join(", ")
        );
    }
    let refreshed = labels(ResumeAction::Refreshed);
    if !refreshed.is_empty() {
        println!(
            "   Routing:  {} for {}",
            sty.green("active"),
            refreshed.join(", ")
        );
    }
    let left = labels(ResumeAction::LeftDisabled);
    if !left.is_empty() {
        println!(
            "   Routing:  {} for {} (explicitly disabled — `burnwall enable-routing` to turn on)",
            sty.yellow("left off"),
            left.join(", ")
        );
    }
}

/// Resolve `logging.file` (with `~/` expansion) to a concrete path. Empty
/// string disables file logging.
pub(crate) fn resolved_log_path(
    logging: &crate::config::types::LoggingConfig,
) -> Option<std::path::PathBuf> {
    let raw = logging.file.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return dirs::home_dir().map(|h| h.join(rest));
    }
    Some(std::path::PathBuf::from(raw))
}

/// Effective upstream for one provider: an explicitly-passed CLI flag (any
/// value differing from the built-in default) wins; else a non-empty
/// `[upstreams]` config entry (trailing slash trimmed so path joins stay
/// clean); else the built-in provider endpoint. A flag explicitly set *to*
/// the default is indistinguishable from unset — and means the default, so
/// the ambiguity is harmless.
fn resolve_upstream(cli_value: &str, builtin_default: &str, configured: &str) -> String {
    if cli_value != builtin_default {
        return cli_value.to_string();
    }
    let configured = configured.trim();
    if !configured.is_empty() {
        return configured.trim_end_matches('/').to_string();
    }
    builtin_default.to_string()
}

/// Route panics through `tracing` so they land in the configured log even
/// when stderr is detached — the daemon child runs with stdio null, so
/// without this a panic in a background task (the response tee, a
/// connection task) vanishes without a trace and an abruptly-closed socket
/// is undiagnosable. The request pipeline's own panic catcher converts
/// handler panics to logged 502s; this hook covers everything outside it.
/// Chains the default hook so foreground runs still print to stderr.
/// Logs the panic's message and location only — never request content.
pub(crate) fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "unknown location".to_string());
            let msg = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("non-string panic payload");
            tracing::error!("panic at {location}: {msg}");
            default_hook(info);
        }));
    });
}

fn init_tracing(log_file: Option<std::path::PathBuf>, level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = || {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let lvl = if level.trim().is_empty() {
                "info"
            } else {
                level.trim()
            };
            EnvFilter::new(format!("{lvl},hyper=warn,h2=warn"))
        })
    };
    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Size cap without a rotation dep: shove an oversized log aside once
        // at startup so the file can't grow unbounded across months of uptime.
        const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
        if std::fs::metadata(&path)
            .map(|m| m.len() > MAX_LOG_BYTES)
            .unwrap_or(false)
        {
            let _ = std::fs::rename(&path, path.with_extension("log.old"));
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => {
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(filter())
                    .with_ansi(false)
                    .with_writer(std::sync::Arc::new(file))
                    .try_init();
                return;
            }
            Err(e) => {
                eprintln!(
                    "burnwall: could not open log file {}: {e} — logging to stdout",
                    path.display()
                );
            }
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter())
        .try_init();
}

/// Apply approved third-party rule packs from `<data dir>/rules/*.toml`. Each
/// is applied only when its current content hash matches the TOFU pin in
/// storage (invariant I6); edited or unapproved packs are skipped with a
/// warning. Fail-open: an unreadable dir / file contributes nothing.
fn apply_third_party_packs(storage: &Arc<Storage>, ruleset: &mut crate::security::Ruleset) {
    let Ok(dir) = crate::storage::data_dir().map(|d| d.join("rules")) else {
        return;
    };
    let Ok(read) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(pack) = crate::security::packs::RulePack::parse(&content) else {
            continue;
        };
        let hash = crate::security::packs::content_hash(content.as_bytes());
        match storage.rule_pack_approved_hash(&pack.id) {
            Ok(Some(approved)) if approved == hash => pack.apply_to_ruleset(ruleset),
            Ok(Some(_)) => tracing::warn!(
                "rule pack '{}' changed since approval — skipped; re-run `burnwall rules add` to approve",
                pack.id
            ),
            _ => tracing::warn!(
                "rule pack '{}' is not approved — skipped (run `burnwall rules add`)",
                pack.id
            ),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn print_banner(
    host: &str,
    port: u16,
    args: &StartArgs,
    storage: &Arc<Storage>,
    security: &Arc<SecurityEngine>,
    budget: &Arc<BudgetTracker>,
    project_profile: Option<&(std::path::PathBuf, config::project::ProjectProfile)>,
    rule_packs: &[String],
    cache_injection: bool,
    resilience: &Arc<crate::proxy::resilience::Resilience>,
    #[cfg(feature = "observe")] otel: Option<&crate::observe::otel::SpanWriter>,
) {
    let _ = storage;
    let sty = crate::term::Styler::stdout();
    println!(
        "{}",
        sty.cyan(&sty.bold(&format!("🛡️  Burnwall v{}", env!("CARGO_PKG_VERSION"))))
    );
    println!(
        "   Proxy:    {}",
        sty.green(&format!("http://{}:{}", host, port))
    );
    println!("   Routes:");
    println!("     /anthropic/* → {}", args.upstream_anthropic);
    println!("     /openai/*    → {}", args.upstream_openai);
    println!("     /google/*    → {}", args.upstream_google);
    println!(
        "   Security: {} deny paths, {} allow paths, {} deny commands, mounts={}, secrets={}",
        security.rules().deny_paths.len(),
        security.rules().allow_paths.len(),
        security.rules().deny_commands.len(),
        security.rules().block_network_mounts,
        security.rules().detect_secrets,
    );
    if !rule_packs.is_empty() {
        println!(
            "   Rules:    {} official pack(s): {}",
            rule_packs.len(),
            rule_packs.join(", ")
        );
    }
    let cfg = budget.config();
    if cfg.daily_usd > 0.0 {
        println!(
            "   Budget:   ${:.2}/day (today: ${:.4})",
            cfg.daily_usd,
            budget.today_spent()
        );
    } else {
        println!("   Budget:   unlimited");
    }
    if let Some((path, profile)) = project_profile {
        let cap = match profile.budget.daily_max_usd {
            Some(c) if c.is_finite() && c > 0.0 => format!("budget cap ${:.2}/day", c),
            _ => "no budget cap".to_string(),
        };
        println!(
            "   Project:  {} ({} allow, {} deny paths; {})",
            path.display(),
            profile.allow_paths.len(),
            profile.deny_paths.len(),
            cap,
        );
    }
    if cache_injection {
        println!("   Cache:    Anthropic cache_control injection ON");
    }
    if resilience.enabled {
        println!("   Resilience: endpoint failover ON (circuit breaker active)");
    }
    #[cfg(feature = "observe")]
    if let Some(w) = otel {
        println!("   OTel:     GenAI spans → {}", w.path().display());
    }
    println!("   {}", sty.green("🟢 Ready. Press Ctrl-C to stop."));
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    /// `MakeWriter` capturing into a shared buffer, so the test can assert
    /// on what the panic hook emitted through tracing.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    #[test]
    fn panics_are_routed_into_tracing() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Capture(buf.clone()))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            super::install_panic_hook();
            // The hook runs on the panicking thread, where the scoped
            // subscriber is active; catch_unwind keeps the test alive. The
            // chained default hook prints to (libtest-captured) stderr.
            let _ = std::panic::catch_unwind(|| panic!("sentinel-panic-for-log"));
        });
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(text.contains("panic at"), "panic was logged: {text}");
        assert!(text.contains("sentinel-panic-for-log"), "{text}");
        assert!(text.contains("start.rs"), "location captured: {text}");
    }

    #[test]
    fn unclean_prior_exit_lines_escalate_and_point_to_recover() {
        // One-off reads as a soft "didn't shut down cleanly"; a streak
        // escalates to "almost always antivirus". Both route the user to the
        // recovery command, and on Windows name the exclusion fix.
        let one = super::unclean_prior_exit_lines(1).join("\n");
        assert!(one.contains("did not shut down cleanly"), "{one}");
        assert!(one.contains("burnwall recover"), "{one}");

        let many = super::unclean_prior_exit_lines(4).join("\n");
        assert!(many.contains("4 times in a row"), "{many}");
        assert!(many.contains("antivirus"), "{many}");
        assert!(many.contains("burnwall recover"), "{many}");
        #[cfg(windows)]
        assert!(many.contains("Add-MpPreference"), "{many}");
    }

    #[test]
    fn drain_retires_only_when_draining_and_idle() {
        let idle = 60;
        // Not draining → never retire, however long idle.
        assert!(!super::drain_should_retire(false, 1_000, 0, idle));
        // Draining but still active (recent request) → keep relaying.
        assert!(!super::drain_should_retire(true, 1_000, 990, idle));
        // Draining and idle past the window → retire (frees the port).
        assert!(super::drain_should_retire(true, 1_000, 940, idle));
        assert!(super::drain_should_retire(true, 1_000, 900, idle));
    }

    #[test]
    fn upstream_resolution_precedence() {
        // CLI flag (≠ default) wins; else non-empty config; else built-in.
        let d = super::DEFAULT_UPSTREAM_ANTHROPIC;
        assert_eq!(
            super::resolve_upstream("http://flag:1", d, "http://cfg:2"),
            "http://flag:1"
        );
        assert_eq!(
            super::resolve_upstream(d, d, "http://cfg:2/"),
            "http://cfg:2"
        );
        assert_eq!(super::resolve_upstream(d, d, "  "), d);
    }
}
