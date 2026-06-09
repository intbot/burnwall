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
use crate::proxy::{serve_with_shutdown, AppState};
use crate::security::SecurityEngine;
use crate::storage::Storage;

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
    /// Override the Anthropic upstream URL (useful for testing).
    #[arg(long, default_value = "https://api.anthropic.com")]
    pub upstream_anthropic: String,
    /// Override the OpenAI upstream URL.
    #[arg(long, default_value = "https://api.openai.com")]
    pub upstream_openai: String,
    /// Override the Google Gemini upstream URL.
    #[arg(long, default_value = "https://generativelanguage.googleapis.com")]
    pub upstream_google: String,
    /// Auto-inject Anthropic `cache_control` markers on outbound requests.
    /// Overrides `proxy.cache_injection` from config when present.
    #[arg(long)]
    pub rewrite_anthropic_cache: bool,
}

pub async fn run_cmd(args: StartArgs) -> anyhow::Result<()> {
    if args.daemon {
        return daemon::spawn_background(&args).await;
    }

    init_tracing();

    // Refuse to start a second proxy on top of a running one — `bind` below
    // is the real backstop, but this gives a clearer message in the common
    // case (and cleans up a stale PID file from a previous crashed run).
    if let Some(pid) = daemon::running_pid()? {
        anyhow::bail!(
            "Burnwall is already running (PID {pid}). Use `burnwall stop` to stop it first."
        );
    }

    let cfg_path = config::default_path()?;
    let user_config = config::load_or_default(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

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

    let port = args.port.unwrap_or(user_config.proxy.port);
    let host_str = args
        .host
        .clone()
        .unwrap_or_else(|| user_config.proxy.host.clone());

    let cache_injection = args.rewrite_anthropic_cache || user_config.proxy.cache_injection;

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
        http_client: reqwest::Client::new(),
        security,
        budget,
        loop_detector,
        storage,
        cache_injection,
        resilience,
        #[cfg(feature = "observe")]
        otel,
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

    let result = serve_with_shutdown(listener, Arc::new(state), daemon::shutdown_signal()).await;
    daemon::remove_pid_file().ok();
    result.context("proxy serve")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn")),
        )
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
    println!("   Proxy:    {}", sty.green(&format!("http://{}:{}", host, port)));
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
