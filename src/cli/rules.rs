//! `burnwall rules` — manage security-rule packs.
//!
//! - `list` — bundled official packs (inherently trusted, I4) + installed
//!   third-party packs with their TOFU status.
//! - `install <id>` — enable a bundled official pack (zero-network).
//! - `test <pack> <file>` — playground: run a pack against a sample body.
//! - `add <file> [--yes]` — install a third-party pack from a local file with
//!   Trust-On-First-Use: you review what it adds (I7) and the content is
//!   SHA-256-pinned, so a later edit re-prompts (I6). Trust comes from your
//!   approval, never the pack's self-declared metadata (I4).
//! - `revoke <id>` — remove an installed third-party pack.
//!
//! Remote `install <url>` + signing are deliberately out of scope (v0.7).

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::config;
use crate::security::packs;
use crate::storage::{self, Storage};

#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List official + installed rule packs and their status.
    List {
        /// Emit JSON instead of the table view.
        #[arg(long)]
        json: bool,
    },
    /// Enable a bundled official rule pack by id (applies on next `start`).
    Install {
        /// Pack id, e.g. `django`. See `burnwall rules list`.
        name: String,
    },
    /// Playground: run a pack against a sample request body and show what it
    /// would block. No live traffic, no config changes.
    Test {
        /// An official pack id (e.g. `django`) or a path to a pack `.toml`.
        pack: String,
        /// Path to a JSON request body to test against.
        file: PathBuf,
    },
    /// Install a third-party rule pack from a local file (Trust-On-First-Use).
    Add {
        /// Path to a local pack `.toml` file.
        file: PathBuf,
        /// Skip the interactive approval prompt (the summary is still shown).
        #[arg(long)]
        yes: bool,
    },
    /// Revoke (and remove) an installed third-party rule pack by id.
    Revoke {
        /// Pack id to revoke.
        name: String,
    },
}

pub fn run_cmd(args: RulesArgs) -> anyhow::Result<()> {
    match args.action {
        RulesAction::List { json } => list(json),
        RulesAction::Install { name } => install(&name),
        RulesAction::Test { pack, file } => test(&pack, &file),
        RulesAction::Add { file, yes } => add(&file, yes),
        RulesAction::Revoke { name } => revoke(&name),
    }
}

// ── list ───────────────────────────────────────────────────────────────────

struct ThirdParty {
    id: String,
    name: String,
    rules: usize,
    status: &'static str,
}

fn list(json: bool) -> anyhow::Result<()> {
    let path = config::default_path()?;
    let cfg = config::load_or_default(&path).context("loading config")?;
    let enabled: std::collections::HashSet<&str> =
        cfg.rules.enabled.iter().map(String::as_str).collect();
    let third = collect_third_party();
    let mut out = std::io::stdout().lock();

    if json {
        let official: Vec<_> = packs::OFFICIAL_PACKS
            .iter()
            .filter_map(|(id, toml)| {
                packs::RulePack::parse(toml).map(|p| {
                    serde_json::json!({
                        "id": p.id, "name": p.name, "version": p.version,
                        "rules": p.rule_count(),
                        "trust": "official-bundled",  // never a pack-declared field (I4)
                        "enabled": enabled.contains(*id),
                    })
                })
            })
            .collect();
        let third_json: Vec<_> = third
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id, "name": t.name, "rules": t.rules,
                    "trust": "third-party", "status": t.status,
                })
            })
            .collect();
        let value = serde_json::json!({ "official": official, "third_party": third_json });
        writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?;
        return Ok(());
    }

    writeln!(out, "📦 Official rule packs (bundled, trusted):")?;
    for (id, toml) in packs::OFFICIAL_PACKS {
        if let Some(p) = packs::RulePack::parse(toml) {
            let mark = if enabled.contains(id) {
                "✓ enabled "
            } else {
                "  available"
            };
            writeln!(
                out,
                "   {mark}  {:<16} {:>3} rules   {}",
                p.id,
                p.rule_count(),
                p.name
            )?;
        }
    }
    if !third.is_empty() {
        writeln!(out)?;
        writeln!(out, "📥 Installed third-party packs (Trust-On-First-Use):")?;
        for t in &third {
            writeln!(
                out,
                "   {:<12}  {:<16} {:>3} rules   {}",
                t.status, t.id, t.rules, t.name
            )?;
        }
    }
    writeln!(out)?;
    writeln!(out, "Enable an official pack:  burnwall rules install <id>")?;
    writeln!(
        out,
        "Add a third-party pack:   burnwall rules add <file.toml>"
    )?;
    Ok(())
}

/// Enumerate installed third-party packs (files under `<data>/rules/`) and
/// classify each against its TOFU pin: approved / edited / unapproved.
fn collect_third_party() -> Vec<ThirdParty> {
    let mut out = Vec::new();
    let Ok(dir) = storage::data_dir().map(|d| d.join("rules")) else {
        return out;
    };
    let Ok(read) = std::fs::read_dir(&dir) else {
        return out;
    };
    let store = Storage::open_default().ok();
    for entry in read.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Some(pack) = packs::RulePack::parse(&content) else {
            continue;
        };
        let hash = packs::content_hash(content.as_bytes());
        let approved = store
            .as_ref()
            .and_then(|s| s.rule_pack_approved_hash(&pack.id).ok().flatten());
        let status = match approved {
            Some(h) if h == hash => "✓ approved",
            Some(_) => "⚠ edited",
            None => "⚠ unapproved",
        };
        out.push(ThirdParty {
            id: pack.id.clone(),
            name: pack.name.clone(),
            rules: pack.rule_count(),
            status,
        });
    }
    out
}

// ── install (official) ───────────────────────────────────────────────────

fn install(name: &str) -> anyhow::Result<()> {
    if packs::load_official(name).is_none() {
        let ids = packs::official_ids().join(", ");
        anyhow::bail!("'{name}' is not a known official pack. Available: {ids}");
    }
    let path = config::default_path()?;
    let mut cfg = config::load_or_default(&path).context("loading config")?;
    if cfg.rules.enabled.iter().any(|e| e == name) {
        println!("ℹ️  rule pack '{name}' is already enabled.");
        return Ok(());
    }
    cfg.rules.enabled.push(name.to_string());
    config::save(&path, &cfg).context("writing config")?;
    println!("✅ Enabled rule pack '{name}'. It applies on the next `burnwall start`.");
    Ok(())
}

// ── test (playground) ──────────────────────────────────────────────────────

fn test(pack_ref: &str, file: &Path) -> anyhow::Result<()> {
    let pack = match packs::load_official(pack_ref) {
        Some(p) => p,
        None => packs::RulePack::parse_file(Path::new(pack_ref)).with_context(|| {
            format!("'{pack_ref}' is not an official pack id and did not parse as a pack file")
        })?,
    };
    let body = std::fs::read(file)
        .with_context(|| format!("reading sample request body {}", file.display()))?;

    let mut ruleset = crate::security::Ruleset::default();
    pack.apply_to_ruleset(&mut ruleset);
    let engine = crate::security::SecurityEngine::new(ruleset);

    let mut out = std::io::stdout().lock();
    writeln!(out, "🧪 Pack '{}' vs {}", pack.id, file.display())?;
    writeln!(
        out,
        "   (effective ruleset = built-in defaults + this pack)"
    )?;
    match engine.scan(&body) {
        Some(v) => writeln!(
            out,
            "   🛡️  BLOCKED — {}: {}",
            v.kind.event_type(),
            v.matched
        )?,
        None => writeln!(out, "   ✓ allowed — no rule matched")?,
    }
    Ok(())
}

// ── add / revoke (third-party, TOFU) ───────────────────────────────────────

fn add(src: &Path, yes: bool) -> anyhow::Result<()> {
    let content =
        std::fs::read_to_string(src).with_context(|| format!("reading {}", src.display()))?;
    let pack =
        packs::RulePack::parse(&content).context("file did not parse as a valid rule pack")?;
    let hash = packs::content_hash(content.as_bytes());

    let store = Storage::open_default().context("opening storage")?;
    let prior = store.rule_pack_approved_hash(&pack.id)?;

    print_add_summary(&pack, prior.as_deref(), &hash);

    if !yes && !prompt_yes()? {
        println!("Aborted — '{}' not installed.", pack.id);
        return Ok(());
    }

    let dir = storage::data_dir()
        .context("locating data dir")?
        .join("rules");
    std::fs::create_dir_all(&dir).context("creating rules dir")?;
    let dest = dir.join(format!("{}.toml", pack.id));
    std::fs::write(&dest, content.as_bytes()).context("installing pack file")?;
    store.approve_rule_pack(&pack.id, &dest.to_string_lossy(), &hash)?;
    println!(
        "✅ Installed and approved '{}'. It applies on the next `burnwall start`.",
        pack.id
    );
    Ok(())
}

fn revoke(name: &str) -> anyhow::Result<()> {
    let store = Storage::open_default().context("opening storage")?;
    let pin_removed = store.revoke_rule_pack(name)?;
    let dest = storage::data_dir()
        .context("locating data dir")?
        .join("rules")
        .join(format!("{name}.toml"));
    let file_removed = std::fs::remove_file(&dest).is_ok();
    if pin_removed || file_removed {
        println!("✅ Revoked rule pack '{name}'.");
    } else {
        println!("ℹ️  No installed pack '{name}' to revoke.");
    }
    Ok(())
}

/// The reviewable approval summary (invariant I7) — always printed before any
/// approval. Shows true provenance (third-party, not the file's claim — I4) and
/// the change status against any prior pin (I6).
fn print_add_summary(pack: &packs::RulePack, prior: Option<&str>, hash: &str) {
    println!(
        "📦 Third-party rule pack: {} ({}) v{}",
        pack.id, pack.name, pack.version
    );
    println!("   Trust:  third-party — provenance is YOUR approval, not the file's claim.");
    match prior {
        Some(h) if h == hash => println!("   Status: already approved (unchanged)"),
        Some(_) => {
            println!("   Status: ⚠️  CHANGED since last approval — review carefully (possible tampering)")
        }
        None => println!("   Status: new — not previously approved"),
    }
    println!(
        "   Adds {} deny-path, {} deny-command, {} secret-pattern rule(s):",
        pack.deny_paths.len(),
        pack.deny_commands.len(),
        pack.secret_patterns.len()
    );
    for p in &pack.deny_paths {
        println!("     deny path:    {p}");
    }
    for c in &pack.deny_commands {
        println!("     deny command: {c}");
    }
    for s in &pack.secret_patterns {
        println!("     secret:       {}", s.name);
    }
    println!("   (Declarative + deny-only: a pack can only ADD restrictions, never loosen.)");
}

fn prompt_yes() -> anyhow::Result<bool> {
    use std::io::BufRead;
    print!("Approve and install this pack? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
