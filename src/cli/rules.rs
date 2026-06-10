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
//! - `keygen` / `sign` — publisher side: make an Ed25519 keypair and sign a pack.
//! - `verify` / `fetch <url>` — consumer side: verify a pack's detached
//!   signature against trusted `[rules].publishers`, and fetch+verify+install a
//!   signed remote pack. A remote pack is only trusted if its signature matches
//!   a configured publisher key; even then it stays deny-only/append-only.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::config;
use crate::security::{packs, signing};
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
    /// Lint a pack against the community-registry acceptance rules — stricter
    /// than the runtime parser. Rejects forbidden/unknown keys, uncompilable or
    /// over-broad rules, and (with `--sig`) checks the signature. Exits non-zero
    /// on any error, so the `burnwall-rules` CI validator can call it directly.
    Lint {
        /// Pack `.toml` to lint.
        file: PathBuf,
        /// Optional detached signature (hex) to verify as part of the lint.
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Extra trusted publisher key(s) (hex) for `--sig` verification.
        #[arg(long = "publisher")]
        publishers: Vec<String>,
        /// Emit JSON instead of the text report.
        #[arg(long)]
        json: bool,
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
    /// Generate an Ed25519 publisher signing key (writes the secret seed; prints
    /// the public key to share with consumers' `[rules].publishers`).
    Keygen {
        /// Where to write the secret key seed (32 bytes).
        out: PathBuf,
    },
    /// Sign a pack file with a publisher key — prints (or writes) a detached
    /// hex signature.
    Sign {
        /// Pack `.toml` to sign.
        file: PathBuf,
        /// Path to the signing-key seed (from `rules keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Write the signature here instead of printing it.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a local pack's detached signature against trusted publishers.
    Verify {
        /// Pack `.toml` to verify.
        file: PathBuf,
        /// Path to the detached signature (hex).
        #[arg(long)]
        sig: PathBuf,
        /// Extra trusted publisher key(s) (hex), in addition to config.
        #[arg(long = "publisher")]
        publishers: Vec<String>,
    },
    /// Fetch, verify, and install a signed remote rule pack from a URL.
    Fetch {
        /// URL of the pack `.toml`.
        url: String,
        /// URL of the detached signature (default: `<url>.sig`).
        #[arg(long)]
        sig: Option<String>,
        /// Extra trusted publisher key(s) (hex), in addition to config.
        #[arg(long = "publisher")]
        publishers: Vec<String>,
        /// Skip the interactive approval prompt (the summary is still shown).
        #[arg(long)]
        yes: bool,
    },
}

pub fn run_cmd(args: RulesArgs) -> anyhow::Result<()> {
    match args.action {
        RulesAction::List { json } => list(json),
        RulesAction::Install { name } => install(&name),
        RulesAction::Test { pack, file } => test(&pack, &file),
        RulesAction::Lint {
            file,
            sig,
            publishers,
            json,
        } => lint_cmd(&file, sig.as_deref(), &publishers, json),
        RulesAction::Add { file, yes } => add(&file, yes),
        RulesAction::Revoke { name } => revoke(&name),
        RulesAction::Keygen { out } => keygen(&out),
        RulesAction::Sign { file, key, out } => sign(&file, &key, out.as_deref()),
        RulesAction::Verify {
            file,
            sig,
            publishers,
        } => verify(&file, &sig, &publishers),
        RulesAction::Fetch {
            url,
            sig,
            publishers,
            yes,
        } => fetch(&url, sig.as_deref(), &publishers, yes),
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

/// M-M6: a pack id becomes a file name under the rules dir, so an id like
/// `..\..\x` would escape it. Reject anything but the registry id alphabet
/// before the id is ever joined to a path.
pub fn validate_pack_id(id: &str) -> anyhow::Result<()> {
    let ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        anyhow::bail!(
            "invalid pack id '{id}' — ids may only contain lowercase letters, digits, '-' and '_'"
        );
    }
    Ok(())
}

fn add(src: &Path, yes: bool) -> anyhow::Result<()> {
    let content =
        std::fs::read_to_string(src).with_context(|| format!("reading {}", src.display()))?;
    let pack =
        packs::RulePack::parse(&content).context("file did not parse as a valid rule pack")?;
    validate_pack_id(&pack.id)?;
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
    validate_pack_id(name)?;
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

// ── signed remote packs (v0.9) ───────────────────────────────────────────────

/// Trusted publishers from `[rules].publishers` plus any `--publisher` keys.
fn gather_publishers(extra: &[String]) -> anyhow::Result<Vec<signing::Publisher>> {
    let cfg = config::load_or_default(&config::default_path()?).context("loading config")?;
    let mut out: Vec<signing::Publisher> = cfg
        .rules
        .publishers
        .iter()
        .map(|p| signing::Publisher {
            name: p.name.clone(),
            key_hex: p.key.clone(),
        })
        .collect();
    for (i, key_hex) in extra.iter().enumerate() {
        out.push(signing::Publisher {
            name: format!("--publisher[{i}]"),
            key_hex: key_hex.clone(),
        });
    }
    Ok(out)
}

fn keygen(out: &Path) -> anyhow::Result<()> {
    if out.exists() {
        anyhow::bail!(
            "{} already exists — refusing to overwrite a key",
            out.display()
        );
    }
    let key = signing::generate();
    std::fs::write(out, key.to_bytes()).with_context(|| format!("writing {}", out.display()))?;
    set_key_perms(out)?;
    println!(
        "🔑 Wrote secret signing key (keep it private) to {}",
        out.display()
    );
    println!("   Public key — share it; consumers add it under [rules].publishers:");
    println!("   {}", signing::public_key_hex(&key));
    Ok(())
}

fn sign(file: &Path, key: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let seed = std::fs::read(key).with_context(|| format!("reading key {}", key.display()))?;
    let signing_key = signing::signing_key_from_seed(&seed)
        .context("key file is not a 32-byte Ed25519 seed (use `rules keygen`)")?;
    let signature = signing::sign_hex(&signing_key, &bytes);
    match out {
        Some(path) => {
            std::fs::write(path, &signature)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("✍️  Wrote signature to {}", path.display());
        }
        None => println!("{signature}"),
    }
    Ok(())
}

fn verify(file: &Path, sig: &Path, extra: &[String]) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let sig_hex =
        std::fs::read_to_string(sig).with_context(|| format!("reading {}", sig.display()))?;
    let publishers = gather_publishers(extra)?;
    if publishers.is_empty() {
        anyhow::bail!(
            "no trusted publishers — add one under [rules].publishers or pass --publisher <hex>"
        );
    }
    match signing::verify_hex(&bytes, &sig_hex, &publishers) {
        Some(name) => {
            println!("✅ Signature verifies — signed by trusted publisher '{name}'.");
            Ok(())
        }
        None => anyhow::bail!("signature does NOT verify against any trusted publisher"),
    }
}

/// `rules lint` — run the registry-acceptance linter over a pack, optionally
/// verifying its signature, and exit non-zero on any error. This is what the
/// `burnwall-rules` CI gate invokes; it's the product's own parser, so a pack
/// that lints clean here is one the binary will accept.
fn lint_cmd(
    file: &Path,
    sig: Option<&Path>,
    publishers: &[String],
    json: bool,
) -> anyhow::Result<()> {
    let content =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let findings = packs::lint(&content);

    // Optional signature check, folded into the overall pass/fail.
    let sig_result: Option<Result<String, String>> =
        sig.map(|sigpath| check_signature(file, sigpath, publishers));

    let errors = findings
        .iter()
        .filter(|f| f.severity == packs::LintSeverity::Error)
        .count();
    let warnings = findings.len() - errors;
    let sig_failed = matches!(&sig_result, Some(Err(_)));

    let mut out = std::io::stdout().lock();
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "clean": errors == 0 && !sig_failed,
            "errors": errors,
            "warnings": warnings,
            "findings": findings.iter().map(|f| serde_json::json!({
                "severity": f.severity.as_str(),
                "code": f.code,
                "message": f.message,
            })).collect::<Vec<_>>(),
            "signature": match &sig_result {
                None => serde_json::Value::Null,
                Some(Ok(name)) => serde_json::json!({ "verified": true, "publisher": name }),
                Some(Err(e)) => serde_json::json!({ "verified": false, "error": e }),
            },
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
    } else {
        writeln!(out, "🔎 Linting {}", file.display())?;
        for f in &findings {
            let glyph = match f.severity {
                packs::LintSeverity::Error => "✗",
                packs::LintSeverity::Warning => "⚠",
            };
            writeln!(out, "   {glyph} [{}] {}", f.code, f.message)?;
        }
        match &sig_result {
            Some(Ok(name)) => writeln!(out, "   ✓ signature verifies (publisher '{name}')")?,
            Some(Err(e)) => writeln!(out, "   ✗ signature: {e}")?,
            None => {}
        }
        writeln!(out)?;
        if errors == 0 && !sig_failed {
            writeln!(out, "✅ registry-clean ({warnings} warning(s))")?;
        }
    }

    if errors > 0 || sig_failed {
        anyhow::bail!(
            "lint failed: {errors} error(s){}",
            if sig_failed { " + signature" } else { "" }
        );
    }
    Ok(())
}

/// Verify a detached signature → `Ok(publisher)` / `Err(reason)`. Reuses the
/// same trusted-publisher resolution as `verify`/`fetch`. Returns `Err` rather
/// than bailing so the linter can report it as one finding among others.
fn check_signature(file: &Path, sig: &Path, extra: &[String]) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| format!("reading pack: {e}"))?;
    let sig_hex = std::fs::read_to_string(sig).map_err(|e| format!("reading signature: {e}"))?;
    let publishers = gather_publishers(extra).map_err(|e| format!("loading publishers: {e}"))?;
    if publishers.is_empty() {
        return Err("no trusted publishers (config or --publisher)".to_string());
    }
    match signing::verify_hex(&bytes, &sig_hex, &publishers) {
        Some(name) => Ok(name),
        None => Err("does not verify against any trusted publisher".to_string()),
    }
}

fn fetch(url: &str, sig_url: Option<&str>, extra: &[String], yes: bool) -> anyhow::Result<()> {
    let publishers = gather_publishers(extra)?;
    if publishers.is_empty() {
        anyhow::bail!(
            "no trusted publishers — a remote pack can't be verified. Add one under \
             [rules].publishers or pass --publisher <hex>."
        );
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;
    let pack_bytes = client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching pack from {url}"))?
        .bytes()
        .context("reading pack body")?
        .to_vec();
    let sig_location = sig_url
        .map(String::from)
        .unwrap_or_else(|| format!("{url}.sig"));
    let sig_hex = client
        .get(&sig_location)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching signature from {sig_location}"))?
        .text()
        .context("reading signature")?;

    // Verify BEFORE parsing or trusting anything from the pack.
    let signer = signing::verify_hex(&pack_bytes, &sig_hex, &publishers).ok_or_else(|| {
        anyhow::anyhow!(
            "signature does NOT verify against any trusted publisher — refusing to install"
        )
    })?;

    let content = String::from_utf8(pack_bytes).context("pack is not valid UTF-8")?;
    let pack = packs::RulePack::parse(&content)
        .context("fetched file did not parse as a valid rule pack")?;
    validate_pack_id(&pack.id)?;
    let hash = packs::content_hash(content.as_bytes());

    // M-M7: compare against the prior TOFU pin so a re-fetch that CHANGED the
    // pack is flagged in the summary instead of looking like a fresh install.
    let store = Storage::open_default().context("opening storage")?;
    let prior = store.rule_pack_approved_hash(&pack.id)?;

    println!(
        "📥 Fetched '{}' v{} — signature verified (publisher '{}').",
        pack.id, pack.version, signer
    );
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
        "✅ Installed '{}' (publisher '{}'). It applies on the next `burnwall start`.",
        pack.id, signer
    );
    Ok(())
}

#[cfg(unix)]
fn set_key_perms(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_key_perms(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
