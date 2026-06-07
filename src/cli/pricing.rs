//! `burnwall pricing` — inspect and manage the rate card.
//!
//! - `list` — the effective rate card (built-in entries plus any
//!   `~/.burnwall/pricing.toml` overrides), so you can see exactly what a model
//!   is billed at and whether a local override is in effect.
//! - `path` — where the override file lives; offers to scaffold a commented
//!   starter file so adding a new model is copy-paste.
//!
//! Signed remote pricing cards (`sign` / `verify` / `update`) build on top of
//! this in the same command group and reuse the Ed25519 machinery from
//! `security::signing`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::config;
use crate::pricing::{self, overrides};
use crate::security::signing;

#[derive(Args, Debug)]
pub struct PricingArgs {
    #[command(subcommand)]
    pub action: PricingAction,
}

#[derive(Subcommand, Debug)]
pub enum PricingAction {
    /// Show the effective rate card (built-in + local overrides).
    List {
        /// Emit JSON instead of the table view.
        #[arg(long)]
        json: bool,
    },
    /// Print the override file path; optionally write a starter template.
    Path {
        /// Create a commented starter `pricing.toml` if none exists.
        #[arg(long)]
        init: bool,
    },
    /// Fetch, verify, and install a signed remote pricing card. The card is a
    /// `pricing.toml` whose detached Ed25519 signature must verify against a
    /// trusted `[pricing].publishers` key before it is written.
    Update {
        /// URL of the pricing card. Defaults to the latest GitHub release asset.
        #[arg(long)]
        url: Option<String>,
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
    /// Verify a local pricing card's detached signature against trusted
    /// publishers (no install).
    Verify {
        /// Pricing card `.toml` to verify.
        file: PathBuf,
        /// Path to the detached signature (hex).
        #[arg(long)]
        sig: PathBuf,
        /// Extra trusted publisher key(s) (hex), in addition to config.
        #[arg(long = "publisher")]
        publishers: Vec<String>,
    },
    /// Sign a pricing card with a publisher key — prints (or writes) a detached
    /// hex signature. Reuses the same key format as `burnwall rules keygen`.
    Sign {
        /// Pricing card `.toml` to sign.
        file: PathBuf,
        /// Path to the signing-key seed (from `burnwall rules keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Write the signature here instead of printing it.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

pub fn run_cmd(args: PricingArgs) -> anyhow::Result<()> {
    match args.action {
        PricingAction::List { json } => list(json),
        PricingAction::Path { init } => path(init),
        PricingAction::Update {
            url,
            sig,
            publishers,
            yes,
        } => update(url.as_deref(), sig.as_deref(), &publishers, yes),
        PricingAction::Verify {
            file,
            sig,
            publishers,
        } => verify(&file, &sig, &publishers),
        PricingAction::Sign { file, key, out } => sign(&file, &key, out.as_deref()),
    }
}

/// A single effective rate-card row for display.
struct Row {
    model: String,
    p: pricing::ModelPricing,
    source: &'static str,
}

fn effective_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    // Overrides first — they win. Label whether each replaces a built-in or is
    // a brand-new model the binary never shipped with.
    for (name, p) in overrides::table() {
        let replaces_builtin = pricing::rates::KNOWN_MODELS
            .iter()
            .any(|(k, _)| k == name || name.starts_with(&format!("{k}-")));
        rows.push(Row {
            model: name.clone(),
            p: *p,
            source: if replaces_builtin {
                "override"
            } else {
                "override (new)"
            },
        });
    }
    // Built-in card. Mark entries shadowed by an exact-name override.
    let override_names: std::collections::HashSet<&str> =
        overrides::table().iter().map(|(n, _)| n.as_str()).collect();
    for (name, p) in pricing::rates::KNOWN_MODELS {
        rows.push(Row {
            model: (*name).to_string(),
            p: *p,
            source: if override_names.contains(name) {
                "built-in (shadowed)"
            } else {
                "built-in"
            },
        });
    }
    rows
}

fn list(json: bool) -> anyhow::Result<()> {
    let rows = effective_rows();
    let mut out = std::io::stdout().lock();

    if json {
        let arr: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "model": r.model,
                    "input_per_mtok": r.p.input_per_mtok,
                    "cache_write_per_mtok": r.p.cache_write_per_mtok,
                    "cache_read_per_mtok": r.p.cache_read_per_mtok,
                    "output_per_mtok": r.p.output_per_mtok,
                    "source": r.source,
                })
            })
            .collect();
        let value = serde_json::json!({
            "last_updated": pricing::PRICING_LAST_UPDATED,
            "override_count": overrides::count(),
            "models": arr,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?;
        return Ok(());
    }

    writeln!(out, "💲 Effective pricing (USD per 1M tokens)")?;
    writeln!(
        out,
        "   Built-in card last updated {}",
        pricing::PRICING_LAST_UPDATED
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "   {:<26} {:>7} {:>8} {:>7} {:>8}  SOURCE",
        "MODEL", "INPUT", "C-WRITE", "C-READ", "OUTPUT"
    )?;
    for r in &rows {
        writeln!(
            out,
            "   {:<26} {:>7.2} {:>8.2} {:>7.2} {:>8.2}  {}",
            r.model,
            r.p.input_per_mtok,
            r.p.cache_write_per_mtok,
            r.p.cache_read_per_mtok,
            r.p.output_per_mtok,
            r.source,
        )?;
    }
    writeln!(out)?;
    let n = overrides::count();
    if n == 0 {
        writeln!(
            out,
            "   No overrides active. Add one: burnwall pricing path --init"
        )?;
    } else {
        let where_ = overrides::override_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "pricing.toml".to_string());
        writeln!(out, "   {n} override(s) active from {where_}")?;
    }
    Ok(())
}

fn path(init: bool) -> anyhow::Result<()> {
    let Some(path) = overrides::override_path() else {
        anyhow::bail!("could not locate the burnwall data directory");
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", path.display())?;
    if path.exists() {
        writeln!(out, "   (exists — {} override(s) loaded)", overrides::count())?;
        return Ok(());
    }
    if init {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, overrides::sample_toml())
            .with_context(|| format!("writing {}", path.display()))?;
        writeln!(out, "   ✓ wrote a commented starter file — edit it, then run `burnwall pricing list` to confirm.")?;
    } else {
        writeln!(
            out,
            "   (does not exist — create it, or run `burnwall pricing path --init`)"
        )?;
    }
    Ok(())
}

// ── signed remote cards (C) ─────────────────────────────────────────────────

/// Default card URL: the latest GitHub release asset (version-agnostic).
const DEFAULT_REPO: &str = "intbot/burnwall";
fn default_card_url() -> String {
    format!("https://github.com/{DEFAULT_REPO}/releases/latest/download/pricing.toml")
}

/// Trusted publishers from `[pricing].publishers` plus any `--publisher` keys.
fn gather_publishers(extra: &[String]) -> anyhow::Result<Vec<signing::Publisher>> {
    let cfg = config::load_or_default(config::default_path()?).context("loading config")?;
    let mut out: Vec<signing::Publisher> = cfg
        .pricing
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

fn sign(file: &Path, key: &Path, out: Option<&Path>) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    // Validate it parses as a pricing card before signing, so a publisher can't
    // accidentally sign a malformed file.
    let text = String::from_utf8(bytes.clone()).context("card is not valid UTF-8")?;
    overrides::parse(&text).context("file does not parse as a pricing card")?;

    let seed = std::fs::read(key).with_context(|| format!("reading key {}", key.display()))?;
    let signing_key = signing::signing_key_from_seed(&seed)
        .context("key file is not a 32-byte Ed25519 seed (use `burnwall rules keygen`)")?;
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
            "no trusted publishers — add one under [pricing].publishers or pass --publisher <hex>"
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

fn update(
    url: Option<&str>,
    sig_url: Option<&str>,
    extra: &[String],
    yes: bool,
) -> anyhow::Result<()> {
    let publishers = gather_publishers(extra)?;
    if publishers.is_empty() {
        anyhow::bail!(
            "no trusted publishers — a remote card can't be verified. Add one under \
             [pricing].publishers or pass --publisher <hex>."
        );
    }

    let url = url.map(String::from).unwrap_or_else(default_card_url);
    let sig_location = sig_url
        .map(String::from)
        .unwrap_or_else(|| format!("{url}.sig"));

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;
    let card_bytes = client
        .get(&url)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching pricing card from {url}"))?
        .bytes()
        .context("reading card body")?
        .to_vec();
    let sig_hex = client
        .get(&sig_location)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching signature from {sig_location}"))?
        .text()
        .context("reading signature")?;

    // Verify BEFORE parsing or trusting anything from the card.
    let signer = signing::verify_hex(&card_bytes, &sig_hex, &publishers).ok_or_else(|| {
        anyhow::anyhow!(
            "signature does NOT verify against any trusted publisher — refusing to install"
        )
    })?;

    let content = String::from_utf8(card_bytes).context("card is not valid UTF-8")?;
    let table = overrides::parse(&content).context("fetched file did not parse as a pricing card")?;

    println!(
        "📥 Fetched pricing card — signature verified (publisher '{}').",
        signer
    );
    println!("   {} model price entr(ies):", table.len());
    for (name, p) in &table {
        println!(
            "     {:<26} in {:.2}  out {:.2}  (USD/MTok)",
            name, p.input_per_mtok, p.output_per_mtok
        );
    }

    if !yes && !prompt_yes()? {
        println!("Aborted — pricing card not installed.");
        return Ok(());
    }

    let dest = overrides::override_path().context("locating the override path")?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("creating data dir")?;
    }
    std::fs::write(&dest, content.as_bytes())
        .with_context(|| format!("writing {}", dest.display()))?;
    println!(
        "✅ Installed pricing card to {} (publisher '{}'). It applies on the next command.",
        dest.display(),
        signer
    );
    Ok(())
}

fn prompt_yes() -> anyhow::Result<bool> {
    use std::io::BufRead;
    print!("Install this pricing card? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
