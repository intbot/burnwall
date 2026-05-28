//! `burnwall audit` — cryptographic audit receipts + compliance exports (v0.8).
//!
//! - `seal`   — append new forwarded/blocked actions to the signed hash chain.
//! - `verify` — re-walk the chain (hashes + signatures + live source rows).
//! - `export` — dump the receipts (json | csv).
//! - `aibom`  — CycloneDX AI Bill of Materials for the window.
//! - `sarif`  — security blocks as SARIF 2.1.0 (GitHub code scanning).

use std::io::Write;

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::audit::{aibom, sarif, AuditChain, VerifyReport};
use crate::observe::digest::Digest;
use crate::storage::{ReceiptRow, Storage};

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Seal new forwarded/blocked actions into the signed hash chain.
    Seal,
    /// Verify the receipt chain — hashes, signatures, and live source rows.
    Verify,
    /// Export the audit receipts.
    Export(ExportArgs),
    /// Export a CycloneDX AI Bill of Materials for the window.
    Aibom(WindowArgs),
    /// Export security blocks as SARIF 2.1.0 (for GitHub code scanning).
    Sarif(WindowArgs),
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output format: `json` or `csv`.
    #[arg(long, default_value = "json")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct WindowArgs {
    /// How many days back to include (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
}

pub fn run_cmd(args: AuditArgs) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let mut out = std::io::stdout().lock();

    match args.command {
        AuditCommand::Seal => {
            let chain = AuditChain::open_default().context("opening audit key")?;
            let report = chain.seal(&storage)?;
            writeln!(
                out,
                "🔏 Sealed {} new receipt{} into the audit chain.",
                report.sealed,
                plural(report.sealed)
            )?;
            writeln!(out, "   Public key: {}", chain.public_key_hex())?;
        }
        AuditCommand::Verify => {
            let chain = AuditChain::open_default().context("opening audit key")?;
            match chain.verify(&storage)? {
                VerifyReport::Intact { count } => {
                    writeln!(
                        out,
                        "✅ Audit chain intact — {} receipt{} verified.",
                        count,
                        plural(count as u64)
                    )?;
                    writeln!(out, "   Public key: {}", chain.public_key_hex())?;
                }
                VerifyReport::Tampered {
                    seq,
                    reason,
                    checked,
                } => {
                    writeln!(out, "❌ Audit chain TAMPERED at receipt #{seq}: {reason}")?;
                    writeln!(out, "   ({checked} receipt(s) verified before the failure)")?;
                    anyhow::bail!("audit verification failed");
                }
            }
        }
        AuditCommand::Export(a) => {
            let receipts = storage.all_receipts()?;
            let public_key = AuditChain::open_default().ok().map(|c| c.public_key_hex());
            match a.format.as_str() {
                "json" => write_receipts_json(&mut out, &receipts, public_key.as_deref())?,
                "csv" => write_receipts_csv(&mut out, &receipts)?,
                other => anyhow::bail!("unknown format '{other}': use json or csv"),
            }
        }
        AuditCommand::Aibom(a) => {
            let digest = Digest::build(&storage, a.days)?;
            let now = chrono::Utc::now().to_rfc3339();
            let serial = format!("urn:uuid:{}", uuid::Uuid::new_v4());
            let bom = aibom::build(&digest, &now, &serial);
            writeln!(out, "{}", serde_json::to_string_pretty(&bom).unwrap())?;
        }
        AuditCommand::Sarif(a) => {
            let events = storage.security_events_since_days(a.days)?;
            let log = sarif::build(&events);
            writeln!(out, "{}", serde_json::to_string_pretty(&log).unwrap())?;
        }
    }
    Ok(())
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn write_receipts_json(
    w: &mut impl Write,
    receipts: &[ReceiptRow],
    public_key: Option<&str>,
) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "public_key": public_key,
        "count": receipts.len(),
        "receipts": receipts.iter().map(|r| json!({
            "seq": r.seq,
            "sealed_at": r.sealed_at,
            "source": r.source,
            "source_id": r.source_id,
            "timestamp": r.timestamp,
            "action": r.action,
            "provider": r.provider,
            "model": r.model,
            "detail": r.detail,
            "content_hash": r.content_hash,
            "prev_hash": r.prev_hash,
            "hash": r.hash,
            "signature": r.signature,
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn write_receipts_csv(w: &mut impl Write, receipts: &[ReceiptRow]) -> std::io::Result<()> {
    writeln!(
        w,
        "seq,sealed_at,source,source_id,timestamp,action,provider,model,detail,content_hash,prev_hash,hash,signature"
    )?;
    for r in receipts {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.seq,
            csv(&r.sealed_at),
            csv(&r.source),
            r.source_id,
            csv(&r.timestamp),
            csv(&r.action),
            csv(r.provider.as_deref().unwrap_or("")),
            csv(r.model.as_deref().unwrap_or("")),
            csv(r.detail.as_deref().unwrap_or("")),
            csv(&r.content_hash),
            csv(&r.prev_hash),
            csv(&r.hash),
            csv(&r.signature),
        )?;
    }
    Ok(())
}

/// RFC-4180 field quoting: wrap in quotes and double internal quotes when the
/// field contains a comma, quote, or newline.
fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
