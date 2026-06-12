//! `burnwall audit` — cryptographic audit receipts + compliance exports (v0.8).
//!
//! - `seal`   — append new forwarded/blocked actions to the signed hash chain.
//! - `verify` — re-walk the chain (hashes + signatures + live source rows).
//! - `export` — dump the receipts (json | csv).
//! - `aibom`  — CycloneDX AI Bill of Materials for the window.
//! - `sarif`  — security blocks as SARIF 2.1.0 (GitHub code scanning), now
//!   carrying the crosswalk control IDs on each rule/result.
//! - `spdx`   — SPDX 3.0 (AI profile) bill of materials for the window.
//! - `coverage` — the named-risk coverage sheet (OWASP / EU AI Act control IDs
//!   each block evidences); `--json` for the machine-readable matrix.
//! - `evidence` — the sealed receipts grouped by compliance regime
//!   (SOC 2 / ISO 42001 / NIST AI RMF / FINRA 17a-4 / EU AI Act), as JSON.
//! - `pack`   — one-command compliance evidence pack (receipts + AIBOM + SARIF
//!   + a framework-mapping manifest) you can hand to a security/audit team.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::audit::{AuditChain, VerifyReport, aibom, compliance, sarif, spdx};
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
    /// Deliberately start a new chain segment under the current key after the
    /// previous audit key was lost or replaced. Archives the old segment's
    /// public key and chain head, then lets `seal` resume.
    Rekey,
    /// Export the audit receipts.
    Export(ExportArgs),
    /// Export a CycloneDX AI Bill of Materials for the window.
    Aibom(WindowArgs),
    /// Export security blocks as SARIF 2.1.0 (for GitHub code scanning).
    Sarif(WindowArgs),
    /// Export an SPDX 3.0 (AI profile) bill of materials for the window.
    Spdx(WindowArgs),
    /// Print the named-risk coverage sheet (which OWASP / EU AI Act controls
    /// each Burnwall block evidences). `--json` emits the full matrix.
    Coverage(CoverageArgs),
    /// Emit a framework-labelled evidence bundle (JSON): the sealed receipts
    /// grouped by SOC 2 / ISO 42001 / NIST AI RMF / FINRA 17a-4 / EU AI Act.
    Evidence(WindowArgs),
    /// Bundle a compliance evidence pack: signed receipts + CycloneDX AIBOM +
    /// SARIF + a framework-mapping manifest, into one directory.
    Pack(PackArgs),
}

#[derive(Args, Debug)]
pub struct CoverageArgs {
    /// Emit the machine-readable coverage matrix as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PackArgs {
    /// How many days back to include (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Output directory (default: ./burnwall-evidence-<date>).
    #[arg(long)]
    pub out: Option<PathBuf>,
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
        AuditCommand::Rekey => {
            let chain = AuditChain::open_default().context("opening audit key")?;
            let report = chain.rekey(&storage)?;
            writeln!(out, "🔑 Started a new audit chain segment.")?;
            writeln!(
                out,
                "   Closed segment: {} receipt{} signed by {} (head {})",
                report.receipts,
                plural(report.receipts),
                report.old_key.as_deref().unwrap_or("an unknown key"),
                report
                    .chain_head
                    .as_deref()
                    .map(|h| &h[..h.len().min(8)])
                    .unwrap_or("genesis"),
            )?;
            writeln!(out, "   Segment record: {}", report.archive.display())?;
            writeln!(out, "   New public key: {}", report.new_key)?;
            writeln!(
                out,
                "   Receipts sealed before the rekey verify only against the archived key; \
                 `burnwall audit seal` can now resume."
            )?;
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
        AuditCommand::Spdx(a) => {
            let digest = Digest::build(&storage, a.days)?;
            let now = chrono::Utc::now().to_rfc3339();
            let serial = format!("urn:uuid:{}", uuid::Uuid::new_v4());
            let doc = spdx::build(&digest, &now, &serial);
            writeln!(out, "{}", serde_json::to_string_pretty(&doc).unwrap())?;
        }
        AuditCommand::Coverage(a) => {
            if a.json {
                writeln!(out, "{}", coverage_json())?;
            } else {
                write_coverage_sheet(&mut out)?;
            }
        }
        AuditCommand::Evidence(a) => {
            // Best-effort seal so the bundle reflects the latest actions.
            let chain = AuditChain::open_default().ok();
            if let Some(c) = &chain {
                let _ = c.seal(&storage);
            }
            let public_key = chain.as_ref().map(|c| c.public_key_hex());
            let receipts = storage.all_receipts()?;
            let _ = a.days; // evidence covers the whole sealed chain, not a window
            let pack = compliance::evidence_pack(&receipts, public_key.as_deref());
            writeln!(out, "{}", evidence_json(&pack))?;
        }
        AuditCommand::Pack(a) => {
            write_evidence_pack(&mut out, &storage, a.days, a.out)?;
        }
    }
    Ok(())
}

/// The full coverage matrix as machine-readable JSON.
fn coverage_json() -> String {
    use serde_json::json;
    let rows: Vec<_> = compliance::coverage_matrix()
        .into_iter()
        .map(|row| {
            json!({
                "event_type": row.event_type,
                "controls": row.controls.iter().map(|c| json!({
                    "framework": c.framework.name(),
                    "control_id": c.control_id,
                    "label": c.short_label,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let value = json!({
        "note": "Maps existing Burnwall protections to named risk-control IDs. \
                 This is labeling, not new protection, and is not a certification.",
        "coverage": rows,
    });
    serde_json::to_string_pretty(&value).unwrap()
}

/// One-page human-readable "which named risks Burnwall covers" sheet.
fn write_coverage_sheet(out: &mut impl Write) -> anyhow::Result<()> {
    writeln!(out, "Burnwall — named-risk coverage")?;
    writeln!(
        out,
        "Which industry risk-control IDs each block evidences. This maps existing"
    )?;
    writeln!(
        out,
        "protections to named controls — it is labeling, not new protection, and is"
    )?;
    writeln!(out, "not a certification.\n")?;
    writeln!(out, "{:<24}  EVIDENCES", "EVENT TYPE")?;
    writeln!(out, "{:<24}  {}", "-".repeat(24), "-".repeat(40))?;
    for row in compliance::coverage_matrix() {
        let ids: Vec<String> = row
            .controls
            .iter()
            .map(|c| format!("{} {}", c.framework.name(), c.control_id))
            .collect();
        writeln!(out, "{:<24}  {}", row.event_type, ids.join("; "))?;
    }
    writeln!(
        out,
        "\nFrameworks: OWASP Agentic AI (ASI-T*/LLM*), OWASP MCP Top 10 (MCP*), EU AI Act (articles)."
    )?;
    Ok(())
}

/// The framework-labelled evidence bundle as JSON.
fn evidence_json(pack: &compliance::EvidencePack) -> String {
    use serde_json::json;
    let groups: Vec<_> = pack
        .groups
        .iter()
        .map(|g| {
            json!({
                "framework": g.regime,
                "obligation": g.obligation,
                "receipt_count": g.receipt_count,
                "blocked_receipts": g.blocked_receipts,
                "forwarded_receipts": g.forwarded_receipts,
                "receipt_seqs": g.receipt_seqs,
            })
        })
        .collect();
    let value = json!({
        "public_key": pack.public_key,
        "total_receipts": pack.total_receipts,
        "note": pack.note,
        "frameworks": groups,
    });
    serde_json::to_string_pretty(&value).unwrap()
}

/// Build a self-contained compliance evidence pack: the existing artifacts
/// (signed receipts, CycloneDX 1.6 AIBOM, SARIF 2.1.0) plus a manifest that maps
/// each to the controls auditors ask for (ISO 42001, EU AI Act, FINRA). The
/// artifacts already exist — the value here is one command + the mapping.
fn write_evidence_pack(
    out: &mut impl Write,
    storage: &Storage,
    days: i64,
    out_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let now = chrono::Local::now();
    let date = now.format("%Y-%m-%d").to_string();
    let dir = out_dir.unwrap_or_else(|| PathBuf::from(format!("burnwall-evidence-{date}")));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // Seal first so the pack reflects the latest actions (best-effort — a
    // missing key or zero new actions must not fail the export).
    let chain = AuditChain::open_default().ok();
    if let Some(c) = &chain {
        let _ = c.seal(storage);
    }
    let public_key = chain.as_ref().map(|c| c.public_key_hex());

    // 1) Signed receipts.
    let receipts = storage.all_receipts()?;
    let mut buf = Vec::new();
    write_receipts_json(&mut buf, &receipts, public_key.as_deref())?;
    std::fs::write(dir.join("receipts.json"), &buf).context("writing receipts.json")?;

    // 2) CycloneDX 1.6 AIBOM.
    let digest = Digest::build(storage, days)?;
    let serial = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let bom = aibom::build(&digest, &now.to_rfc3339(), &serial);
    std::fs::write(
        dir.join("aibom.cdx.json"),
        serde_json::to_string_pretty(&bom).unwrap(),
    )
    .context("writing aibom.cdx.json")?;

    // 3) SARIF 2.1.0 security findings.
    let events = storage.security_events_since_days(days)?;
    let sarif_log = sarif::build(&events);
    std::fs::write(
        dir.join("security.sarif.json"),
        serde_json::to_string_pretty(&sarif_log).unwrap(),
    )
    .context("writing security.sarif.json")?;

    // 4) Framework-mapping manifest.
    let manifest = evidence_manifest(
        &date,
        days,
        receipts.len(),
        events.len(),
        digest.models.len(),
        public_key.as_deref(),
    );
    std::fs::write(dir.join("MANIFEST.md"), manifest).context("writing MANIFEST.md")?;

    writeln!(out, "🧾 Evidence pack written to {}", dir.display())?;
    writeln!(
        out,
        "   receipts.json        — {} signed hash-chained receipt(s)",
        receipts.len()
    )?;
    writeln!(
        out,
        "   aibom.cdx.json       — CycloneDX 1.6 AI Bill of Materials"
    )?;
    writeln!(
        out,
        "   security.sarif.json  — SARIF 2.1.0 ({} security event(s))",
        events.len()
    )?;
    writeln!(
        out,
        "   MANIFEST.md          — control mapping (ISO 42001 / EU AI Act / FINRA)"
    )?;
    if public_key.is_none() {
        writeln!(
            out,
            "   ⚠  no audit key found — receipts are unsigned; run `burnwall audit seal` first"
        )?;
    }
    Ok(())
}

fn evidence_manifest(
    date: &str,
    days: i64,
    receipts: usize,
    events: usize,
    models: usize,
    public_key: Option<&str>,
) -> String {
    let key = public_key.unwrap_or("(no audit key — receipts unsigned)");
    format!(
        "# Burnwall compliance evidence pack\n\
         \n\
         - Generated: {date}\n\
         - Window: last {days} day(s)\n\
         - Receipts: {receipts} · Security events: {events} · Models: {models}\n\
         - Audit public key (Ed25519): `{key}`\n\
         \n\
         All artifacts are metadata only — no prompt content, no API keys.\n\
         Verify the receipt chain at any time with `burnwall audit verify`.\n\
         \n\
         ## Artifacts → controls\n\
         \n\
         | File | What it is | Maps to |\n\
         |------|-----------|---------|\n\
         | `receipts.json` | Ed25519 hash-chained, tamper-evident log of every forwarded/blocked AI action (model, timestamp, action, cost). | EU AI Act Art. 12 (record-keeping) & Art. 26 (deployer logs); FINRA prompt/output-log & model-version expectations; ISO/IEC 42001 operational logging. |\n\
         | `aibom.cdx.json` | CycloneDX 1.6 AI Bill of Materials — models used (as ML-model components), MCP tools/services, and window totals. | ISO/IEC 42001 AI-system inventory & model lineage; AIBOM / SBOM-for-AI procurement requirements; EU AI Act technical documentation. |\n\
         | `security.sarif.json` | SARIF 2.1.0 record of blocked attempts (denied paths/commands, secrets, exfiltration). | Evidence of active guardrails / data-egress control; ingestible by GitHub code scanning and SIEMs. |\n\
         \n\
         > Mapping is provided to help a reviewer locate evidence; it is not a\n\
         > certification or legal attestation. Confirm scope against your own\n\
         > obligations.\n"
    )
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
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
