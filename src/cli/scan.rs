//! `burnwall scan` — file mode for CI and pre-commit: scan agent configs and
//! transcripts on disk (not live traffic) for committed credentials and
//! invisible-Unicode instruction smuggling. Findings print as `file:line`
//! lines and can export as SARIF 2.1.0 for GitHub code scanning.
//!
//! Exit code: 0 by default even with findings (SARIF/code-scanning owns the
//! triage); `--fail-on-findings` makes any finding exit non-zero for plain
//! CI gating without a SARIF upload.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use clap::Args;

use crate::security::filescan;

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Files or directories to scan. A directory is walked recursively for
    /// agent config files (CLAUDE.md, .cursorrules, .mcp.json, .claude/…).
    /// Defaults to the current directory.
    pub paths: Vec<PathBuf>,
    /// In directories, scan every text file — not just known agent configs.
    #[arg(long)]
    pub all_files: bool,
    /// Write a SARIF 2.1.0 report to this file (`-` for stdout).
    #[cfg(feature = "audit")]
    #[arg(long, value_name = "FILE")]
    pub sarif: Option<PathBuf>,
    /// Exit non-zero when anything is found (plain CI gating).
    #[arg(long)]
    pub fail_on_findings: bool,
}

pub fn run_cmd(args: ScanArgs) -> anyhow::Result<()> {
    let roots = if args.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        args.paths.clone()
    };

    let targets = filescan::collect_targets(&roots, args.all_files);
    let mut findings = Vec::new();
    for path in &targets {
        findings.extend(filescan::scan_file(path));
    }

    #[cfg(feature = "audit")]
    let sarif_to_stdout = args.sarif.as_deref() == Some(std::path::Path::new("-"));
    #[cfg(not(feature = "audit"))]
    let sarif_to_stdout = false;

    // Human report (suppressed when SARIF goes to stdout — one format per
    // stream so the output stays machine-consumable).
    if !sarif_to_stdout {
        let mut out = std::io::stdout().lock();
        for f in &findings {
            writeln!(out, "{}  {}:{}  {}", icon(f), f.path, f.line, f.message)?;
        }
        writeln!(
            out,
            "{} file(s) scanned, {} finding(s).",
            targets.len(),
            findings.len()
        )?;
        if targets.is_empty() {
            writeln!(
                out,
                "(no agent config files found — pass paths explicitly, or use --all-files)"
            )?;
        }
    }

    #[cfg(feature = "audit")]
    if let Some(sarif_path) = &args.sarif {
        let doc = crate::audit::sarif::build_file_findings(&findings);
        let text = serde_json::to_string_pretty(&doc).context("serializing SARIF")?;
        if sarif_to_stdout {
            println!("{text}");
        } else {
            std::fs::write(sarif_path, text)
                .with_context(|| format!("writing {}", sarif_path.display()))?;
            println!("SARIF report written to {}", sarif_path.display());
        }
    }

    if args.fail_on_findings && !findings.is_empty() {
        anyhow::bail!("scan found {} finding(s)", findings.len());
    }
    Ok(())
}

fn icon(f: &filescan::Finding) -> &'static str {
    match f.level() {
        "error" => "❌",
        _ => "⚠️ ",
    }
}
