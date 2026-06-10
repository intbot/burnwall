//! `burnwall report-bug` — write a **sanitized, local** report of recent blocks
//! so a user who hit a false positive can file a useful issue. Zero-telemetry:
//! nothing is sent anywhere. The report carries only metadata already in the
//! DB — rule labels (`~/.ssh`, `recursive force delete`), pattern *names*
//! (`AWS access key ID`, never the value), event types, timestamps, and
//! provider/model — plus OS/version. The user reviews the file and attaches it
//! to a GitHub issue themselves.

use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct ReportBugArgs {
    /// How many days of recent blocks to include (default 1 = today).
    #[arg(long, default_value_t = 1)]
    pub days: i64,
    /// Print the report to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,
}

pub fn run_cmd(args: ReportBugArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let events = storage.security_events_since_days(args.days.max(1))?;

    let report = build_report(&events, args.days.max(1));

    if args.stdout {
        print!("{report}");
        return Ok(());
    }

    let dir = crate::storage::data_dir().context("locating data dir")?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("bug-report-{stamp}.md"));
    std::fs::write(&path, &report).with_context(|| format!("writing {}", path.display()))?;

    let issues = format!("{}/issues/new", env!("CARGO_PKG_REPOSITORY"));
    println!("📋  Wrote a sanitized bug report (no payload content, nothing sent):");
    println!("      {}", path.display());
    println!();
    println!("   Review it, then open an issue and attach it:");
    println!("      {issues}");
    println!();
    println!("   If a block was a false positive, mention what you were doing when it fired.");
    Ok(())
}

fn build_report(events: &[crate::storage::SecurityEvent], days: i64) -> String {
    let mut s = String::new();
    s.push_str("# Burnwall bug report\n\n");
    s.push_str(&format!("- Version: {}\n", env!("CARGO_PKG_VERSION")));
    s.push_str(&format!("- OS: {} {}\n", std::env::consts::OS, std::env::consts::ARCH));
    s.push_str(&format!(
        "- Generated: {}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z")
    ));
    s.push_str(&format!("- Window: last {days} day(s)\n\n"));
    s.push_str(
        "> This report contains only metadata (rule labels, pattern names, timestamps).\n\
         > No request/response payloads, secrets, or file contents are included.\n\n",
    );

    s.push_str("## Recent blocks\n\n");
    if events.is_empty() {
        s.push_str("(none in this window)\n\n");
    } else {
        s.push_str("| Time (local) | Type | Rule / pattern | Provider/Model |\n");
        s.push_str("|---|---|---|---|\n");
        for e in events {
            let pm = match (&e.provider, &e.model) {
                (Some(p), Some(m)) => format!("{p}/{m}"),
                (Some(p), None) => p.clone(),
                _ => "-".to_string(),
            };
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                e.timestamp
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S"),
                e.event_type,
                e.details.replace('|', "\\|"),
                pm,
            ));
        }
        s.push('\n');
    }

    s.push_str("## What I was doing\n\n");
    s.push_str("<!-- Describe the action that triggered the block; this helps confirm a false positive. -->\n");
    s
}
