//! `burnwall share` — an opt-in, screenshot-friendly, *signed* value card.
//!
//! A zero-telemetry tool produces nothing to share automatically — so virality,
//! if any, has to be earned: the user chooses to post a card. To keep it honest
//! (no faked numbers), the card's figures are signed with the local audit key
//! and can be verified against the printed public key. Nothing leaves the
//! machine; this just renders text the user may copy.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::audit::AuditChain;
use crate::pricing;
use crate::providers::TokenUsage;
use crate::storage::{ModelBreakdown, Storage};

#[derive(Args, Debug)]
pub struct ShareArgs {
    /// How many days the card summarizes (default 30).
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Skip signing (no audit key needed) — emits an unsigned card.
    #[arg(long)]
    pub no_sign: bool,
}

pub fn run_cmd(args: ShareArgs) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let rows = storage.breakdown_since_days(args.days)?;
    let (spent, saved) = spend_and_savings(&rows);
    let blocked = storage
        .security_events_since_days(args.days)?
        .len();

    // Canonical, signable payload — the exact numbers shown, so a verifier can
    // confirm the card wasn't doctored.
    let payload = format!(
        "burnwall-card|days={}|spent={:.2}|saved={:.2}|blocked={}",
        args.days, spent, saved, blocked
    );

    let signature = if args.no_sign {
        None
    } else {
        match AuditChain::open_default() {
            Ok(chain) => Some((chain.sign_hex(payload.as_bytes()), chain.public_key_hex())),
            Err(_) => None,
        }
    };

    let mut out = std::io::stdout().lock();
    let line1 = format!("🔥 Burnwall · last {} days", args.days);
    let line2 = format!("💰 ${:.2} spent · ${:.2} saved by caching", spent, saved);
    let line3 = format!("🛡  {blocked} risky action{} blocked", if blocked == 1 { "" } else { "s" });
    let width = [line1.len(), line2.len(), line3.len()].into_iter().max().unwrap_or(40) + 2;
    let rule = "─".repeat(width);

    writeln!(out, "┌{rule}┐")?;
    writeln!(out, "  {line1}")?;
    writeln!(out, "  {line2}")?;
    writeln!(out, "  {line3}")?;
    match &signature {
        Some((sig, pubkey)) => {
            let sig_short = &sig[..sig.len().min(16)];
            let key_short = &pubkey[..pubkey.len().min(16)];
            writeln!(out, "  🔐 signed {sig_short}… · key {key_short}…")?;
        }
        None => writeln!(out, "  (unsigned — run `burnwall audit seal` once to enable signing)")?,
    }
    writeln!(out, "└{rule}┘")?;
    if let Some((sig, pubkey)) = &signature {
        writeln!(out)?;
        writeln!(out, "verify: payload \"{payload}\"")?;
        writeln!(out, "        sig {sig}")?;
        writeln!(out, "        key {pubkey}")?;
    }
    Ok(())
}

/// Total real spend and cache-captured savings over the rows (USD), using the
/// same cache-aware math as `burnwall savings`.
fn spend_and_savings(rows: &[ModelBreakdown]) -> (f64, f64) {
    let mut real = 0.0;
    let mut without = 0.0;
    for r in rows {
        if let Some(p) = pricing::get_pricing(&r.model) {
            let usage = TokenUsage {
                input_tokens: r.input_tokens,
                output_tokens: r.output_tokens,
                cache_creation_tokens: r.cache_creation_tokens,
                cache_read_tokens: r.cache_read_tokens,
            };
            real += pricing::cost(&usage, p);
            without += pricing::cost_without_cache(&usage, p);
        }
    }
    (real, (without - real).max(0.0))
}
