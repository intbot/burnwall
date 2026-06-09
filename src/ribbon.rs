//! The canonical Burnwall status ribbon.
//!
//! One renderer, many surfaces: the Claude Code `statusLine` adapter
//! ([`crate::cli::statusline`]) feeds a [`Ribbon`] from the tool's stdin JSON;
//! later surfaces (the editor status bar, `burnwall watch`) feed the same
//! struct from the proxy's database. Keeping the formatting in one place means
//! every surface shows an identical line.
//!
//! ### Context-window honesty
//!
//! The context gauge is the one field we cannot always know. [`Ctx`] makes the
//! trust level explicit so we never render a number we can't stand behind:
//!
//! - [`Ctx::Exact`] — the tool reported it (Claude Code's `used_percentage`).
//! - [`Ctx::Estimate`] — we computed it from prompt tokens ÷ model window, for a
//!   tool that doesn't report it (e.g. Aider). Rendered with a `~` marker.
//! - [`Ctx::Unknown`] — the window is untrusted (extended/unknown model);
//!   rendered as `—` rather than a wrong percentage.
//! - [`Ctx::Hidden`] — the tool shows its own accurate gauge (Codex, Gemini),
//!   so we omit ours to avoid a contradicting number.

use std::fmt::Write as _;

/// Context-window state, with its trust level encoded so the renderer can be
/// honest by construction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ctx {
    /// Tool-reported percentage (0–100). Rendered as a coloured bar + percent.
    Exact(f64),
    /// Estimated percentage (0–100) from prompt tokens ÷ model window. Rendered
    /// with a `~` marker to flag it as our estimate, not the tool's number.
    Estimate(f64),
    /// Window untrusted (extended-context or unknown model). Rendered as `—`.
    Unknown,
    /// Omit the context segment entirely (the tool already shows its own).
    Hidden,
}

/// Whether the surfaced tool's traffic is actually flowing through Burnwall.
/// Only the unhealthy states render anything — the happy path stays clean, and
/// the `🔥 burnwall` prefix already implies "protected".
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Routing {
    /// Confirmed routed through the proxy. Renders nothing (no clutter).
    Proxied,
    /// Going straight to the provider — Burnwall sees nothing: no security
    /// scanning, no cost capture. Rendered as a loud warning.
    Direct,
    /// Routed, but the `BURNWALL_BYPASS` kill switch makes the proxy a pure
    /// relay (checks off). Rendered as a softer caution.
    Bypassed,
    /// The surface has no environment context to judge routing. Renders nothing.
    Unknown,
}

/// Subscription-plan limit headroom, derived from a [`crate::plan::PlanSnapshot`].
/// When present, it *replaces* the dollar cost segment — for a flat-rate plan the
/// scarce resource is window headroom, not (notional) money.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanLimits {
    /// Label of the binding window (`5h` / `7d`).
    pub primary_label: String,
    /// Binding-window utilization, 0–100.
    pub primary_pct: f64,
    /// Seconds until the binding window resets, if known.
    pub primary_reset_in: Option<i64>,
    /// Optional second window `(label, utilization 0–100)` — some providers
    /// expose only one.
    pub secondary: Option<(String, f64)>,
    /// The provider reports the plan as currently throttled.
    pub throttled: bool,
}

/// All the data the ribbon can display. Surfaces fill what they know; the
/// renderer drops segments that don't apply.
#[derive(Debug, Clone)]
pub struct Ribbon {
    /// Short model label, e.g. `sonnet-4.6` (see [`short_model`]).
    pub model: String,
    /// Originating tool, e.g. `codex` — shown in cross-tool surfaces only.
    pub tool: Option<String>,
    /// Input (prompt) tokens for the turn.
    pub up: u64,
    /// Output (completion) tokens for the turn.
    pub down: u64,
    /// Cost of the most recent turn, if known.
    pub msg_usd: Option<f64>,
    /// Cost of the current session, if the surface has a session concept
    /// (Claude Code's status line does; the DB-sourced `watch` view does not).
    pub sess_usd: Option<f64>,
    /// Total spend today across all tools (from the proxy DB), if known.
    pub today_usd: Option<f64>,
    /// Security blocks today (from the proxy DB).
    pub blocks_today: u64,
    /// Subscription-plan limit headroom. When `Some`, the renderer shows it in
    /// place of the dollar cost segment (subscription mode).
    pub plan: Option<PlanLimits>,
    /// Whether traffic is actually flowing through the proxy. Warns when it
    /// isn't; silent on the healthy path.
    pub routing: Routing,
    /// Context-window gauge.
    pub ctx: Ctx,
}

impl Ribbon {
    /// Render the one-line ribbon. `color` toggles ANSI escapes (off for status
    /// bars and other surfaces that don't render them).
    pub fn render(&self, color: bool) -> String {
        let mut s = String::new();
        let _ = write!(s, "🔥 burnwall · {}", self.model);
        if let Some(t) = &self.tool {
            let _ = write!(s, " ({t})");
        }
        // Routing health sits right after the model so an unprotected tool is
        // impossible to miss. Shown only when something is wrong.
        match self.routing {
            Routing::Direct => {
                let _ = write!(s, " · {}", warn_segment("⚠ DIRECT (unprotected)", color, Hue::Red));
            }
            Routing::Bypassed => {
                let _ = write!(s, " · {}", warn_segment("⚠ bypass", color, Hue::Yellow));
            }
            Routing::Proxied | Routing::Unknown => {}
        }
        let _ = write!(s, " · ↑{} ↓{}", human_k(self.up), human_k(self.down));
        // Subscription mode replaces the (notional) dollar cost with real plan
        // headroom; otherwise show the dollar cost + today's spend.
        match &self.plan {
            Some(p) => {
                let _ = write!(
                    s,
                    " · {} {} {}",
                    p.primary_label,
                    bar(p.primary_pct, color),
                    pct_label(p.primary_pct, color)
                );
                if let Some(secs) = p.primary_reset_in {
                    let _ = write!(s, " ({})", human_duration(secs));
                }
                if let Some((label, pct)) = &p.secondary {
                    let _ = write!(s, " · {} {}", label, pct_label(*pct, color));
                }
                if p.throttled {
                    let _ = write!(s, " · ⛔ throttled");
                }
            }
            None => {
                // Cost segment: show msg (per-turn) and/or sess, whichever are known.
                match (self.msg_usd, self.sess_usd) {
                    (Some(m), Some(sess)) => {
                        let _ = write!(s, " · ${:.2} msg ${:.2} sess", m, sess);
                    }
                    (Some(m), None) => {
                        let _ = write!(s, " · ${:.2} msg", m);
                    }
                    (None, Some(sess)) => {
                        let _ = write!(s, " · ${:.2} sess", sess);
                    }
                    (None, None) => {}
                }
                if let Some(today) = self.today_usd {
                    let _ = write!(s, " · ${today:.2} today");
                }
            }
        }
        if self.blocks_today > 0 {
            let _ = write!(s, " · 🛡{}", self.blocks_today);
        }
        match self.ctx {
            Ctx::Exact(p) => {
                let _ = write!(s, " · ctx {} {}", bar(p, color), pct_label(p, color));
            }
            Ctx::Estimate(p) => {
                // `~` marks this as our estimate, not the tool's number.
                let _ = write!(s, " · ctx ~{} ~{}%", bar(p, color), p.round() as i64);
            }
            Ctx::Unknown => {
                let _ = write!(s, " · ctx —");
            }
            Ctx::Hidden => {}
        }
        s
    }
}

/// Compact "time until" label for a reset countdown: `45m`, `2h28m`, `2d7h`.
/// Non-positive (already reset) renders as `now`.
pub fn human_duration(secs: i64) -> String {
    if secs <= 0 {
        return "now".to_string();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h{:02}m", mins % 60);
    }
    format!("{}d{}h", hours / 24, hours % 24)
}

/// Compact token count: `615`, `4.7k`, `13k`.
pub fn human_k(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=9_999 => format!("{:.1}k", n as f64 / 1000.0),
        _ => format!("{:.0}k", n as f64 / 1000.0),
    }
}

/// Shorten a provider model id for display: peel off a trailing variant tag,
/// strip a date suffix, drop the `claude-` prefix, and render the trailing
/// `-<minor>` as `.<minor>` (`claude-sonnet-4-6-20250514` → `sonnet-4.6`).
/// A trailing bracketed variant tag like `[1m]` (the 1M-context variant) is
/// kept and upper-cased (`claude-opus-4-8[1m]` → `opus-4.8[1M]`) — without
/// peeling it first, the `]` would defeat the version-dotting step. Non-Claude
/// ids that already carry a dot (`gpt-5.4`) pass through unchanged.
pub fn short_model(id: &str) -> String {
    let s = id.trim();
    // Peel a trailing bracketed variant tag (e.g. `[1m]`). Upper-case it so the
    // unit (`m` = million) reads as `1M`; re-attached after the base is dotted.
    let (mut base, tag) = match s.rfind('[') {
        Some(idx) if s.ends_with(']') => (&s[..idx], s[idx..].to_uppercase()),
        _ => (s, String::new()),
    };
    // Strip a `-YYYYMMDD` date suffix.
    if let Some(idx) = base.rfind('-') {
        let date = &base[idx + 1..];
        if date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()) {
            base = &base[..idx];
        }
    }
    let base = base.strip_prefix("claude-").unwrap_or(base);
    // `name-<major>-<minor>` → `name-<major>.<minor>` (Claude family).
    let normalized = match base.rfind('-') {
        Some(idx) => {
            let (head, tail) = (&base[..idx], &base[idx + 1..]);
            let head_ends_digit = head.bytes().last().is_some_and(|b| b.is_ascii_digit());
            if head_ends_digit && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
                format!("{head}.{tail}")
            } else {
                base.to_string()
            }
        }
        None => base.to_string(),
    };
    format!("{normalized}{tag}")
}

/// Known model context-window sizes (tokens), matched by name prefix. Used only
/// to *estimate* the gauge for tools that don't report it; an unknown model
/// yields no estimate (the caller renders [`Ctx::Unknown`]).
const CONTEXT_WINDOWS: &[(&str, u64)] = &[
    ("claude-opus-4", 200_000),
    ("claude-sonnet-4", 200_000),
    ("claude-haiku-4", 200_000),
    ("gpt-5", 400_000),
    ("gemini-2.5", 1_000_000),
    ("gemini-2.0", 1_000_000),
];

/// Context window for `model`, if known.
pub fn context_window_for(model: &str) -> Option<u64> {
    CONTEXT_WINDOWS
        .iter()
        .find(|(k, _)| model.starts_with(k))
        .map(|(_, w)| *w)
}

/// Estimate the context gauge from the prompt token count, honest by
/// construction: an unknown window — or a prompt larger than the window we
/// assumed (a sign of extended-context mode we can't see) — yields
/// [`Ctx::Unknown`] rather than a misleading percentage.
pub fn ctx_estimate(model: &str, prompt_tokens: u64) -> Ctx {
    match context_window_for(model) {
        Some(w) if prompt_tokens <= w => {
            Ctx::Estimate((prompt_tokens as f64 / w as f64 * 100.0).clamp(0.0, 100.0))
        }
        _ => Ctx::Unknown,
    }
}

// ───────────────────────────── rendering helpers ─────────────────────────────

/// An 8-cell bar, adaptively coloured by fill level.
fn bar(pct: f64, color: bool) -> String {
    let p = pct.clamp(0.0, 100.0);
    let filled = ((p / 100.0) * 8.0).round() as usize;
    let filled = filled.min(8);
    let raw = format!("[{}{}]", "▓".repeat(filled), "░".repeat(8 - filled));
    if color {
        colorize(&raw, ctx_color(p))
    } else {
        raw
    }
}

/// A short, optionally-coloured warning chip (e.g. the not-routed banner). Bold
/// so it stands out from the metric segments around it.
fn warn_segment(text: &str, color: bool, hue: Hue) -> String {
    if color {
        let code = hue_code(hue);
        format!("\x1b[1;{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn pct_label(pct: f64, color: bool) -> String {
    let raw = format!("{}%", pct.round() as i64);
    if color {
        colorize(&raw, ctx_color(pct))
    } else {
        raw
    }
}

#[derive(Clone, Copy)]
enum Hue {
    Green,
    Yellow,
    Orange,
    Red,
}

/// Thresholds: green <50%, yellow 50–70%, orange 70–85%, red ≥85%.
fn ctx_color(pct: f64) -> Hue {
    if pct < 50.0 {
        Hue::Green
    } else if pct < 70.0 {
        Hue::Yellow
    } else if pct < 85.0 {
        Hue::Orange
    } else {
        Hue::Red
    }
}

fn hue_code(hue: Hue) -> &'static str {
    match hue {
        Hue::Green => "32",
        Hue::Yellow => "33",
        Hue::Orange => "38;5;208",
        Hue::Red => "31",
    }
}

fn colorize(s: &str, hue: Hue) -> String {
    format!("\x1b[{}m{s}\x1b[0m", hue_code(hue))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Ribbon {
        Ribbon {
            model: "sonnet-4.6".to_string(),
            tool: None,
            up: 13_000,
            down: 615,
            msg_usd: Some(0.05),
            sess_usd: Some(0.16),
            today_usd: Some(2.40),
            blocks_today: 0,
            plan: None,
            routing: Routing::Unknown,
            ctx: Ctx::Exact(22.0),
        }
    }

    #[test]
    fn renders_full_line_without_color() {
        let s = base().render(false);
        assert_eq!(
            s,
            "🔥 burnwall · sonnet-4.6 · ↑13k ↓615 · $0.05 msg $0.16 sess · $2.40 today · ctx [▓▓░░░░░░] 22%"
        );
    }

    #[test]
    fn blocks_segment_only_when_nonzero() {
        let mut r = base();
        r.blocks_today = 0;
        assert!(!r.render(false).contains("🛡"));
        r.blocks_today = 2;
        assert!(r.render(false).contains("🛡2"));
    }

    #[test]
    fn omits_msg_when_unknown() {
        let mut r = base();
        r.msg_usd = None;
        let s = r.render(false);
        assert!(s.contains("$0.16 sess"));
        assert!(!s.contains("msg"));
    }

    #[test]
    fn db_path_shows_msg_and_today_without_session() {
        // The watch/DB surface has no session concept.
        let mut r = base();
        r.sess_usd = None;
        let s = r.render(false);
        assert!(s.contains("$0.05 msg"));
        assert!(!s.contains("sess"));
        assert!(s.contains("$2.40 today"));
    }

    #[test]
    fn omits_today_when_absent() {
        let mut r = base();
        r.today_usd = None;
        assert!(!r.render(false).contains("today"));
    }

    #[test]
    fn estimate_gets_tilde_marker() {
        let mut r = base();
        r.ctx = Ctx::Estimate(48.0);
        let s = r.render(false);
        assert!(s.contains("ctx ~["), "estimate bar must carry ~: {s}");
        assert!(s.contains("~48%"));
    }

    #[test]
    fn unknown_renders_dash_not_a_number() {
        let mut r = base();
        r.ctx = Ctx::Unknown;
        let s = r.render(false);
        assert!(s.contains("ctx —"));
        assert!(!s.contains('%'));
    }

    #[test]
    fn hidden_omits_context_segment() {
        let mut r = base();
        r.ctx = Ctx::Hidden;
        let s = r.render(false);
        assert!(!s.contains("ctx"));
    }

    #[test]
    fn tool_label_shown_when_present() {
        let mut r = base();
        r.tool = Some("codex".to_string());
        assert!(r.render(false).contains("🔥 burnwall · sonnet-4.6 (codex)"));
    }

    #[test]
    fn human_k_formatting() {
        assert_eq!(human_k(615), "615");
        assert_eq!(human_k(4_731), "4.7k");
        assert_eq!(human_k(13_456), "13k");
    }

    #[test]
    fn human_duration_formatting() {
        assert_eq!(human_duration(0), "now");
        assert_eq!(human_duration(-5), "now");
        assert_eq!(human_duration(45 * 60), "45m");
        assert_eq!(human_duration(2 * 3600 + 28 * 60), "2h28m");
        assert_eq!(human_duration(2 * 86400 + 7 * 3600), "2d7h");
    }

    #[test]
    fn plan_segment_replaces_cost_in_subscription_mode() {
        let mut r = base();
        r.plan = Some(PlanLimits {
            primary_label: "5h".to_string(),
            primary_pct: 11.0,
            primary_reset_in: Some(2 * 3600 + 28 * 60),
            secondary: Some(("7d".to_string(), 10.0)),
            throttled: false,
        });
        let s = r.render(false);
        // Limit headroom shown; notional dollars suppressed.
        assert!(s.contains("5h [▓░░░░░░░] 11% (2h28m)"), "got: {s}");
        assert!(s.contains("7d 10%"));
        assert!(!s.contains("msg"));
        assert!(!s.contains("sess"));
        assert!(!s.contains("today"));
        // Shared segments still render.
        assert!(s.contains("🔥 burnwall · sonnet-4.6"));
        assert!(s.contains("↑13k ↓615"));
        assert!(s.contains("ctx ["));
    }

    #[test]
    fn plan_segment_flags_throttled() {
        let mut r = base();
        r.plan = Some(PlanLimits {
            primary_label: "5h".to_string(),
            primary_pct: 100.0,
            primary_reset_in: Some(600),
            secondary: Some(("7d".to_string(), 80.0)),
            throttled: true,
        });
        assert!(r.render(false).contains("⛔ throttled"));
    }

    #[test]
    fn short_model_normalizes_names() {
        assert_eq!(short_model("claude-sonnet-4-6"), "sonnet-4.6");
        assert_eq!(short_model("claude-opus-4-8-20250514"), "opus-4.8");
        assert_eq!(short_model("gpt-5.4"), "gpt-5.4");
        assert_eq!(short_model("gpt-5.4-mini"), "gpt-5.4-mini");
        assert_eq!(short_model("gemini-2.5-pro"), "gemini-2.5-pro");
    }

    #[test]
    fn short_model_keeps_and_uppercases_variant_tag() {
        // The 1M-context variant tag survives, upper-cased, and the version is
        // still dotted (the `[1m]` previously defeated the dotting).
        assert_eq!(short_model("claude-opus-4-8[1m]"), "opus-4.8[1M]");
        assert_eq!(short_model("claude-sonnet-4-6[1m]"), "sonnet-4.6[1M]");
        // Date suffix + variant tag together.
        assert_eq!(short_model("claude-opus-4-8-20250514[1m]"), "opus-4.8[1M]");
    }

    #[test]
    fn ctx_estimate_trusts_known_window_and_flags_overflow() {
        // Within a known window → Estimate.
        match ctx_estimate("claude-sonnet-4-6", 44_000) {
            Ctx::Estimate(p) => assert!((p - 22.0).abs() < 0.5),
            other => panic!("expected Estimate, got {other:?}"),
        }
        // Prompt exceeds the assumed window (extended mode) → Unknown, not a wrong %.
        assert_eq!(ctx_estimate("claude-sonnet-4-6", 512_000), Ctx::Unknown);
        // Unknown model → Unknown.
        assert_eq!(ctx_estimate("who-knows-1", 1000), Ctx::Unknown);
    }

    #[test]
    fn color_output_contains_ansi() {
        let s = base().render(true);
        assert!(s.contains("\x1b["), "colored render should contain ANSI codes");
    }

    #[test]
    fn direct_routing_renders_loud_warning() {
        let mut r = base();
        r.routing = Routing::Direct;
        let s = r.render(false);
        assert!(s.contains("⚠ DIRECT (unprotected)"), "got: {s}");
        // Placed right after the model, before the token counts.
        let warn_at = s.find("DIRECT").unwrap();
        let up_at = s.find("↑13k").unwrap();
        assert!(warn_at < up_at, "warning should precede the token segment");
    }

    #[test]
    fn bypass_routing_renders_caution() {
        let mut r = base();
        r.routing = Routing::Bypassed;
        let s = r.render(false);
        assert!(s.contains("⚠ bypass"));
        assert!(!s.contains("DIRECT"));
    }

    #[test]
    fn proxied_and_unknown_routing_render_nothing() {
        for routing in [Routing::Proxied, Routing::Unknown] {
            let mut r = base();
            r.routing = routing;
            let s = r.render(false);
            assert!(!s.contains('⚠'), "{routing:?} should not warn: {s}");
        }
    }

    #[test]
    fn direct_warning_is_bold_red_in_color_mode() {
        let mut r = base();
        r.routing = Routing::Direct;
        let s = r.render(true);
        assert!(s.contains("\x1b[1;31m"), "expected bold-red warning: {s}");
    }
}
