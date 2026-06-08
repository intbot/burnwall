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
    /// Context-window gauge.
    pub ctx: Ctx,
}

impl Ribbon {
    /// Render the one-line ribbon. `color` toggles ANSI escapes (off for status
    /// bars and other surfaces that don't render them).
    pub fn render(&self, color: bool) -> String {
        let mut s = String::new();
        let _ = write!(s, "🔥 {}", self.model);
        if let Some(t) = &self.tool {
            let _ = write!(s, " ({t})");
        }
        let _ = write!(s, " · ↑{} ↓{}", human_k(self.up), human_k(self.down));
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

/// Compact token count: `615`, `4.7k`, `13k`.
pub fn human_k(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=9_999 => format!("{:.1}k", n as f64 / 1000.0),
        _ => format!("{:.0}k", n as f64 / 1000.0),
    }
}

/// Shorten a provider model id for display: strip a date suffix, drop the
/// `claude-` prefix, and render the trailing `-<minor>` as `.<minor>`
/// (`claude-sonnet-4-6-20250514` → `sonnet-4.6`). Non-Claude ids that already
/// carry a dot (`gpt-5.4`) pass through unchanged.
pub fn short_model(id: &str) -> String {
    let mut s = id.trim();
    // Strip a `-YYYYMMDD` date suffix.
    if let Some(idx) = s.rfind('-') {
        let tail = &s[idx + 1..];
        if tail.len() == 8 && tail.bytes().all(|b| b.is_ascii_digit()) {
            s = &s[..idx];
        }
    }
    let s = s.strip_prefix("claude-").unwrap_or(s);
    // `name-<major>-<minor>` → `name-<major>.<minor>` (Claude family).
    if let Some(idx) = s.rfind('-') {
        let (head, tail) = (&s[..idx], &s[idx + 1..]);
        let head_ends_digit = head.bytes().last().is_some_and(|b| b.is_ascii_digit());
        if head_ends_digit && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return format!("{head}.{tail}");
        }
    }
    s.to_string()
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

fn colorize(s: &str, hue: Hue) -> String {
    let code = match hue {
        Hue::Green => "32",
        Hue::Yellow => "33",
        Hue::Orange => "38;5;208",
        Hue::Red => "31",
    };
    format!("\x1b[{code}m{s}\x1b[0m")
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
            ctx: Ctx::Exact(22.0),
        }
    }

    #[test]
    fn renders_full_line_without_color() {
        let s = base().render(false);
        assert_eq!(
            s,
            "🔥 sonnet-4.6 · ↑13k ↓615 · $0.05 msg $0.16 sess · $2.40 today · ctx [▓▓░░░░░░] 22%"
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
        assert!(r.render(false).contains("🔥 sonnet-4.6 (codex)"));
    }

    #[test]
    fn human_k_formatting() {
        assert_eq!(human_k(615), "615");
        assert_eq!(human_k(4_731), "4.7k");
        assert_eq!(human_k(13_456), "13k");
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
}
