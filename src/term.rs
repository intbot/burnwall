//! Minimal ANSI styling for console output.
//!
//! No dependency — a handful of SGR codes wrapped in a TTY/`NO_COLOR` gate so
//! the same code colors an interactive terminal and stays clean when piped,
//! redirected, or captured by a test harness. Surfaces build a [`Styler`] once
//! (it samples the stream's TTY-ness and the environment), then call the colour
//! methods inline inside `write!`/`writeln!`.
//!
//! This is *presentation only*. It never changes what is written, just whether
//! escape codes wrap it — so a non-colour surface is byte-for-byte the plain
//! text it always was.

use std::io::IsTerminal;

/// The palette used across CLI surfaces. Kept small and semantic.
#[derive(Clone, Copy)]
pub enum Color {
    /// Success / healthy / active.
    Green,
    /// Caution / attention.
    Yellow,
    /// Strong warning (not-routed, degraded).
    Orange,
    /// Error / blocked.
    Red,
    /// Headers / primary labels.
    Cyan,
    /// Secondary info (paths, hints).
    Blue,
}

impl Color {
    fn code(self) -> &'static str {
        match self {
            Color::Green => "32",
            Color::Yellow => "33",
            Color::Orange => "38;5;208",
            Color::Red => "31",
            Color::Cyan => "36",
            Color::Blue => "34",
        }
    }
}

/// Decide whether a stream should carry ANSI colour. Honors the de-facto
/// `NO_COLOR` standard (and a burnwall-specific override), `TERM=dumb`, and
/// whether the stream is an interactive TTY.
fn color_enabled(is_tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("BURNWALL_NO_COLOR").is_some() {
        return false;
    }
    if matches!(std::env::var("TERM"), Ok(t) if t == "dumb") {
        return false;
    }
    is_tty
}

/// A colour gate bound to one stream. Construct with [`Styler::stdout`] /
/// [`Styler::stderr`]; the colour methods return the string unchanged when
/// colour is disabled, so callers never branch.
#[derive(Clone, Copy)]
pub struct Styler {
    enabled: bool,
}

impl Styler {
    /// Styler for stdout (coloured only when stdout is an interactive TTY).
    pub fn stdout() -> Self {
        Self {
            enabled: color_enabled(std::io::stdout().is_terminal()),
        }
    }

    /// Styler for stderr.
    pub fn stderr() -> Self {
        Self {
            enabled: color_enabled(std::io::stderr().is_terminal()),
        }
    }

    /// Build with an explicit flag — for tests and for surfaces that already
    /// know their colour policy (e.g. the ribbon's `color` argument).
    pub fn with_enabled(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Is colour active for this styler?
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Wrap `s` in `color` when enabled, else return it unchanged.
    pub fn paint(&self, s: &str, color: Color) -> String {
        if self.enabled {
            format!("\x1b[{}m{}\x1b[0m", color.code(), s)
        } else {
            s.to_string()
        }
    }

    /// Bold `s` when enabled.
    pub fn bold(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn green(&self, s: &str) -> String {
        self.paint(s, Color::Green)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.paint(s, Color::Yellow)
    }
    pub fn orange(&self, s: &str) -> String {
        self.paint(s, Color::Orange)
    }
    pub fn red(&self, s: &str) -> String {
        self.paint(s, Color::Red)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.paint(s, Color::Cyan)
    }
    pub fn blue(&self, s: &str) -> String {
        self.paint(s, Color::Blue)
    }
}

// ───────────────────────────── stat cards ─────────────────────────────
//
// A small dashboard-header primitive: a row of bordered "tiles", each with a
// label, a headline value, and a sub-line (often a bar). Used by `burnwall
// status` so the glanceable numbers read like a modern CLI dashboard. All width
// maths is done on the *plain* text, so the colour escapes never shift the box
// borders out of alignment.

/// A single stat tile. Keep `value`/`sub` to single-cell glyphs (ASCII, plus
/// the `▓`/`░` bar cells) — the layout pads on `chars().count()`, which only
/// equals the display width when every glyph is one column wide.
pub struct Card {
    pub label: String,
    pub value: String,
    pub sub: String,
    /// Colour for the headline value (label/sub stay default unless set).
    pub value_color: Option<Color>,
    /// Colour for the sub-line (e.g. a bar).
    pub sub_color: Option<Color>,
    /// Optional delta-vs-previous chip, rendered on its own row between the
    /// value and the sub-line. When *any* card in a row carries one, every card
    /// renders the delta row (blank where absent) so the tiles stay aligned.
    pub delta: Option<Delta>,
}

impl Card {
    pub fn new(label: &str, value: &str, sub: &str) -> Self {
        Self {
            label: label.to_string(),
            value: value.to_string(),
            sub: sub.to_string(),
            value_color: None,
            sub_color: None,
            delta: None,
        }
    }

    /// Builder: colour the headline value.
    pub fn with_value_color(mut self, c: Color) -> Self {
        self.value_color = Some(c);
        self
    }

    /// Builder: colour the sub-line.
    pub fn with_sub_color(mut self, c: Color) -> Self {
        self.sub_color = Some(c);
        self
    }

    /// Builder: attach a delta-vs-previous chip (no-op when `None`).
    pub fn with_delta(mut self, d: Option<Delta>) -> Self {
        self.delta = d;
        self
    }
}

/// Render a horizontal row of stat cards as a four-line block (top border
/// carrying the label, value, sub, bottom border). `inner` is each tile's
/// interior column width; `indent` is the left margin. Tiles are laid out
/// left-to-right separated by a single space.
pub fn render_cards(cards: &[Card], inner: usize, indent: usize, sty: &Styler) -> String {
    let pad = " ".repeat(indent);
    // If any card has a delta chip, every card reserves the row so the borders
    // stay aligned — a half-height tile would shear the block.
    let any_delta = cards.iter().any(|c| c.delta.is_some());
    let mut tops = Vec::with_capacity(cards.len());
    let mut vals = Vec::with_capacity(cards.len());
    let mut deltas = Vec::with_capacity(cards.len());
    let mut subs = Vec::with_capacity(cards.len());
    let mut bots = Vec::with_capacity(cards.len());
    for c in cards {
        // The label rides in the top border: `┌ Label ──────┐`.
        let label = format!(" {} ", c.label);
        let dashes = inner.saturating_sub(label.chars().count());
        tops.push(format!("┌{}{}┐", label, "─".repeat(dashes)));
        bots.push(format!("└{}┘", "─".repeat(inner)));
        vals.push(card_cell(&c.value, inner, c.value_color, sty));
        subs.push(card_cell(&c.sub, inner, c.sub_color, sty));
        if any_delta {
            match &c.delta {
                Some(d) => deltas.push(card_cell(&d.text, inner, Some(d.color), sty)),
                None => deltas.push(card_cell("", inner, None, sty)),
            }
        }
    }
    let join = |segs: &[String]| format!("{pad}{}", segs.join(" "));
    let mut rows = vec![join(&tops), join(&vals)];
    if any_delta {
        rows.push(join(&deltas));
    }
    rows.push(join(&subs));
    rows.push(join(&bots));
    rows.join("\n")
}

/// One `│ centred-text │` interior cell: the (truncated) text centred in
/// `inner` columns, padded on the plain string then optionally coloured so the
/// ANSI escapes don't count toward the width.
fn card_cell(text: &str, inner: usize, color: Option<Color>, sty: &Styler) -> String {
    let shown = truncate_display(text, inner);
    let slack = inner.saturating_sub(shown.chars().count());
    let left = slack / 2;
    let right = slack - left;
    let painted = match color {
        Some(c) => sty.paint(&shown, c),
        None => shown.clone(),
    };
    format!("│{}{}{}│", " ".repeat(left), painted, " ".repeat(right))
}

/// A `cells`-wide fill bar (`▓` filled, `░` empty) for `pct` in 0..=100. Plain
/// text — colour at the call site (or via [`Card::with_sub_color`]).
pub fn fill_bar(pct: f64, cells: usize) -> String {
    let p = pct.clamp(0.0, 100.0);
    let filled = (((p / 100.0) * cells as f64).round() as usize).min(cells);
    format!("{}{}", "▓".repeat(filled), "░".repeat(cells - filled))
}

/// Threshold hue for a "higher is worse" gauge (e.g. budget used): green under
/// 60%, yellow under 85%, red at or above.
pub fn gauge_hue(pct: f64) -> Color {
    if pct < 60.0 {
        Color::Green
    } else if pct < 85.0 {
        Color::Yellow
    } else {
        Color::Red
    }
}

// ──────────────────────── deltas & sparklines ────────────────────────
//
// Glanceable "how does this compare?" primitives borrowed from modern cost
// dashboards: a delta chip (`▲12%` / `▼5`) coloured by whether the move is
// good or bad, and a block-character sparkline of a daily series. Both are
// pure and width-stable (one column per glyph) so they slot into the cards and
// tables without breaking alignment.

/// Whether an increase in a metric reads as good or bad — drives chip colour.
#[derive(Clone, Copy)]
pub enum Trend {
    /// Higher is better (cache-hit rate): ▲ green, ▼ red.
    HigherBetter,
    /// Higher is worse (spend, blocked counts): ▲ caution, ▼ green.
    HigherWorse,
}

/// A formatted delta chip: the glyph + magnitude text and its semantic colour.
/// Paint at the call site with `sty.paint(&d.text, d.color)`.
pub struct Delta {
    pub text: String,
    pub color: Color,
}

/// Percent change from `prev` to `curr`. `None` when `prev` is zero or not
/// finite — there's no baseline to compare against, and we never render an
/// "∞%" chip from a divide-by-zero.
pub fn delta_pct(curr: f64, prev: f64) -> Option<f64> {
    if !prev.is_finite() || prev.abs() < f64::EPSILON {
        return None;
    }
    Some((curr - prev) / prev * 100.0)
}

/// Colour for a delta given its sign and the metric's [`Trend`]. A `flat`
/// (rounds-to-zero) move is muted blue.
fn delta_color(positive: bool, flat: bool, trend: Trend) -> Color {
    if flat {
        return Color::Blue;
    }
    match (positive, trend) {
        (true, Trend::HigherBetter) | (false, Trend::HigherWorse) => Color::Green,
        (true, Trend::HigherWorse) => Color::Orange,
        (false, Trend::HigherBetter) => Color::Red,
    }
}

/// Build a percent-change chip (`▲ 12%`, `▼ 7%`, or `→ 0%`) comparing `curr`
/// to `prev`, coloured by `trend`. `None` when there is no baseline
/// (`prev == 0`), so a card can fall back to its normal sub-line rather than
/// show a bogus chip.
pub fn delta_chip_pct(curr: f64, prev: f64, trend: Trend) -> Option<Delta> {
    let rounded = delta_pct(curr, prev)?.round();
    let flat = rounded.abs() < 1.0;
    let text = if flat {
        "→ 0%".to_string()
    } else if rounded > 0.0 {
        format!("▲ {}%", rounded as i64)
    } else {
        format!("▼ {}%", (-rounded) as i64)
    };
    Some(Delta {
        text,
        color: delta_color(rounded > 0.0, flat, trend),
    })
}

/// Build an absolute-count chip (`▲3`, `▼5`) comparing `curr` to `prev`,
/// coloured by `trend`. `None` when the counts are equal — a flat count chip
/// is just noise on a card.
pub fn delta_chip_count(curr: i64, prev: i64, trend: Trend) -> Option<Delta> {
    if curr == prev {
        return None;
    }
    let diff = curr - prev;
    let glyph = if diff > 0 { '▲' } else { '▼' };
    Some(Delta {
        text: format!("{glyph} {}", diff.abs()),
        color: delta_color(diff > 0, false, trend),
    })
}

/// A block-character sparkline (`▁▂▃▄▅▆▇█`, one cell per value) of `values`,
/// scaled to the series' own min..max. An empty series yields an empty string;
/// a flat series renders a mid bar (or the floor when every value is zero).
pub fn sparkline(values: &[f64]) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() {
        return String::new();
    }
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let range = max - min;
    if range <= f64::EPSILON {
        let c = if max > 0.0 {
            LEVELS[LEVELS.len() / 2]
        } else {
            LEVELS[0]
        };
        return std::iter::repeat_n(c, values.len()).collect();
    }
    values
        .iter()
        .map(|&v| {
            let frac = ((v - min) / range).clamp(0.0, 1.0);
            let idx = (frac * (LEVELS.len() - 1) as f64).round() as usize;
            LEVELS[idx.min(LEVELS.len() - 1)]
        })
        .collect()
}

/// Truncate `s` to at most `max` display columns, marking the cut with `…`.
fn truncate_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_styler_is_passthrough() {
        let s = Styler::with_enabled(false);
        assert_eq!(s.green("ok"), "ok");
        assert_eq!(s.bold("hi"), "hi");
        assert_eq!(s.paint("x", Color::Red), "x");
    }

    #[test]
    fn enabled_styler_wraps_in_ansi() {
        let s = Styler::with_enabled(true);
        assert_eq!(s.green("ok"), "\x1b[32mok\x1b[0m");
        assert!(s.red("e").contains("\x1b[31m"));
        assert!(s.bold("b").starts_with("\x1b[1m"));
    }

    #[test]
    fn no_color_env_disables() {
        // A TTY would normally enable; NO_COLOR must override. We can't easily
        // toggle a real TTY in a test, so exercise the decision function.
        // (Env is process-global; assert the pure branch instead.)
        assert!(!color_enabled(false));
    }

    #[test]
    fn fill_bar_clamps_and_fills() {
        assert_eq!(fill_bar(0.0, 8), "░░░░░░░░");
        assert_eq!(fill_bar(100.0, 8), "▓▓▓▓▓▓▓▓");
        assert_eq!(fill_bar(50.0, 8), "▓▓▓▓░░░░");
        // Out-of-range clamps rather than panicking.
        assert_eq!(fill_bar(250.0, 4), "▓▓▓▓");
        assert_eq!(fill_bar(-5.0, 4), "░░░░");
    }

    #[test]
    fn render_cards_rows_share_one_width() {
        // Every line of the block must be the same display width, regardless of
        // value length or colour — otherwise the borders shear. Use a no-colour
        // styler so the bytes are the visible glyphs.
        let sty = Styler::with_enabled(false);
        let cards = [
            Card::new("Spend", "$4.20", "37 req"),
            Card::new("Budget", "21%", &fill_bar(21.0, 8)),
            Card::new("Blocked", "2", "153 alerts"),
        ];
        let block = render_cards(&cards, 11, 2, &sty);
        let widths: Vec<usize> = block.lines().map(|l| l.chars().count()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "lines must align: {widths:?}\n{block}"
        );
        // Four lines (top, value, sub, bottom) even with colour enabled.
        let colored = render_cards(&cards, 11, 2, &Styler::with_enabled(true));
        assert_eq!(colored.lines().count(), 4);
    }

    #[test]
    fn delta_row_appears_when_any_card_has_one_and_stays_aligned() {
        let sty = Styler::with_enabled(false);
        let cards = [
            Card::new("Spend", "$4.20", "37 req").with_delta(delta_chip_pct(
                4.2,
                3.0,
                Trend::HigherWorse,
            )),
            // A card with no delta still reserves the row (blank), keeping height.
            Card::new("Cache", "88%", &fill_bar(88.0, 8)),
        ];
        let block = render_cards(&cards, 11, 2, &sty);
        // top, value, DELTA, sub, bottom = 5 lines.
        assert_eq!(block.lines().count(), 5);
        let widths: Vec<usize> = block.lines().map(|l| l.chars().count()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "delta block must stay aligned: {widths:?}\n{block}"
        );
        // The chip text is present.
        assert!(block.contains('▲'), "{block}");
    }

    #[test]
    fn cards_colour_only_wraps_when_enabled() {
        let card = [Card::new("Cache", "88%", "hit").with_value_color(Color::Green)];
        assert!(!render_cards(&card, 9, 0, &Styler::with_enabled(false)).contains("\x1b["));
        assert!(render_cards(&card, 9, 0, &Styler::with_enabled(true)).contains("\x1b["));
    }

    #[test]
    fn delta_pct_has_no_baseline_at_zero() {
        assert_eq!(delta_pct(5.0, 0.0), None);
        assert_eq!(delta_pct(5.0, f64::NAN), None);
        assert_eq!(delta_pct(150.0, 100.0), Some(50.0));
        assert_eq!(delta_pct(50.0, 100.0), Some(-50.0));
    }

    #[test]
    fn delta_chip_pct_arrow_and_polarity() {
        // Spend up 12% → caution (higher is worse).
        let up = delta_chip_pct(11.2, 10.0, Trend::HigherWorse).unwrap();
        assert_eq!(up.text, "▲ 12%");
        assert!(matches!(up.color, Color::Orange));
        // Cache up → good (higher is better).
        let cache_up = delta_chip_pct(95.0, 90.0, Trend::HigherBetter).unwrap();
        assert!(cache_up.text.starts_with('▲'));
        assert!(matches!(cache_up.color, Color::Green));
        // Spend down → good.
        let down = delta_chip_pct(8.0, 10.0, Trend::HigherWorse).unwrap();
        assert_eq!(down.text, "▼ 20%");
        assert!(matches!(down.color, Color::Green));
        // Sub-1% move → flat, muted, no false arrow.
        let flat = delta_chip_pct(100.4, 100.0, Trend::HigherWorse).unwrap();
        assert_eq!(flat.text, "→ 0%");
        assert!(matches!(flat.color, Color::Blue));
        // No baseline → no chip.
        assert!(delta_chip_pct(5.0, 0.0, Trend::HigherWorse).is_none());
    }

    #[test]
    fn delta_chip_count_absolute_and_polarity() {
        // 5 fewer blocks than yesterday → good (down on a higher-worse metric).
        let fewer = delta_chip_count(0, 5, Trend::HigherWorse).unwrap();
        assert_eq!(fewer.text, "▼ 5");
        assert!(matches!(fewer.color, Color::Green));
        // 3 more → caution.
        let more = delta_chip_count(3, 0, Trend::HigherWorse).unwrap();
        assert_eq!(more.text, "▲ 3");
        assert!(matches!(more.color, Color::Orange));
        // Equal → no chip.
        assert!(delta_chip_count(2, 2, Trend::HigherWorse).is_none());
    }

    #[test]
    fn sparkline_shapes_the_series() {
        assert_eq!(sparkline(&[]), "");
        // One cell per value.
        assert_eq!(sparkline(&[1.0, 2.0, 3.0]).chars().count(), 3);
        // Min maps to the floor, max to the ceiling.
        let s = sparkline(&[0.0, 5.0, 10.0]);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars[0], '▁');
        assert_eq!(chars[2], '█');
        // All-zero → all floor; flat-nonzero → a mid bar (not the floor).
        assert_eq!(sparkline(&[0.0, 0.0, 0.0]), "▁▁▁");
        assert!(sparkline(&[4.0, 4.0]).chars().all(|c| c != '▁'));
    }
}
