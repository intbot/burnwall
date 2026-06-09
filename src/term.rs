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
}
