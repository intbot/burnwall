//! Secret pattern detection.
//!
//! Each pattern is a distinctive prefix + length signature with a low false-
//! positive rate. We err on the side of recall — better to occasionally
//! flag a non-secret than to let a real credential leak. The matched value
//! is reported by name; the raw secret is never logged.
//!
//! ### Built-in vs pack-authored patterns
//! Built-in patterns are compile-time-correct constants ([`PATTERNS`]).
//! Rule packs (v0.6) may contribute additional patterns at runtime via
//! [`SecretPattern::compile`], which **safe-compiles** an untrusted pattern
//! with bounded program/DFA size (invariant I5) so a hostile regex fails to
//! compile rather than exhausting memory. Rust's `regex` is linear-time and
//! has no backreferences/lookaround, so catastrophic backtracking (ReDoS) is
//! not reachable — the size caps only bound memory. `name` is a
//! `Cow<'static, str>`: borrowed for built-ins, owned for pack patterns.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// Compiled-program size cap for a pack-authored pattern (bytes).
const MAX_REGEX_SIZE: usize = 64 * 1024;
/// Lazy-DFA size cap for a pack-authored pattern (bytes).
const MAX_REGEX_DFA_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: Cow<'static, str>,
    pub regex: Regex,
}

impl SecretPattern {
    /// A built-in (trusted, compile-time-correct) pattern.
    fn builtin(name: &'static str, pattern: &'static str) -> SecretPattern {
        SecretPattern {
            name: Cow::Borrowed(name),
            regex: Regex::new(pattern).expect("built-in secret pattern must compile"),
        }
    }

    /// Safe-compile an untrusted (rule-pack) pattern. Returns `None` if the
    /// pattern is invalid or its compiled size exceeds the cap — the caller
    /// skips it (fail-open). The name is owned (community names aren't
    /// `'static`).
    pub fn compile(name: &str, pattern: &str) -> Option<SecretPattern> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_SIZE)
            .dfa_size_limit(MAX_REGEX_DFA_SIZE)
            .build()
            .ok()?;
        Some(SecretPattern {
            name: Cow::Owned(name.to_string()),
            regex,
        })
    }
}

/// Built-in secret patterns. Compiled once on first use via `LazyLock`.
pub static PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern::builtin("AWS access key ID", r"\bAKIA[0-9A-Z]{16}\b"),
        SecretPattern::builtin("private key header", r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
        SecretPattern::builtin("GitHub personal access token", r"\bghp_[A-Za-z0-9]{36}\b"),
        SecretPattern::builtin("OpenAI API key", r"\bsk-[A-Za-z0-9]{48}\b"),
        SecretPattern::builtin("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{36,}\b"),
        SecretPattern::builtin("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        // Added v0.6. All keep a distinctive prefix + length so the false-
        // positive rate stays low; deliberately NO generic-entropy or JWT
        // pattern (those over-block legitimate traffic at the always-block tier).
        SecretPattern::builtin("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        SecretPattern::builtin(
            "Google OAuth client secret",
            r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
        ),
        SecretPattern::builtin("Stripe secret key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        SecretPattern::builtin(
            "GitHub fine-grained PAT",
            r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
        ),
        SecretPattern::builtin("npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        SecretPattern::builtin(
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        ),
    ]
});

/// Name of the first **built-in** pattern that matches `value`, or `None`.
pub fn first_match(value: &str) -> Option<&'static str> {
    PATTERNS.iter().find(|p| p.regex.is_match(value)).map(|p| {
        // Built-ins are always borrowed; this is the &'static name.
        match &p.name {
            Cow::Borrowed(s) => *s,
            Cow::Owned(_) => unreachable!("built-in patterns carry borrowed names"),
        }
    })
}

/// Name of the first pattern in `patterns` that matches `value`, or `None`.
/// Used for pack-contributed patterns (owned names).
pub fn first_match_in<'a>(value: &str, patterns: &'a [SecretPattern]) -> Option<&'a str> {
    patterns
        .iter()
        .find(|p| p.regex.is_match(value))
        .map(|p| p.name.as_ref())
}
