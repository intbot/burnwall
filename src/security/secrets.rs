//! Secret pattern detection.
//!
//! Each pattern is a distinctive prefix + length signature with a low false-
//! positive rate. We err on the side of recall — better to occasionally
//! flag a non-secret than to let a real credential leak. The matched value
//! is reported by name; the raw secret is never logged.

use std::sync::LazyLock;

use regex::Regex;

pub struct SecretPattern {
    pub name: &'static str,
    pub regex: Regex,
}

/// Compiled secret patterns. Compiled once on first use via `LazyLock`.
pub static PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            name: "AWS access key ID",
            regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        },
        SecretPattern {
            name: "private key header",
            regex: Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----").unwrap(),
        },
        SecretPattern {
            name: "GitHub personal access token",
            regex: Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
        },
        SecretPattern {
            name: "OpenAI API key",
            regex: Regex::new(r"\bsk-[A-Za-z0-9]{48}\b").unwrap(),
        },
        SecretPattern {
            name: "Anthropic API key",
            regex: Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{36,}\b").unwrap(),
        },
        SecretPattern {
            name: "Slack token",
            regex: Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
        },
    ]
});

/// Return the name of the first secret pattern that matches `value`,
/// or `None` if no pattern matches.
pub fn first_match(value: &str) -> Option<&'static str> {
    PATTERNS
        .iter()
        .find(|p| p.regex.is_match(value))
        .map(|p| p.name)
}
