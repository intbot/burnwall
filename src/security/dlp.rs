//! Egress / DLP detection (v0.6.5).
//!
//! A request-side check for **data exfiltration** — structured-sensitive data
//! the credential denylist in [`super::secrets`] does not cover. It is opt-in
//! (`[security].dlp`) and errs toward **precision**, not recall: a false block
//! on the always-block path hurts adoption more than a missed PII string, and
//! the user opted in expecting blocks.
//!
//! Two detectors, both gated on a structural check that makes random matches
//! vanishingly unlikely:
//! - **Credit-card number** — a 13–19 digit run (optional space/dash
//!   separators) whose leading digit is a real card industry identifier
//!   (3–6) and which passes the **Luhn** checksum. Luhn + IIN + length is what
//!   keeps the false-positive rate near zero.
//! - **US Social Security number** — the dashed `NNN-NN-NNNN` form only (a
//!   bare 9-digit run is far too common to block), excluding the group
//!   combinations the SSA never issues (`000`/`666`/`9xx` area, `00` group,
//!   `0000` serial).
//!
//! Only the **category name** is ever reported — never the matched value.

use std::sync::LazyLock;

use regex::Regex;

/// Candidate credit-card run: 13–19 digits with optional single space/dash
/// separators. (`[ \-]` is space-or-hyphen — NOT a range.)
static CC_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d(?:[ \-]?\d){12,18}").expect("CC regex compiles"));

/// US SSN in dashed form, captured by group so we can reject invalid issues.
static SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").expect("SSN regex compiles"));

/// The first DLP category `value` matches, or `None`.
pub fn first_match(value: &str) -> Option<&'static str> {
    if contains_valid_credit_card(value) {
        return Some("credit card number");
    }
    if contains_valid_ssn(value) {
        return Some("US Social Security number");
    }
    None
}

fn contains_valid_credit_card(value: &str) -> bool {
    for m in CC_CANDIDATE.find_iter(value) {
        let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        let len = digits.len();
        if !(13..=19).contains(&len) {
            continue;
        }
        // Major Industry Identifier: real cards start 3 (Amex/Diners),
        // 4 (Visa), 5/2 (Mastercard), or 6 (Discover). This alone removes the
        // bulk of incidental long digit strings before the Luhn check.
        match digits.as_bytes()[0] {
            b'3'..=b'6' => {}
            _ => continue,
        }
        if luhn_valid(&digits) {
            return true;
        }
    }
    false
}

/// Luhn (mod-10) checksum. `digits` must be ASCII digits only.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for c in digits.bytes().rev() {
        let mut d = (c - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn contains_valid_ssn(value: &str) -> bool {
    for caps in SSN.captures_iter(value) {
        let area: u32 = caps[1].parse().unwrap_or(0);
        let group: u32 = caps[2].parse().unwrap_or(0);
        let serial: u32 = caps[3].parse().unwrap_or(0);
        // Group combinations the SSA never assigns.
        if area == 0 || area == 666 || area >= 900 {
            continue;
        }
        if group == 0 || serial == 0 {
            continue;
        }
        return true;
    }
    false
}
