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
    first_match_masked(value).map(|(name, _)| name)
}

/// [`first_match`] plus a **masked, recognisable preview** of the matched value
/// (e.g. `4111…1111`) for the block message — the raw value is never returned,
/// echoed, or logged. Mirrors [`super::secrets::first_match_masked`].
pub fn first_match_masked(value: &str) -> Option<(&'static str, String)> {
    if let Some(m) = credit_card_match(value) {
        return Some(("credit card number", super::secrets::mask_match(m)));
    }
    if let Some(m) = ssn_match(value) {
        return Some(("US Social Security number", super::secrets::mask_match(m)));
    }
    None
}

/// The first substring of `value` that is a Luhn-valid card number, or `None`.
fn credit_card_match(value: &str) -> Option<&str> {
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
            return Some(m.as_str());
        }
    }
    None
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

/// The first substring of `value` that is a validly-issued dashed SSN, or `None`.
fn ssn_match(value: &str) -> Option<&str> {
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
        return Some(caps.get(0).unwrap().as_str());
    }
    None
}
