//! Unit tests for `burnwall::security::dlp` — egress / DLP detection (v0.6.5).
//! Card numbers below are standard test PANs, never real accounts.

use burnwall::security::dlp::first_match;

// ───────────────────────────── Credit cards ─────────────────────────────

#[test]
fn luhn_valid_visa_is_flagged() {
    assert_eq!(first_match("4111111111111111"), Some("credit card number"));
    assert_eq!(first_match("4242424242424242"), Some("credit card number"));
}

#[test]
fn separated_card_is_flagged() {
    assert_eq!(
        first_match("card: 4111 1111 1111 1111 thanks"),
        Some("credit card number")
    );
    assert_eq!(
        first_match("5555-5555-5555-4444"),
        Some("credit card number")
    );
}

#[test]
fn amex_15_digits_is_flagged() {
    assert_eq!(first_match("378282246310005"), Some("credit card number"));
}

#[test]
fn luhn_invalid_number_is_not_flagged() {
    // Same as a valid Visa but last digit changed → fails Luhn.
    assert_eq!(first_match("4111111111111112"), None);
}

#[test]
fn luhn_valid_but_wrong_industry_identifier_is_rejected() {
    // 16 zeros pass Luhn (sum 0) but '0' is not a card MII (3–6) → rejected.
    // This is the precision guard that keeps incidental digit runs out.
    assert_eq!(first_match("0000000000000000"), None);
}

#[test]
fn short_digit_runs_are_not_cards() {
    assert_eq!(first_match("1234"), None);
    assert_eq!(first_match("order 12345 shipped"), None);
}

// ───────────────────────────────── SSNs ─────────────────────────────────

#[test]
fn valid_dashed_ssn_is_flagged() {
    assert_eq!(
        first_match("123-45-6789"),
        Some("US Social Security number")
    );
    assert_eq!(
        first_match("SSN: 123-45-6789."),
        Some("US Social Security number")
    );
}

#[test]
fn bare_nine_digits_is_not_treated_as_ssn() {
    // Only the dashed form is flagged (bare 9-digit is too common to block).
    assert_eq!(first_match("123456789"), None);
}

#[test]
fn invalid_ssn_groups_are_not_flagged() {
    assert_eq!(first_match("000-12-3456"), None); // area 000
    assert_eq!(first_match("666-12-3456"), None); // area 666
    assert_eq!(first_match("900-12-3456"), None); // area >= 900
    assert_eq!(first_match("123-00-6789"), None); // group 00
    assert_eq!(first_match("123-45-0000"), None); // serial 0000
}

#[test]
fn ordinary_text_is_clean() {
    assert_eq!(
        first_match("the quick brown fox jumps over 13 lazy dogs"),
        None
    );
    assert_eq!(first_match(""), None);
}
