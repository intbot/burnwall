//! Security engine tests.
//!
//! Exercises [`SecurityEngine::scan`] against:
//! - the two real-shape fixtures (`request_with_blocked_path.json`,
//!   `request_safe_tool_use.json`),
//! - each rule family in isolation (path / command / mount / secret),
//! - edge cases (non-JSON body, deeply nested structure, both literal `~`
//!   and expanded `/Users/...` path forms).

use std::fs;

use burnwall::security::{Ruleset, SecurityEngine, ViolationKind};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{}", name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
}

fn engine() -> SecurityEngine {
    SecurityEngine::with_defaults()
}

// ─────────────────────────── Fixture-based ───────────────────────────

#[test]
fn fixture_blocked_path_is_caught() {
    // Fixture has command "cat /Users/developer/.ssh/id_rsa". Rule "~/.ssh"
    // must match via the shared "/.ssh" suffix.
    let violation = engine()
        .scan(&fixture("request_with_blocked_path.json"))
        .expect("expected a violation");

    assert_eq!(violation.kind, ViolationKind::Path);
    assert_eq!(violation.matched, "~/.ssh");
}

#[test]
fn fixture_safe_tool_use_passes_through() {
    // "ls -la ./src/" — no rule should match. Returns None.
    assert!(engine()
        .scan(&fixture("request_safe_tool_use.json"))
        .is_none());
}

// ──────────────────────────── Path rules ────────────────────────────

#[test]
fn matches_literal_tilde_form() {
    let body = br#"{"x": "cat ~/.ssh/id_rsa"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Path);
    assert_eq!(v.matched, "~/.ssh");
}

#[test]
fn matches_expanded_unix_form() {
    let body = br#"{"x": "cat /home/alice/.ssh/known_hosts"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Path);
}

#[test]
fn matches_expanded_windows_form() {
    let body = br#"{"x": "type C:\\Users\\alice\\.ssh\\config"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Path);
}

#[test]
fn matches_absolute_path_rule() {
    let body = br#"{"x": "cat /etc/passwd"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Path);
    assert_eq!(v.matched, "/etc/passwd");
}

#[test]
fn does_not_match_unrelated_directory_with_ssh_in_name() {
    // ".ssh" appears but only with non-slash prefix (dot.ssh).
    let body = br#"{"x": "cat ./dot.ssh.example"}"#;
    assert!(engine().scan(body).is_none());
}

// ────────────────────────── Command rules ──────────────────────────

#[test]
fn matches_rm_rf_root() {
    let body = br#"{"x": "rm -rf / --no-preserve-root"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Command);
    assert_eq!(v.matched, "rm -rf /");
}

#[test]
fn matches_chmod_777() {
    let body = br#"{"x": "chmod 777 /etc"}"#;
    // /etc is not /etc/passwd, so the chmod rule should hit first (depending
    // on ordering). Either way, it must be blocked.
    let v = engine().scan(body).expect("violation");
    assert!(matches!(
        v.kind,
        ViolationKind::Command | ViolationKind::Path
    ));
}

#[test]
fn safe_commands_pass() {
    let body = br#"{"x": "rm file.txt"}"#;
    assert!(engine().scan(body).is_none());
}

// ──────────────────────────── Mount rules ────────────────────────────

#[test]
fn blocks_macos_volumes() {
    let body = br#"{"x": "cp file /Volumes/external/backup"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Mount);
    assert_eq!(v.matched, "/Volumes/");
}

#[test]
fn blocks_smb_url() {
    let body = br#"{"x": "mount smb://fileserver/share"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Mount);
    assert_eq!(v.matched, "smb://");
}

#[test]
fn blocks_unc_path() {
    // JSON-escaped \\server\share → two real backslashes in the parsed string.
    let body = br#"{"x": "copy \\\\server\\share\\file.txt local"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Mount);
}

#[test]
fn mount_blocking_can_be_disabled() {
    let rules = Ruleset {
        block_network_mounts: false,
        ..Ruleset::default()
    };
    let engine = SecurityEngine::new(rules);
    let body = br#"{"x": "ls /Volumes/disk"}"#;
    assert!(engine.scan(body).is_none());
}

// ──────────────────────────── Secrets ────────────────────────────

#[test]
fn detects_aws_access_key_id() {
    // Fake but pattern-matching key.
    let body = br#"{"x": "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Secret);
    assert_eq!(v.matched, "AWS access key ID");
}

#[test]
fn detects_private_key_header() {
    let body = br#"{"x": "config: -----BEGIN OPENSSH PRIVATE KEY-----\nMIIEpAIB..."}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Secret);
    assert_eq!(v.matched, "private key header");
}

#[test]
fn detects_github_pat() {
    // ghp_ + 36 alnum chars
    let body = br#"{"x": "GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Secret);
    assert_eq!(v.matched, "GitHub personal access token");
}

#[test]
fn secret_detection_can_be_disabled() {
    let rules = Ruleset {
        detect_secrets: false,
        ..Ruleset::default()
    };
    let engine = SecurityEngine::new(rules);
    let body = br#"{"x": "key=AKIAIOSFODNN7EXAMPLE"}"#;
    assert!(engine.scan(body).is_none());
}

// ──────────────────────────── Edge cases ────────────────────────────

#[test]
fn non_json_body_returns_none() {
    // Fail-open per D9: non-chat endpoints may not have JSON bodies.
    assert!(engine().scan(b"<html>").is_none());
    assert!(engine().scan(b"").is_none());
}

#[test]
fn scans_deeply_nested_structure() {
    // The denied path is buried four levels deep inside a tool_use input.
    let body = br#"{
        "messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "name": "bash", "input": {
                    "command": "cat ~/.aws/credentials"
                }}
            ]}
        ]
    }"#;
    let v = engine().scan(body).expect("violation");
    assert_eq!(v.kind, ViolationKind::Path);
    assert_eq!(v.matched, "~/.aws");
}

#[test]
fn violation_event_type_maps_to_storage_schema() {
    // The four kinds must map to the strings stored in
    // `security_events.event_type` per SPEC.md.
    assert_eq!(ViolationKind::Path.event_type(), "path_blocked");
    assert_eq!(ViolationKind::Command.event_type(), "command_blocked");
    assert_eq!(ViolationKind::Mount.event_type(), "mount_blocked");
    assert_eq!(ViolationKind::Secret.event_type(), "secret_detected");
}

#[test]
fn violation_message_is_human_readable() {
    let v = engine()
        .scan(&fixture("request_with_blocked_path.json"))
        .unwrap();
    let msg = v.message();
    assert!(msg.contains("denied path"));
    assert!(msg.contains("~/.ssh"));
}
