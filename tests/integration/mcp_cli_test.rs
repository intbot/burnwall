//! End-to-end tests for the `burnwall mcp` management group (list / approve /
//! revoke / export), driven via `assert_cmd` with a `BURNWALL_DATA_DIR`
//! sandbox. The DB is seeded directly (the same path the binary opens).

use std::path::PathBuf;

use assert_cmd::Command;
use burnwall::storage::{McpEvent, SecurityEvent, Storage};
use chrono::Utc;
use predicates::prelude::*;

fn burnwall(data_dir: &PathBuf) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").expect("binary");
    cmd.env("BURNWALL_DATA_DIR", data_dir);
    cmd
}

fn open(dir: &PathBuf) -> Storage {
    std::fs::create_dir_all(dir).unwrap();
    Storage::open(dir.join("burnwall.db")).expect("open")
}

#[test]
fn list_shows_seen_tools_and_trust_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        s.observe_mcp_tool("github", "read_file", "fp1").unwrap();
        s.observe_mcp_tool("github", "write_file", "fp2").unwrap();
        s.approve_mcp_tool("github", "read_file").unwrap();
    }

    burnwall(&path)
        .args(["mcp", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("read_file"))
        .stdout(predicate::str::contains("write_file"))
        .stdout(predicate::str::contains("approved"))
        .stdout(predicate::str::contains("pending"));
}

#[test]
fn list_json_emits_trust_states() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        s.observe_mcp_tool("fs", "ls", "fp").unwrap();
    }

    let output = burnwall(&path)
        .args(["mcp", "list", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(v["count"], 1);
    assert_eq!(v["tools"][0]["server"], "fs");
    assert_eq!(v["tools"][0]["tool"], "ls");
    assert_eq!(v["tools"][0]["trust"], "pending");
}

#[test]
fn approve_tool_then_state_is_approved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        s.observe_mcp_tool("github", "read_file", "fp").unwrap();
    }

    burnwall(&path)
        .args(["mcp", "approve", "github", "read_file"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Approved 'read_file'"));

    // Verify persisted.
    let s = open(&path);
    assert_eq!(
        s.mcp_tool_trust_state("github", "read_file")
            .unwrap()
            .as_deref(),
        Some("approved"),
    );
}

#[test]
fn approve_whole_server_reports_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        s.observe_mcp_tool("fs", "a", "1").unwrap();
        s.observe_mcp_tool("fs", "b", "2").unwrap();
    }

    burnwall(&path)
        .args(["mcp", "approve", "fs"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Approved 2 tool(s)"));
}

#[test]
fn revoke_returns_tool_to_pending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        s.observe_mcp_tool("fs", "a", "1").unwrap();
        s.approve_mcp_tool("fs", "a").unwrap();
    }

    burnwall(&path)
        .args(["mcp", "revoke", "fs", "a"])
        .assert()
        .success();

    let s = open(&path);
    assert_eq!(
        s.mcp_tool_trust_state("fs", "a").unwrap().as_deref(),
        Some("pending"),
    );
}

#[test]
fn export_json_has_tool_calls_and_security_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        let mut e = McpEvent::new("read_file", Some("1"), 200);
        e.timestamp = Utc::now();
        e = e.with_upstream_uri("http://localhost:8080/mcp");
        s.insert_mcp_event(&e).unwrap();

        let sec =
            SecurityEvent::new("mcp_tool_unapproved", "github").with_provider("mcp", "danger");
        s.insert_security_event(&sec).unwrap();
        // A non-MCP event must be excluded from the MCP export.
        let other = SecurityEvent::new("path_blocked", "~/.ssh").with_provider("anthropic", "x");
        s.insert_security_event(&other).unwrap();
    }

    let output = burnwall(&path)
        .args(["mcp", "export", "--format", "json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(v["tool_calls"].as_array().unwrap().len(), 1);
    assert_eq!(v["tool_calls"][0]["tool_name"], "read_file");
    // Only the provider=mcp security event is included.
    assert_eq!(v["security_events"].as_array().unwrap().len(), 1);
    assert_eq!(v["security_events"][0]["event_type"], "mcp_tool_unapproved");
}

#[test]
fn export_csv_has_header_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    {
        let s = open(&path);
        let mut e = McpEvent::new("read_file", Some("1"), 200);
        e.timestamp = Utc::now();
        s.insert_mcp_event(&e).unwrap();
    }

    let output = burnwall(&path)
        .args(["mcp", "export", "--format", "csv"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next().unwrap(),
        "timestamp,category,tool,status,detail"
    );
    let row = lines.next().expect("a data row");
    assert!(row.contains("tool_call"), "got {row}");
    assert!(row.contains("read_file"), "got {row}");
}

#[test]
fn list_empty_is_friendly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    open(&path); // create empty DB

    burnwall(&path)
        .args(["mcp", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(none"));
}
