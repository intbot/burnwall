//! Tests for `burnwall init` — tool detection, shell-rc generation, and the
//! end-to-end CLI invocation in dry-run and `--apply` modes.
//!
//! Tool detection is exercised by manipulating `PATH` to contain a
//! controlled set of fake binaries.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use burnwall::cli::init::{append_to_rc, binary_in_path_var, detect_tools, Shell};
use predicates::prelude::*;

fn make_fake_binary(dir: &PathBuf, name: &str) {
    fs::create_dir_all(dir).unwrap();
    let path = if cfg!(windows) {
        dir.join(format!("{}.exe", name))
    } else {
        dir.join(name)
    };
    fs::write(&path, b"#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
    }
}

// ────────────────────────── shell + paths ──────────────────────────

#[test]
fn shell_rc_paths_match_convention() {
    let home = dirs::home_dir().expect("home dir");
    assert_eq!(Shell::Zsh.rc_path().unwrap(), home.join(".zshrc"));
    assert_eq!(Shell::Bash.rc_path().unwrap(), home.join(".bashrc"));
    assert_eq!(
        Shell::Fish.rc_path().unwrap(),
        home.join(".config").join("fish").join("config.fish")
    );
    // PowerShell intentionally returns None (we don't auto-edit $PROFILE).
    assert!(Shell::Powershell.rc_path().is_none());
}

#[test]
fn shell_export_lines_match_syntax() {
    let zsh = Shell::Zsh.export_lines("http://localhost:4100");
    assert_eq!(zsh.len(), 2);
    assert!(zsh[0].starts_with("export ANTHROPIC_BASE_URL="));
    assert!(zsh[1].starts_with("export OPENAI_BASE_URL="));

    let fish = Shell::Fish.export_lines("http://localhost:4100");
    assert!(fish[0].starts_with("set -gx ANTHROPIC_BASE_URL"));

    let ps = Shell::Powershell.export_lines("http://localhost:4100");
    assert!(ps[0].starts_with("$env:ANTHROPIC_BASE_URL"));
}

// ────────────────────────── binary detection ──────────────────────────

#[test]
fn detect_tools_runs_without_panicking() {
    // We don't assert which binaries are present (depends on dev machine)
    // — just that detection returns the four known entries.
    let detections = detect_tools();
    assert_eq!(detections.len(), 4);
    let names: Vec<_> = detections.iter().map(|d| d.binary.as_str()).collect();
    assert!(names.contains(&"claude"));
    assert!(names.contains(&"codex"));
    assert!(names.contains(&"aider"));
    assert!(names.contains(&"opencode"));
}

#[test]
fn binary_in_path_var_finds_planted_binary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    make_fake_binary(&path, "claude");

    // Pass an isolated PATH; no global env mutation, no race risk.
    let path_var = std::ffi::OsString::from(&path);
    assert!(binary_in_path_var("claude", &path_var));
    assert!(!binary_in_path_var("aider", &path_var));
}

#[test]
fn binary_in_path_var_returns_false_for_empty_path() {
    let empty = std::ffi::OsString::new();
    assert!(!binary_in_path_var("claude", &empty));
    assert!(!binary_in_path_var("anything", &empty));
}

// ────────────────────────── rc-file append ──────────────────────────

#[test]
fn append_to_rc_writes_marker_block_once() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".zshrc");
    fs::write(&rc, "alias ll='ls -l'\n").unwrap();

    let lines = vec!["export X=1".to_string(), "export Y=2".to_string()];
    let modified = append_to_rc(&rc, &lines).unwrap();
    assert!(modified);
    let content = fs::read_to_string(&rc).unwrap();
    assert!(content.contains("alias ll"));
    assert!(content.contains("export X=1"));
    assert!(content.contains("export Y=2"));
    assert!(content.contains("# Added by burnwall init"));

    // Idempotent: second call sees the marker, skips writing.
    let modified_again = append_to_rc(&rc, &lines).unwrap();
    assert!(!modified_again);
    let content_after = fs::read_to_string(&rc).unwrap();
    assert_eq!(content, content_after, "second append must not modify file");
}

#[test]
fn append_to_rc_creates_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join("config").join("fish").join("config.fish");
    let lines = vec!["set -gx X 1".to_string()];
    append_to_rc(&rc, &lines).unwrap();
    assert!(rc.exists());
}

// ────────────────────────── end-to-end CLI ──────────────────────────

fn burnwall(data_dir: &PathBuf) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").expect("binary");
    cmd.env("BURNWALL_DATA_DIR", data_dir);
    cmd
}

#[test]
fn init_dry_run_prints_plan_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();

    burnwall(&path)
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Detecting AI tools"))
        .stdout(predicate::str::contains("ANTHROPIC_BASE_URL"))
        .stdout(predicate::str::contains("OPENAI_BASE_URL"))
        .stdout(predicate::str::contains("--apply"));
}

#[test]
fn init_creates_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("burnwall_data");

    burnwall(&path).arg("init").assert().success();
    assert!(path.exists(), "data dir should be created by init");
}

// `burnwall stop` behavior moved out of init_test in v0.2 — the daemon
// integration suite (`tests/integration/daemon_test.rs`) owns the full
// stop lifecycle now, including the "not running" and "stale PID file"
// cases that used to live here as a v0.1 stub assertion.

// ────────────────────────── config-driven start ──────────────────────────
// We can't easily exercise `burnwall start` end-to-end here (it binds a
// port and runs forever), but we can verify the config-loading wiring by
// constructing the same components the start command does.

#[test]
fn start_command_picks_up_budget_from_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "set", "budget.daily", "7.50"])
        .assert()
        .success();

    // The config show output should reflect the new value, AND the next
    // load_or_default in the start command would pick the same value.
    burnwall(&path)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("daily = 7.5"));

    // Direct check via the config module that the runtime conversion picks
    // up the new value (this is what start.rs does internally).
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("BURNWALL_DATA_DIR", &path) };
    let cfg = burnwall::config::load_or_default(burnwall::config::default_path().unwrap()).unwrap();
    let runtime: burnwall::budget::BudgetConfig = (&cfg.budget).into();
    assert!((runtime.daily_usd - 7.5).abs() < 1e-9);
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("BURNWALL_DATA_DIR") };
}
