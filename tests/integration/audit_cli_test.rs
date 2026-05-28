//! End-to-end CLI coverage for the v0.8 audit + compliance commands. Runs the
//! real binary against a sandboxed (empty) data dir — the data-path logic is
//! covered by the in-crate unit tests in `src/audit`; this asserts the command
//! wiring, arg parsing, and output shape.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").unwrap();
    cmd.env("BURNWALL_DATA_DIR", dir);
    cmd
}

#[test]
fn audit_seal_then_verify_on_empty_db() {
    let dir = tempfile::tempdir().unwrap();
    bin(dir.path())
        .args(["audit", "seal"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sealed 0"));
    bin(dir.path())
        .args(["audit", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("intact"));
}

#[test]
fn audit_aibom_outputs_cyclonedx() {
    let dir = tempfile::tempdir().unwrap();
    bin(dir.path())
        .args(["audit", "aibom", "--days", "7"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CycloneDX"))
        .stdout(predicate::str::contains("1.6"));
}

#[test]
fn audit_sarif_outputs_sarif_log() {
    let dir = tempfile::tempdir().unwrap();
    bin(dir.path())
        .args(["audit", "sarif"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2.1.0"))
        .stdout(predicate::str::contains("burnwall"));
}

#[test]
fn audit_export_json_and_csv() {
    let dir = tempfile::tempdir().unwrap();
    bin(dir.path())
        .args(["audit", "export", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("receipts"));
    bin(dir.path())
        .args(["audit", "export", "--format", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("seq,sealed_at"));
}

#[test]
fn report_text_and_json() {
    let dir = tempfile::tempdir().unwrap();
    bin(dir.path())
        .args(["report", "--days", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Burnwall report"));
    bin(dir.path())
        .args(["report", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("total_cost_usd"));
}
