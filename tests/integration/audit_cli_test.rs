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

#[test]
fn audit_pack_writes_evidence_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("evidence");
    bin(dir.path())
        .args(["audit", "pack", "--days", "7", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("Evidence pack written"))
        .stdout(predicate::str::contains("ISO 42001"));

    // All four artifacts exist.
    for f in ["receipts.json", "aibom.cdx.json", "security.sarif.json", "MANIFEST.md"] {
        assert!(out.join(f).exists(), "missing {f}");
    }

    // The AIBOM is schema-identifiable CycloneDX 1.6 (conformance check, #12).
    let bom: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("aibom.cdx.json")).unwrap()).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    assert!(bom["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
    assert!(bom["metadata"]["timestamp"].is_string());

    // The manifest maps artifacts to the frameworks auditors ask for.
    let manifest = std::fs::read_to_string(out.join("MANIFEST.md")).unwrap();
    assert!(manifest.contains("EU AI Act"));
    assert!(manifest.contains("FINRA"));
    assert!(manifest.contains("receipts.json"));
}
