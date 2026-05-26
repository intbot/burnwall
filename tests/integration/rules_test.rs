//! Integration tests for `burnwall rules list / install` (Phase B).
//! Hermetic: each run points `BURNWALL_DATA_DIR` at a temp dir so the user's
//! real config is never touched.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::tempdir;

fn burnwall(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").unwrap();
    cmd.env("BURNWALL_DATA_DIR", data_dir);
    cmd
}

#[test]
fn rules_list_shows_official_packs() {
    let dir = tempdir().unwrap();
    burnwall(dir.path())
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(contains("django"))
        .stdout(contains("infrastructure"))
        .stdout(contains("available"));
}

#[test]
fn rules_install_enables_and_persists() {
    let dir = tempdir().unwrap();
    burnwall(dir.path())
        .args(["rules", "install", "django"])
        .assert()
        .success()
        .stdout(contains("Enabled rule pack 'django'"));

    // The enable persisted to config and shows in the JSON listing.
    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("\"id\": \"django\""))
        .stdout(contains("\"enabled\": true"))
        .stdout(contains("\"trust\": \"official-bundled\""));
}

#[test]
fn rules_install_is_idempotent() {
    let dir = tempdir().unwrap();
    burnwall(dir.path())
        .args(["rules", "install", "react"])
        .assert()
        .success();
    burnwall(dir.path())
        .args(["rules", "install", "react"])
        .assert()
        .success()
        .stdout(contains("already enabled"));
}

#[test]
fn rules_install_unknown_pack_fails() {
    let dir = tempdir().unwrap();
    burnwall(dir.path())
        .args(["rules", "install", "not-a-real-pack"])
        .assert()
        .failure()
        .stderr(contains("not a known official pack"));
}

#[test]
fn rules_test_blocks_a_matching_sample() {
    let dir = tempdir().unwrap();
    let sample = dir.path().join("sample.json");
    std::fs::write(
        &sample,
        r#"{"content": "SECRET_KEY = 'abcdefghijklmnopqrstuvwxyz123456'"}"#,
    )
    .unwrap();

    burnwall(dir.path())
        .args(["rules", "test", "django"])
        .arg(&sample)
        .assert()
        .success()
        .stdout(contains("BLOCKED"))
        .stdout(contains("Django SECRET_KEY"));
}

#[test]
fn rules_test_allows_a_benign_sample() {
    let dir = tempdir().unwrap();
    let sample = dir.path().join("ok.json");
    std::fs::write(&sample, r#"{"content": "hello world"}"#).unwrap();

    burnwall(dir.path())
        .args(["rules", "test", "django"])
        .arg(&sample)
        .assert()
        .success()
        .stdout(contains("allowed"));
}

// ── Phase D — third-party `rules add` + TOFU trust ─────────────────────────

const THIRD_PARTY_PACK: &str = r#"
id = "corp-internal"
name = "Corp internal rules"
version = "0.1.0"
deny_paths = ["/corp/secret-config"]

[[secret_patterns]]
name = "Corp API token"
regex = "CORP-[A-Z0-9]{8}"
"#;

fn write_pack(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let p = dir.join("pack.toml");
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn rules_add_installs_and_approves() {
    let dir = tempdir().unwrap();
    let pack = write_pack(dir.path(), THIRD_PARTY_PACK);
    burnwall(dir.path())
        .args(["rules", "add", "--yes"])
        .arg(&pack)
        .assert()
        .success()
        .stdout(contains("Installed and approved 'corp-internal'"));

    // It now shows as an approved third-party pack — and as third-party, never
    // official (invariant I4).
    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("\"id\": \"corp-internal\""))
        .stdout(contains("\"trust\": \"third-party\""))
        .stdout(contains("approved"));
}

#[test]
fn i7_rules_add_shows_review_and_can_decline() {
    let dir = tempdir().unwrap();
    let pack = write_pack(dir.path(), THIRD_PARTY_PACK);
    // Decline at the prompt → the summary is shown but nothing is installed.
    burnwall(dir.path())
        .args(["rules", "add"])
        .arg(&pack)
        .write_stdin("n\n")
        .assert()
        .success()
        .stdout(contains("/corp/secret-config")) // review surface (I7)
        .stdout(contains("Corp API token"))
        .stdout(contains("Aborted"));

    // Nothing was installed.
    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("\"corp-internal\"").not());
}

#[test]
fn i4_third_party_claiming_official_is_still_third_party() {
    let dir = tempdir().unwrap();
    // A pack that *claims* to be official — the `publisher` key is ignored and
    // trust derives only from the user's approval (I4).
    let pack = write_pack(
        dir.path(),
        r#"
id = "fake-official"
name = "Totally Official"
publisher = "burnwall-official"
deny_paths = ["/x"]
"#,
    );
    burnwall(dir.path())
        .args(["rules", "add", "--yes"])
        .arg(&pack)
        .assert()
        .success();

    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        // It appears under third_party with trust "third-party" — never the
        // bundled "official-bundled" provenance.
        .stdout(contains("\"id\": \"fake-official\""))
        .stdout(contains("\"trust\": \"third-party\""));
}

#[test]
fn i6_edited_pack_is_reflagged() {
    let dir = tempdir().unwrap();
    let pack = write_pack(dir.path(), THIRD_PARTY_PACK);
    burnwall(dir.path())
        .args(["rules", "add", "--yes"])
        .arg(&pack)
        .assert()
        .success();

    // Tamper with the INSTALLED copy under <data>/rules/.
    let installed = dir.path().join("rules").join("corp-internal.toml");
    let mut body = std::fs::read_to_string(&installed).unwrap();
    body.push_str("\ndeny_commands = [\"rm -rf /\"]\n");
    std::fs::write(&installed, body).unwrap();

    // The content hash no longer matches the pin → flagged as edited (I6).
    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("edited"));
}

#[test]
fn rules_revoke_removes_pack() {
    let dir = tempdir().unwrap();
    let pack = write_pack(dir.path(), THIRD_PARTY_PACK);
    burnwall(dir.path())
        .args(["rules", "add", "--yes"])
        .arg(&pack)
        .assert()
        .success();
    burnwall(dir.path())
        .args(["rules", "revoke", "corp-internal"])
        .assert()
        .success()
        .stdout(contains("Revoked rule pack 'corp-internal'"));
    burnwall(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("\"corp-internal\"").not());
}
