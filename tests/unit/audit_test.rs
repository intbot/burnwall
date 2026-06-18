//! Audit-chain hardening tests (M-H1 / M-M3 / M-M4):
//!
//! - M-H1: a lost/regenerated audit key must REFUSE to seal (instead of
//!   silently forking the chain into a forever-TAMPERED state), and
//!   `audit rekey` must archive the old segment and let sealing resume.
//! - M-M3: two concurrent `seal` runs must not fork the chain.
//! - M-M4: SARIF results must carry a `locations` array (GitHub code scanning
//!   rejects results without one).

use burnwall::audit::{AuditChain, VerifyReport, sarif};
use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, SecurityEvent, Storage};

fn usage(input: u64, output: u64) -> TokenUsage {
    TokenUsage {
        input_tokens: input,
        output_tokens: output,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    }
}

fn seed_request(storage: &Storage) {
    storage
        .insert_request(&RequestRecord::successful(
            "anthropic",
            "claude",
            &usage(100, 50),
            0.5,
            None,
        ))
        .unwrap();
}

// ── M-H1: key loss → refuse to seal; rekey → resume ─────────────────────────

#[test]
fn lost_key_refuses_to_seal_and_rekey_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("audit_ed25519.key");
    let storage = Storage::open_in_memory().unwrap();

    seed_request(&storage);
    let original = AuditChain::open(&key_path).unwrap();
    assert_eq!(original.seal(&storage).unwrap().sealed, 1);
    drop(original);

    // Simulate key loss: the key file vanishes, receipts + sidecar remain.
    std::fs::remove_file(&key_path).unwrap();
    let regenerated = AuditChain::open(&key_path).unwrap();

    seed_request(&storage);
    let err = regenerated.seal(&storage).expect_err("seal must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("audit key changed or lost"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains("burnwall audit rekey"),
        "error must name the remediation command: {msg}"
    );

    // Deliberate rekey: archives the closed segment, records the new pubkey,
    // and sealing resumes.
    let report = regenerated.rekey(&storage).unwrap();
    assert!(report.old_key.is_some(), "old segment key should be known");
    assert_eq!(report.receipts, 1);
    assert!(report.chain_head.is_some());
    assert!(report.archive.exists(), "segment archive must be written");
    let archived = std::fs::read_to_string(&report.archive).unwrap();
    assert!(archived.contains(report.old_key.as_deref().unwrap()));

    assert_eq!(regenerated.seal(&storage).unwrap().sealed, 1);
}

#[test]
fn legacy_chain_without_sidecar_still_refuses_a_regenerated_key() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("audit_ed25519.key");
    let storage = Storage::open_in_memory().unwrap();

    seed_request(&storage);
    let original = AuditChain::open(&key_path).unwrap();
    assert_eq!(original.seal(&storage).unwrap().sealed, 1);
    drop(original);

    // Pre-sidecar chain: both the key AND the recorded pubkey are gone. The
    // tail-signature check must still detect that the fresh key never signed
    // the existing chain.
    std::fs::remove_file(&key_path).unwrap();
    std::fs::remove_file(key_path.with_extension("pub")).unwrap();
    let regenerated = AuditChain::open(&key_path).unwrap();

    seed_request(&storage);
    let err = regenerated.seal(&storage).expect_err("seal must refuse");
    assert!(err.to_string().contains("burnwall audit rekey"));
}

#[test]
fn reopening_the_same_key_seals_without_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("audit_ed25519.key");
    let storage = Storage::open_in_memory().unwrap();

    seed_request(&storage);
    AuditChain::open(&key_path).unwrap().seal(&storage).unwrap();

    // Same key file, fresh open — the normal restart path must be untouched.
    seed_request(&storage);
    let reopened = AuditChain::open(&key_path).unwrap();
    assert_eq!(reopened.seal(&storage).unwrap().sealed, 1);
    assert_eq!(
        reopened.verify(&storage).unwrap(),
        VerifyReport::Intact { count: 2 }
    );
}

// ── M-M3: concurrent seals must not fork the chain ──────────────────────────

#[test]
fn concurrent_seals_do_not_fork_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("burnwall.db");
    let key = dir.path().join("k.key");

    let s1 = Storage::open(&db).unwrap();
    for _ in 0..6 {
        seed_request(&s1);
    }
    let s2 = Storage::open(&db).unwrap();
    let c1 = AuditChain::open(&key).unwrap();
    let c2 = AuditChain::open(&key).unwrap();

    use std::sync::atomic::{AtomicU64, Ordering};
    let total = AtomicU64::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| total.fetch_add(c1.seal(&s1).unwrap().sealed, Ordering::SeqCst));
        scope.spawn(|| total.fetch_add(c2.seal(&s2).unwrap().sealed, Ordering::SeqCst));
    });

    // Every row sealed exactly once between the two runs, and the resulting
    // chain is a single intact line — no duplicate prev_hash fork.
    assert_eq!(total.load(Ordering::SeqCst), 6);
    assert_eq!(c1.verify(&s1).unwrap(), VerifyReport::Intact { count: 6 });
}

// ── M-M4: SARIF results carry synthetic locations ────────────────────────────

#[test]
fn sarif_results_carry_synthetic_locations() {
    let mut event = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa");
    event.id = Some(7);
    let log = sarif::build(&[event]);

    let result = &log["runs"][0]["results"][0];
    let location = &result["locations"][0]["physicalLocation"];
    assert_eq!(
        location["artifactLocation"]["uri"],
        "burnwall://security-events/7"
    );
    assert!(
        location["region"]["startLine"].is_number(),
        "GitHub's SARIF validator wants a region next to the artifactLocation"
    );
}

// ── file mode: `burnwall scan` SARIF carries real file/line locations ────────

#[test]
fn sarif_file_findings_carry_real_locations_and_levels() {
    use burnwall::security::filescan;

    let findings = filescan::scan_text(
        ".claude\\settings.json",
        "{\"key\": \"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}\nok\nhi\u{200B}\u{200B}there\n",
    );
    assert_eq!(findings.len(), 2, "one secret + one invisible-text finding");

    let log = sarif::build_file_findings(&findings);
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    let secret = &results[0];
    assert_eq!(secret["ruleId"], "secret_in_file");
    assert_eq!(secret["level"], "error");
    let loc = &secret["locations"][0]["physicalLocation"];
    // Real file + line, with Windows separators normalized for SARIF.
    assert_eq!(loc["artifactLocation"]["uri"], ".claude/settings.json");
    assert_eq!(loc["region"]["startLine"], 1);
    // Masked: the key body must not be echoed into the report.
    assert!(
        !secret["message"]["text"]
            .as_str()
            .unwrap()
            .contains("AAAAAAAAAAAAAAAA")
    );

    let invisible = &results[1];
    assert_eq!(invisible["ruleId"], "invisible_text");
    assert_eq!(invisible["level"], "warning");
    assert_eq!(
        invisible["locations"][0]["physicalLocation"]["region"]["startLine"],
        3
    );
}
