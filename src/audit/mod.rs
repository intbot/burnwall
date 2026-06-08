//! Cryptographic audit receipts (v0.8).
//!
//! `burnwall audit seal` walks the `requests` and `security_events` logs in
//! chronological order and appends, for each not-yet-sealed row, a signed link
//! in a hash chain:
//!
//! - `content_hash` = SHA-256 over the canonical text of the source row, so a
//!   later edit to that row is detectable.
//! - `hash` = SHA-256(prev_hash ‖ content_hash), so deleting, reordering, or
//!   inserting any receipt breaks every later link.
//! - `signature` = Ed25519 over `hash` with a local key, so the chain cannot be
//!   forged or extended without the key.
//!
//! Everything is metadata only — the source rows never hold prompt content.
//! `burnwall audit verify` re-walks the chain, re-derives each `content_hash`
//! from the live source row, and checks every hash link and signature.
//!
//! The CycloneDX AIBOM (`aibom`) and SARIF (`sarif`) exports live in the
//! sibling modules; they read the request/security logs directly and do not
//! depend on receipts.

pub mod aibom;
pub mod sarif;

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::storage::{data_dir, ReceiptRow, RequestRecord, SecurityEvent, Storage};

/// 64 hex zeros — the `prev_hash` of the first receipt in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// File name of the local Ed25519 signing key under the data dir.
const KEY_FILE: &str = "audit_ed25519.key";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("audit signing key is malformed (expected 32 bytes, found {0})")]
    BadKey(usize),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Holds the local Ed25519 signing key and seals/verifies receipts.
pub struct AuditChain {
    key: SigningKey,
}

impl AuditChain {
    /// Load the signing key from `<data_dir>/audit_ed25519.key`, generating and
    /// persisting (0600 on Unix) a fresh keypair on first use.
    pub fn open_default() -> Result<Self> {
        Self::open(&data_dir()?.join(KEY_FILE))
    }

    /// Load (or, if absent, generate) the signing key at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let key = if path.exists() {
            let bytes = std::fs::read(path)?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuditError::BadKey(bytes.len()))?;
            SigningKey::from_bytes(&seed)
        } else {
            let key = SigningKey::generate(&mut rand_core::OsRng);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, key.to_bytes())?;
            set_key_perms(path)?;
            key
        };
        Ok(Self { key })
    }

    /// The verifying (public) key, hex-encoded. Safe to publish — it lets a
    /// third party verify the chain without being able to forge it.
    pub fn public_key_hex(&self) -> String {
        hex(self.key.verifying_key().as_bytes())
    }

    /// Sign arbitrary bytes with the local audit key, returning a hex
    /// signature. Lets `burnwall share` emit a *verifiable* value card whose
    /// numbers can't be faked (verify against [`AuditChain::public_key_hex`]).
    pub fn sign_hex(&self, bytes: &[u8]) -> String {
        hex(&self.key.sign(bytes).to_bytes())
    }

    /// Seal every not-yet-sealed request + security event into the chain, in
    /// chronological order. Idempotent: rows already sealed are skipped (the
    /// `audit_receipts.UNIQUE(source, source_id)` constraint backs this).
    pub fn seal(&self, storage: &Storage) -> Result<SealReport> {
        let mut prev = storage
            .last_receipt_hash()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let mut pending: Vec<Pending> = Vec::new();
        for r in storage.unsealed_requests()? {
            pending.push(Pending::Request(r));
        }
        for e in storage.unsealed_security_events()? {
            pending.push(Pending::Security(e));
        }
        // Deterministic chain order: by source timestamp, then source kind,
        // then rowid (stable tie-breaks for events sharing a timestamp).
        pending.sort_by(|a, b| {
            a.timestamp()
                .cmp(&b.timestamp())
                .then_with(|| a.source().cmp(b.source()))
                .then_with(|| a.source_id().cmp(&b.source_id()))
        });

        let mut sealed = 0u64;
        for p in &pending {
            let content_hash = sha256_hex(p.canonical().as_bytes());
            let hash = link_hash(&prev, &content_hash);
            let signature = hex(&self.key.sign(hash.as_bytes()).to_bytes());
            storage.insert_receipt(
                p.source(),
                p.source_id(),
                &p.timestamp().to_rfc3339(),
                p.action(),
                p.provider(),
                p.model(),
                p.detail().as_deref(),
                &content_hash,
                &prev,
                &hash,
                &signature,
            )?;
            prev = hash;
            sealed += 1;
        }
        Ok(SealReport { sealed })
    }

    /// Re-walk the chain: check each hash link, re-derive each `content_hash`
    /// from the live source row, and verify each Ed25519 signature.
    pub fn verify(&self, storage: &Storage) -> Result<VerifyReport> {
        let receipts = storage.all_receipts()?;
        let verifying = self.key.verifying_key();
        let mut prev = GENESIS_HASH.to_string();

        for r in &receipts {
            // 1. Chain link: this receipt must point at the running prev hash.
            if r.prev_hash != prev {
                return Ok(VerifyReport::tampered(
                    r,
                    "broken chain link — a receipt was inserted, deleted, or reordered",
                    receipts.len(),
                ));
            }
            // 2. Source row integrity: re-derive content_hash from the live row.
            match self.recompute_content_hash(storage, r)? {
                Some(expected) if expected != r.content_hash => {
                    return Ok(VerifyReport::tampered(
                        r,
                        "source row was modified after sealing",
                        receipts.len(),
                    ));
                }
                None => {
                    return Ok(VerifyReport::tampered(
                        r,
                        "source row is missing (deleted after sealing)",
                        receipts.len(),
                    ));
                }
                _ => {}
            }
            // 3. Hash integrity: hash must equal SHA-256(prev ‖ content_hash).
            let expect_hash = link_hash(&prev, &r.content_hash);
            if expect_hash != r.hash {
                return Ok(VerifyReport::tampered(
                    r,
                    "receipt hash does not match its contents",
                    receipts.len(),
                ));
            }
            // 4. Signature: Ed25519 over the hash must verify under our key.
            let ok = decode_hex(&r.signature)
                .and_then(|b| Signature::from_slice(&b).ok())
                .map(|sig| verifying.verify_strict(r.hash.as_bytes(), &sig).is_ok())
                .unwrap_or(false);
            if !ok {
                return Ok(VerifyReport::tampered(
                    r,
                    "signature does not verify (forged or wrong key)",
                    receipts.len(),
                ));
            }
            prev = r.hash.clone();
        }
        Ok(VerifyReport::Intact {
            count: receipts.len(),
        })
    }

    /// Re-derive a receipt's `content_hash` from the live source row, or `None`
    /// if that row no longer exists.
    fn recompute_content_hash(&self, storage: &Storage, r: &ReceiptRow) -> Result<Option<String>> {
        let canonical = match r.source.as_str() {
            "request" => storage
                .get_request(r.source_id)?
                .map(|row| canonical_request(&row)),
            "security_event" => storage
                .get_security_event(r.source_id)?
                .map(|row| canonical_security_event(&row)),
            _ => None,
        };
        Ok(canonical.map(|c| sha256_hex(c.as_bytes())))
    }
}

/// Outcome of a `seal` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealReport {
    pub sealed: u64,
}

/// Outcome of a `verify` run.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyReport {
    /// The whole chain checks out. `count` receipts verified.
    Intact { count: usize },
    /// Verification failed at the receipt with sequence `seq`.
    Tampered {
        seq: i64,
        reason: String,
        checked: usize,
    },
}

impl VerifyReport {
    fn tampered(r: &ReceiptRow, reason: &str, checked: usize) -> Self {
        VerifyReport::Tampered {
            seq: r.seq,
            reason: reason.to_string(),
            checked,
        }
    }
}

/// One source row waiting to be sealed.
enum Pending {
    Request(RequestRecord),
    Security(SecurityEvent),
}

impl Pending {
    fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Pending::Request(r) => r.timestamp,
            Pending::Security(e) => e.timestamp,
        }
    }
    fn source(&self) -> &'static str {
        match self {
            Pending::Request(_) => "request",
            Pending::Security(_) => "security_event",
        }
    }
    fn source_id(&self) -> i64 {
        match self {
            Pending::Request(r) => r.id.unwrap_or(0),
            Pending::Security(e) => e.id.unwrap_or(0),
        }
    }
    fn action(&self) -> &'static str {
        match self {
            Pending::Request(r) if r.blocked => "block",
            Pending::Request(_) => "forward",
            Pending::Security(_) => "security",
        }
    }
    fn provider(&self) -> Option<&str> {
        match self {
            Pending::Request(r) => Some(r.provider.as_str()),
            Pending::Security(e) => e.provider.as_deref(),
        }
    }
    fn model(&self) -> Option<&str> {
        match self {
            Pending::Request(r) => Some(r.model.as_str()),
            Pending::Security(e) => e.model.as_deref(),
        }
    }
    fn detail(&self) -> Option<String> {
        match self {
            Pending::Request(r) => r.block_reason.clone(),
            Pending::Security(e) => Some(e.event_type.clone()),
        }
    }
    fn canonical(&self) -> String {
        match self {
            Pending::Request(r) => canonical_request(r),
            Pending::Security(e) => canonical_security_event(e),
        }
    }
}

/// Canonical text of a request row — every field that matters, newline
/// separated. Used for the receipt's `content_hash`; identical at seal and
/// verify time because both read the same stored row.
pub fn canonical_request(r: &RequestRecord) -> String {
    format!(
        "request\nid={}\nts={}\nprovider={}\nmodel={}\nblocked={}\nreason={}\ncost={}\nin={}\ncc={}\ncr={}\nout={}\nstatus={}",
        r.id.unwrap_or(0),
        r.timestamp.to_rfc3339(),
        r.provider,
        r.model,
        r.blocked as u8,
        r.block_reason.as_deref().unwrap_or(""),
        r.cost_usd,
        r.input_tokens,
        r.cache_creation_tokens,
        r.cache_read_tokens,
        r.output_tokens,
        r.http_status.map(|s| s.to_string()).unwrap_or_default(),
    )
}

/// Canonical text of a security-event row.
pub fn canonical_security_event(e: &SecurityEvent) -> String {
    format!(
        "security_event\nid={}\nts={}\ntype={}\ndetails={}\nprovider={}\nmodel={}",
        e.id.unwrap_or(0),
        e.timestamp.to_rfc3339(),
        e.event_type,
        e.details,
        e.provider.as_deref().unwrap_or(""),
        e.model.as_deref().unwrap_or(""),
    )
}

fn link_hash(prev_hash: &str, content_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(content_hash.as_bytes());
    hex(&h.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(unix)]
fn set_key_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_key_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::TokenUsage;
    use crate::storage::{RequestRecord, SecurityEvent, Storage};

    fn usage(input: u64, output: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    }

    fn seed_rows(storage: &Storage) {
        storage
            .insert_request(&RequestRecord::successful(
                "anthropic",
                "claude-opus-4-7",
                &usage(100, 50),
                0.5,
                None,
            ))
            .unwrap();
        storage
            .insert_security_event(
                &SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
                    .with_provider("anthropic", "claude-opus-4-7"),
            )
            .unwrap();
        storage
            .insert_request(&RequestRecord::blocked(
                "openai",
                "gpt-5.5",
                "budget_exceeded",
                None,
            ))
            .unwrap();
    }

    #[test]
    fn seal_then_verify_is_intact_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open_in_memory().unwrap();
        seed_rows(&storage);
        let chain = AuditChain::open(&dir.path().join("k.key")).unwrap();

        assert_eq!(chain.seal(&storage).unwrap().sealed, 3);
        assert_eq!(
            chain.verify(&storage).unwrap(),
            VerifyReport::Intact { count: 3 }
        );
        // A second seal finds nothing new; verify still passes.
        assert_eq!(chain.seal(&storage).unwrap().sealed, 0);
        assert_eq!(
            chain.verify(&storage).unwrap(),
            VerifyReport::Intact { count: 3 }
        );
    }

    #[test]
    fn unsealed_rows_added_after_seal_do_not_break_verify() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open_in_memory().unwrap();
        storage
            .insert_request(&RequestRecord::successful(
                "anthropic",
                "claude",
                &usage(10, 5),
                0.1,
                None,
            ))
            .unwrap();
        let chain = AuditChain::open(&dir.path().join("k.key")).unwrap();
        chain.seal(&storage).unwrap();

        // A new action arrives but has not been sealed.
        storage
            .insert_request(&RequestRecord::successful(
                "openai",
                "gpt",
                &usage(10, 5),
                0.2,
                None,
            ))
            .unwrap();
        assert_eq!(
            chain.verify(&storage).unwrap(),
            VerifyReport::Intact { count: 1 }
        );
        assert_eq!(chain.seal(&storage).unwrap().sealed, 1);
        assert_eq!(
            chain.verify(&storage).unwrap(),
            VerifyReport::Intact { count: 2 }
        );
    }

    #[test]
    fn modifying_a_sealed_source_row_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open_in_memory().unwrap();
        storage
            .insert_request(&RequestRecord::successful(
                "anthropic",
                "claude",
                &usage(100, 50),
                0.5,
                None,
            ))
            .unwrap();
        let chain = AuditChain::open(&dir.path().join("k.key")).unwrap();
        chain.seal(&storage).unwrap();

        // Tamper with the underlying row.
        storage
            .with_conn(|conn| {
                conn.execute("UPDATE requests SET cost_usd = 999.0 WHERE id = 1", [])?;
                Ok(())
            })
            .unwrap();

        match chain.verify(&storage).unwrap() {
            VerifyReport::Tampered { reason, .. } => {
                assert!(reason.contains("modified"), "unexpected reason: {reason}");
            }
            other => panic!("expected tamper, got {other:?}"),
        }
    }

    #[test]
    fn deleting_a_receipt_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open_in_memory().unwrap();
        for _ in 0..3 {
            storage
                .insert_request(&RequestRecord::successful(
                    "anthropic",
                    "claude",
                    &usage(10, 5),
                    0.1,
                    None,
                ))
                .unwrap();
        }
        let chain = AuditChain::open(&dir.path().join("k.key")).unwrap();
        chain.seal(&storage).unwrap();

        storage
            .with_conn(|conn| {
                conn.execute("DELETE FROM audit_receipts WHERE seq = 2", [])?;
                Ok(())
            })
            .unwrap();

        assert!(matches!(
            chain.verify(&storage).unwrap(),
            VerifyReport::Tampered { .. }
        ));
    }

    #[test]
    fn a_different_key_fails_signature_verification() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open_in_memory().unwrap();
        storage
            .insert_request(&RequestRecord::successful(
                "anthropic",
                "claude",
                &usage(10, 5),
                0.1,
                None,
            ))
            .unwrap();
        AuditChain::open(&dir.path().join("k1.key"))
            .unwrap()
            .seal(&storage)
            .unwrap();

        let other = AuditChain::open(&dir.path().join("k2.key")).unwrap();
        match other.verify(&storage).unwrap() {
            VerifyReport::Tampered { reason, .. } => {
                assert!(reason.contains("signature"), "unexpected reason: {reason}");
            }
            other => panic!("expected signature failure, got {other:?}"),
        }
    }

    #[test]
    fn aibom_is_cyclonedx_shaped() {
        use crate::observe::digest::{Digest, McpToolEntry, ModelEntry, SecurityCount};
        let digest = Digest {
            days: 7,
            turns: 12,
            blocked: 1,
            total_cost_usd: 3.47,
            models: vec![ModelEntry {
                provider: "anthropic".into(),
                model: "claude-opus-4-7".into(),
                requests: 12,
                cost_usd: 3.47,
            }],
            mcp_tools: vec![McpToolEntry {
                server: "fs".into(),
                tool: "read".into(),
                trust_state: "approved".into(),
            }],
            mcp_tool_calls: 4,
            distinct_mcp_tools: vec!["read".into()],
            security_by_type: vec![SecurityCount {
                event_type: "path_blocked".into(),
                count: 1,
            }],
            distinct_targets: vec!["~/.ssh".into()],
        };
        let bom = aibom::build(&digest, "2026-05-28T00:00:00Z", "urn:uuid:test");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");
        assert_eq!(bom["components"][0]["type"], "machine-learning-model");
        assert_eq!(bom["components"][0]["name"], "claude-opus-4-7");
        assert_eq!(bom["services"][0]["name"], "fs");
    }

    #[test]
    fn sarif_has_rules_and_results() {
        let events = vec![
            SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
                .with_provider("anthropic", "claude"),
            SecurityEvent::new("secret_detected", "sk-REDACTED"),
        ];
        let log = sarif::build(&events);
        assert_eq!(log["version"], "2.1.0");
        assert_eq!(log["runs"][0]["tool"]["driver"]["name"], "burnwall");
        assert_eq!(
            log["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let results = log["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
    }
}
