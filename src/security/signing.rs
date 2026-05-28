//! Ed25519 signing for rule packs (v0.9).
//!
//! Lets a publisher sign a rule pack and a consumer verify a remote pack's
//! detached signature against a configured set of trusted publisher keys before
//! installing it. Pure functions — no I/O, no network — so the trust decision
//! is fully unit-testable. `burnwall rules fetch/verify/sign/keygen` wrap these.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// A trusted publisher: a label and its hex-encoded Ed25519 verifying key.
#[derive(Debug, Clone)]
pub struct Publisher {
    pub name: String,
    pub key_hex: String,
}

/// Generate a fresh signing key (publishers keep the seed private).
pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Load a signing key from a 32-byte seed.
pub fn signing_key_from_seed(seed: &[u8]) -> Option<SigningKey> {
    let arr: [u8; 32] = seed.try_into().ok()?;
    Some(SigningKey::from_bytes(&arr))
}

/// Hex-encode the public (verifying) key of a signing key.
pub fn public_key_hex(key: &SigningKey) -> String {
    hex(key.verifying_key().as_bytes())
}

/// Sign `bytes`, returning the detached signature as hex.
pub fn sign_hex(key: &SigningKey, bytes: &[u8]) -> String {
    use ed25519_dalek::Signer;
    hex(&key.sign(bytes).to_bytes())
}

/// Verify a detached hex signature over `bytes` against a list of trusted
/// publishers. Returns the name of the first publisher whose key verifies, or
/// `None` if the signature is malformed or no trusted key matches. An empty
/// `publishers` list always returns `None` — nothing is trusted by default.
pub fn verify_hex(bytes: &[u8], sig_hex: &str, publishers: &[Publisher]) -> Option<String> {
    let sig_bytes = decode_hex(sig_hex.trim())?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;
    for publisher in publishers {
        if let Some(vk) = verifying_key_from_hex(&publisher.key_hex) {
            if vk.verify_strict(bytes, &signature).is_ok() {
                return Some(publisher.name.clone());
            }
        }
    }
    None
}

fn verifying_key_from_hex(key_hex: &str) -> Option<VerifyingKey> {
    let bytes = decode_hex(key_hex.trim())?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pubs(name: &str, key: &SigningKey) -> Vec<Publisher> {
        vec![Publisher {
            name: name.to_string(),
            key_hex: public_key_hex(key),
        }]
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = generate();
        let body = b"[pack]\nid = \"django\"\n";
        let sig = sign_hex(&key, body);
        assert_eq!(
            verify_hex(body, &sig, &pubs("acme", &key)).as_deref(),
            Some("acme")
        );
    }

    #[test]
    fn tampered_body_fails() {
        let key = generate();
        let sig = sign_hex(&key, b"original");
        assert_eq!(verify_hex(b"tampered", &sig, &pubs("acme", &key)), None);
    }

    #[test]
    fn untrusted_key_fails() {
        let signer = generate();
        let other = generate();
        let body = b"pack-bytes";
        let sig = sign_hex(&signer, body);
        // Only `other` is trusted, but `signer` signed it.
        assert_eq!(verify_hex(body, &sig, &pubs("other", &other)), None);
    }

    #[test]
    fn empty_publishers_trusts_nothing() {
        let key = generate();
        let body = b"pack-bytes";
        let sig = sign_hex(&key, body);
        assert_eq!(verify_hex(body, &sig, &[]), None);
    }

    #[test]
    fn malformed_signature_fails() {
        let key = generate();
        assert_eq!(verify_hex(b"x", "not-hex!!", &pubs("acme", &key)), None);
        assert_eq!(verify_hex(b"x", "abcd", &pubs("acme", &key)), None);
    }

    #[test]
    fn seed_roundtrip_signs_identically() {
        let key = generate();
        let seed = key.to_bytes();
        let restored = signing_key_from_seed(&seed).unwrap();
        let body = b"pack";
        assert_eq!(sign_hex(&key, body), sign_hex(&restored, body));
    }
}
