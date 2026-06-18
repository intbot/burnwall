//! Guard test for the TLS / no-MITM promises in SECURITY.md.
//!
//! A proxy that sits in your API traffic must never weaken TLS or inject a root
//! CA. Rather than try to assert reqwest's internal config at runtime (it's
//! opaque), we assert the *invariant at the source level*: the forbidden
//! patterns never appear anywhere in `src/`. If someone later adds one, this
//! test fails and forces a deliberate review.

use std::fs;
use std::path::Path;

/// Patterns that would weaken TLS or turn Burnwall into a MITM. None may appear
/// in shipped source.
const FORBIDDEN: &[&str] = &[
    "danger_accept_invalid_certs",
    "danger_accept_invalid_hostnames",
    "add_root_certificate",
    "use_preconfigured_tls",
    // native-tls's dangerous escape hatch (we use rustls and keep validation on)
    "danger_configure",
];

fn scan_dir(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, hits);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // Skip this guard test itself (it names the patterns on purpose).
            if path.file_name().and_then(|n| n.to_str()) == Some("tls_integrity_test.rs") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&path) {
                for pat in FORBIDDEN {
                    if content.contains(pat) {
                        hits.push(format!("{}: {}", path.display(), pat));
                    }
                }
            }
        }
    }
}

#[test]
fn no_tls_weakening_or_ca_injection_in_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    scan_dir(&root, &mut hits);
    assert!(
        hits.is_empty(),
        "Forbidden TLS-weakening / CA-injection pattern(s) found in src — this \
         breaks the SECURITY.md no-MITM promise:\n{}",
        hits.join("\n")
    );
}
