//! JSON scanner.
//!
//! Walks every string leaf of a `serde_json::Value` (no schema knowledge —
//! per ARCHITECTURE.md "any string value containing a denied path or command
//! triggers a block") and applies the matching primitives from
//! [`super::rules`] and [`super::secrets`]. Returns the **first** violation
//! found and stops scanning — there's no value in collecting all violations,
//! the proxy blocks on any one.

use serde_json::Value;

use super::rules::{self, Ruleset};
use super::secrets;
use super::{Violation, ViolationKind};

pub fn scan(value: &Value, rules: &Ruleset) -> Option<Violation> {
    match value {
        Value::Object(map) => {
            for (_, v) in map {
                if let Some(violation) = scan(v, rules) {
                    return Some(violation);
                }
            }
            None
        }
        Value::Array(arr) => {
            for v in arr {
                if let Some(violation) = scan(v, rules) {
                    return Some(violation);
                }
            }
            None
        }
        Value::String(s) => check_string(s, rules),
        _ => None,
    }
}

fn check_string(s: &str, rules: &Ruleset) -> Option<Violation> {
    // Order: paths → commands → mounts → secrets. Paths are the highest-
    // signal category; secrets last so a path-blocked SSH key dump doesn't
    // also accidentally trip the private-key regex.
    //
    // A leaf matching a project `allow_paths` exception skips the path-deny
    // checks entirely — but command, mount, and secret checks below still
    // run, so `allow_paths` can never green-light a dangerous command.
    let path_allowed = rules
        .allow_paths
        .iter()
        .any(|allow| rules::path_matches(s, allow));
    if !path_allowed {
        for rule in &rules.deny_paths {
            if rules::path_matches(s, rule) {
                return Some(Violation {
                    kind: ViolationKind::Path,
                    matched: rule.clone(),
                });
            }
        }
    }
    for rule in &rules.deny_commands {
        if rules::command_matches(s, rule) {
            return Some(Violation {
                kind: ViolationKind::Command,
                matched: rule.clone(),
            });
        }
    }
    if rules.block_network_mounts && rules::mount_matches(s) {
        return Some(Violation {
            kind: ViolationKind::Mount,
            matched: extract_mount_prefix(s).to_string(),
        });
    }
    if rules.detect_secrets {
        if let Some(name) = secrets::first_match(s) {
            return Some(Violation {
                kind: ViolationKind::Secret,
                matched: name.to_string(),
            });
        }
    }
    None
}

/// Best-effort label for which mount needle hit, for the violation message.
fn extract_mount_prefix(s: &str) -> &'static str {
    for needle in rules::NETWORK_MOUNT_NEEDLES {
        if s.contains(needle) {
            return needle;
        }
    }
    "network mount"
}
