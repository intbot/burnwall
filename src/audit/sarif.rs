//! SARIF 2.1.0 export of security blocks (v0.8).
//!
//! Renders `security_events` as a SARIF run so blocks can be uploaded to
//! GitHub code scanning (the Security tab) with zero custom integration. Each
//! distinct `event_type` becomes a rule; each event a result at `error` level.
//! Metadata only — `details` may already be redacted by `log_redact_details`.

use serde_json::{Value, json};

use crate::storage::SecurityEvent;

/// Build a SARIF 2.1.0 log document from a list of security events.
pub fn build(events: &[SecurityEvent]) -> Value {
    let mut rule_ids: Vec<String> = events.iter().map(|e| e.event_type.clone()).collect();
    rule_ids.sort();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": pascal_case(id),
                "shortDescription": {"text": describe(id)},
                "defaultConfiguration": {"level": "error"},
            })
        })
        .collect();

    let results: Vec<Value> = events
        .iter()
        .map(|e| {
            json!({
                "ruleId": e.event_type,
                "level": "error",
                "message": {"text": format!("Burnwall blocked a {} attempt: {}", e.event_type, e.details)},
                // GitHub code scanning rejects results without a location
                // (M-M4). Security events have no source file, so emit a
                // synthetic per-event URI; `region` is required alongside it
                // by the upload validator.
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": format!("burnwall://security-events/{}", e.id.unwrap_or(0)),
                        },
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "provider": e.provider,
                    "model": e.model,
                    "timestamp": e.timestamp.to_rfc3339(),
                },
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "burnwall",
                    "informationUri": "https://github.com/intbot/burnwall",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
        }],
    })
}

/// Human-readable one-liner for a known event type.
fn describe(event_type: &str) -> &'static str {
    match event_type {
        "path_blocked" => "Access to a sensitive filesystem path was blocked.",
        "command_blocked" => "Execution of a dangerous command was blocked.",
        "mount_blocked" => "Access to a network/mounted path was blocked.",
        "secret_detected" => "A credential or secret in the payload was blocked.",
        "dlp_blocked" => "Exfiltration-prone data (e.g. card/SSN) was blocked.",
        "mcp_tool_unapproved" => "A call to an unapproved MCP tool was blocked.",
        _ => "A Burnwall security rule fired.",
    }
}

/// `path_blocked` -> `PathBlocked`.
fn pascal_case(id: &str) -> String {
    id.split(['_', '-'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                Some(first) => first.to_uppercase().chain(c).collect::<String>(),
                None => String::new(),
            }
        })
        .collect()
}
