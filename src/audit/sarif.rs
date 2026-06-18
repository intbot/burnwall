//! SARIF 2.1.0 export of security blocks (v0.8).
//!
//! Renders `security_events` as a SARIF run so blocks can be uploaded to
//! GitHub code scanning (the Security tab) with zero custom integration. Each
//! distinct `event_type` becomes a rule; each event a result at `error` level.
//! Metadata only — `details` may already be redacted by `log_redact_details`.

use serde_json::{Value, json};

use crate::audit::compliance;
use crate::storage::SecurityEvent;

/// Build a SARIF 2.1.0 log document from a list of security events.
pub fn build(events: &[SecurityEvent]) -> Value {
    let mut rule_ids: Vec<String> = events.iter().map(|e| e.event_type.clone()).collect();
    rule_ids.sort();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            // Cross-walk control IDs ride on the rule so a SIEM / GitHub code
            // scanning surfaces "this block evidences EU AI Act Art. 12,
            // ASI-T05, …" without any extra integration. Carried two ways for
            // tool compatibility: `properties.tags` (a flat, widely-rendered
            // string list) and a structured `properties.compliance` array.
            let refs = compliance::mappings_for(id);
            json!({
                "id": id,
                "name": pascal_case(id),
                "shortDescription": {"text": describe(id)},
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "tags": control_tags(&refs),
                    "compliance": compliance_props(&refs),
                },
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
                    "tags": control_tags(&compliance::mappings_for(&e.event_type)),
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

/// SARIF 2.1.0 for **file** findings (`burnwall scan` / CI): same driver,
/// but results carry real file + line locations, and each result's level
/// comes from the finding (`error` for a committed credential, `warning`
/// for invisible-text smuggling) — file mode is advisory, not a block log.
pub fn build_file_findings(findings: &[crate::security::filescan::Finding]) -> Value {
    let mut rule_ids: Vec<&'static str> = findings.iter().map(|f| f.rule).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": pascal_case(id),
                "shortDescription": {"text": describe(id)},
                "defaultConfiguration": {
                    "level": if *id == "secret_in_file" { "error" } else { "warning" },
                },
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule,
                "level": f.level(),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        // SARIF wants forward slashes regardless of host OS.
                        "artifactLocation": {"uri": f.path.replace('\\', "/")},
                        "region": {"startLine": f.line.max(1)},
                    }
                }],
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
        "secret_in_file" => "A credential is committed in an agent config or transcript file.",
        "invisible_text" => {
            "Invisible Unicode characters are hidden inside ASCII text — possible instruction smuggling."
        }
        _ => "A Burnwall security rule fired.",
    }
}

/// Flat `properties.tags` list: the control IDs a block evidences, prefixed
/// with the framework so they read unambiguously in a SARIF viewer
/// (e.g. `"EU AI Act:EU AI Act Art. 12"`, `"OWASP Agentic AI:ASI-T05"`).
fn control_tags(refs: &[compliance::ControlRef]) -> Vec<String> {
    refs.iter()
        .map(|c| format!("{}:{}", c.framework.name(), c.control_id))
        .collect()
}

/// Structured `properties.compliance` array — one object per cross-referenced
/// control, for consumers that want the framework / id / label split out.
fn compliance_props(refs: &[compliance::ControlRef]) -> Vec<Value> {
    refs.iter()
        .map(|c| {
            json!({
                "framework": c.framework.name(),
                "controlId": c.control_id,
                "label": c.short_label,
            })
        })
        .collect()
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
