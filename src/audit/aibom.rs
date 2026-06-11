//! CycloneDX AI Bill of Materials export (v0.8).
//!
//! Renders the same [`Digest`] that powers `burnwall digest` as a schema-valid
//! CycloneDX 1.6 JSON BOM: each model is a `machine-learning-model` component,
//! each MCP server a `service`, and window-level totals ride in metadata
//! properties. Metadata only — no prompt content.

use serde_json::{Value, json};

use crate::observe::digest::Digest;

/// Build a CycloneDX 1.6 BOM document from a digest. `generated_at` is an
/// RFC 3339 timestamp and `serial` a `urn:uuid:...` serial number (both passed
/// in so the output is deterministic in tests).
pub fn build(digest: &Digest, generated_at: &str, serial: &str) -> Value {
    let components: Vec<Value> = digest
        .models
        .iter()
        .map(|m| {
            json!({
                "type": "machine-learning-model",
                "bom-ref": format!("model:{}/{}", m.provider, m.model),
                "name": m.model,
                "publisher": m.provider,
                "properties": [
                    {"name": "burnwall:requests", "value": m.requests.to_string()},
                    {"name": "burnwall:cost_usd", "value": format!("{:.6}", m.cost_usd)},
                ],
            })
        })
        .collect();

    // MCP servers → services, each carrying its tools + approval state.
    let mut by_server: std::collections::BTreeMap<
        &str,
        Vec<&crate::observe::digest::McpToolEntry>,
    > = std::collections::BTreeMap::new();
    for t in &digest.mcp_tools {
        by_server.entry(t.server.as_str()).or_default().push(t);
    }
    let services: Vec<Value> = by_server
        .iter()
        .map(|(server, tools)| {
            let props: Vec<Value> = tools
                .iter()
                .map(|t| json!({"name": format!("burnwall:tool:{}", t.tool), "value": t.trust_state}))
                .collect();
            json!({
                "bom-ref": format!("mcp:{}", server),
                "name": server,
                "properties": props,
            })
        })
        .collect();

    let security: Vec<Value> = digest
        .security_by_type
        .iter()
        .map(|s| json!({"name": format!("burnwall:security:{}", s.event_type), "value": s.count.to_string()}))
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {
                "components": [
                    {"type": "application", "name": "burnwall", "version": env!("CARGO_PKG_VERSION")}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "ai-agent-session",
                "name": "ai-agent-session",
            },
            "properties": [
                {"name": "burnwall:window_days", "value": digest.days.to_string()},
                {"name": "burnwall:turns", "value": digest.turns.to_string()},
                {"name": "burnwall:blocked", "value": digest.blocked.to_string()},
                {"name": "burnwall:total_cost_usd", "value": format!("{:.6}", digest.total_cost_usd)},
                {"name": "burnwall:mcp_tool_calls", "value": digest.mcp_tool_calls.to_string()},
            ],
        },
        "components": components,
        "services": services,
        "properties": security,
    })
}
