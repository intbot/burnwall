//! SPDX 3.0 AI-profile bill-of-materials export (v0.9).
//!
//! Renders the same [`Digest`] that powers `burnwall digest` / the CycloneDX
//! AIBOM as an SPDX 3.0 document using the AI profile: each model seen becomes
//! an `ai_AIPackage` element, each MCP server a `software_Package`, the session
//! a root `software_Sbom`, and the security checks that fired ride as
//! annotations. Relationships tie the models + MCP packages to the session SBOM.
//! Metadata only — no prompt content (the underlying [`Digest`] never holds any).
//!
//! SPDX 3.0 is JSON-LD shaped: a `@context`, a `spdxVersion` of `"SPDX-3.0"`,
//! a `creationInfo`, and a flat `@graph` of typed elements joined by
//! relationships. We mirror `aibom.rs`'s deterministic builder (timestamp +
//! serial passed in) so the output is stable in tests.

use serde_json::{Value, json};

use crate::audit::compliance;
use crate::observe::digest::Digest;

/// SPDX 3.0 spec version string.
const SPDX_VERSION: &str = "SPDX-3.0";

/// Build an SPDX 3.0 (AI profile) document from a digest. `created` is an
/// RFC 3339 timestamp and `serial` a stable namespace/serial (e.g.
/// `urn:uuid:...`) — both passed in so the output is deterministic in tests.
pub fn build(digest: &Digest, created: &str, serial: &str) -> Value {
    let creation_info = json!({
        "@id": "_:creationinfo",
        "type": "CreationInfo",
        "specVersion": SPDX_VERSION,
        "created": created,
        "createdBy": [{
            "type": "Tool",
            "spdxId": "spdx:tool-burnwall",
            "name": "burnwall",
            "suppliedBy": {"type": "Organization", "name": "burnwall"},
            "release": {"version": env!("CARGO_PKG_VERSION")},
        }],
    });

    // Root SBOM element representing the AI-agent session window.
    let session_id = "spdx:ai-agent-session";
    let session = json!({
        "type": "software_Sbom",
        "spdxId": session_id,
        "creationInfo": "_:creationinfo",
        "name": "ai-agent-session",
        "software_sbomType": ["analyzed"],
        "rootElement": [session_id],
    });

    let mut graph: Vec<Value> = vec![creation_info, session];
    let mut relationships: Vec<Value> = Vec::new();

    // Each model → an SPDX 3.0 AI-profile package (`ai_AIPackage`).
    for (i, m) in digest.models.iter().enumerate() {
        let id = format!("spdx:model-{i}");
        graph.push(json!({
            "type": "ai_AIPackage",
            "spdxId": id,
            "creationInfo": "_:creationinfo",
            "name": m.model,
            "suppliedBy": {"type": "Organization", "name": m.provider},
            "ai_typeOfModel": ["large language model"],
            "software_primaryPurpose": "other",
            "annotation": [
                spdx_metric(&id, "burnwall:requests", &m.requests.to_string()),
                spdx_metric(&id, "burnwall:cost_usd", &format!("{:.6}", m.cost_usd)),
            ],
        }));
        relationships.push(rel(
            &format!("spdx:rel-model-{i}"),
            session_id,
            "CONTAINS",
            &id,
        ));
    }

    // Each MCP server → a software package with its advertised tools/trust as
    // annotations; related to the session as a runtime dependency.
    let mut by_server: std::collections::BTreeMap<
        &str,
        Vec<&crate::observe::digest::McpToolEntry>,
    > = std::collections::BTreeMap::new();
    for t in &digest.mcp_tools {
        by_server.entry(t.server.as_str()).or_default().push(t);
    }
    for (i, (server, tools)) in by_server.iter().enumerate() {
        let id = format!("spdx:mcp-{i}");
        let annotations: Vec<Value> = tools
            .iter()
            .map(|t| spdx_metric(&id, &format!("burnwall:tool:{}", t.tool), &t.trust_state))
            .collect();
        graph.push(json!({
            "type": "software_Package",
            "spdxId": id,
            "creationInfo": "_:creationinfo",
            "name": server,
            "software_primaryPurpose": "application",
            "annotation": annotations,
        }));
        relationships.push(rel(
            &format!("spdx:rel-mcp-{i}"),
            session_id,
            "DEPENDS_ON",
            &id,
        ));
    }

    // Security checks that fired → annotations on the session, each labelled
    // with the controls it evidences (honest: this records the count, the
    // crosswalk is the cross-reference, not a claim of certification).
    for (i, s) in digest.security_by_type.iter().enumerate() {
        let tags: Vec<String> = compliance::mappings_for(&s.event_type)
            .iter()
            .map(|c| format!("{}:{}", c.framework.name(), c.control_id))
            .collect();
        graph.push(json!({
            "type": "Annotation",
            "spdxId": format!("spdx:security-{i}"),
            "creationInfo": "_:creationinfo",
            "annotationType": "OTHER",
            "subject": session_id,
            "statement": format!(
                "burnwall:security:{} fired {} time(s); evidences: {}",
                s.event_type,
                s.count,
                tags.join(", "),
            ),
        }));
    }

    graph.extend(relationships);

    json!({
        "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "spdxVersion": SPDX_VERSION,
        "namespace": serial,
        "@graph": graph,
    })
}

/// A small measurement annotation on an SPDX element.
fn spdx_metric(subject: &str, key: &str, value: &str) -> Value {
    json!({
        "type": "Annotation",
        "creationInfo": "_:creationinfo",
        "annotationType": "OTHER",
        "subject": subject,
        "statement": format!("{key}={value}"),
    })
}

/// An SPDX 3.0 relationship element.
fn rel(spdx_id: &str, from: &str, rel_type: &str, to: &str) -> Value {
    json!({
        "type": "Relationship",
        "spdxId": spdx_id,
        "creationInfo": "_:creationinfo",
        "from": from,
        "relationshipType": rel_type,
        "to": [to],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::digest::{McpToolEntry, ModelEntry, SecurityCount};

    fn sample_digest() -> Digest {
        Digest {
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
        }
    }

    #[test]
    fn spdx_has_top_level_shape() {
        let doc = build(&sample_digest(), "2026-05-28T00:00:00Z", "urn:uuid:test");
        assert_eq!(doc["spdxVersion"], "SPDX-3.0");
        assert!(doc["@context"].is_string());
        assert_eq!(doc["namespace"], "urn:uuid:test");
        assert!(doc["@graph"].is_array(), "SPDX 3.0 is a graph of elements");
    }

    #[test]
    fn spdx_graph_carries_ai_package_sbom_and_relationships() {
        let doc = build(&sample_digest(), "2026-05-28T00:00:00Z", "urn:uuid:test");
        let graph = doc["@graph"].as_array().unwrap();
        let types: Vec<&str> = graph.iter().filter_map(|e| e["type"].as_str()).collect();
        assert!(types.contains(&"ai_AIPackage"), "an AI package per model");
        assert!(types.contains(&"software_Sbom"), "a root SBOM element");
        assert!(
            types.contains(&"Relationship"),
            "relationships join models to the session"
        );
        // The model element names the model and its supplier (provider).
        let model = graph.iter().find(|e| e["type"] == "ai_AIPackage").unwrap();
        assert_eq!(model["name"], "claude-opus-4-7");
        assert_eq!(model["suppliedBy"]["name"], "anthropic");
    }

    #[test]
    fn spdx_mcp_server_becomes_a_package() {
        let doc = build(&sample_digest(), "2026-05-28T00:00:00Z", "urn:uuid:test");
        let graph = doc["@graph"].as_array().unwrap();
        let pkg = graph
            .iter()
            .find(|e| e["type"] == "software_Package" && e["name"] == "fs");
        assert!(pkg.is_some(), "MCP server fs should be a software package");
    }

    #[test]
    fn spdx_security_annotation_carries_control_ids() {
        let doc = build(&sample_digest(), "2026-05-28T00:00:00Z", "urn:uuid:test");
        let graph = doc["@graph"].as_array().unwrap();
        let ann = graph
            .iter()
            .find(|e| {
                e["type"] == "Annotation"
                    && e["statement"]
                        .as_str()
                        .map(|s| s.contains("path_blocked"))
                        .unwrap_or(false)
            })
            .expect("a security annotation for path_blocked");
        let stmt = ann["statement"].as_str().unwrap();
        assert!(
            stmt.contains("EU AI Act Art. 12"),
            "the security annotation should cite the record-keeping control: {stmt}"
        );
    }

    #[test]
    fn spdx_empty_digest_is_still_valid_shape() {
        let empty = Digest {
            days: 7,
            turns: 0,
            blocked: 0,
            total_cost_usd: 0.0,
            models: vec![],
            mcp_tools: vec![],
            mcp_tool_calls: 0,
            distinct_mcp_tools: vec![],
            security_by_type: vec![],
            distinct_targets: vec![],
        };
        let doc = build(&empty, "2026-05-28T00:00:00Z", "urn:uuid:test");
        assert_eq!(doc["spdxVersion"], "SPDX-3.0");
        // Still has creationInfo + the root SBOM element.
        let graph = doc["@graph"].as_array().unwrap();
        assert!(graph.iter().any(|e| e["type"] == "software_Sbom"));
    }
}
