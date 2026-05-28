//! Agent Bill of Materials — a window-scoped digest of what the agent did
//! (v0.7). Assembled entirely from existing metadata in storage: which models
//! ran and what they cost, which MCP servers/tools were touched, how many tool
//! calls were made, and what security checks fired. No prompt content — the
//! underlying rows never hold any.
//!
//! Kept as a structured value so both `burnwall digest` (v0.7) and the
//! CycloneDX AIBOM export (v0.8) render from the same source of truth.

use crate::storage::{Result, Storage};

/// One model's footprint over the window.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelEntry {
    pub provider: String,
    pub model: String,
    pub requests: i64,
    pub cost_usd: f64,
}

/// One MCP tool the agent's servers advertised, with its approval state.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolEntry {
    pub server: String,
    pub tool: String,
    pub trust_state: String,
}

/// A count of security events of one type.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityCount {
    pub event_type: String,
    pub count: u64,
}

/// The assembled bill of materials.
#[derive(Debug, Clone, PartialEq)]
pub struct Digest {
    pub days: i64,
    /// Total forwarded + blocked requests in the window ("turns").
    pub turns: i64,
    pub blocked: i64,
    pub total_cost_usd: f64,
    pub models: Vec<ModelEntry>,
    pub mcp_tools: Vec<McpToolEntry>,
    pub mcp_tool_calls: i64,
    pub distinct_mcp_tools: Vec<String>,
    pub security_by_type: Vec<SecurityCount>,
    /// Distinct security-event detail strings (e.g. blocked paths). May read
    /// `<redacted>` when `security.log_redact_details` is on.
    pub distinct_targets: Vec<String>,
}

impl Digest {
    /// Assemble the digest over the last `days` local days (clamped to ≥1).
    pub fn build(storage: &Storage, days: i64) -> Result<Digest> {
        let days = days.max(1);

        // Models + cost (forwarded, non-blocked rows).
        let breakdown = storage.breakdown_since_days(days)?;
        // `+ 0.0` coerces the IEEE additive identity `-0.0` (what an empty f64
        // sum yields) to `+0.0`, so an empty window prints "$0.00" not "$-0.00".
        let total_cost_usd: f64 = breakdown.iter().map(|b| b.cost).sum::<f64>() + 0.0;
        let models: Vec<ModelEntry> = breakdown
            .iter()
            .map(|b| ModelEntry {
                provider: b.provider.clone(),
                model: b.model.clone(),
                requests: b.requests,
                cost_usd: b.cost,
            })
            .collect();

        // Turns + blocked count from per-day totals (includes blocked rows).
        let daily = storage.daily_totals(days)?;
        let turns: i64 = daily.iter().map(|d| d.total_requests).sum();
        let blocked: i64 = daily.iter().map(|d| d.total_blocked).sum();

        // MCP tools advertised + tool-call activity.
        let mcp_tools: Vec<McpToolEntry> = storage
            .mcp_tools_all()?
            .into_iter()
            .map(|r| McpToolEntry {
                server: r.server,
                tool: r.tool_name,
                trust_state: r.trust_state,
            })
            .collect();
        let mcp_events = storage.mcp_events_since_days(days)?;
        let mcp_tool_calls = mcp_events.len() as i64;
        let mut distinct_mcp_tools: Vec<String> =
            mcp_events.iter().map(|e| e.tool_name.clone()).collect();
        distinct_mcp_tools.sort();
        distinct_mcp_tools.dedup();

        // Security events grouped by type + distinct targets.
        let events = storage.security_events_since_days(days)?;
        let mut by_type: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        let mut targets: Vec<String> = Vec::new();
        for e in &events {
            *by_type.entry(e.event_type.clone()).or_insert(0) += 1;
            targets.push(e.details.clone());
        }
        targets.sort();
        targets.dedup();
        let security_by_type: Vec<SecurityCount> = by_type
            .into_iter()
            .map(|(event_type, count)| SecurityCount { event_type, count })
            .collect();

        Ok(Digest {
            days,
            turns,
            blocked,
            total_cost_usd,
            models,
            mcp_tools,
            mcp_tool_calls,
            distinct_mcp_tools,
            security_by_type,
            distinct_targets: targets,
        })
    }
}
