//! Insert/query operations on [`Storage`].
//!
//! All queries are parameterized — no string interpolation of user data.
//! The `chrono` feature on rusqlite handles `DateTime<Utc>` ↔ TEXT in RFC
//! 3339 form. Timestamps are *stored* in UTC, but every date query uses
//! `DATE(timestamp, 'localtime')` so that "a date" means the user's local
//! calendar day — `status` and `history` should not show a UTC-shifted
//! "today". Callers therefore pass local `YYYY-MM-DD` strings (the CLI
//! derives them from `chrono::Local`).

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::{
    models::{
        DailyTotal, McpEvent, McpToolRow, ModelBreakdown, ReceiptRow, RequestRecord, SecurityEvent,
    },
    Result, Storage,
};

/// Outcome of recording a tool advertised by an MCP server, relative to what
/// we last fingerprinted for that (server, tool) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpToolObservation {
    /// First time this tool has been seen on this server.
    New,
    /// Seen before, definition unchanged.
    Unchanged,
    /// Seen before, but the definition changed since — a possible rug pull.
    Changed,
}

impl Storage {
    /// Insert a request log row. Returns the new rowid.
    pub fn insert_request(&self, r: &RequestRecord) -> Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO requests (
                    timestamp, provider, model,
                    input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                    cost_usd, blocked, block_reason, session_id, request_hash,
                    latency_ms, http_status
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    r.timestamp,
                    r.provider,
                    r.model,
                    r.input_tokens as i64,
                    r.cache_creation_tokens as i64,
                    r.cache_read_tokens as i64,
                    r.output_tokens as i64,
                    r.cost_usd,
                    r.blocked as i64,
                    r.block_reason,
                    r.session_id,
                    r.request_hash,
                    r.latency_ms,
                    r.http_status,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a security event row. Returns the new rowid.
    pub fn insert_security_event(&self, e: &SecurityEvent) -> Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO security_events (timestamp, event_type, details, provider, model)
                 VALUES (?1,?2,?3,?4,?5)",
                params![e.timestamp, e.event_type, e.details, e.provider, e.model],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Record a tool advertised by an MCP server and report how it compares
    /// to the last fingerprint we stored for it. A `New` tool is inserted; a
    /// `Changed` one has its fingerprint + `last_seen` updated so the next
    /// change is measured from here; `Unchanged` just refreshes `last_seen`.
    pub fn observe_mcp_tool(
        &self,
        server: &str,
        tool_name: &str,
        fingerprint: &str,
    ) -> Result<McpToolObservation> {
        self.with_conn(|conn| {
            let existing: Option<String> = conn
                .query_row(
                    "SELECT fingerprint FROM mcp_tools WHERE server = ?1 AND tool_name = ?2",
                    params![server, tool_name],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                None => {
                    conn.execute(
                        "INSERT INTO mcp_tools (server, tool_name, fingerprint) VALUES (?1,?2,?3)",
                        params![server, tool_name, fingerprint],
                    )?;
                    Ok(McpToolObservation::New)
                }
                Some(prev) if prev == fingerprint => {
                    conn.execute(
                        "UPDATE mcp_tools SET last_seen = datetime('now')
                         WHERE server = ?1 AND tool_name = ?2",
                        params![server, tool_name],
                    )?;
                    Ok(McpToolObservation::Unchanged)
                }
                Some(_) => {
                    // A silent definition change resets approval to 'pending'
                    // (v0.6.5): a tool that mutated must be re-approved before
                    // an enforce-mode `tools/call` to it forwards again.
                    conn.execute(
                        "UPDATE mcp_tools
                         SET fingerprint = ?1, trust_state = 'pending', last_seen = datetime('now')
                         WHERE server = ?2 AND tool_name = ?3",
                        params![fingerprint, server, tool_name],
                    )?;
                    Ok(McpToolObservation::Changed)
                }
            }
        })
    }

    /// The approval state of an MCP tool, or `None` if it has never been seen
    /// in a `tools/list`. Drives enforce-mode gating of `tools/call`.
    pub fn mcp_tool_trust_state(&self, server: &str, tool: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let state = conn
                .query_row(
                    "SELECT trust_state FROM mcp_tools WHERE server = ?1 AND tool_name = ?2",
                    params![server, tool],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(state)
        })
    }

    /// Approve one MCP tool. Returns `true` if a matching (seen) tool existed.
    pub fn approve_mcp_tool(&self, server: &str, tool: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE mcp_tools SET trust_state = 'approved'
                 WHERE server = ?1 AND tool_name = ?2",
                params![server, tool],
            )?;
            Ok(n > 0)
        })
    }

    /// Approve every tool currently seen for a server. Returns the count.
    pub fn approve_mcp_server(&self, server: &str) -> Result<usize> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE mcp_tools SET trust_state = 'approved' WHERE server = ?1",
                params![server],
            )?;
            Ok(n)
        })
    }

    /// Revoke approval for one tool (back to 'pending'). `true` if it existed.
    pub fn revoke_mcp_tool(&self, server: &str, tool: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE mcp_tools SET trust_state = 'pending'
                 WHERE server = ?1 AND tool_name = ?2",
                params![server, tool],
            )?;
            Ok(n > 0)
        })
    }

    /// Revoke approval for every tool of a server. Returns the count.
    pub fn revoke_mcp_server(&self, server: &str) -> Result<usize> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE mcp_tools SET trust_state = 'pending' WHERE server = ?1",
                params![server],
            )?;
            Ok(n)
        })
    }

    /// All advertised MCP tools and their trust state, ordered by server then
    /// tool. Drives `burnwall mcp list`.
    pub fn mcp_tools_all(&self) -> Result<Vec<McpToolRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT server, tool_name, trust_state, last_seen
                 FROM mcp_tools
                 ORDER BY server ASC, tool_name ASC",
            )?;
            let rows: rusqlite::Result<Vec<McpToolRow>> = stmt
                .query_map([], |row| {
                    Ok(McpToolRow {
                        server: row.get(0)?,
                        tool_name: row.get(1)?,
                        trust_state: row.get(2)?,
                        last_seen: row.get::<_, DateTime<Utc>>(3)?,
                    })
                })?
                .collect();
            Ok(rows?)
        })
    }

    /// Record (or update) a Trust-On-First-Use approval for a third-party rule
    /// pack: pins its content hash so a later edit re-flags it (invariant I6).
    pub fn approve_rule_pack(&self, pack_id: &str, source_path: &str, sha256: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO rule_trust (pack_id, source_path, sha256, approved_at)
                 VALUES (?1, ?2, ?3, datetime('now'))
                 ON CONFLICT(pack_id) DO UPDATE SET
                     source_path = excluded.source_path,
                     sha256 = excluded.sha256,
                     approved_at = datetime('now')",
                params![pack_id, source_path, sha256],
            )?;
            Ok(())
        })
    }

    /// The pinned (approved) content hash for a third-party rule pack, if any.
    pub fn rule_pack_approved_hash(&self, pack_id: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let hash = conn
                .query_row(
                    "SELECT sha256 FROM rule_trust WHERE pack_id = ?1",
                    params![pack_id],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(hash)
        })
    }

    /// Remove a third-party rule pack's approval. Returns `true` if a row was
    /// deleted.
    pub fn revoke_rule_pack(&self, pack_id: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM rule_trust WHERE pack_id = ?1",
                params![pack_id],
            )?;
            Ok(n > 0)
        })
    }

    /// Fetch a single request by rowid. Returns `Ok(None)` if not found.
    pub fn get_request(&self, id: i64) -> Result<Option<RequestRecord>> {
        self.with_conn(|conn| {
            let r = conn
                .query_row(
                    "SELECT id, timestamp, provider, model,
                            input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                            cost_usd, blocked, block_reason, session_id, request_hash,
                            latency_ms, http_status
                     FROM requests WHERE id = ?1",
                    params![id],
                    row_to_request,
                )
                .optional()?;
            Ok(r)
        })
    }

    /// Sum of `cost_usd` for the given local date (`YYYY-MM-DD`). Powers the
    /// budget check; `date` is matched against each row's timestamp in local
    /// time, so callers pass a `chrono::Local`-derived date.
    pub fn total_cost_for_date(&self, date: &str) -> Result<f64> {
        self.with_conn(|conn| {
            let cost: f64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM requests
                 WHERE DATE(timestamp, 'localtime') = ?1",
                params![date],
                |row| row.get(0),
            )?;
            Ok(cost)
        })
    }

    /// The most recent successful (non-blocked) request, if any. Powers the
    /// DB-sourced status ribbon (`burnwall watch` / editor bar): the last
    /// real turn's model, token counts, and cost.
    pub fn most_recent_request(&self) -> Result<Option<RequestRecord>> {
        self.with_conn(|conn| {
            let r = conn
                .query_row(
                    "SELECT id, timestamp, provider, model,
                            input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                            cost_usd, blocked, block_reason, session_id, request_hash,
                            latency_ms, http_status
                     FROM requests WHERE blocked = 0
                     ORDER BY timestamp DESC LIMIT 1",
                    [],
                    row_to_request,
                )
                .optional()?;
            Ok(r)
        })
    }

    /// All requests within the given local date, oldest first.
    pub fn requests_for_date(&self, date: &str) -> Result<Vec<RequestRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, provider, model,
                        input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                        cost_usd, blocked, block_reason, session_id, request_hash,
                        latency_ms, http_status
                 FROM requests
                 WHERE DATE(timestamp, 'localtime') = ?1
                 ORDER BY timestamp ASC",
            )?;
            let rows: rusqlite::Result<Vec<RequestRecord>> =
                stmt.query_map(params![date], row_to_request)?.collect();
            Ok(rows?)
        })
    }

    /// Per-day totals covering the last `days` local days (newest first).
    /// Empty days are omitted. Drives the `burnwall history` table.
    pub fn daily_totals(&self, days: i64) -> Result<Vec<DailyTotal>> {
        self.with_conn(|conn| {
            // `DATE('now', 'localtime', '-N days')` gives the local date N
            // days ago. Bind `-N days` as a parameter, not concatenated.
            let offset = format!("-{} days", days);
            let mut stmt = conn.prepare(
                "SELECT
                    DATE(timestamp, 'localtime')                            AS date,
                    COALESCE(SUM(cost_usd), 0.0)               AS total_cost,
                    COUNT(*)                                   AS total_requests,
                    COALESCE(SUM(blocked), 0)                  AS total_blocked,
                    COALESCE(SUM(cache_read_tokens), 0)        AS total_cache_read,
                    COALESCE(SUM(input_tokens + cache_creation_tokens + cache_read_tokens), 0) AS total_prompt
                 FROM requests
                 WHERE DATE(timestamp, 'localtime') >= DATE('now', 'localtime', ?1)
                 GROUP BY DATE(timestamp, 'localtime')
                 ORDER BY DATE(timestamp, 'localtime') DESC",
            )?;
            let rows: rusqlite::Result<Vec<DailyTotal>> = stmt
                .query_map(params![offset], |row| {
                    let cache_read: i64 = row.get(4)?;
                    let prompt: i64 = row.get(5)?;
                    let hit_rate = if prompt > 0 {
                        cache_read as f64 / prompt as f64
                    } else {
                        0.0
                    };
                    Ok(DailyTotal {
                        date: row.get(0)?,
                        total_cost: row.get(1)?,
                        total_requests: row.get(2)?,
                        total_blocked: row.get(3)?,
                        cache_hit_rate: hit_rate,
                    })
                })?
                .collect();
            Ok(rows?)
        })
    }

    /// Per-provider / per-model aggregates for a single UTC date. Powers
    /// the table in `burnwall status`. Excludes blocked rows (which have
    /// zero token counts and zero cost — they'd just clutter the output).
    pub fn breakdown_for_date(&self, date: &str) -> Result<Vec<ModelBreakdown>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT
                    provider,
                    model,
                    COALESCE(SUM(cost_usd), 0.0)                    AS cost,
                    COUNT(*)                                        AS requests,
                    COALESCE(SUM(input_tokens), 0)                  AS input_tokens,
                    COALESCE(SUM(cache_creation_tokens), 0)         AS cache_creation_tokens,
                    COALESCE(SUM(cache_read_tokens), 0)             AS cache_read_tokens,
                    COALESCE(SUM(output_tokens), 0)                 AS output_tokens
                 FROM requests
                 WHERE DATE(timestamp, 'localtime') = ?1 AND blocked = 0
                 GROUP BY provider, model
                 ORDER BY cost DESC",
            )?;
            let rows: rusqlite::Result<Vec<ModelBreakdown>> = stmt
                .query_map(params![date], row_to_model_breakdown)?
                .collect();
            Ok(rows?)
        })
    }

    /// Sum of `cost_usd` for a local calendar month (`YYYY-MM`). Powers the
    /// monthly burndown in `burnwall history`.
    pub fn cost_for_month(&self, month: &str) -> Result<f64> {
        self.with_conn(|conn| {
            let cost: f64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM requests
                 WHERE strftime('%Y-%m', timestamp, 'localtime') = ?1",
                params![month],
                |row| row.get(0),
            )?;
            Ok(cost)
        })
    }

    /// Per-provider / per-model aggregates over the last `days` local days
    /// (newest-cost first), excluding blocked rows. Drives `burnwall explore`.
    pub fn breakdown_since_days(&self, days: i64) -> Result<Vec<ModelBreakdown>> {
        self.with_conn(|conn| {
            let offset = format!("-{} days", days - 1);
            let mut stmt = conn.prepare(
                "SELECT
                    provider,
                    model,
                    COALESCE(SUM(cost_usd), 0.0)                    AS cost,
                    COUNT(*)                                        AS requests,
                    COALESCE(SUM(input_tokens), 0)                  AS input_tokens,
                    COALESCE(SUM(cache_creation_tokens), 0)         AS cache_creation_tokens,
                    COALESCE(SUM(cache_read_tokens), 0)             AS cache_read_tokens,
                    COALESCE(SUM(output_tokens), 0)                 AS output_tokens
                 FROM requests
                 WHERE DATE(timestamp, 'localtime') >= DATE('now', 'localtime', ?1) AND blocked = 0
                 GROUP BY provider, model
                 ORDER BY cost DESC",
            )?;
            let rows: rusqlite::Result<Vec<ModelBreakdown>> = stmt
                .query_map(params![offset], row_to_model_breakdown)?
                .collect();
            Ok(rows?)
        })
    }

    /// Per-request latency + status samples over the last `days` local days,
    /// for forwarded (non-blocked) requests that recorded a latency. Drives
    /// `burnwall metrics`. Blocked rows are excluded — they never reached an
    /// upstream, so they carry no latency/status.
    #[cfg(feature = "observe")]
    pub fn latency_samples_since_days(
        &self,
        days: i64,
    ) -> Result<Vec<crate::observe::metrics::LatencySample>> {
        self.with_conn(|conn| {
            let offset = format!("-{} days", days - 1);
            let mut stmt = conn.prepare(
                "SELECT provider, model, latency_ms, http_status
                 FROM requests
                 WHERE DATE(timestamp, 'localtime') >= DATE('now', 'localtime', ?1)
                   AND blocked = 0
                   AND latency_ms IS NOT NULL
                 ORDER BY timestamp ASC",
            )?;
            let rows: rusqlite::Result<Vec<_>> = stmt
                .query_map(params![offset], |row| {
                    Ok(crate::observe::metrics::LatencySample {
                        provider: row.get(0)?,
                        model: row.get(1)?,
                        latency_ms: row.get(2)?,
                        http_status: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    })
                })?
                .collect();
            Ok(rows?)
        })
    }

    /// Total request count for a date (blocked + ok).
    pub fn request_count_for_date(&self, date: &str) -> Result<i64> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM requests WHERE DATE(timestamp, 'localtime') = ?1",
                params![date],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// Number of blocked requests on the given date.
    pub fn blocked_count_for_date(&self, date: &str) -> Result<i64> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM requests
                 WHERE DATE(timestamp, 'localtime') = ?1 AND blocked = 1",
                params![date],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// Number of security events on the given date.
    pub fn security_event_count_for_date(&self, date: &str) -> Result<i64> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM security_events WHERE DATE(timestamp, 'localtime') = ?1",
                params![date],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// All security events from the last `days` local days, newest first.
    /// `days = 1` = today only.
    pub fn security_events_since_days(&self, days: i64) -> Result<Vec<SecurityEvent>> {
        self.with_conn(|conn| {
            let offset = format!("-{} days", days - 1);
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, event_type, details, provider, model
                 FROM security_events
                 WHERE DATE(timestamp, 'localtime') >= DATE('now', 'localtime', ?1)
                 ORDER BY timestamp DESC",
            )?;
            let rows: rusqlite::Result<Vec<SecurityEvent>> = stmt
                .query_map(params![offset], row_to_security_event)?
                .collect();
            Ok(rows?)
        })
    }

    /// Add to the "would-have-cached" projection accumulator for the given
    /// local date. Called from the proxy handler when cache injection is
    /// off and an Anthropic Messages request flows through. The projection
    /// is rough (char-count tokenization heuristic) and exists purely so
    /// `burnwall status` can show the user the foregone savings.
    pub fn record_cache_projection(&self, date: &str, savings_usd: f64) -> Result<()> {
        if !savings_usd.is_finite() || savings_usd <= 0.0 {
            return Ok(());
        }
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO daily_projection (date, projected_cache_savings_usd)
                 VALUES (?1, ?2)
                 ON CONFLICT(date) DO UPDATE SET
                     projected_cache_savings_usd = projected_cache_savings_usd + excluded.projected_cache_savings_usd,
                     updated_at = datetime('now')",
                params![date, savings_usd],
            )?;
            Ok(())
        })
    }

    /// Insert an MCP tool-invocation row from `burnwall mcp-watch`.
    pub fn insert_mcp_event(&self, e: &McpEvent) -> Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO mcp_events (timestamp, tool_name, rpc_id, upstream_status, upstream_uri)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    e.timestamp,
                    e.tool_name,
                    e.rpc_id,
                    e.upstream_status,
                    e.upstream_uri,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Count MCP events recorded today (local date).
    pub fn mcp_event_count_for_date(&self, date: &str) -> Result<i64> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM mcp_events
                 WHERE DATE(timestamp, 'localtime') = ?1",
                params![date],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    /// All MCP events from the last `days` local days, newest first.
    /// `days = 1` = today only. Drives `burnwall mcp export`.
    pub fn mcp_events_since_days(&self, days: i64) -> Result<Vec<McpEvent>> {
        self.with_conn(|conn| {
            let offset = format!("-{} days", days - 1);
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, tool_name, rpc_id, upstream_status, upstream_uri
                 FROM mcp_events
                 WHERE DATE(timestamp, 'localtime') >= DATE('now', 'localtime', ?1)
                 ORDER BY timestamp DESC",
            )?;
            let rows: rusqlite::Result<Vec<McpEvent>> = stmt
                .query_map(params![offset], row_to_mcp_event)?
                .collect();
            Ok(rows?)
        })
    }

    /// All MCP events from the given local date, newest first.
    pub fn mcp_events_for_date(&self, date: &str) -> Result<Vec<McpEvent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, tool_name, rpc_id, upstream_status, upstream_uri
                 FROM mcp_events
                 WHERE DATE(timestamp, 'localtime') = ?1
                 ORDER BY timestamp DESC",
            )?;
            let rows: rusqlite::Result<Vec<McpEvent>> = stmt
                .query_map(params![date], row_to_mcp_event)?
                .collect();
            Ok(rows?)
        })
    }

    /// Read the accumulated projection for a local date. Returns 0.0 when
    /// no projection has been recorded — distinct from "cache injection
    /// is on", which the caller checks separately.
    pub fn cache_projection_for_date(&self, date: &str) -> Result<f64> {
        self.with_conn(|conn| {
            let value: f64 = conn
                .query_row(
                    "SELECT projected_cache_savings_usd FROM daily_projection
                     WHERE date = ?1",
                    params![date],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0.0);
            Ok(value)
        })
    }

    /// Fetch one security event by rowid. Used by `burnwall audit verify` to
    /// re-derive a receipt's content hash from the live source row.
    pub fn get_security_event(&self, id: i64) -> Result<Option<SecurityEvent>> {
        self.with_conn(|conn| {
            let r = conn
                .query_row(
                    "SELECT id, timestamp, event_type, details, provider, model
                     FROM security_events WHERE id = ?1",
                    params![id],
                    row_to_security_event,
                )
                .optional()?;
            Ok(r)
        })
    }

    /// Forwarded/blocked request rows not yet sealed into the audit chain,
    /// oldest first. Drives `burnwall audit seal`.
    pub fn unsealed_requests(&self) -> Result<Vec<RequestRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, provider, model,
                        input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                        cost_usd, blocked, block_reason, session_id, request_hash,
                        latency_ms, http_status
                 FROM requests
                 WHERE id NOT IN (SELECT source_id FROM audit_receipts WHERE source = 'request')
                 ORDER BY id ASC",
            )?;
            let rows: rusqlite::Result<Vec<RequestRecord>> =
                stmt.query_map([], row_to_request)?.collect();
            Ok(rows?)
        })
    }

    /// Security-event rows not yet sealed, oldest first.
    pub fn unsealed_security_events(&self) -> Result<Vec<SecurityEvent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, event_type, details, provider, model
                 FROM security_events
                 WHERE id NOT IN (SELECT source_id FROM audit_receipts WHERE source = 'security_event')
                 ORDER BY id ASC",
            )?;
            let rows: rusqlite::Result<Vec<SecurityEvent>> =
                stmt.query_map([], row_to_security_event)?.collect();
            Ok(rows?)
        })
    }

    /// The hash of the most recently sealed receipt (the chain tail), or
    /// `None` when no receipts have been sealed yet.
    pub fn last_receipt_hash(&self) -> Result<Option<String>> {
        self.with_conn(|conn| {
            let h = conn
                .query_row(
                    "SELECT hash FROM audit_receipts ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(h)
        })
    }

    /// Persist one sealed receipt. The hashes + Ed25519 signature are computed
    /// by the caller (`crate::audit`); storage only stores them.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_receipt(
        &self,
        source: &str,
        source_id: i64,
        timestamp: &str,
        action: &str,
        provider: Option<&str>,
        model: Option<&str>,
        detail: Option<&str>,
        content_hash: &str,
        prev_hash: &str,
        hash: &str,
        signature: &str,
    ) -> Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO audit_receipts
                    (source, source_id, timestamp, action, provider, model, detail,
                     content_hash, prev_hash, hash, signature)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    source,
                    source_id,
                    timestamp,
                    action,
                    provider,
                    model,
                    detail,
                    content_hash,
                    prev_hash,
                    hash,
                    signature
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// All sealed receipts in chain (seq) order. Drives `burnwall audit verify`
    /// and `burnwall audit export`.
    pub fn all_receipts(&self) -> Result<Vec<ReceiptRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT seq, sealed_at, source, source_id, timestamp, action, provider, model,
                        detail, content_hash, prev_hash, hash, signature
                 FROM audit_receipts ORDER BY seq ASC",
            )?;
            let rows: rusqlite::Result<Vec<ReceiptRow>> =
                stmt.query_map([], row_to_receipt)?.collect();
            Ok(rows?)
        })
    }

    /// Security events for a local date — used by `burnwall status`.
    pub fn security_events_for_date(&self, date: &str) -> Result<Vec<SecurityEvent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, event_type, details, provider, model
                 FROM security_events
                 WHERE DATE(timestamp, 'localtime') = ?1
                 ORDER BY timestamp ASC",
            )?;
            let rows: rusqlite::Result<Vec<SecurityEvent>> = stmt
                .query_map(params![date], row_to_security_event)?
                .collect();
            Ok(rows?)
        })
    }
}

fn row_to_security_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityEvent> {
    Ok(SecurityEvent {
        id: Some(row.get(0)?),
        timestamp: row.get::<_, DateTime<Utc>>(1)?,
        event_type: row.get(2)?,
        details: row.get(3)?,
        provider: row.get(4)?,
        model: row.get(5)?,
    })
}

fn row_to_receipt(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptRow> {
    Ok(ReceiptRow {
        seq: row.get(0)?,
        sealed_at: row.get(1)?,
        source: row.get(2)?,
        source_id: row.get(3)?,
        timestamp: row.get(4)?,
        action: row.get(5)?,
        provider: row.get(6)?,
        model: row.get(7)?,
        detail: row.get(8)?,
        content_hash: row.get(9)?,
        prev_hash: row.get(10)?,
        hash: row.get(11)?,
        signature: row.get(12)?,
    })
}

fn row_to_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestRecord> {
    Ok(RequestRecord {
        id: Some(row.get(0)?),
        timestamp: row.get::<_, DateTime<Utc>>(1)?,
        provider: row.get(2)?,
        model: row.get(3)?,
        input_tokens: row.get::<_, i64>(4)? as u64,
        cache_creation_tokens: row.get::<_, i64>(5)? as u64,
        cache_read_tokens: row.get::<_, i64>(6)? as u64,
        output_tokens: row.get::<_, i64>(7)? as u64,
        cost_usd: row.get(8)?,
        blocked: row.get::<_, i64>(9)? != 0,
        block_reason: row.get(10)?,
        session_id: row.get(11)?,
        request_hash: row.get(12)?,
        latency_ms: row.get(13)?,
        http_status: row.get(14)?,
    })
}

/// Column order: `id, timestamp, tool_name, rpc_id, upstream_status, upstream_uri`.
fn row_to_mcp_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<McpEvent> {
    Ok(McpEvent {
        id: Some(row.get(0)?),
        timestamp: row.get::<_, DateTime<Utc>>(1)?,
        tool_name: row.get(2)?,
        rpc_id: row.get(3)?,
        upstream_status: row.get(4)?,
        upstream_uri: row.get(5)?,
    })
}

/// Column order: `provider, model, cost, requests, input_tokens,
/// cache_creation_tokens, cache_read_tokens, output_tokens`.
fn row_to_model_breakdown(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModelBreakdown> {
    Ok(ModelBreakdown {
        provider: row.get(0)?,
        model: row.get(1)?,
        cost: row.get(2)?,
        requests: row.get(3)?,
        input_tokens: row.get::<_, i64>(4)? as u64,
        cache_creation_tokens: row.get::<_, i64>(5)? as u64,
        cache_read_tokens: row.get::<_, i64>(6)? as u64,
        output_tokens: row.get::<_, i64>(7)? as u64,
    })
}
