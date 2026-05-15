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
    models::{DailyTotal, ModelBreakdown, RequestRecord, SecurityEvent},
    Result, Storage,
};

impl Storage {
    /// Insert a request log row. Returns the new rowid.
    pub fn insert_request(&self, r: &RequestRecord) -> Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO requests (
                    timestamp, provider, model,
                    input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                    cost_usd, blocked, block_reason, session_id, request_hash
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
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

    /// Fetch a single request by rowid. Returns `Ok(None)` if not found.
    pub fn get_request(&self, id: i64) -> Result<Option<RequestRecord>> {
        self.with_conn(|conn| {
            let r = conn
                .query_row(
                    "SELECT id, timestamp, provider, model,
                            input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                            cost_usd, blocked, block_reason, session_id, request_hash
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

    /// All requests within the given local date, oldest first.
    pub fn requests_for_date(&self, date: &str) -> Result<Vec<RequestRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, provider, model,
                        input_tokens, cache_creation_tokens, cache_read_tokens, output_tokens,
                        cost_usd, blocked, block_reason, session_id, request_hash
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
                .query_map(params![date], |row| {
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
                .query_map(params![offset], |row| {
                    Ok(SecurityEvent {
                        id: Some(row.get(0)?),
                        timestamp: row.get::<_, DateTime<Utc>>(1)?,
                        event_type: row.get(2)?,
                        details: row.get(3)?,
                        provider: row.get(4)?,
                        model: row.get(5)?,
                    })
                })?
                .collect();
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
                .query_map(params![date], |row| {
                    Ok(SecurityEvent {
                        id: Some(row.get(0)?),
                        timestamp: row.get::<_, DateTime<Utc>>(1)?,
                        event_type: row.get(2)?,
                        details: row.get(3)?,
                        provider: row.get(4)?,
                        model: row.get(5)?,
                    })
                })?
                .collect();
            Ok(rows?)
        })
    }
}

fn row_to_request(row: &rusqlite::Row) -> rusqlite::Result<RequestRecord> {
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
    })
}
