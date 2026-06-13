//! SQLite storage layer.
//!
//! [`Storage`] wraps a single `rusqlite::Connection` in a `Mutex`. SQLite's
//! default threading model is one-writer-many-readers, and our query volume
//! (hundreds per day, not thousands per second) is comfortably inside the
//! single-connection budget — see `docs/ARCHITECTURE.md` "Shared State".
//!
//! Tables are defined by [`SCHEMA`] and created on `open()`; subsequent opens
//! are idempotent (every statement is `IF NOT EXISTS`). Future schema changes
//! will need a real migration runner — out of scope for v0.1.
//!
//! Storage is unencrypted on disk by design — it holds only metadata
//! (timestamps, token counts, costs, model names), never API keys or
//! prompt content. The default `open_default()` path applies `0700`/`0600`
//! permissions on Unix and relies on the user-profile ACL on Windows.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

pub mod models;
pub mod repository;

pub use models::{
    DailyTotal, McpEvent, McpToolRow, ModelBreakdown, ReceiptRow, RequestRecord, SecurityEvent,
};
pub use repository::McpToolObservation;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0.0,
    blocked INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT,
    session_id TEXT,
    request_hash TEXT,
    latency_ms INTEGER,
    http_status INTEGER
);

CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_provider_model ON requests(provider, model);
CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(blocked);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    details TEXT NOT NULL,
    provider TEXT,
    model TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);

CREATE TABLE IF NOT EXISTS daily_summary (
    date TEXT PRIMARY KEY,
    total_cost REAL NOT NULL DEFAULT 0.0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_blocked INTEGER NOT NULL DEFAULT 0,
    cache_savings REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-day accumulator of the "would-have-cached" savings projection,
-- written from the proxy handler only when cache injection is OFF and the
-- request was an Anthropic Messages-API call eligible for marker insertion.
-- Read by `burnwall status` to surface the foregone savings.
CREATE TABLE IF NOT EXISTS daily_projection (
    date TEXT PRIMARY KEY,
    projected_cache_savings_usd REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Pass-through audit log of MCP tool invocations seen by `burnwall
-- mcp-watch`. Read-only first: we record the tool name + JSON-RPC id +
-- HTTP status returned by the upstream MCP server, never the argument
-- payload (could contain prompt content).
CREATE TABLE IF NOT EXISTS mcp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    tool_name TEXT NOT NULL,
    rpc_id TEXT,
    upstream_status INTEGER NOT NULL DEFAULT 0,
    upstream_uri TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_events_timestamp ON mcp_events(timestamp);

-- Fingerprint of each tool an MCP server has advertised, keyed by
-- (server, tool_name). Written by `burnwall mcp-watch` the first time a
-- tool is seen in a `tools/list` reply; a later reply whose fingerprint
-- differs is a silent post-approval change ("rug pull") and is recorded as
-- a security_event. Holds no argument payloads or prompt content — only the
-- tool's advertised identity.
-- `trust_state` (v0.6.5): 'pending' (seen, not approved) or 'approved'
-- (`burnwall mcp approve`). In enforce mode (`mcp.require_approval`) a
-- `tools/call` to a tool that is not 'approved' is blocked. A rug-pull
-- fingerprint change resets an approved tool back to 'pending'.
CREATE TABLE IF NOT EXISTS mcp_tools (
    server TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    trust_state TEXT NOT NULL DEFAULT 'pending',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (server, tool_name)
);

-- Trust-On-First-Use pins for installed third-party rule packs (v0.6). A pack
-- under <data dir>/rules/ is applied at startup ONLY if its current SHA-256
-- matches the pinned `sha256` here (invariant I6) — an edited/unapproved pack
-- is skipped. `burnwall rules add` writes the pin after the user approves;
-- `rules revoke` deletes it. Official packs are bundled/trusted and do not
-- appear here (invariant I4).
CREATE TABLE IF NOT EXISTS rule_trust (
    pack_id     TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    approved_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Cryptographic audit receipts (v0.8). `burnwall audit seal` appends one
-- receipt per forwarded/blocked request and per security event, in
-- chronological order, forming a hash chain signed with a local Ed25519 key.
-- `content_hash` is a SHA-256 over the canonical text of the SOURCE row, so a
-- later edit to that row is detectable; `hash` = SHA-256(prev_hash || content_hash),
-- so deleting/reordering any receipt breaks every later link; `signature` is
-- Ed25519 over `hash`, so the chain cannot be forged without the key. Metadata
-- only — the underlying rows never hold prompt content. `burnwall audit verify`
-- re-walks the chain and re-derives each `content_hash` from its source row.
CREATE TABLE IF NOT EXISTS audit_receipts (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    sealed_at    TEXT NOT NULL DEFAULT (datetime('now')),
    source       TEXT NOT NULL,        -- 'request' | 'security_event'
    source_id    INTEGER NOT NULL,     -- rowid in the source table
    timestamp    TEXT NOT NULL,        -- the source row's timestamp (RFC 3339)
    action       TEXT NOT NULL,        -- 'forward' | 'block' | 'security'
    provider     TEXT,
    model        TEXT,
    detail       TEXT,
    content_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL,
    signature    TEXT NOT NULL,
    UNIQUE(source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_receipts_timestamp ON audit_receipts(timestamp);

-- Generic local key/value store for small bits of CLI state that aren't worth
-- a dedicated table — e.g. the once/day gate for the `burnwall status` usage
-- nudge (last-shown date + which finding was last shown, so it rotates).
-- Metadata only: keys and values are short ASCII tokens set by Burnwall itself,
-- never prompt content. Additive + downgrade-safe (an older binary just ignores
-- a table it doesn't read).
CREATE TABLE IF NOT EXISTS meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("SQLite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("home directory not found")]
    NoHomeDir,
    #[error(
        "database schema v{found} is newer than this binary supports (v{supported}) — \
         it was written by a newer Burnwall. Upgrade, or point BURNWALL_DATA_DIR elsewhere."
    )]
    SchemaTooNew { found: i64, supported: i64 },
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    /// Open the default user database at `~/.burnwall/burnwall.db`, creating
    /// the directory tree and securing perms (0700 dir / 0600 file on Unix;
    /// default user-profile ACL on Windows).
    pub fn open_default() -> Result<Self> {
        let dir = data_dir()?;
        std::fs::create_dir_all(&dir)?;
        set_secure_dir_perms(&dir)?;
        let path = dir.join("burnwall.db");
        let storage = Self::open(&path)?;
        set_secure_file_perms(&path)?;
        Ok(storage)
    }

    /// Open a database at the given path, running migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open a fresh in-memory database — used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run a closure with a locked connection. Crate-internal helper for
    /// [`repository`].
    ///
    /// Recovers a poisoned lock instead of cascading the panic: a closure that
    /// panicked may have aborted mid-statement, but SQLite rolls back an
    /// incomplete statement/transaction when it drops, so the connection stays
    /// usable for the next caller — one bad query must not wedge all storage.
    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&conn)
    }
}

/// Connection-level pragmas applied on every open. WAL lets readers run
/// concurrently with the single writer; `busy_timeout` makes a contended
/// write wait-and-retry instead of failing immediately with `SQLITE_BUSY`.
/// Both are harmless on an in-memory database (journal mode stays `memory`).
fn configure(conn: &Connection) -> Result<()> {
    // Set `busy_timeout` FIRST, as its own statement, *before* the WAL switch
    // (D-M6). The one-time DELETE→WAL conversion on the first launch after a
    // WAL-introducing upgrade needs brief exclusivity; with no busy handler
    // armed, a concurrent statusline/daemon open races it into an instant
    // `SQLITE_BUSY` that aborts `burnwall start`. Arming the timeout first
    // makes the loser wait-and-retry instead.
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    Ok(())
}

/// Schema version this binary writes/understands. Bump on every migration so
/// an older binary can refuse a DB it would mis-read (D-M7).
const SCHEMA_VERSION: i64 = 1;

fn migrate(conn: &Connection) -> Result<()> {
    // Refuse to open a DB stamped newer than we understand: an old binary
    // running against a newer schema (after a rolled-back upgrade) silently
    // mis-reading rows is the worst post-update failure. Additive migrations
    // are still downgrade-safe today (version 0/1), so only a *strictly
    // greater* stamp is fatal.
    let on_disk: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if on_disk > SCHEMA_VERSION {
        return Err(StorageError::SchemaTooNew {
            found: on_disk,
            supported: SCHEMA_VERSION,
        });
    }

    conn.execute_batch(SCHEMA)?;
    // Forward-add columns introduced after a table first shipped. Idempotent:
    // skipped when the column already exists (a DB created from the current
    // SCHEMA already has it). Identifiers are hardcoded, not user input.
    ensure_column(
        conn,
        "mcp_tools",
        "trust_state",
        "TEXT NOT NULL DEFAULT 'pending'",
    )?;
    // v0.7 observability: per-request upstream latency + HTTP status.
    ensure_column(conn, "requests", "latency_ms", "INTEGER")?;
    ensure_column(conn, "requests", "http_status", "INTEGER")?;

    if on_disk < SCHEMA_VERSION {
        conn.execute_batch(&format!("PRAGMA user_version={SCHEMA_VERSION};"))?;
    }
    Ok(())
}

/// Add `column` to `table` if it is not already present. A lightweight
/// stand-in for a real migration runner — used only for additive, defaulted
/// columns. `table`/`column`/`decl` are compile-time constants.
fn ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let present = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(std::result::Result::ok)
        .any(|name| name == column);
    drop(stmt);
    if !present {
        match conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        ) {
            Ok(_) => {}
            // Tolerate the check-then-ALTER race (D-M6): two processes opening
            // at once can both see the column missing; the loser's ALTER fails
            // with "duplicate column name", which is success for our purposes.
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The Burnwall data directory.
///
/// Defaults to `$HOME/.burnwall/` on Unix (`%USERPROFILE%\.burnwall\` on
/// Windows), overridable via the `BURNWALL_DATA_DIR` environment variable
/// — used by integration tests so they don't pollute the user's real
/// directory.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BURNWALL_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or(StorageError::NoHomeDir)?;
    Ok(home.join(".burnwall"))
}

/// Path to the "activity" marker the proxy touches after recording a turn.
/// Status-ribbon surfaces (the editor status bar, `burnwall watch`) watch this
/// file's modification time to refresh event-driven instead of polling.
pub fn watch_signal_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("watch.signal"))
}

/// Best-effort bump of the [`watch_signal_path`] marker. Called off the proxy's
/// response path (after the client already has its bytes), so the tiny write
/// never adds to request latency. Errors are intentionally swallowed — a failed
/// refresh nudge must never affect request handling.
pub fn touch_watch_signal(turn_marker: &str) {
    if let Ok(path) = watch_signal_path() {
        let _ = std::fs::write(path, turn_marker.as_bytes());
    }
}

#[cfg(unix)]
fn set_secure_dir_perms(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(dir)?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_secure_file_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_secure_dir_perms(_dir: &Path) -> Result<()> {
    // Windows: rely on the default user-profile ACL — files under
    // %USERPROFILE% are not readable by other users without elevation.
    Ok(())
}

#[cfg(not(unix))]
fn set_secure_file_perms(_path: &Path) -> Result<()> {
    Ok(())
}
