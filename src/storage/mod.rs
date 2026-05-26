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

pub use models::{DailyTotal, McpEvent, McpToolRow, ModelBreakdown, RequestRecord, SecurityEvent};
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
    request_hash TEXT
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
"#;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("SQLite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("home directory not found")]
    NoHomeDir,
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
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open a fresh in-memory database — used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run a closure with a locked connection. Crate-internal helper for
    /// [`repository`].
    pub(crate) fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let conn = self.conn.lock().expect("storage mutex poisoned");
        f(&conn)
    }
}

fn migrate(conn: &Connection) -> Result<()> {
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
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        )?;
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
