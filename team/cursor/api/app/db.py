"""SQLite storage. One file, created on first use."""
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts                 INTEGER NOT NULL,   -- ms since epoch, UTC
    user_email         TEXT    NOT NULL,   -- lower-case
    model              TEXT,
    kind               TEXT,
    conversation_id    TEXT,
    charged_cents      REAL    NOT NULL DEFAULT 0,   -- what counts against the limit
    model_cents        REAL,                         -- tokenUsage.totalCents
    token_fee_cents    REAL,                         -- cursorTokenFee
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cache_write_tokens INTEGER,
    cache_read_tokens  INTEGER,
    is_headless        INTEGER,
    cloud_agent_id     TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_user_ts ON events (user_email, ts);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS ix_events_conv ON events (conversation_id);

CREATE TABLE IF NOT EXISTS members (
    email              TEXT PRIMARY KEY,   -- lower-case
    name               TEXT,
    user_id            TEXT,
    role               TEXT,
    is_removed         INTEGER,
    limit_dollars      REAL,               -- effectivePerUserLimitDollars
    cycle_spend_cents  REAL,               -- overallSpendCents for the current cycle
    updated_at         TEXT
);

CREATE TABLE IF NOT EXISTS notices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,   -- ISO, UTC
    created_by  TEXT NOT NULL,
    target      TEXT NOT NULL,   -- '*' for everyone, or a lower-case email
    text        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def get_state(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO sync_state (key, value) VALUES (?, ?) "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))
