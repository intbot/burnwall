"""Copy members, limits and usage events from the Cursor Admin API into SQLite.

Events are fetched one UTC day at a time and each day is replaced as a whole, so re-fetching a day
(late-arriving events) never creates duplicates. Each sync re-fetches from the day before the last
synced day up to now.
"""
import logging
import sqlite3
from datetime import date, datetime, timedelta, timezone

from . import db
from .config import Settings
from .cursor_api import CursorAdminClient

DAY_MS = 86_400_000
log = logging.getLogger(__name__)

EVENT_COLUMNS = ("ts", "user_email", "model", "kind", "conversation_id", "charged_cents", "model_cents",
                 "token_fee_cents", "input_tokens", "output_tokens", "cache_write_tokens", "cache_read_tokens",
                 "is_headless", "cloud_agent_id")
INSERT_EVENT = f"INSERT INTO events ({', '.join(EVENT_COLUMNS)}) VALUES ({', '.join('?' * len(EVENT_COLUMNS))})"


def day_ms(d: date) -> int:
    return int(datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp() * 1000)


def _null(value):
    return None if value in (None, "", "null") else value


def event_row(e: dict) -> tuple:
    tu = e.get("tokenUsage") or {}
    return (
        int(e["timestamp"]), (e.get("userEmail") or "").lower(), e.get("model"), e.get("kind"),
        _null(e.get("conversationId")), float(e.get("chargedCents") or 0), tu.get("totalCents"),
        e.get("cursorTokenFee"), tu.get("inputTokens"), tu.get("outputTokens"), tu.get("cacheWriteTokens"),
        tu.get("cacheReadTokens"), int(bool(e.get("isHeadless"))), _null(e.get("cloudAgentId")),
    )


def sync_members(conn: sqlite3.Connection, client: CursorAdminClient, now: datetime) -> int:
    spend = {(r.get("email") or "").lower(): r for r in client.spend()}
    rows = []
    for m in client.members():
        email = (m.get("email") or "").lower()
        s = spend.get(email, {})
        limit = s.get("effectivePerUserLimitDollars") or s.get("monthlyLimitDollars")
        rows.append((email, m.get("name"), m.get("id"), m.get("role"), int(bool(m.get("isRemoved"))),
                     limit, s.get("overallSpendCents"), now.isoformat()))
    with conn:
        conn.executemany(
            "INSERT INTO members (email, name, user_id, role, is_removed, limit_dollars, cycle_spend_cents, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (email) DO UPDATE SET name = excluded.name, "
            "user_id = excluded.user_id, role = excluded.role, is_removed = excluded.is_removed, "
            "limit_dollars = excluded.limit_dollars, cycle_spend_cents = excluded.cycle_spend_cents, "
            "updated_at = excluded.updated_at", rows)
        cycle = getattr(client, "cycle_start_ms", None)
        if cycle:
            db.set_state(conn, "billing_cycle_start", datetime.fromtimestamp(int(cycle) / 1000, timezone.utc).isoformat())
    return len(rows)


def sync_events(conn: sqlite3.Connection, client: CursorAdminClient, start_day: date, now_ms: int) -> int:
    total, d = 0, start_day
    while day_ms(d) <= now_ms:
        start, end = day_ms(d), min(day_ms(d) + DAY_MS - 1, now_ms)
        rows = [event_row(e) for e in client.usage_events(start, end)]
        with conn:
            conn.execute("DELETE FROM events WHERE ts BETWEEN ? AND ?", (start, end))
            conn.executemany(INSERT_EVENT, rows)
            db.set_state(conn, "events_synced_until", str(end))
        log.info("events %s: %d", d, len(rows))
        total += len(rows)
        d += timedelta(days=1)
    return total


def sync(settings: Settings, client: CursorAdminClient | None = None, now: datetime | None = None) -> dict:
    client = client or CursorAdminClient(settings.cursor_admin_api_key)
    now = now or datetime.now(timezone.utc)
    conn = db.connect(settings.db_path)
    try:
        members = sync_members(conn, client, now)
        until = db.get_state(conn, "events_synced_until")
        start_day = (settings.backfill_start if until is None
                     else datetime.fromtimestamp(int(until) / 1000, timezone.utc).date() - timedelta(days=1))
        events = sync_events(conn, client, start_day, int(now.timestamp() * 1000))
        with conn:
            db.set_state(conn, "last_sync_at", now.isoformat())
        return {"members": members, "events_fetched": events, "from_day": start_day.isoformat(),
                "synced_at": now.isoformat()}
    finally:
        conn.close()
