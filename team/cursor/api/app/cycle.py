"""Billing periods. Cursor resets limits at the team's subscription cycle start (subscriptionCycleStart from
/teams/spend), which is the same day and time each month. Most teams' cycle starts on the 1st at 00:00 UTC, but not
every team's.

A period is named by the month it starts in: with a cycle that starts on the 15th, "2026-10" is Oct 15 to Nov 15.
BILLING_CYCLE=auto (default) follows Cursor's cycle start once a sync has seen it, and calendar months until then.
BILLING_CYCLE=calendar always uses UTC calendar months.
"""
import calendar
import sqlite3
from datetime import datetime, timezone
from typing import NamedTuple

from . import db


class Anchor(NamedTuple):
    day: int = 1
    hour: int = 0
    minute: int = 0
    second: int = 0


CALENDAR = Anchor()


def anchor(conn: sqlite3.Connection, mode: str = "auto") -> Anchor:
    if mode == "calendar":
        return CALENDAR
    start = db.get_state(conn, "billing_cycle_start")
    if not start:
        return CALENDAR
    t = datetime.fromisoformat(start).astimezone(timezone.utc)
    return Anchor(t.day, t.hour, t.minute, t.second)


def _start(y: int, m: int, a: Anchor) -> datetime:
    day = min(a.day, calendar.monthrange(y, m)[1])   # a cycle on the 31st starts on the 30th in a 30-day month
    return datetime(y, m, day, a.hour, a.minute, a.second, tzinfo=timezone.utc)


def bounds(period: str, a: Anchor = CALENDAR) -> tuple[datetime, datetime]:
    """'2026-10' -> start and end of the billing period that starts in October."""
    y, m = (int(x) for x in period.split("-"))
    return _start(y, m, a), _start(y + (m == 12), 1 if m == 12 else m + 1, a)


def current(now: datetime, a: Anchor = CALENDAR) -> str:
    """Name of the period that contains now."""
    y, m = now.year, now.month
    if now < _start(y, m, a):
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return f"{y:04d}-{m:02d}"
