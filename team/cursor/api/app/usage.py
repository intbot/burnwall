"""Usage summaries for one billing period (cycle.py: Cursor's cycle, or UTC calendar months). Pure reads from SQLite."""
import sqlite3
import statistics
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from . import coach, cycle, db, news, tokens
from .rules import Rules

DAY_S = 86_400
WEEK_MS = 7 * DAY_S * 1000


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _iso(ms: int | None) -> str | None:
    return None if ms is None else datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()


def _dollars(cents: float) -> float:
    return round(cents / 100, 2)


def pace(spent: float, limit: float, start: datetime, end: datetime, now: datetime, watch_share: float = 0.8) -> dict:
    """Projection for the month. A past month is final; the first day is treated as one full day."""
    days_in_month = (end - start).days
    is_current = start <= now < end
    elapsed = ((min(now, end) - start).total_seconds() / DAY_S) if now > start else 0.0
    rate = spent / max(elapsed, 1.0)
    projected = rate * days_in_month if is_current else spent
    reach = None
    if is_current and spent < limit and rate > 0:
        eta = now + timedelta(days=(limit - spent) / rate)
        reach = eta.date().isoformat() if eta < end else None
    if spent >= limit:
        status = "over_limit"
    elif projected >= limit:
        status = "over_pace"
    elif projected >= watch_share * limit:
        status = "watch"
    else:
        status = "ok"
    return {
        "is_current_month": is_current,
        "days_in_month": days_in_month,
        "days_elapsed": round(elapsed, 2),
        "projected_dollars": round(projected, 2),
        "even_pace_today_dollars": round(limit * min(elapsed, days_in_month) / days_in_month, 2),
        "projected_reach_limit_date": reach,
        "status": status,
    }


def team_median_cost_per_prompt(conn: sqlite3.Connection, until_ms: int, min_prompts: int = 5) -> float | None:
    rows = conn.execute(
        "SELECT SUM(charged_cents) AS c, COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ? "
        "GROUP BY user_email HAVING COUNT(*) >= ?", (until_ms - WEEK_MS, until_ms, min_prompts)).fetchall()
    per_user = [r["c"] / r["n"] for r in rows]
    return _dollars(statistics.median(per_user)) if per_user else None


def summary(conn: sqlite3.Connection, email: str, month: str, now: datetime, default_limit: float = 200.0,
            org_name: str = "your organization", rules: Rules = Rules(), cycle_mode: str = "auto") -> dict:
    """month names the billing period that starts in that month (cycle.py)."""
    email = email.lower()
    start, end = cycle.bounds(month, cycle.anchor(conn, cycle_mode))
    if now < start:
        raise ValueError("month is in the future")
    as_of = min(now, end)

    member = conn.execute("SELECT * FROM members WHERE email = ?", (email,)).fetchone()
    limit = float(member["limit_dollars"]) if member and member["limit_dollars"] else default_limit

    rows = conn.execute(
        "SELECT ts, model, kind, conversation_id, charged_cents, input_tokens, cache_write_tokens, cache_read_tokens, "
        "output_tokens FROM events "
        "WHERE user_email = ? AND ts >= ? AND ts < ? ORDER BY ts", (email, _ms(start), _ms(end))).fetchall()
    spent_cents = sum(r["charged_cents"] for r in rows)
    spent = _dollars(spent_cents)

    # per day, from the start of the period to today (or the whole period if it is over)
    by_day = defaultdict(lambda: [0.0, 0])
    for r in rows:
        d = datetime.fromtimestamp(r["ts"] / 1000, timezone.utc).date()
        by_day[d][0] += r["charged_cents"]
        by_day[d][1] += 1
    last_day = (as_of - timedelta(microseconds=1)).date()
    daily, d, cumulative, reached_on = [], start.date(), 0.0, None
    while d <= last_day:
        cents, n = by_day.get(d, (0.0, 0))
        cumulative += cents
        if reached_on is None and cumulative / 100 >= limit:
            reached_on = d.isoformat()
        daily.append({"date": d.isoformat(), "dollars": _dollars(cents), "prompts": n})
        d += timedelta(days=1)

    by_model = defaultdict(lambda: [0.0, 0])
    for r in rows:
        by_model[r["model"] or "unknown"][0] += r["charged_cents"]
        by_model[r["model"] or "unknown"][1] += 1
    models = [{"model": m, "dollars": _dollars(c), "prompts": n,
               "share": round(c / spent_cents, 4) if spent_cents else 0.0}
              for m, (c, n) in sorted(by_model.items(), key=lambda kv: -kv[1][0])]

    chats = defaultdict(lambda: {"cents": 0.0, "prompts": 0, "models": defaultdict(float)})
    for r in rows:
        if r["conversation_id"]:
            c = chats[r["conversation_id"]]
            c["cents"] += r["charged_cents"]
            c["prompts"] += 1
            c["models"][r["model"] or "unknown"] += r["charged_cents"]
    top_chats = []
    for cid, c in sorted(chats.items(), key=lambda kv: -kv[1]["cents"])[:rules.summary_top_chats]:
        span = conn.execute("SELECT MIN(ts) AS first, MAX(ts) AS last, COUNT(*) AS n FROM events "
                            "WHERE user_email = ? AND conversation_id = ?", (email, cid)).fetchone()
        top_chats.append({
            "conversation_id": cid,
            "started": _iso(span["first"]),
            "last_active": _iso(span["last"]),
            "open_days": round((span["last"] - span["first"]) / 1000 / DAY_S, 1),
            "prompts_this_month": c["prompts"],
            "prompts_total": span["n"],
            "models": [m for m, _ in sorted(c["models"].items(), key=lambda kv: -kv[1])],
            "dollars": _dollars(c["cents"]),
            "share": round(c["cents"] / spent_cents, 4) if spent_cents else 0.0,
        })

    top = max(rows, key=lambda r: r["charged_cents"], default=None)
    top_prompt = None if top is None else {
        "ts": _iso(top["ts"]), "model": top["model"], "conversation_id": top["conversation_id"],
        "dollars": _dollars(top["charged_cents"]), "cache_read_tokens": top["cache_read_tokens"],
    }

    week = conn.execute("SELECT SUM(charged_cents) AS c, COUNT(*) AS n FROM events "
                        "WHERE user_email = ? AND ts >= ? AND ts < ?",
                        (email, _ms(as_of) - WEEK_MS, _ms(as_of))).fetchone()
    latest = conn.execute("SELECT MAX(ts) AS t FROM events").fetchone()["t"]

    out = {
        "email": email,
        "name": member["name"] if member else None,
        "month": month,
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "as_of": now.isoformat(),
        "last_sync_at": db.get_state(conn, "last_sync_at"),
        "data_through": _iso(latest),
        "limit_dollars": limit,
        "spent_dollars": spent,
        "pct_used": round(spent / limit, 4) if limit else None,
        "reached_limit_on": reached_on,
        **pace(spent, limit, start, end, now, rules.pace_watch_share),
        "alerts": {"watch_share": rules.pace_watch_share},
        "prompts": len(rows),
        "cost_per_prompt_7d": _dollars(week["c"] / week["n"]) if week["n"] else None,
        "team_median_cost_per_prompt_7d": team_median_cost_per_prompt(conn, _ms(as_of), rules.team_median_min_prompts),
        "daily": daily,
        "by_model": models,
        "top_chats": top_chats,
        "top_prompt": top_prompt,
    }
    out["tokens"] = tokens.breakdown(conn, rows, _ms(as_of), out["last_sync_at"])
    out["coach"] = coach.build(rows, out, news.team_view(conn, now, out["last_sync_at"], rules), rules)
    out["notices"] = notices_for(conn, email, rules.summary_max_notices)
    out["model_updates"] = news.model_updates(conn, email, now, out["last_sync_at"], org_name, rules)
    out["org_name"] = org_name
    return out


def notices_for(conn: sqlite3.Connection, email: str, limit: int = 5) -> list[dict]:
    rows = conn.execute("SELECT id, created_at, text FROM notices WHERE target IN ('*', ?) "
                        "ORDER BY created_at DESC LIMIT ?", (email.lower(), limit)).fetchall()
    return [dict(r) for r in rows]


def member_list(conn: sqlite3.Connection, month: str, default_limit: float = 200.0, cycle_mode: str = "auto") -> list[dict]:
    """Every current Cursor member with this period's spend, by name (for the dev user picker)."""
    start, end = cycle.bounds(month, cycle.anchor(conn, cycle_mode))
    rows = conn.execute(
        "SELECT m.email, m.name, m.limit_dollars, COALESCE(SUM(e.charged_cents), 0) AS cents FROM members m "
        "LEFT JOIN events e ON e.user_email = m.email AND e.ts >= ? AND e.ts < ? "
        "WHERE COALESCE(m.is_removed, 0) = 0 GROUP BY m.email", (_ms(start), _ms(end))).fetchall()
    out = [{"email": r["email"], "name": r["name"] or r["email"].split("@")[0],
            "spent_dollars": _dollars(r["cents"]), "limit_dollars": float(r["limit_dollars"] or default_limit)}
           for r in rows]
    return sorted(out, key=lambda u: u["name"].lower())


def team_overview(conn: sqlite3.Connection, month: str, now: datetime, default_limit: float = 200.0,
                  cycle_mode: str = "auto", rules: Rules = Rules()) -> list[dict]:
    """One row per person with usage this period, most spend first (admin view)."""
    start, end = cycle.bounds(month, cycle.anchor(conn, cycle_mode))
    rows = conn.execute(
        "SELECT e.user_email, m.name, m.limit_dollars, SUM(e.charged_cents) AS cents, COUNT(*) AS prompts "
        "FROM events e LEFT JOIN members m ON m.email = e.user_email "
        "WHERE e.ts >= ? AND e.ts < ? GROUP BY e.user_email ORDER BY cents DESC", (_ms(start), _ms(end))).fetchall()
    out = []
    for r in rows:
        limit = float(r["limit_dollars"] or default_limit)
        spent = _dollars(r["cents"])
        p = pace(spent, limit, start, end, now, rules.pace_watch_share)
        out.append({"email": r["user_email"], "name": r["name"], "limit_dollars": limit, "spent_dollars": spent,
                    "prompts": r["prompts"], "projected_dollars": p["projected_dollars"], "status": p["status"],
                    "projected_reach_limit_date": p["projected_reach_limit_date"]})
    return out
