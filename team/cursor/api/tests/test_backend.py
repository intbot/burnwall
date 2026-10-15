from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, usage
from app.config import Settings
from app.main import create_app

UTC = timezone.utc
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)   # day 13.5 of 31


def ev(dt: datetime, email: str, model: str, conv: str | None, cents: float, cache_read: int = 0) -> dict:
    return {"timestamp": str(int(dt.timestamp() * 1000)), "userEmail": email, "model": model, "kind": "Included in Business",
            "conversationId": conv if conv else "null", "chargedCents": cents, "cursorTokenFee": 0, "isHeadless": False,
            "tokenUsage": {"inputTokens": 10, "outputTokens": 20, "cacheWriteTokens": 0, "cacheReadTokens": cache_read,
                           "totalCents": cents}}


EVENTS = [
    ev(datetime(2026, 9, 30, 10, tzinfo=UTC), "Pat@example.com", "auto", "c-old", 500),       # previous month
    ev(datetime(2026, 10, 7, 9, tzinfo=UTC), "pat@example.com", "grok-4.7-xhigh-fast", "c1", 3000),
    ev(datetime(2026, 10, 9, 9, tzinfo=UTC), "pat@example.com", "grok-4.7-xhigh-fast", "c1", 4000, 15_700_000),
    ev(datetime(2026, 10, 13, 9, tzinfo=UTC), "pat@example.com", "auto", "c2", 1000),
    ev(datetime(2026, 10, 13, 10, tzinfo=UTC), "pat@example.com", "auto", None, 500),
    ev(datetime(2026, 10, 12, 9, tzinfo=UTC), "sam@example.com", "claude-opus-5-5-high", "c3", 25_000),
]


class FakeClient:
    def __init__(self, events):
        self.events = events

    def members(self):
        return [{"name": "Pat", "email": "Pat@example.com", "id": "u1", "role": "member"},
                {"name": "Sam", "email": "sam@example.com", "id": "u2", "role": "member"}]

    def spend(self):
        return [{"email": "pat@example.com", "effectivePerUserLimitDollars": 200, "overallSpendCents": 9000},
                {"email": "sam@example.com", "effectivePerUserLimitDollars": 200, "overallSpendCents": 25000}]

    def usage_events(self, start_ms, end_ms):
        return [e for e in self.events if start_ms <= int(e["timestamp"]) <= end_ms]


@pytest.fixture
def settings(tmp_path):
    return Settings(cursor_admin_api_key="x", auth_mode="dev", dev_user_email="pat@example.com",
                    admin_emails=["admin@example.com"], sync_enabled=False,
                    backfill_start=date(2026, 9, 1), db_path=tmp_path / "usage.db")


@pytest.fixture
def synced(settings):
    ingest.sync(settings, FakeClient(EVENTS), now=NOW)
    return settings


def test_resync_does_not_duplicate(synced):
    ingest.sync(synced, FakeClient(EVENTS), now=NOW)
    conn = db.connect(synced.db_path)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(EVENTS)
    assert conn.execute("SELECT COUNT(*) FROM events WHERE user_email = 'pat@example.com'").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM events WHERE conversation_id IS NULL").fetchone()[0] == 1


def test_late_event_is_picked_up(synced):
    late = EVENTS + [ev(datetime(2026, 10, 13, 11, tzinfo=UTC), "pat@example.com", "auto", "c2", 100)]
    ingest.sync(synced, FakeClient(late), now=NOW)
    conn = db.connect(synced.db_path)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(late)


def test_summary_numbers(synced):
    s = usage.summary(db.connect(synced.db_path), "Pat@example.com", "2026-10", NOW)
    assert s["spent_dollars"] == 85.0
    assert s["limit_dollars"] == 200
    assert s["prompts"] == 4
    assert len(s["daily"]) == 14 and s["daily"][6] == {"date": "2026-10-07", "dollars": 30.0, "prompts": 1}
    # 85 / 13.5 days * 31 = 195.19 -> just under the limit
    assert s["projected_dollars"] == pytest.approx(195.19, abs=0.01)
    assert s["status"] == "watch"
    assert s["projected_reach_limit_date"] is None
    assert [m["model"] for m in s["by_model"]] == ["grok-4.7-xhigh-fast", "auto"]
    assert s["by_model"][0]["share"] == pytest.approx(70 / 85, abs=1e-4)
    top = s["top_chats"][0]
    assert top["conversation_id"] == "c1" and top["dollars"] == 70.0 and top["open_days"] == 2.0
    assert s["top_prompt"]["dollars"] == 40.0 and s["top_prompt"]["cache_read_tokens"] == 15_700_000


def test_over_limit(synced):
    s = usage.summary(db.connect(synced.db_path), "sam@example.com", "2026-10", NOW)
    assert s["status"] == "over_limit" and s["reached_limit_on"] == "2026-10-12"


def test_past_month_is_final(synced):
    s = usage.summary(db.connect(synced.db_path), "pat@example.com", "2026-09", NOW)
    assert s["spent_dollars"] == 5.0 and s["projected_dollars"] == 5.0 and len(s["daily"]) == 30


def test_api_dev_mode(synced):
    client = TestClient(create_app(synced, clock=lambda: NOW))
    assert client.get("/api/me").json()["email"] == "pat@example.com"
    r = client.get("/api/me/summary")
    assert r.status_code == 200 and r.json()["spent_dollars"] == 85.0
    assert client.get("/api/me/summary", params={"month": "2026-13"}).status_code == 422
    assert client.get("/api/admin/users").status_code == 403
    assert r.json()["org_name"] == "your organization"


def test_org_name(synced):
    client = TestClient(create_app(Settings(**{**synced.__dict__, "org_name": "ACME"}), clock=lambda: NOW))
    assert client.get("/api/me/summary").json()["org_name"] == "ACME"


def test_api_admin(synced):
    s = Settings(**{**synced.__dict__, "dev_user_email": "admin@example.com"})
    client = TestClient(create_app(s, clock=lambda: NOW))
    users = client.get("/api/admin/users").json()
    assert [u["email"] for u in users] == ["sam@example.com", "pat@example.com"]
    assert client.get("/api/admin/users/pat@example.com/summary").json()["spent_dollars"] == 85.0


def test_dev_users_only_with_flag(synced):
    admin = {**synced.__dict__, "dev_user_email": "admin@example.com"}
    off = TestClient(create_app(Settings(**admin), clock=lambda: NOW))
    assert off.get("/api/dev/users").status_code == 404
    assert off.get("/api/me").json()["dev_tools"] is False
    on = TestClient(create_app(Settings(**{**admin, "dev_tools": True}), clock=lambda: NOW))
    assert on.get("/api/me").json()["dev_tools"] is True
    users = on.get("/api/dev/users").json()
    assert [(u["name"], u["spent_dollars"]) for u in users] == [("Pat", 85.0), ("Sam", 250.0)]
    # non-admins never get it, even with the flag on
    pat = TestClient(create_app(Settings(**{**synced.__dict__, "dev_tools": True}), clock=lambda: NOW))
    assert pat.get("/api/dev/users").status_code == 403
    assert pat.get("/api/me").json()["dev_tools"] is False


def test_entra_mode_requires_token(synced):
    s = Settings(**{**synced.__dict__, "auth_mode": "entra", "entra_tenant_id": "t", "entra_audiences": ["api://x"]})
    client = TestClient(create_app(s, clock=lambda: NOW))
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_coach_tips(synced):
    c = usage.summary(db.connect(synced.db_path), "pat@example.com", "2026-10", NOW)["coach"]
    ids = [t["id"] for t in c["tips"]]
    # $70 on grok-4.7-xhigh-fast: the same money shows up as -fast, xhigh and one long chat
    assert set(ids) == {"long_chat", "fast", "max_effort"} and len(ids) <= 3
    fast = next(t for t in c["tips"] if t["id"] == "fast")
    assert fast["saving_dollars"] == pytest.approx(70 * 0.45) and fast["target"] == {"kind": "model", "ids": ["grok-4.7-xhigh-fast"]}
    assert "`grok-4.7-xhigh`" in fast["body"]
    chat = next(t for t in c["tips"] if t["id"] == "long_chat")
    assert chat["target"]["ids"] == ["c1"] and chat["actions"][0]["cmd"] == "how" and "/summarize" in chat["actions"][0]["text"]
    assert chat["actions"][0]["copy_text"].startswith("Summarise this chat")
    assert c["saving_month_dollars"] == pytest.approx(c["saving_dollars"] * 31 / 13.5, abs=0.01)


def test_coach_quiet_month(synced):
    c = usage.summary(db.connect(synced.db_path), "pat@example.com", "2026-09", NOW)["coach"]
    assert c["tips"] == []


def test_notices(synced):
    admin = TestClient(create_app(Settings(**{**synced.__dict__, "dev_user_email": "admin@example.com"}), clock=lambda: NOW))
    pat = TestClient(create_app(synced, clock=lambda: NOW))
    assert pat.post("/api/admin/notices", json={"text": "hi"}).status_code == 403
    a = admin.post("/api/admin/notices", json={"text": "Grok is no longer free."}).json()
    admin.post("/api/admin/notices", json={"text": "Just for Sam", "target": "Sam@example.com"})
    assert admin.post("/api/admin/notices", json={"text": "x", "target": "nobody"}).status_code == 422
    assert [n["text"] for n in pat.get("/api/me/summary").json()["notices"]] == ["Grok is no longer free."]
    assert len(admin.get("/api/admin/users/sam@example.com/summary").json()["notices"]) == 2
    assert admin.delete(f"/api/admin/notices/{a['id']}").status_code == 204
    assert pat.get("/api/me/summary").json()["notices"] == []


def test_model_updates(settings):
    free = []
    for i in range(60):   # a free period on grok-4.7 that ended on Oct 2
        e = ev(datetime(2026, 9, 25, 9, tzinfo=UTC) + (datetime(2026, 10, 2, tzinfo=UTC) - datetime(2026, 9, 25, tzinfo=UTC)) * i / 60,
               "pat@example.com", "grok-4.7-high", "c9", 0)
        e["kind"] = "Free"
        free.append(e)
    noise = ev(datetime(2026, 10, 5, 9, tzinfo=UTC), "sam@example.com", "claude-opus-5-5-high-fast", "c8", 0)
    noise["kind"] = "Free"   # one free prompt on another model is not a free period
    ingest.sync(settings, FakeClient(EVENTS + free + [noise]), now=NOW)
    conn = db.connect(settings.db_path)
    pat = usage.summary(conn, "pat@example.com", "2026-10", NOW)["model_updates"]
    assert [u["kind"] for u in pat] == ["free_ended"] and pat[0]["date"] == "2026-10-02" and "`grok-4.7`" in pat[0]["text"]
    assert usage.summary(conn, "sam@example.com", "2026-10", NOW)["model_updates"] == []   # never used it free


def test_token_breakdown_adds_up(synced):
    t = usage.summary(db.connect(synced.db_path), "pat@example.com", "2026-10", NOW)["tokens"]
    assert t["total_dollars"] == pytest.approx(85.0, abs=0.01)
    assert sum(r["dollars"] for r in t["rows"]) + t["other_dollars"] == pytest.approx(85.0, abs=0.02)
    assert [r["type"] for r in t["rows"]] == ["input", "cache_write", "cache_read", "output"]
    assert t["fast_what_if"] is None   # no normal-speed price to compare with yet


def test_fast_what_if(settings):
    # 30 prompts each on grok-4.7-high ($2/M input, $0.50/M cache reads) and its -fast version (twice the price)
    evs = []
    for i in range(30):
        for model, rate in (("grok-4.7-high", 1), ("grok-4.7-high-fast", 2)):
            e = ev(datetime(2026, 10, 10, 9, tzinfo=UTC) + (NOW - datetime(2026, 10, 10, 9, tzinfo=UTC)) * i / 31,
                   "pat@example.com", model, f"w{i}", 0)
            inp, cr = 100_000 + 7_000 * i, 1_000_000 + 90_000 * (i % 7)
            e["tokenUsage"].update(inputTokens=inp, cacheReadTokens=cr, outputTokens=0)
            e["chargedCents"] = rate * (inp * 2 + cr * 0.5) / 1e4
            evs.append(e)
    ingest.sync(settings, FakeClient(evs), now=NOW)
    s = usage.summary(db.connect(settings.db_path), "pat@example.com", "2026-10", NOW)
    w = s["tokens"]["fast_what_if"]
    assert w["from_model"] == "grok-4.7-high-fast" and w["to_model"] == "grok-4.7-high"
    assert w["normal_dollars"] == pytest.approx(w["actual_dollars"] / 2, rel=0.01)
    assert w["example"]["normal_cache_read"] == pytest.approx(0.5, abs=0.01) and w["example"]["fast_cache_read"] == pytest.approx(1.0, abs=0.01)
    cr = next(r for r in s["tokens"]["rows"] if r["type"] == "cache_read")
    assert cr["rate_per_m"] == pytest.approx(0.75, abs=0.01)   # half the tokens at $0.50, half at $1.00
    fast_tip = next(t for t in s["coach"]["tips"] if t["id"] == "fast")
    assert fast_tip["saving_dollars"] == pytest.approx(w["saving_dollars"], abs=0.01)   # tip and breakdown agree


def test_billing_cycle_periods(synced):
    from app import cycle
    a = cycle.Anchor(15, 17, 0, 0)          # a team whose cycle starts on the 15th at 17:00 UTC
    assert cycle.bounds("2026-10", a) == (datetime(2026, 10, 15, 17, tzinfo=UTC), datetime(2026, 11, 15, 17, tzinfo=UTC))
    assert cycle.current(datetime(2026, 10, 15, 16, tzinfo=UTC), a) == "2026-09"
    assert cycle.current(datetime(2026, 1, 3, tzinfo=UTC), a) == "2025-12"
    assert cycle.bounds("2026-02", cycle.Anchor(31))[0] == datetime(2026, 2, 28, tzinfo=UTC)   # short month
    conn = db.connect(synced.db_path)
    db.set_state(conn, "billing_cycle_start", "2026-09-10T00:00:00+00:00")
    conn.commit()
    client = TestClient(create_app(synced, clock=lambda: NOW))
    s = client.get("/api/me/summary").json()
    assert s["month"] == "2026-10" and s["period_start"].startswith("2026-10-10") and s["period_end"].startswith("2026-11-10")
    assert s["spent_dollars"] == 15.0 and s["days_in_month"] == 31   # only the two Oct 13 prompts are after Oct 10
    h = client.get("/health").json()
    assert h["period"] == "2026-10" and h["period_matches_cursor"] is False   # Cursor's stored start is last cycle's
    cal = TestClient(create_app(Settings(**{**synced.__dict__, "billing_cycle": "calendar"}), clock=lambda: NOW))
    assert cal.get("/api/me/summary").json()["period_start"].startswith("2026-10-01")


def test_model_versions():
    from app import rates
    assert rates.version("claude-opus-5-5") == ("claude-opus", (5, 5))
    assert rates.version("claude-4.6-opus") == ("claude-opus", (4, 6))
    assert rates.version("gpt-5.4-nano") == ("gpt-nano", (5, 4))
    assert rates.version("default") is None and rates.version("composer-2.5") == ("composer", (2, 5))


def test_older_version_tip():
    from app import coach
    rows = [{"model": m, "charged_cents": c, "conversation_id": None, "cache_read_tokens": 0}
            for m, c in [("claude-opus-5-thinking-high", 4000), ("claude-opus-5-thinking-high", 2000), ("auto", 1000)]]
    summary = {"top_chats": [], "tokens": None, "projected_dollars": 70, "is_current_month": False,
               "cost_per_prompt_7d": None, "team_median_cost_per_prompt_7d": None, "status": "ok", "limit_dollars": 200}
    team = {"newer": {"claude-opus-5": "claude-opus-5-5"}, "ratio": {"claude-opus-5": 0.7}, "current": {"claude-opus-5-5": "claude-opus"}}
    tip = next(t for t in coach.build(rows, summary, team)["tips"] if t["id"] == "legacy")
    assert tip["saving_dollars"] == pytest.approx(60 * 0.3) and "`claude-opus-5-5`" in tip["body"] and "30%" in tip["body"]
    # the same version priced the same is not a money tip
    same = {**team, "ratio": {"claude-opus-5": 0.97}}
    assert not any(t["id"] == "legacy" for t in coach.build(rows, summary, same)["tips"])
    # thresholds come from rules
    from app.rules import Rules, load_rules
    assert not any(t["id"] == "legacy" for t in coach.build(rows, summary, team, Rules(coach_older_model_min_dollars=100))["tips"])
    r = load_rules({"COACH_LONG_CHAT_PROMPTS": "25", "COACH_FAST_MIN_SHARE": "0.5"}.get)
    assert r.coach_long_chat_prompts == 25 and r.coach_fast_min_share == 0.5 and r.news_max_items == 3


def test_pace_and_list_rules(synced):
    from app.rules import Rules
    conn = db.connect(synced.db_path)
    s = usage.summary(conn, "pat@example.com", "2026-10", NOW, rules=Rules(pace_watch_share=0.99, summary_top_chats=1))
    assert s["status"] == "ok" and s["alerts"] == {"watch_share": 0.99}   # projected 195 of 200 is under 99%
    assert len(s["top_chats"]) == 1
    assert usage.summary(conn, "pat@example.com", "2026-10", NOW)["alerts"] == {"watch_share": 0.8}


def test_cache_write_models(settings):
    # model-a charges $4/M for cache writes, model-b writes cache but only charges for input
    evs = []
    for i in range(30):
        for model, cw_rate in (("model-a-1", 4.0), ("model-b-1", 0.0)):
            e = ev(datetime(2026, 10, 10, 9, tzinfo=UTC) + (NOW - datetime(2026, 10, 10, 9, tzinfo=UTC)) * i / 31,
                   "pat@example.com", model, f"cw{i}", 0)
            inp, cw = 100_000 + 5_000 * i, 200_000 + 30_000 * (i % 5)
            e["tokenUsage"].update(inputTokens=inp, cacheWriteTokens=cw, cacheReadTokens=0, outputTokens=0)
            e["chargedCents"] = (inp * 2 + cw * cw_rate) / 1e4
            evs.append(e)
    ingest.sync(settings, FakeClient(evs), now=NOW)
    t = usage.summary(db.connect(settings.db_path), "pat@example.com", "2026-10", NOW)["tokens"]
    assert t["cache_write_models"] == {"charged": ["model-a-1"], "free": ["model-b-1"]}
