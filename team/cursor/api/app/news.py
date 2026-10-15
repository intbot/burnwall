"""Model updates worked out from the organization's own usage, shown under "Model updates" in the sidebar.
The date is shown above each item, so the text doesn't repeat it.

Cursor's Admin API has no model or price list, so these come from the usage events:
  new model   a model family first used in the organization in the last NEWS_RECENT_DAYS, compared with the version before it
  free ended  a family whose prompts were free and are now charged (shown to people who used it free)
Prices come from rates.py, so comparisons are for the same tokens at the newer model's usual token mix.
team_view() gives coaching the same picture: which versions the team has moved to, and what they cost.
Thresholds are in rules.py.
"""
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

from . import rates
from .rules import Rules

DAY_MS = 86_400_000
_cache: dict = {}


def _date(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).date().isoformat()


def _pct(x: float) -> int:
    return int(round(x * 100 / 5) * 5)


def _team(conn: sqlite3.Connection, now_ms: int, rules: Rules) -> dict:
    data_start = conn.execute("SELECT MIN(ts) FROM events").fetchone()[0] or now_ms
    first = defaultdict(lambda: [now_ms, 0])            # family -> [first ts, prompts]
    for r in conn.execute("SELECT model, MIN(ts) AS a, COUNT(*) AS n FROM events GROUP BY model"):
        f = first[rates.family(r["model"])]
        f[0], f[1] = min(f[0], r["a"]), f[1] + r["n"]
    recent = defaultdict(int)                           # family -> prompts in the last COACH_CURRENT_MODEL_DAYS
    for r in conn.execute("SELECT model, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY model",
                          (now_ms - rules.coach_current_model_days * DAY_MS,)):
        recent[rates.family(r["model"])] += r["n"]
    # a free period: almost every prompt on the family was free up to a date, and it has been charged since.
    # (A few free prompts on any model are normal, e.g. failed requests, and aren't a promo.)
    last_free = defaultdict(int)
    for r in conn.execute("SELECT model, MAX(ts) AS last FROM events WHERE kind = 'Free' GROUP BY model"):
        fam = rates.family(r["model"])
        last_free[fam] = max(last_free[fam], r["last"])
    free = {}                                           # family -> last free ts
    for fam, last in last_free.items():
        models = [r["model"] for r in conn.execute("SELECT DISTINCT model FROM events") if rates.family(r["model"]) == fam]
        q = f"model IN ({', '.join('?' * len(models))})"
        n_free, n_all = conn.execute(f"SELECT SUM(kind = 'Free'), COUNT(*) FROM events WHERE {q} AND ts <= ?",
                                     (*models, last)).fetchone()
        charged = conn.execute(f"SELECT 1 FROM events WHERE {q} AND ts > ? AND charged_cents > 0 LIMIT 1", (*models, last)).fetchone()
        if charged and n_free >= rules.news_free_min_prompts and n_free >= rules.news_free_share * n_all:
            free[fam] = last
    fits = rates.team_fits(conn, now_ms, None)["family"]
    return {"data_start": data_start, "first": dict(first), "recent": dict(recent), "free": free, "fits": fits,
            **_lineup(dict(recent), fits, rules)}


def _price_ratio(fits: dict, new: str, old: str) -> float | None:
    """What the old family's usual tokens would cost on the new one, as a share of what they cost now."""
    (rn, _), (ro, to) = fits.get(new, {}).get("normal", (None, None)), fits.get(old, {}).get("normal", (None, None))
    if not rn or not ro:
        return None
    mx = rates.mix(to)
    return rates.cost_per_million(rn, mx) / rates.cost_per_million(ro, mx)


def _lineup(recent: dict, fits: dict, rules: Rules) -> dict:
    """The newest version of each model the team uses (enough recent prompts), and the older versions of it.
    newer: old family -> newest family; ratio: old family -> price ratio; current: newest family -> stem."""
    best = {}
    for fam, n in recent.items():
        v = rates.version(fam)
        if v and n >= rules.coach_current_model_min_prompts and (v[0] not in best or v[1] > best[v[0]][0]):
            best[v[0]] = (v[1], fam)
    newer, ratio = {}, {}
    for fam in recent:
        v = rates.version(fam)
        if v and v[0] in best and v[1] < best[v[0]][0]:
            newer[fam] = best[v[0]][1]
            ratio[fam] = _price_ratio(fits, newer[fam], fam)
    current = {new: stem for stem, (_, new) in best.items() if new in newer.values()}
    return {"newer": newer, "ratio": ratio, "current": current}


def _team_cached(conn: sqlite3.Connection, now: datetime, sync_key: str | None, rules: Rules) -> dict:
    now_ms = int(now.timestamp() * 1000)
    key = (str(conn.execute("PRAGMA database_list").fetchone()[2]), sync_key, now_ms // (DAY_MS // 24), rules)
    if _cache.get("key") != key:
        _cache.update(key=key, team=_team(conn, now_ms, rules))
    return _cache["team"]


def team_view(conn: sqlite3.Connection, now: datetime, sync_key: str | None, rules: Rules = Rules()) -> dict:
    t = _team_cached(conn, now, sync_key, rules)
    return {"newer": t["newer"], "ratio": t["ratio"], "current": t["current"]}


def _compare(fits: dict, new: str, old: str, rules: Rules) -> str:
    (rn, tn), (ro, _) = fits.get(new, {}).get("normal", (None, None)), fits.get(old, {}).get("normal", (None, None))
    if not rn or not ro:
        return ""
    mx = rates.mix(tn)
    change = rates.cost_per_million(rn, mx) / rates.cost_per_million(ro, mx) - 1
    if abs(change) < rules.news_same_price_band:
        return f" It costs about the same as `{old}`."
    return f" It costs about {_pct(abs(change))}% {'less' if change < 0 else 'more'} than `{old}` for the same tokens."


def _fast_premium(fits: dict, fam: str, rules: Rules) -> str:
    (rn, _), (rf, tf) = fits.get(fam, {}).get("normal", (None, None)), fits.get(fam, {}).get("fast", (None, None))
    if not rn or not rf:
        return ""
    ratio = rates.cost_per_million(rf, rates.mix(tf)) / rates.cost_per_million(rn, rates.mix(tf))
    return f" `-fast` versions cost about {round(ratio * 2) / 2:g}× the normal ones." if ratio >= rules.news_fast_premium_min else ""


def model_updates(conn: sqlite3.Connection, email: str, now: datetime, sync_key: str | None,
                  org_name: str = "your organization", rules: Rules = Rules()) -> list[dict]:
    now_ms = int(now.timestamp() * 1000)
    t = _team_cached(conn, now, sync_key, rules)
    recent = now_ms - rules.news_recent_days * DAY_MS
    mine, free_mine = defaultdict(float), set()        # this person's families, and the ones they used free
    for r in conn.execute("SELECT model, kind, SUM(charged_cents) AS c FROM events WHERE user_email = ? AND ts >= ? "
                          "GROUP BY model, kind", (email.lower(), recent)):
        mine[rates.family(r["model"])] += r["c"] or 0
        if r["kind"] == "Free":
            free_mine.add(rates.family(r["model"]))
    items = []   # (rank, item): what changed for a model you use first, then what's new

    versions = {f: rates.version(f) for f in t["first"]}
    for fam, (first_ts, n) in t["first"].items():
        if first_ts < max(recent, t["data_start"] + rules.news_new_model_grace_days * DAY_MS) or n < rules.news_new_model_min_prompts or not versions[fam]:
            continue
        stem, ver = versions[fam]
        older = [(v[1], f) for f, v in versions.items() if v and v[0] == stem and v[1] < ver]
        prev = max(older)[1] if older else None
        compare = _compare(t["fits"], fam, prev, rules) if prev else ""
        rank = 1 if fam in mine or prev in mine else 2
        items.append((rank, -mine.get(prev, 0), {"date": _date(first_ts), "kind": "new_model",
                      "text": f"New at {org_name}: `{fam}`.{compare}"}))

    # one line for the free periods that ended together, your most-used family first
    ended = sorted((f for f, last in t["free"].items() if last >= recent and f in free_mine), key=lambda f: -mine.get(f, 0))
    if ended:
        names = [f"`{f}`" for f in ended[:3]] + ([f"{len(ended) - 3} more"] if len(ended) > 3 else [])
        listed = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
        last = max(t["free"][f] for f in ended)
        items.append((0, 0, {"date": _date(last), "kind": "free_ended",
                      "text": f"{listed} {'is' if len(names) == 1 else 'are'} no longer free. Those prompts now count against your limit."
                              f"{_fast_premium(t['fits'], ended[0], rules)}"}))

    items.sort(key=lambda i: (i[0], i[1], -int(i[2]["date"].replace("-", ""))))   # most relevant to you first
    return sorted((i for *_, i in items[:rules.news_max_items]), key=lambda i: i["date"], reverse=True)   # shown newest first
