"""What each model costs per million tokens, fitted from what Cursor actually charged.

Cursor's usage events carry token counts by type and the charge, but not the price list. For each model
we fit charged = input*a + cache_write*b + cache_read*c + output*d with no negative rates, over recent
charged events. The fitted rates include any per-token fee Cursor adds on top of the model provider's price,
so they are what a token actually costs against a person's limit.

The sums the fit needs are additive, so a model family's rates come from adding its models' sums.
"""
import itertools
import re
import sqlite3

TYPES = ("input", "cache_write", "cache_read", "output")
COLS = ("input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens")
MIN_EVENTS = 20
FIT_DAYS = 30
FIT_WINDOWS = (7, 14, FIT_DAYS)
PREFER_EVENTS = 100   # use a shorter window once it has this many charged prompts
DAY_MS = 86_400_000


def family(model: str | None) -> str:
    """'claude-opus-5-5-xhigh' -> 'claude-opus-5-5'; 'grok-4.7-high-fast' -> 'grok-4.7'."""
    return re.sub(r"(-thinking)?(-(low|medium|high|xhigh|max))?(-thinking)?(-fast)?$", "", model or "")


_NUM = re.compile(r"^\d+(?:\.\d+)*$")


def version(fam: str | None) -> tuple[str, tuple[int, ...]] | None:
    """A family's name without its version, and the version: 'claude-opus-5-5' and 'claude-4.6-opus' ->
    ('claude-opus', (5, 5)) and ('claude-opus', (4, 6)); 'gpt-5.4-nano' -> ('gpt-nano', (5, 4)). None if unversioned."""
    parts = (fam or "").split("-")
    nums = [i for i, p in enumerate(parts) if _NUM.match(p)]
    if not nums:
        return None
    run = [nums[0]]                       # the first run of numeric parts is the version
    for i in nums[1:]:
        if i != run[-1] + 1:
            break
        run.append(i)
    stem = "-".join(p for i, p in enumerate(parts) if i not in run)
    return (stem, tuple(int(x) for i in run for x in parts[i].split("."))) if stem else None


def model_sums(conn: sqlite3.Connection, since_ms: int, until_ms: int, models: list[str] | None = None) -> dict[str, dict]:
    """Per model: event count, token totals by type (millions) and the sums for a least-squares fit."""
    x = [f"COALESCE({c}, 0) / 1e6" for c in COLS]
    y = "charged_cents / 100.0"
    xtx = [f"SUM(({x[i]}) * ({x[j]}))" for i in range(4) for j in range(4)]
    xty = [f"SUM(({x[i]}) * {y})" for i in range(4)]
    tot = [f"SUM({x[i]})" for i in range(4)]
    where, args = "charged_cents > 0 AND ts >= ? AND ts < ?", [since_ms, until_ms]
    if models:
        where += f" AND model IN ({', '.join('?' * len(models))})"
        args += models
    rows = conn.execute(f"SELECT model, COUNT(*) AS n, SUM({y} * {y}) AS yty, {', '.join(xtx + xty + tot)} "
                        f"FROM events WHERE {where} GROUP BY model", args).fetchall()
    out = {}
    for r in rows:
        v = list(r)[3:]
        out[r["model"]] = {"n": r["n"], "yty": r["yty"], "xtx": [v[i * 4:(i + 1) * 4] for i in range(4)],
                           "xty": v[16:20], "tokens": v[20:24]}
    return out


def add(sums: list[dict]) -> dict:
    return {"n": sum(s["n"] for s in sums), "yty": sum(s["yty"] for s in sums),
            "xtx": [[sum(s["xtx"][i][j] for s in sums) for j in range(4)] for i in range(4)],
            "xty": [sum(s["xty"][i] for s in sums) for i in range(4)],
            "tokens": [sum(s["tokens"][i] for s in sums) for i in range(4)]}


def _solve(a: list[list[float]], b: list[float]) -> list[float] | None:
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(m[r][c]))
        if abs(m[p][c]) < 1e-12:
            return None
        m[c], m[p] = m[p], m[c]
        for r in range(n):
            if r != c:
                f = m[r][c] / m[c][c]
                m[r] = [m[r][k] - f * m[c][k] for k in range(n + 1)]
    return [m[i][n] / m[i][i] for i in range(n)]


def fit(s: dict) -> list[float] | None:
    """Non-negative $/M rates for the four token types, or None with too few events."""
    if s["n"] < MIN_EVENTS:
        return None
    used = [i for i in range(4) if s["tokens"][i] > 0]
    best = None
    for k in range(1, len(used) + 1):
        for cols in itertools.combinations(used, k):
            coef = _solve([[s["xtx"][i][j] for j in cols] for i in cols], [s["xty"][i] for i in cols])
            if coef is None or min(coef) < 0:
                continue
            f = [0.0] * 4
            for i, c in zip(cols, coef):
                f[i] = c
            sse = s["yty"] - 2 * sum(f[i] * s["xty"][i] for i in range(4)) + \
                sum(f[i] * s["xtx"][i][j] * f[j] for i in range(4) for j in range(4))
            if best is None or sse < best[0]:
                best = (sse, f)
    return best[1] if best else None


def cost_per_million(rates: list[float], mix: list[float]) -> float:
    """$ per million tokens for a token mix (shares of each type)."""
    return sum(r * m for r, m in zip(rates, mix))


def mix(tokens: list[float]) -> list[float]:
    t = sum(tokens)
    return [x / t for x in tokens] if t else [0.0] * 4


_fits_cache: dict = {}


def team_fits(conn: sqlite3.Connection, until_ms: int, sync_key: str | None) -> dict:
    """Rates for every model and model family as of until_ms (last 7, 14 or 30 days), cached per sync and hour.

    {"model": {model: rates or None}, "family": {family: {"normal": (rates, tokens), "fast": (rates, tokens)}}}
    """
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    key = (path, sync_key, until_ms // 3_600_000)
    if key in _fits_cache:
        return _fits_cache[key]
    # the most recent window with enough prompts, so a price change (like the end of a free period) ages out fast
    windows = [model_sums(conn, until_ms - d * DAY_MS, until_ms) for d in FIT_WINDOWS]
    sums = {}
    for model in windows[-1]:
        sums[model] = next((w[model] for w in windows if model in w and w[model]["n"] >= PREFER_EVENTS), windows[-1][model])
    groups: dict = {}
    for model, s in sums.items():
        groups.setdefault(family(model), {"normal": [], "fast": []})["fast" if model.endswith("-fast") else "normal"].append(s)
    fams = {}
    for fam, g in groups.items():
        fams[fam] = {}
        for speed, members in g.items():
            total = add(members) if members else None
            fams[fam][speed] = (fit(total), total["tokens"]) if total else (None, None)
    out = {"model": {m: fit(s) for m, s in sums.items()}, "family": fams}
    if len(_fits_cache) > 32:
        _fits_cache.clear()
    _fits_cache[key] = out
    return out


def rates_for(model: str | None, fits: dict) -> list[float] | None:
    """The model's own fit, else its family's at the same speed."""
    if model and fits["model"].get(model):
        return fits["model"][model]
    speed = "fast" if (model or "").endswith("-fast") else "normal"
    return fits["family"].get(family(model), {}).get(speed, (None, None))[0]
