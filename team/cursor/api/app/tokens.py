"""Where a person's money went this month, by token type ("Where your money goes" in the breakdown tab).

Cursor reports each prompt's token counts by type and what it charged, but not how the charge splits
across the types. Each charge is split in proportion to that model's fitted rate for each type
(rates.py), so the cost column adds up to the actual spend. Free prompts are left out, and charges
that come with no token counts (usage corrections, reviews) are shown as "Other".

The -fast what-if prices the person's -fast prompts at the normal-speed version's fitted rates.
cache_write_models says which of the person's models charge for cache writes, from the same fits, so the
breakdown doesn't need a price list.
"""
from . import rates

FALLBACK = [1.0, 1.25, 0.1, 5.0]   # relative weights when a model has no fit yet; only the split uses them
FREE_RATE = 0.01                    # $/M below which a fitted rate counts as not charged
DAY_MS = 86_400_000


def _m(tokens: float) -> float:
    return round(tokens / 1e6, 3)


def breakdown(conn, rows: list, as_of_ms: int, sync_key: str | None) -> dict:
    """rows: the month's events for one person with token columns and charged_cents."""
    fits = rates.team_fits(conn, as_of_ms, sync_key)
    tok = [0.0] * 4
    cents = [0.0] * 4
    other = 0.0
    fast: dict[str, dict] = {}            # -fast model -> its tokens and charge this month
    cw: dict[str, list] = {}              # family -> [cents, charges for cache writes] for models that wrote cache
    for r in rows:
        c = r["charged_cents"] or 0
        if c <= 0:
            continue
        t = [r["input_tokens"] or 0, r["cache_write_tokens"] or 0, r["cache_read_tokens"] or 0, r["output_tokens"] or 0]
        if not any(t):
            other += c
            continue
        fitted = rates.rates_for(r["model"], fits)
        w = fitted or FALLBACK
        if fitted and t[1]:
            e = cw.setdefault(rates.family(r["model"]), [0.0, fitted[1] >= FREE_RATE])
            e[0] += c
        weights = [w[i] * t[i] for i in range(4)]
        total_w = sum(weights) or sum(t)
        for i in range(4):
            tok[i] += t[i]
            cents[i] += c * (weights[i] if sum(weights) else t[i]) / total_w
        if (r["model"] or "").endswith("-fast"):
            f = fast.setdefault(r["model"], {"tokens": [0.0] * 4, "cents": 0.0})
            f["tokens"] = [a + b for a, b in zip(f["tokens"], t)]
            f["cents"] += c

    total_tok, total_c = sum(tok), sum(cents) + other
    out_rows = [{"type": rates.TYPES[i], "tokens_m": _m(tok[i]), "dollars": round(cents[i] / 100, 2),
                 "rate_per_m": round(cents[i] / 100 / (tok[i] / 1e6), 2) if tok[i] else None} for i in range(4)]
    return {
        "rows": out_rows,
        "other_dollars": round(other / 100, 2),
        "total_tokens_m": _m(total_tok),
        "total_dollars": round(total_c / 100, 2),
        "fast_what_if": _fast_what_if(fast, fits),
        "cache_write_models": {k: [f for f, (_, paid) in sorted(cw.items(), key=lambda kv: -kv[1][0]) if paid == (k == "charged")]
                               for k in ("charged", "free")},
    }


def _fast_what_if(fast: dict, fits: dict) -> dict | None:
    """Same tokens on the normal-speed versions. Only models whose normal version has a fitted price count."""
    priced, actual, alt = [], 0.0, 0.0
    for model, f in sorted(fast.items(), key=lambda kv: -kv[1]["cents"]):
        normal = model[: -len("-fast")]
        r = rates.rates_for(normal, fits)
        if not r:
            continue
        cost = sum(r[i] * f["tokens"][i] / 1e6 for i in range(4))   # dollars
        priced.append((model, normal, f["cents"] / 100, cost))
        actual += f["cents"] / 100
        alt += cost
    if not priced or actual - alt < 1:
        return None
    top_model, top_normal, _, _ = priced[0]
    rf, rn = rates.rates_for(top_model, fits), rates.rates_for(top_normal, fits)
    return {
        "from_model": top_model if len(priced) == 1 else None, "to_model": top_normal if len(priced) == 1 else None,
        "models": [p[0] for p in priced],
        "actual_dollars": round(actual, 2), "normal_dollars": round(alt, 2), "saving_dollars": round(actual - alt, 2),
        # cache-read prices for the example in "How to read this"
        "example": {"fast_model": top_model, "normal_model": top_normal,
                    "fast_cache_read": round(rf[2], 2) if rf else None, "normal_cache_read": round(rn[2], 2) if rn else None},
    }
