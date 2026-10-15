"""Coaching for one person's month: up to 3 habits to change, and up to 2 good habits to keep.

Worked out from the person's own events.
Each bad habit has a good counterpart (long chats / short chats, -fast / normal speed, max effort /
high effort, an older model version / the newest one), so most people also see something they're doing right.

Savings are rough and only given where the usage data gives a basis for them:
  -fast         the same tokens priced at the normal version's fitted rates (tokens.py), else a fixed share
  older version the same tokens priced at the newest version's fitted rates, after any -fast saving
  long chat     part of what prompts after the Nth cost above the chat's own first-N average
The header total stacks them on what's left after each one and is capped at a share of spend.
Thresholds are in rules.py and can be set per deployment.
"""
import re
import statistics
from collections import defaultdict

from . import rates
from .rules import Rules

MAX_EFFORT_RE = re.compile(r"xhigh|-max\b|-max-")

RESTART_PROMPT = (
    "Summarise this chat so I can continue in a new one: the goal, the decisions we made, what has changed "
    "so far (files and functions), what is still open, and the next step. Keep it under 300 words."
)
HOW_CHANGE_MODEL = (
    "In the chat box, click the model name under the message box and pick {to}. The choice sticks for new "
    "chats. Switching models inside a long chat makes the new model re-read the whole chat, so switch at the "
    "start of a chat."
)
HOW_COMPACT = (
    "1. Same task, carrying on: type /summarize in that chat. Cursor compresses the earlier conversation into a "
    "summary, so later prompts re-send the summary instead of all {prompts} prompts.\n\n"
    "2. New task: start a new chat. If you need the old one, type @, choose Chats and pick it.\n\n"
    "3. Keep an eye on it: the context ring next to the chat input shows how full the chat is (click it for a "
    "breakdown). Cursor only summarizes on its own when the chat is close to full, so summarize at about "
    "{restart} prompts instead of waiting."
)
HOW_SMALL_CONTEXT = (
    "1. Start a new chat for each task, and attach only the files the task needs.\n\n"
    "2. Ask for a short plan before the agent starts editing.\n\n"
    "3. When a chat gets long, type /summarize in it, or start a new chat and add the old one with @ > Chats.\n\n"
    "The context ring next to the chat input shows how full a chat is."
)


def _d(cents: float) -> float:
    return round(cents / 100, 2)


def _money(dollars: float) -> str:
    return f"${dollars:,.0f}" if dollars >= 10 else f"${dollars:,.2f}"


def _pct(share: float) -> str:
    return f"{share:.0%}"


def _restart_excess(events: list, after: int) -> float:
    """Cents spent on prompts after the first `after` above the chat's own average for those."""
    if len(events) <= after:
        return 0.0
    base = statistics.mean(e["charged_cents"] for e in events[:after])
    return sum(max(0.0, e["charged_cents"] - base) for e in events[after:])


def build(rows: list, summary: dict, team: dict | None = None, rules: Rules = Rules()) -> dict:
    """rows: this period's events for the person, oldest first. summary: usage.summary() without coaching.
    team: news.team_view(), the model versions the team has moved to and their prices."""
    team = team or {"newer": {}, "ratio": {}, "current": {}}
    r_ = rules
    total = sum(r["charged_cents"] for r in rows)
    out = {"tips": [], "keep_doing": [], "saving_dollars": 0.0, "saving_month_dollars": 0.0,
           "long_chat_prompts": r_.coach_long_chat_prompts}
    if total <= 0:
        return out

    by_model = defaultdict(float)
    by_chat = defaultdict(list)
    for r in rows:
        by_model[r["model"] or "unknown"] += r["charged_cents"]
        if r["conversation_id"]:
            by_chat[r["conversation_id"]].append(r)
    tips = []

    # 1. a long chat
    top = summary["top_chats"][0] if summary["top_chats"] else None
    if top and top["dollars"] >= r_.coach_long_chat_min_dollars \
            and (top["share"] >= r_.coach_long_chat_min_share or top["dollars"] >= r_.coach_long_chat_big_dollars) \
            and (top["prompts_total"] >= r_.coach_long_chat_prompts or top["open_days"] >= r_.coach_long_chat_open_days):
        days = round(top["open_days"])
        age = f"{days} day{'s' if days != 1 else ''} old" if days >= 1 else "open today"
        excess = _restart_excess(by_chat[top["conversation_id"]], r_.coach_long_chat_prompts)
        tips.append({
            "id": "long_chat", "severity": "crit", "title": "One chat is costing you the most",
            "body": f"Your chat from {{chat_started}} is {age} with {top['prompts_total']} prompts, "
                    f"{_pct(top['share'])} of your month. Every new prompt re-reads all of them. "
                    f"Type `/summarize` in it, or start a new chat for the next task.",
            "chat_started": top["started"], "at_stake_dollars": top["dollars"],
            "saving_dollars": _d(excess * r_.coach_long_chat_saving)
            if excess * r_.coach_long_chat_saving >= r_.coach_min_saving_dollars * 100 else None,
            "pill": {"dollars": top["dollars"], "saving": False, "title": "What this chat has cost this month"},
            "target": {"kind": "chat", "ids": [top["conversation_id"]]},
            "actions": [{"cmd": "how", "label": "How to compact", "title": "Shrink a long chat", "primary": True,
                         "text": HOW_COMPACT.format(prompts=top["prompts_total"], restart=r_.coach_long_chat_prompts),
                         "copy_label": "Copy restart prompt", "copy_text": RESTART_PROMPT},
                        {"cmd": "see", "label": "See in breakdown"}],
        })

    # 2. -fast variants
    fast = {m: c for m, c in by_model.items() if "-fast" in m}
    fast_cents = sum(fast.values())
    if fast_cents / total >= r_.coach_fast_min_share:
        m = max(fast, key=fast.get)
        to = m.replace("-fast", "")
        what_if = (summary.get("tokens") or {}).get("fast_what_if")
        saving = what_if["saving_dollars"] * 100 if what_if else fast_cents * r_.coach_fast_fallback_saving
        less = f"about {_pct(what_if['saving_dollars'] / what_if['actual_dollars'])} less" if what_if else "less"
        tips.append({
            "id": "fast", "severity": "warn", "title": "You're paying for `-fast`",
            "body": f"{_pct(fast_cents / total)} of your spend is on `-fast` models, mostly `{m}`. "
                    f"`{to}` does the same work for {less}.",
            "at_stake_dollars": _d(fast_cents), "saving_dollars": _d(saving),
            "pill": {"dollars": _d(saving), "saving": True, "title": "Rough saving this month on the normal model"},
            "target": {"kind": "model", "ids": sorted(fast)},
            "actions": [{"cmd": "how", "label": "How to change model", "text": HOW_CHANGE_MODEL.format(to=f"`{to}`")},
                        {"cmd": "see", "label": "See in breakdown"}],
        })

    # 3. max / xhigh effort
    maxed = {m: c for m, c in by_model.items() if MAX_EFFORT_RE.search(m)}
    max_cents = sum(maxed.values())
    if max_cents / total >= r_.coach_max_effort_min_share:
        m = max(maxed, key=maxed.get)
        tips.append({
            "id": "max_effort", "severity": "warn", "title": "You lean on max effort",
            "body": f"{_pct(max_cents / total)} of your spend is on max or xhigh models, mostly `{m}`. "
                    f"Use high effort by default and turn it up only for one hard task.",
            "at_stake_dollars": _d(max_cents), "saving_dollars": None,
            "pill": {"dollars": _d(max_cents), "saving": False, "title": "Spent on max or xhigh models this month"},
            "target": {"kind": "model", "ids": sorted(maxed)},
            "actions": [{"cmd": "how", "label": "How to change model", "text": HOW_CHANGE_MODEL.format(to="the high version")},
                        {"cmd": "see", "label": "See in breakdown"}],
        })

    # 4. an older version of a model the team has moved on from, when the newest one is cheaper
    cheaper = 1 - r_.coach_older_model_min_cheaper
    legacy = {m: c for m, c in by_model.items()
              if rates.family(m) in team["newer"] and (team["ratio"].get(rates.family(m)) or 9) <= cheaper}
    legacy_cents = sum(legacy.values())
    if legacy and legacy_cents >= r_.coach_older_model_min_dollars * 100:
        # on an older -fast model, the -fast tip already takes its share off, so this one counts from what's left
        fast_left = 1 - r_.coach_fast_fallback_saving
        saving = sum(c * (1 - team["ratio"][rates.family(m)]) * (fast_left if "-fast" in m else 1) for m, c in legacy.items())
        top_m = max(legacy, key=legacy.get)
        old, new = rates.family(top_m), team["newer"][rates.family(top_m)]
        tips.append({
            "id": "legacy", "severity": "warn", "title": "You're on an older version",
            "body": f"{_money(_d(legacy_cents))} this month went to older versions, mostly `{top_m}`. "
                    f"`{new}` is newer and about {_pct(1 - team['ratio'][old])} cheaper for the same tokens.",
            "at_stake_dollars": _d(legacy_cents), "saving_dollars": _d(saving),
            "pill": {"dollars": _d(saving), "saving": True, "title": f"Rough saving this month on {new}"},
            "target": {"kind": "model", "ids": sorted(legacy)},
            "actions": [{"cmd": "how", "label": "How to change model", "text": HOW_CHANGE_MODEL.format(to=f"`{new}`")},
                        {"cmd": "see", "label": "See in breakdown"}],
        })

    # 5. huge context (only when no single chat explains it)
    big = r_.coach_big_context_tokens
    big_label = f"{big / 1e6:g}M"
    big_cents = sum(r["charged_cents"] for r in rows if (r["cache_read_tokens"] or 0) > big)
    if big_cents / total >= r_.coach_big_context_min_share and not any(t["id"] == "long_chat" for t in tips):
        biggest = max(rows, key=lambda r: r["cache_read_tokens"] or 0)
        tips.append({
            "id": "big_context", "severity": "warn", "title": "Your prompts re-read a lot of history",
            "body": f"{_pct(big_cents / total)} of your spend came from prompts that re-read over {big_label} tokens. "
                    f"The biggest re-read {(biggest['cache_read_tokens'] or 0) / 1e6:,.0f}M.",
            "at_stake_dollars": _d(big_cents), "saving_dollars": None,
            "pill": {"dollars": _d(big_cents), "saving": False, "title": f"Spent on prompts that re-read over {big_label} tokens"},
            "target": None,
            "actions": [{"cmd": "how", "label": "How to keep it small", "title": "Keep a chat's context small", "text": HOW_SMALL_CONTEXT},
                        {"cmd": "see", "label": "See in breakdown"}],
        })

    tips.sort(key=lambda t: -t["at_stake_dollars"])
    tips = tips[:r_.coach_max_tips]
    # stack the savings: each one applies to what the earlier ones leave
    left = total / 100
    for s in sorted((t["saving_dollars"] for t in tips if t["saving_dollars"]), reverse=True):
        left -= s * left / (total / 100)
    saving = min(total / 100 - left, r_.coach_max_saving_share * total / 100)
    scale = summary["projected_dollars"] / (total / 100) if summary["is_current_month"] else 1
    out.update(tips=tips, saving_dollars=round(saving, 2), saving_month_dollars=round(saving * scale, 2))

    out["keep_doing"] = _keep_doing(rows, by_model, by_chat, total, summary, {t["id"] for t in tips}, team, r_)
    return out


def _keep_doing(rows, by_model, by_chat, total, summary, tip_ids, team, r_) -> list[dict]:
    """Good habits worth encouraging, most useful first. Never praises what a tip criticises."""
    keep = []
    share = lambda pred: sum(c for m, c in by_model.items() if pred(m)) / total
    enough = len(rows) >= r_.coach_habit_min_prompts   # too few prompts to call anything a habit

    sizes = sorted(len(v) for v in by_chat.values() if len(v) >= 2)   # one-prompt chats say little about habits
    if len(sizes) >= r_.coach_short_chat_min_chats and statistics.median(sizes) <= r_.coach_short_chat_median:
        exception = " The long chat above is the exception." if "long_chat" in tip_ids else ""
        keep.append({"id": "short_chats", "title": "Short, focused chats",
                     "body": f"Half of your {len(sizes)} chats this month finished within {statistics.median(sizes):.0f} prompts.{exception}"})
    # on the newest version of a model that has older versions in use
    current = defaultdict(float)
    for m, c in by_model.items():
        if rates.family(m) in team["current"]:
            current[rates.family(m)] += c
    if "legacy" not in tip_ids and current and sum(current.values()) / total >= r_.coach_current_model_min_share \
            and share(lambda m: rates.family(m) in team["newer"]) <= r_.coach_current_model_max_older:
        fam = max(current, key=current.get)
        keep.append({"id": "current_model", "title": "On the newest version",
                     "body": f"Your `{team['current'][fam]}` prompts use `{fam}`, the newest version in use here."})
    if "max_effort" not in tip_ids and enough and share(lambda m: bool(MAX_EFFORT_RE.search(m))) <= r_.coach_effort_max_share \
            and share(lambda m: "-high" in m or "-medium" in m) >= r_.coach_effort_min_share:
        keep.append({"id": "effort", "title": "High effort, not max",
                     "body": "Most of your spend is on high or medium effort. Save max and xhigh for the one hard task."})
    if "fast" not in tip_ids and enough and share(lambda m: "-fast" in m) <= r_.coach_no_fast_max_share \
            and share(lambda m: m != "auto") >= r_.coach_no_fast_min_chosen:
        keep.append({"id": "no_fast", "title": "Normal speed, not -fast",
                     "body": "You rarely use `-fast` models, which cost more for the same work."})
    auto = [r for r in rows if (r["model"] or "") == "auto"]
    if len(auto) >= r_.coach_auto_min_prompts:
        avg = _d(sum(r["charged_cents"] for r in auto) / len(auto))
        keep.append({"id": "auto", "title": "Using Auto",
                     "body": f"{len(auto)} prompts on Auto at {_money(avg)} each on average. That's the cheapest way to work."})
    mine, team = summary["cost_per_prompt_7d"], summary["team_median_cost_per_prompt_7d"]
    if mine is not None and team is not None and mine <= team:
        keep.append({"id": "per_prompt", "title": "Cheaper than most per prompt",
                     "body": f"{_money(mine)} per prompt over the last 7 days. The team median is {_money(team)}."})
    if summary["is_current_month"] and summary["status"] == "ok":
        keep.append({"id": "on_pace", "title": "On track for the month",
                     "body": f"On pace for {_money(summary['projected_dollars'])} of your {_money(summary['limit_dollars'])}."})
    return keep[:r_.coach_max_keep]
