"""Coaching, model-update and pace thresholds. Each one can be overridden by an environment variable named after
the field in upper case, for example COACH_LONG_CHAT_PROMPTS=25 or NEWS_NEW_MODEL_MIN_PROMPTS=50.

The team-wide prompt counts (COACH_CURRENT_MODEL_MIN_PROMPTS, NEWS_NEW_MODEL_MIN_PROMPTS, NEWS_FREE_MIN_PROMPTS)
assume a team of a hundred or more active people. A smaller team wants them lower, roughly in proportion.
"""
import os
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Rules:
    # coaching tips (coach.py)
    coach_max_tips: int = 3
    coach_max_keep: int = 2
    coach_long_chat_prompts: int = 20          # a chat past this many prompts (or open this many days) is "long"
    coach_long_chat_open_days: float = 1.0
    coach_long_chat_min_dollars: float = 5.0
    coach_long_chat_min_share: float = 0.15    # of the person's month...
    coach_long_chat_big_dollars: float = 25.0  # ...or at least this much
    coach_long_chat_saving: float = 0.5        # share of the excess a restart saves (summaries are re-read too)
    coach_min_saving_dollars: float = 1.0      # smaller savings aren't quoted
    coach_fast_min_share: float = 0.30
    coach_fast_fallback_saving: float = 0.45   # when the normal version has no fitted price yet
    coach_max_effort_min_share: float = 0.30
    coach_older_model_min_dollars: float = 20.0
    coach_older_model_min_cheaper: float = 0.10   # the newer version must be at least this much cheaper
    coach_current_model_days: int = 30            # window for which versions the team uses now
    coach_current_model_min_prompts: int = 200    # team prompts in that window before a version counts as current
    coach_big_context_tokens: int = 5_000_000
    coach_big_context_min_share: float = 0.30
    coach_max_saving_share: float = 0.6        # the header never claims more than this share of spend
    # good habits to keep (coach.py)
    coach_habit_min_prompts: int = 20          # fewer prompts in the month are too few to call anything a habit
    coach_short_chat_median: int = 15          # median chat length (prompts) that counts as short...
    coach_short_chat_min_chats: int = 5        # ...over at least this many chats of 2+ prompts
    coach_current_model_min_share: float = 0.30   # of spend on the newest versions...
    coach_current_model_max_older: float = 0.05   # ...with at most this much on older ones
    coach_effort_max_share: float = 0.10       # at most this much on max/xhigh...
    coach_effort_min_share: float = 0.30       # ...and at least this much on high/medium
    coach_no_fast_max_share: float = 0.05      # at most this much on -fast...
    coach_no_fast_min_chosen: float = 0.30     # ...and at least this much on models picked by hand (not Auto)
    coach_auto_min_prompts: int = 10
    # model updates (news.py)
    news_recent_days: int = 45
    news_new_model_min_prompts: int = 200      # team-wide, so a one-off trial doesn't count as news
    news_new_model_grace_days: int = 3         # models seen in the first days of the data aren't new, just new to us
    news_same_price_band: float = 0.10         # within this, a new version "costs about the same"
    news_fast_premium_min: float = 1.5         # mention the -fast price when it's at least this multiple
    news_free_min_prompts: int = 50
    news_free_share: float = 0.8
    news_max_items: int = 3
    # pace and alerts (usage.py, and the extension's alerts)
    pace_watch_share: float = 0.8              # "watch" when the projection, or an alert when the spend, reaches this
    team_median_min_prompts: int = 5           # people with fewer prompts in 7 days are left out of the team median
    summary_top_chats: int = 5
    summary_max_notices: int = 5


def load_rules(env=os.environ.get) -> Rules:
    values = {}
    for f in fields(Rules):
        raw = env(f.name.upper())
        if raw not in (None, ""):
            values[f.name] = int(float(raw)) if isinstance(f.default, int) else float(raw)
    return Rules(**values)
