//! Per-model, per-token-type pricing rates.
//!
//! Rates are expressed in **dollars per 1M tokens** (USD/MTok). The table is a
//! `const` slice — embedded in the binary, no I/O, no allocation. A user-
//! supplied `~/.burnwall/pricing.toml` override is loaded on top in a later
//! session (see `internal/SPEC.md` "Pricing Database").
//!
//! ### Model-name normalization
//!
//! Provider responses include date-suffixed model IDs (e.g.
//! `claude-sonnet-4-6-20250514`, `gpt-5.4-2026-01-15`). [`get_pricing`] matches
//! the longest known prefix followed by `-`, so a date suffix is transparent.
//! **Order in [`KNOWN_MODELS`] matters:** longer prefixes (e.g. `gpt-5.4-mini`)
//! must appear before shorter ones (`gpt-5.4`) or `gpt-5.4-mini-2026-...`
//! would mis-match the shorter entry first.
//!
//! ### Anthropic cache duration
//!
//! The rates below assume 5-minute cache write (1.25× input). The 1-hour
//! write rate (2× input) is signalled by `cache_control` in the **request**,
//! not the response, so we can't reliably tell from the response alone.
//! See `internal/SPEC.md` Pricing Notes for the trade-off.

/// Date the embedded rate card was last edited, `YYYY-MM-DD`. Bump
/// whenever you change [`KNOWN_MODELS`]. The status command warns the user
/// if this date is more than 30 days behind today.
pub const PRICING_LAST_UPDATED: &str = "2026-06-10";

/// USD per million tokens, broken out by token type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPricing {
    pub input_per_mtok: f64,
    pub cache_write_per_mtok: f64,
    pub cache_read_per_mtok: f64,
    pub output_per_mtok: f64,
}

pub const KNOWN_MODELS: &[(&str, ModelPricing)] = &[
    // ─────────── Anthropic (verified against the published rate card 2026-06-10) ───────────
    // Cache rates follow the standard Anthropic multipliers (write 1.25× input
    // for the 5-minute TTL, read 0.1× input). Legacy models are listed too:
    // they stay billable until retirement, and a pinned older model would
    // otherwise track as $0 — the most expensive miss is the worst one.
    (
        "claude-fable-5",
        ModelPricing {
            input_per_mtok: 10.00,
            cache_write_per_mtok: 12.50,
            cache_read_per_mtok: 1.00,
            output_per_mtok: 50.00,
        },
    ),
    (
        "claude-mythos-5",
        ModelPricing {
            input_per_mtok: 10.00,
            cache_write_per_mtok: 12.50,
            cache_read_per_mtok: 1.00,
            output_per_mtok: 50.00,
        },
    ),
    (
        "claude-opus-4-8",
        ModelPricing {
            input_per_mtok: 5.00,
            cache_write_per_mtok: 6.25,
            cache_read_per_mtok: 0.50,
            output_per_mtok: 25.00,
        },
    ),
    (
        "claude-opus-4-7",
        ModelPricing {
            input_per_mtok: 5.00,
            cache_write_per_mtok: 6.25,
            cache_read_per_mtok: 0.50,
            output_per_mtok: 25.00,
        },
    ),
    (
        "claude-opus-4-6",
        ModelPricing {
            input_per_mtok: 5.00,
            cache_write_per_mtok: 6.25,
            cache_read_per_mtok: 0.50,
            output_per_mtok: 25.00,
        },
    ),
    (
        "claude-opus-4-5",
        ModelPricing {
            input_per_mtok: 5.00,
            cache_write_per_mtok: 6.25,
            cache_read_per_mtok: 0.50,
            output_per_mtok: 25.00,
        },
    ),
    // Opus 4.1 and Opus 4 are deprecated but still billable — at 3× the
    // current Opus rate, so missing them would silently drop the priciest
    // traffic. Keyed as the alias (`-4-0`) plus the exact dated ID rather
    // than a bare `claude-opus-4` prefix, which would shadow-match every
    // future `claude-opus-4-9`-style release at the wrong rate.
    (
        "claude-opus-4-1",
        ModelPricing {
            input_per_mtok: 15.00,
            cache_write_per_mtok: 18.75,
            cache_read_per_mtok: 1.50,
            output_per_mtok: 75.00,
        },
    ),
    (
        "claude-opus-4-0",
        ModelPricing {
            input_per_mtok: 15.00,
            cache_write_per_mtok: 18.75,
            cache_read_per_mtok: 1.50,
            output_per_mtok: 75.00,
        },
    ),
    (
        "claude-opus-4-20250514",
        ModelPricing {
            input_per_mtok: 15.00,
            cache_write_per_mtok: 18.75,
            cache_read_per_mtok: 1.50,
            output_per_mtok: 75.00,
        },
    ),
    (
        "claude-sonnet-4-6",
        ModelPricing {
            input_per_mtok: 3.00,
            cache_write_per_mtok: 3.75,
            cache_read_per_mtok: 0.30,
            output_per_mtok: 15.00,
        },
    ),
    (
        "claude-sonnet-4-5",
        ModelPricing {
            input_per_mtok: 3.00,
            cache_write_per_mtok: 3.75,
            cache_read_per_mtok: 0.30,
            output_per_mtok: 15.00,
        },
    ),
    (
        "claude-sonnet-4-0",
        ModelPricing {
            input_per_mtok: 3.00,
            cache_write_per_mtok: 3.75,
            cache_read_per_mtok: 0.30,
            output_per_mtok: 15.00,
        },
    ),
    (
        "claude-sonnet-4-20250514",
        ModelPricing {
            input_per_mtok: 3.00,
            cache_write_per_mtok: 3.75,
            cache_read_per_mtok: 0.30,
            output_per_mtok: 15.00,
        },
    ),
    (
        "claude-haiku-4-5",
        ModelPricing {
            input_per_mtok: 1.00,
            cache_write_per_mtok: 1.25,
            cache_read_per_mtok: 0.10,
            output_per_mtok: 5.00,
        },
    ),
    // ─────────── OpenAI (verified against the published rate card 2026-06-10) ───────────
    // No cache write cost — caching is automatic; cached input bills at 10% of
    // input. Tiered long-context pricing exists for the flagship models; this
    // flat card uses the standard (short-context) tier. `-pro` models have no
    // cached-input rate, so cache_read is 0 there.
    // Ordering: `gpt-5.5-pro` before `gpt-5.5`; mini/nano/pro before `gpt-5.4`.
    (
        "gpt-5.5-pro",
        ModelPricing {
            input_per_mtok: 30.00,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.0,
            output_per_mtok: 180.00,
        },
    ),
    (
        "gpt-5.5",
        ModelPricing {
            input_per_mtok: 5.00,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.50,
            output_per_mtok: 30.00,
        },
    ),
    (
        "gpt-5.4-mini",
        ModelPricing {
            input_per_mtok: 0.75,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.075,
            output_per_mtok: 4.50,
        },
    ),
    (
        "gpt-5.4-nano",
        ModelPricing {
            input_per_mtok: 0.20,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.02,
            output_per_mtok: 1.25,
        },
    ),
    (
        "gpt-5.4-pro",
        ModelPricing {
            input_per_mtok: 30.00,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.0,
            output_per_mtok: 180.00,
        },
    ),
    (
        "gpt-5.4",
        ModelPricing {
            input_per_mtok: 2.50,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.25,
            output_per_mtok: 15.00,
        },
    ),
    // The Codex CLI's dedicated model — high-volume agentic coding traffic.
    (
        "gpt-5.3-codex",
        ModelPricing {
            input_per_mtok: 1.75,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.175,
            output_per_mtok: 14.00,
        },
    ),
    // ─────────── Google Gemini (verified against the published rate card 2026-06-10) ───────────
    // Implicit caching — no explicit cache-write cost on the response path
    // (the per-hour cache-storage fee is not response-derivable and is not
    // modeled). Tiered >200k-prompt pricing exists on the pro models; this
    // flat card uses the standard ≤200k tier.
    // Longest prefixes first: `-flash-lite` before `-flash`, `-pro` / `-flash`
    // before any shorter family key, per the module docs.
    (
        "gemini-3.5-flash",
        ModelPricing {
            input_per_mtok: 1.50,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.15,
            output_per_mtok: 9.00,
        },
    ),
    // Catches the `gemini-3.1-pro-preview` ID via the `-` suffix rule.
    (
        "gemini-3.1-pro",
        ModelPricing {
            input_per_mtok: 2.00,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.20,
            output_per_mtok: 12.00,
        },
    ),
    (
        "gemini-3.1-flash-lite",
        ModelPricing {
            input_per_mtok: 0.25,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.025,
            output_per_mtok: 1.50,
        },
    ),
    // Catches the `gemini-3-flash-preview` ID via the `-` suffix rule.
    (
        "gemini-3-flash",
        ModelPricing {
            input_per_mtok: 0.50,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.05,
            output_per_mtok: 3.00,
        },
    ),
    (
        "gemini-2.5-pro",
        ModelPricing {
            input_per_mtok: 1.25,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.125,
            output_per_mtok: 10.00,
        },
    ),
    (
        "gemini-2.5-flash-lite",
        ModelPricing {
            input_per_mtok: 0.10,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.01,
            output_per_mtok: 0.40,
        },
    ),
    (
        "gemini-2.5-flash",
        ModelPricing {
            input_per_mtok: 0.30,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.03,
            output_per_mtok: 2.50,
        },
    ),
    (
        "gemini-2.0-flash",
        ModelPricing {
            input_per_mtok: 0.10,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.025,
            output_per_mtok: 0.40,
        },
    ),
];

/// Look up pricing for a model name. Matches exact name or `name-<suffix>` so
/// date-stamped IDs from provider responses resolve to their canonical entry.
/// Returns `None` for unknown models — callers must handle this (the proxy
/// logs and stores cost = unknown rather than crashing; see fail-open policy).
///
/// User-supplied overrides from `~/.burnwall/pricing.toml` (see
/// [`super::overrides`]) are consulted **first**, so an override wins over the
/// built-in card for the same model and a brand-new model can be priced without
/// a release. The override table lives in a process-global `OnceLock`, so the
/// returned reference is still `'static`.
pub fn get_pricing(model: &str) -> Option<&'static ModelPricing> {
    get_pricing_with(model, super::overrides::table())
}

/// Like [`get_pricing`], but searches `overrides` ahead of the built-in card.
/// Split out so the precedence + longest-prefix logic is unit-testable without
/// touching the process-global override table. Built-in entries are `'static`
/// and coerce to the override lifetime `'a`.
pub fn get_pricing_with<'a>(
    model: &str,
    overrides: &'a [(String, ModelPricing)],
) -> Option<&'a ModelPricing> {
    if let Some(p) = match_prefix(model, overrides) {
        return Some(p);
    }
    match_prefix(model, KNOWN_MODELS)
}

/// Find the entry whose key equals `model` or is a prefix of it followed by
/// `-` (date-suffix tolerance: `claude-sonnet-4-6-20250514`) or `[` (variant
/// tags: Claude Code requests the 1M-context tier as `claude-fable-5[1m]`).
/// Generic over `&str`/`String` keys so the same logic serves both the
/// `const` card and a loaded override table. Callers must order the table
/// longest-key-first for correct disambiguation.
fn match_prefix<'a, K: AsRef<str>>(
    model: &str,
    table: &'a [(K, ModelPricing)],
) -> Option<&'a ModelPricing> {
    for (key, pricing) in table {
        let key = key.as_ref();
        if model == key {
            return Some(pricing);
        }
        if let Some(rest) = model.strip_prefix(key) {
            if rest.starts_with('-') || rest.starts_with('[') {
                return Some(pricing);
            }
        }
    }
    None
}
