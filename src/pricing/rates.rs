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
pub const PRICING_LAST_UPDATED: &str = "2026-05-27";

/// USD per million tokens, broken out by token type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPricing {
    pub input_per_mtok: f64,
    pub cache_write_per_mtok: f64,
    pub cache_read_per_mtok: f64,
    pub output_per_mtok: f64,
}

pub const KNOWN_MODELS: &[(&str, ModelPricing)] = &[
    // ─────────── Anthropic (as of May 2026) ───────────
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
        "claude-sonnet-4-6",
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
    // ─────────── OpenAI (as of May 2026) ───────────
    // No cache write cost — caching is automatic.
    (
        "gpt-5.5",
        ModelPricing {
            input_per_mtok: 2.00,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 1.00,
            output_per_mtok: 10.00,
        },
    ),
    // `gpt-5.4-mini` MUST precede `gpt-5.4` (see module docs).
    (
        "gpt-5.4-mini",
        ModelPricing {
            input_per_mtok: 0.15,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.075,
            output_per_mtok: 0.60,
        },
    ),
    (
        "gpt-5.4",
        ModelPricing {
            input_per_mtok: 1.25,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.625,
            output_per_mtok: 10.00,
        },
    ),
    // ─────────── Google Gemini (as of May 2026) ───────────
    // Implicit caching — no explicit cache-write cost on the response path.
    // Longest prefixes first: `gemini-2.5-pro` / `-flash` before any shorter
    // family key, per the module docs.
    (
        "gemini-2.5-pro",
        ModelPricing {
            input_per_mtok: 1.25,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.3125,
            output_per_mtok: 10.00,
        },
    ),
    (
        "gemini-2.5-flash",
        ModelPricing {
            input_per_mtok: 0.30,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.075,
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
/// `-` (date-suffix tolerance). Generic over `&str`/`String` keys so the same
/// logic serves both the `const` card and a loaded override table. Callers must
/// order the table longest-key-first for correct disambiguation.
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
            if rest.starts_with('-') {
                return Some(pricing);
            }
        }
    }
    None
}
