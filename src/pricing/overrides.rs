//! User-supplied pricing overrides loaded from `~/.burnwall/pricing.toml`.
//!
//! The built-in rate card ([`super::rates::KNOWN_MODELS`]) is a `const` baked
//! into the binary, so a brand-new model or a mid-cycle price change otherwise
//! needs a full release. This module lets a user drop a local TOML file that
//! **overrides or extends** the built-in card without rebuilding — the escape
//! hatch the `status` staleness warning has always advertised.
//!
//! ### Format (`~/.burnwall/pricing.toml`)
//!
//! ```toml
//! # Rates are USD per 1,000,000 tokens. Cache fields are optional (default 0).
//! [[model]]
//! name = "claude-opus-4-9"
//! input_per_mtok = 5.00
//! cache_write_per_mtok = 6.25
//! cache_read_per_mtok = 0.50
//! output_per_mtok = 25.00
//!
//! [[model]]
//! name = "gpt-6"           # two-field minimum is enough
//! input_per_mtok = 2.50
//! output_per_mtok = 12.00
//! ```
//!
//! ### Semantics
//!
//! - Overrides are consulted **before** the built-in card, so an entry whose
//!   name matches a known model wins. A name the binary has never heard of is
//!   simply added.
//! - Matching uses the same longest-known-prefix-followed-by-`-` rule as the
//!   built-in card (date-suffix tolerance). We sort entries by descending key
//!   length on load, so the user never has to worry about ordering
//!   `gpt-6-mini` ahead of `gpt-6`.
//! - **Fail-open:** a missing file is fine (no overrides). A malformed file is
//!   surfaced to the caller (the binary prints a warning and continues with
//!   the built-in card) — a bad override never breaks cost tracking.
//!
//! The loaded table lives in a process-global [`OnceLock`]; because the lock is
//! itself `static`, references into it are `'static`, which lets
//! [`super::get_pricing`] keep its `&'static` return type and every existing
//! caller compile unchanged.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Deserialize;

use super::rates::ModelPricing;

/// One `[[model]]` entry in `pricing.toml`. Cache fields default to `0.0`
/// (matching how OpenAI/Gemini families are expressed in the built-in card —
/// no explicit cache-write cost).
#[derive(Debug, Clone, Deserialize)]
struct OverrideEntry {
    name: String,
    input_per_mtok: f64,
    #[serde(default)]
    cache_write_per_mtok: f64,
    #[serde(default)]
    cache_read_per_mtok: f64,
    output_per_mtok: f64,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OverrideFile {
    #[serde(default)]
    model: Vec<OverrideEntry>,
}

/// Process-global override table. Empty (never set) means "no overrides".
static USER_OVERRIDES: OnceLock<Vec<(String, ModelPricing)>> = OnceLock::new();

/// Parse the contents of a `pricing.toml` into a lookup table, sorted by
/// descending key length so the longest matching prefix wins regardless of the
/// order the user listed entries. Pure — no I/O, so it is fully unit-testable.
pub fn parse(toml_text: &str) -> Result<Vec<(String, ModelPricing)>, toml::de::Error> {
    let file: OverrideFile = toml::from_str(toml_text)?;
    let mut table: Vec<(String, ModelPricing)> = file
        .model
        .into_iter()
        .map(|e| {
            (
                e.name,
                ModelPricing {
                    input_per_mtok: e.input_per_mtok,
                    cache_write_per_mtok: e.cache_write_per_mtok,
                    cache_read_per_mtok: e.cache_read_per_mtok,
                    output_per_mtok: e.output_per_mtok,
                },
            )
        })
        .collect();
    // Longest key first → longest-prefix match without the user ordering
    // `gpt-6-mini` ahead of `gpt-6` by hand (see module docs / rates.rs).
    table.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));
    Ok(table)
}

/// Default location of the override file: `<data dir>/pricing.toml`
/// (i.e. `~/.burnwall/pricing.toml`, honoring `BURNWALL_DATA_DIR`).
pub fn override_path() -> Option<PathBuf> {
    crate::storage::data_dir().ok().map(|d| d.join("pricing.toml"))
}

/// Load the override file (if present) into the process-global table. Idempotent
/// — only the first call installs the table; later calls are no-ops.
///
/// Returns the number of override entries loaded (`0` when no file exists).
/// A malformed file is returned as an error; the binary logs it and proceeds
/// with the built-in card (fail-open).
pub fn init() -> Result<usize, OverrideError> {
    let Some(path) = override_path() else {
        let _ = USER_OVERRIDES.set(Vec::new());
        return Ok(0);
    };
    if !path.exists() {
        let _ = USER_OVERRIDES.set(Vec::new());
        return Ok(0);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| OverrideError::Read {
        path: path.clone(),
        source: e,
    })?;
    let table = parse(&text).map_err(|e| OverrideError::Parse {
        path: path.clone(),
        source: Box::new(e),
    })?;
    let count = table.len();
    let _ = USER_OVERRIDES.set(table);
    Ok(count)
}

/// The installed override table, or an empty slice if none was loaded.
pub fn table() -> &'static [(String, ModelPricing)] {
    USER_OVERRIDES.get().map(Vec::as_slice).unwrap_or(&[])
}

/// How many model price overrides are currently active.
pub fn count() -> usize {
    table().len()
}

/// A starter `pricing.toml` users can copy. Shown by `burnwall pricing path`.
pub fn sample_toml() -> String {
    "\
# Burnwall pricing override — rates in USD per 1,000,000 tokens.
# Entries here OVERRIDE the built-in rate card (matching model name) or ADD
# new models. Cache fields are optional and default to 0.

# [[model]]
# name = \"claude-opus-4-9\"
# input_per_mtok = 5.00
# cache_write_per_mtok = 6.25
# cache_read_per_mtok = 0.50
# output_per_mtok = 25.00

# [[model]]
# name = \"gpt-6\"
# input_per_mtok = 2.50
# output_per_mtok = 12.00
"
    .to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum OverrideError {
    #[error("reading pricing override {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing pricing override {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_entries_and_defaults_cache_fields() {
        let toml = r#"
[[model]]
name = "gpt-6"
input_per_mtok = 2.5
output_per_mtok = 12.0
"#;
        let table = parse(toml).expect("parse");
        assert_eq!(table.len(), 1);
        let (name, p) = &table[0];
        assert_eq!(name, "gpt-6");
        assert_eq!(p.input_per_mtok, 2.5);
        assert_eq!(p.output_per_mtok, 12.0);
        // Cache fields omitted → 0.0.
        assert_eq!(p.cache_write_per_mtok, 0.0);
        assert_eq!(p.cache_read_per_mtok, 0.0);
    }

    #[test]
    fn parse_sorts_longest_key_first() {
        let toml = r#"
[[model]]
name = "gpt-6"
input_per_mtok = 1.0
output_per_mtok = 1.0

[[model]]
name = "gpt-6-mini"
input_per_mtok = 0.1
output_per_mtok = 0.1
"#;
        let table = parse(toml).expect("parse");
        // Longest key must come first so prefix matching resolves the mini
        // variant before the base family.
        assert_eq!(table[0].0, "gpt-6-mini");
        assert_eq!(table[1].0, "gpt-6");
    }

    #[test]
    fn parse_empty_is_ok() {
        assert_eq!(parse("").expect("empty parse").len(), 0);
    }

    #[test]
    fn parse_rejects_malformed() {
        // Missing required `output_per_mtok`.
        let toml = r#"
[[model]]
name = "x"
input_per_mtok = 1.0
"#;
        assert!(parse(toml).is_err());
    }
}
