//! Rule packs — shareable, declarative security-rule bundles (v0.6).
//!
//! A pack is a TOML file carrying only the primitives the engine already has:
//! `deny_paths`, `deny_commands`, and user-authored `secret_patterns`. It maps
//! onto the runtime [`Ruleset`] the same way a `.burnwall.yaml` project profile
//! does — by **extending** the deny lists.
//!
//! ### Security invariants (see internal design doc)
//! - **I1 — declarative only.** A pack is pure data: string lists + regexes.
//!   There is no field that holds code, so an installed pack can never execute
//!   anything.
//! - **I2 — deny-only / append-only.** [`RawPack`] has no `allow_paths` and no
//!   global toggle, and [`RulePack::apply_to_ruleset`] only ever *extends*. A
//!   pack can tighten security but never loosen it. Keys like `allow_paths` /
//!   `enabled` in a pack file are ignored (and warned about).
//! - **I3 — a bad pack never disables the engine.** [`RulePack::parse`] returns
//!   `None` on an oversized/malformed/over-count pack; a single bad
//!   `secret_patterns` entry is skipped. A rejected pack contributes nothing —
//!   the built-in scanner stays fully active.
//! - **I5 — bounded resources.** File-size + rule-count caps here; per-pattern
//!   compiled-size caps in [`super::secrets::SecretPattern::compile`].
//!
//! Format (flat — `[[secret_patterns]]` is the only table, so all the scalar
//! and array keys above it stay top-level):
//! ```toml
//! id = "django"
//! name = "Django security rules"
//! version = "1.0.0"
//!
//! deny_paths    = ["/settings/secrets.py", "/.env.production"]
//! deny_commands = ["python manage.py dumpdata"]
//!
//! [[secret_patterns]]
//! name  = "Django SECRET_KEY literal"
//! regex = '''SECRET_KEY\s*=\s*['"][^'"]{20,}['"]'''
//! ```

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::Ruleset;
use super::secrets::SecretPattern;

/// SHA-256 of a pack's bytes, hex-encoded — the content pin used for
/// Trust-On-First-Use (invariant I6: any byte change re-flags the pack, so a
/// silently-mutated pack is skipped until re-approved). SHA-256 (not the FNV
/// fingerprint used for MCP change-detection) because this is a trust boundary:
/// an attacker must not be able to craft a malicious pack colliding with an
/// approved one.
pub fn content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Max pack file size accepted before parsing (bytes).
const MAX_PACK_BYTES: usize = 256 * 1024;
/// Max total rules (paths + commands + patterns) in one pack.
const MAX_RULES_PER_PACK: usize = 2000;

/// Keys a pack is forbidden from setting. They're ignored by deserialization
/// (the struct has no such fields), but we warn so authors aren't surprised.
const FORBIDDEN_KEYS: &[&str] = &[
    "allow_paths",
    "enabled",
    "detect_secrets",
    "block_network_mounts",
];

// Flat top-level shape: `id`/`name`/`version`/`deny_paths`/`deny_commands`
// are top-level keys and `[[secret_patterns]]` is the only array-of-tables.
// (A `[pack]` wrapper would push the rule keys *into* that table — TOML scopes
// keys to the most recent header — so the format is deliberately flat.)
#[derive(Debug, Deserialize)]
struct RawPack {
    // Defaulted so a missing `id` deserializes (to "") instead of failing the
    // whole parse — `parse` still rejects an empty id (I3), and the registry
    // linter can then report it as the specific `missing-id`, not `malformed-toml`.
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    deny_paths: Vec<String>,
    #[serde(default)]
    deny_commands: Vec<String>,
    #[serde(default)]
    secret_patterns: Vec<RawSecret>,
}

#[derive(Debug, Deserialize)]
struct RawSecret {
    name: String,
    regex: String,
}

/// A parsed, compiled, declarative rule pack. Construction guarantees it can
/// only EXTEND a `Ruleset`'s deny lists (I2) — there is no field that loosens.
#[derive(Debug, Clone)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    pub version: String,
    pub deny_paths: Vec<String>,
    pub deny_commands: Vec<String>,
    pub secret_patterns: Vec<SecretPattern>,
}

impl RulePack {
    /// Parse a pack from TOML text. Returns `None` (fail-open, I3) on an
    /// oversized file, malformed TOML, missing `id`, or an over-count pack.
    /// Individual invalid/oversized secret patterns are skipped (the rest of
    /// the pack still loads).
    pub fn parse(content: &str) -> Option<RulePack> {
        if content.len() > MAX_PACK_BYTES {
            warn!("rule pack rejected: exceeds {MAX_PACK_BYTES} bytes");
            return None;
        }
        let raw: RawPack = match toml::from_str(content) {
            Ok(r) => r,
            Err(e) => {
                warn!("rule pack rejected: malformed TOML: {e}");
                return None;
            }
        };
        if raw.id.trim().is_empty() {
            warn!("rule pack rejected: empty `id`");
            return None;
        }
        let count = raw.deny_paths.len() + raw.deny_commands.len() + raw.secret_patterns.len();
        if count > MAX_RULES_PER_PACK {
            warn!(
                "rule pack '{}' rejected: {count} rules exceeds cap {MAX_RULES_PER_PACK}",
                raw.id
            );
            return None;
        }
        warn_on_forbidden_keys(content, &raw.id);

        let mut secret_patterns = Vec::new();
        for s in raw.secret_patterns {
            match SecretPattern::compile(&s.name, &s.regex) {
                Some(p) => secret_patterns.push(p),
                None => warn!(
                    "rule pack '{}': skipping invalid/oversized pattern '{}'",
                    raw.id, s.name
                ),
            }
        }

        Some(RulePack {
            id: raw.id,
            name: raw.name,
            version: raw.version,
            deny_paths: raw.deny_paths,
            deny_commands: raw.deny_commands,
            secret_patterns,
        })
    }

    /// Read and parse a pack from a file. Fail-open: `None` if the file can't
    /// be read or doesn't parse.
    pub fn parse_file(path: &std::path::Path) -> Option<RulePack> {
        let content = std::fs::read_to_string(path).ok()?;
        RulePack::parse(&content)
    }

    /// Append this pack's rules onto a `Ruleset`. **EXTEND-ONLY (I2):** a pack
    /// can only add denies + secret patterns; it can never touch `allow_paths`
    /// or any global toggle. Mirrors `ProjectProfile::apply_to_ruleset`.
    pub fn apply_to_ruleset(&self, ruleset: &mut Ruleset) {
        ruleset.deny_paths.extend(self.deny_paths.iter().cloned());
        ruleset
            .deny_commands
            .extend(self.deny_commands.iter().cloned());
        ruleset
            .secret_patterns
            .extend(self.secret_patterns.iter().cloned());
    }

    /// Total rule count, for `rules list` display.
    pub fn rule_count(&self) -> usize {
        self.deny_paths.len() + self.deny_commands.len() + self.secret_patterns.len()
    }
}

// ── Registry-acceptance lint (stricter than runtime parse) ───────────────────

/// Top-level keys a pack may carry. The runtime ignores unknown keys; the
/// *registry* rejects them (a pack with surprise keys is a pack we don't
/// understand — and the place to catch a future loosening field).
const ALLOWED_KEYS: &[&str] = &[
    "id",
    "name",
    "version",
    "deny_paths",
    "deny_commands",
    "secret_patterns",
];

/// Deny-path values too broad to accept — they'd block routine safe reads
/// (e.g. `/.env` also trips `.env.example`) and erode trust in the corpus.
const OVERBROAD_PATHS: &[&str] = &["", "/", "~", "~/", ".", "/.", "/.env", "/.git", "~/."];

/// Bare common commands that would over-block normal development if denied.
const OVERBROAD_COMMANDS: &[&str] = &[
    "",
    "rm",
    "delete",
    "git",
    "kubectl",
    "helm",
    "npm",
    "yarn",
    "go",
    "cat",
    "ls",
    "curl",
    "wget",
    "sudo",
    "docker",
    "terraform",
    "python",
    "python3",
    "node",
    "pip",
];

/// Regexes that match (nearly) everything — a secret pattern this broad would
/// flood false positives.
const OVERBROAD_REGEXES: &[&str] = &[
    "", ".", ".*", ".+", ".*?", r"\S+", r"\S*", r"\w+", r"\w*", "(?s).*", r"[\s\S]*",
];

/// Severity of a [`LintFinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Error,
    Warning,
}

impl LintSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            LintSeverity::Error => "error",
            LintSeverity::Warning => "warning",
        }
    }
}

/// One finding from [`lint`]. `code` is a stable machine token (e.g.
/// `forbidden-key`, `overbroad-path`) for CI/JSON consumers.
#[derive(Debug, Clone, PartialEq)]
pub struct LintFinding {
    pub severity: LintSeverity,
    pub code: &'static str,
    pub message: String,
}

impl LintFinding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        LintFinding {
            severity: LintSeverity::Error,
            code,
            message: message.into(),
        }
    }
    fn warn(code: &'static str, message: impl Into<String>) -> Self {
        LintFinding {
            severity: LintSeverity::Warning,
            code,
            message: message.into(),
        }
    }
}

/// `true` when there are no error-severity findings (warnings are acceptable).
pub fn lint_is_clean(findings: &[LintFinding]) -> bool {
    !findings.iter().any(|f| f.severity == LintSeverity::Error)
}

/// Registry-acceptance lint for a pack's TOML. **Stricter than
/// [`RulePack::parse`]:** forbidden/unknown keys, uncompilable regexes, and
/// over-broad rules are *errors* (the runtime only warns or silently skips),
/// plus a false-positive quality gate. Returns every finding; [`lint_is_clean`]
/// decides acceptance. Pure + offline, so the CI validator and unit tests call
/// it directly — and it is *the product's own parser*, which is what makes
/// "valid in the registry" ≡ "the binary accepts it".
pub fn lint(content: &str) -> Vec<LintFinding> {
    let mut out = Vec::new();

    if content.len() > MAX_PACK_BYTES {
        out.push(LintFinding::error(
            "too-large",
            format!("pack is {} bytes (cap {MAX_PACK_BYTES})", content.len()),
        ));
        return out;
    }

    // Key inventory needs the raw table — RawPack silently ignores unknowns.
    let value: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(e) => {
            out.push(LintFinding::error("malformed-toml", format!("{e}")));
            return out;
        }
    };
    let Some(table) = value.as_table() else {
        out.push(LintFinding::error(
            "not-a-table",
            "pack must be a TOML table",
        ));
        return out;
    };
    for key in table.keys() {
        if FORBIDDEN_KEYS.contains(&key.as_str()) {
            out.push(LintFinding::error(
                "forbidden-key",
                format!("key `{key}` would loosen security — packs are deny-only (I2)"),
            ));
        } else if !ALLOWED_KEYS.contains(&key.as_str()) {
            out.push(LintFinding::error(
                "unknown-key",
                format!("key `{key}` is not an allowed pack field"),
            ));
        }
    }

    // Typed content — a type error (e.g. `deny_paths` not an array) is a hard fail.
    let raw: RawPack = match toml::from_str(content) {
        Ok(r) => r,
        Err(e) => {
            out.push(LintFinding::error("malformed-toml", format!("{e}")));
            return out;
        }
    };

    if raw.id.trim().is_empty() {
        out.push(LintFinding::error(
            "missing-id",
            "pack must declare a non-empty `id`",
        ));
    }
    if raw.name.trim().is_empty() {
        out.push(LintFinding::warn("missing-name", "pack has no `name`"));
    }
    if raw.version.trim().is_empty() {
        out.push(LintFinding::warn(
            "missing-version",
            "pack has no `version`",
        ));
    } else if !is_semverish(&raw.version) {
        out.push(LintFinding::warn(
            "version-format",
            format!("`version` \"{}\" is not semver (x.y.z)", raw.version),
        ));
    }

    let total = raw.deny_paths.len() + raw.deny_commands.len() + raw.secret_patterns.len();
    if total == 0 {
        out.push(LintFinding::error("empty-pack", "pack carries no rules"));
    }
    if total > MAX_RULES_PER_PACK {
        out.push(LintFinding::error(
            "too-many-rules",
            format!("{total} rules exceeds cap {MAX_RULES_PER_PACK}"),
        ));
    }

    for p in &raw.deny_paths {
        if OVERBROAD_PATHS.contains(&p.trim()) {
            out.push(LintFinding::error(
                "overbroad-path",
                format!("deny_path `{p}` is too broad — it would block safe reads"),
            ));
        }
    }
    for c in &raw.deny_commands {
        if OVERBROAD_COMMANDS.contains(&c.trim()) {
            out.push(LintFinding::error(
                "overbroad-command",
                format!("deny_command `{c}` is a bare common command — too broad"),
            ));
        }
    }
    for s in &raw.secret_patterns {
        if s.name.trim().is_empty() {
            out.push(LintFinding::error(
                "unnamed-pattern",
                "a secret_pattern has no `name`",
            ));
        }
        if OVERBROAD_REGEXES.contains(&s.regex.trim()) {
            out.push(LintFinding::error(
                "overbroad-regex",
                format!("secret_pattern `{}` matches (nearly) everything", s.name),
            ));
        } else if SecretPattern::compile(&s.name, &s.regex).is_none() {
            out.push(LintFinding::error(
                "bad-regex",
                format!(
                    "secret_pattern `{}` does not compile or exceeds size caps",
                    s.name
                ),
            ));
        }
    }

    out
}

/// Loose semver gate: three dot-separated numeric components (`1.0.0`).
fn is_semverish(v: &str) -> bool {
    let parts: Vec<&str> = v.trim().split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Official rule packs compiled into the binary — inherently trusted, part of
/// the signed release (invariant I4: trust comes from being bundled here, never
/// from a pack's self-declared metadata). `id` → bundled TOML. These are vetted
/// at author time; the `official_packs_all_parse` test guards against a typo
/// shipping a non-parsing pack.
pub const OFFICIAL_PACKS: &[(&str, &str)] = &[
    ("django", include_str!("official/django.toml")),
    ("react", include_str!("official/react.toml")),
    (
        "infrastructure",
        include_str!("official/infrastructure.toml"),
    ),
    ("data-science", include_str!("official/data-science.toml")),
    ("node", include_str!("official/node.toml")),
    ("python", include_str!("official/python.toml")),
    ("go", include_str!("official/go.toml")),
    ("kubernetes", include_str!("official/kubernetes.toml")),
];

/// Ids of all bundled official packs.
pub fn official_ids() -> Vec<&'static str> {
    OFFICIAL_PACKS.iter().map(|(id, _)| *id).collect()
}

/// Parse a bundled official pack by id. `None` if there is no such official
/// pack (or — a build bug — it failed to parse).
pub fn load_official(id: &str) -> Option<RulePack> {
    OFFICIAL_PACKS
        .iter()
        .find(|(pid, _)| *pid == id)
        .and_then(|(_, toml)| RulePack::parse(toml))
}

/// Warn (don't fail) if a pack contains keys a pack is not allowed to set.
/// They're ignored regardless (the structs have no such fields), but surfacing
/// it keeps invariant I2 visible to pack authors.
fn warn_on_forbidden_keys(content: &str, id: &str) {
    let Ok(value) = content.parse::<toml::Value>() else {
        return;
    };
    let Some(table) = value.as_table() else {
        return;
    };
    for key in FORBIDDEN_KEYS {
        if table.contains_key(*key) {
            warn!(
                "rule pack '{id}': key '{key}' is not allowed in a pack and is ignored \
                 (packs can only ADD denies, never loosen — invariant I2)"
            );
        }
    }
}
