//! Per-project security profile — `.burnwall.yaml`.
//!
//! A `.burnwall.yaml` (or `.burnwall.yml`) file in the working directory, or
//! any ancestor of it, layers project-specific rules on top of the global
//! `~/.burnwall/config.toml`. `burnwall start` discovers it once at boot and
//! merges it into the runtime [`Ruleset`] and [`BudgetConfig`].
//!
//! Schema (matches internal/SPEC.md §"v0.2 Additions"):
//! ```yaml
//! allow_paths:
//!   - ./src
//!   - ./tests
//! deny_paths:
//!   - ./secrets
//!   - ./.env
//! mcp_allowed_servers:
//!   - filesystem
//!   - github
//! budget:
//!   daily_max_usd: 10
//! ```
//!
//! ### Merge semantics
//! - `deny_paths` **extend** the global deny list.
//! - `allow_paths` are **exceptions**: a string leaf matching one skips the
//!   path-deny checks (command / mount / secret checks still run). See
//!   [`crate::security::scanner`]. A project can only loosen *path* rules
//!   for its own traffic — it can never green-light a command or a secret.
//! - `mcp_allowed_servers` is an **allowlist** of MCP server names this repo's
//!   agents may reach. ABSENT or empty → no per-project restriction (current
//!   behavior; never blocks a user who hasn't opted in). PRESENT and non-empty
//!   → a `tools/call` routed to a server *not* on the list is blocked at the
//!   MCP firewall. It composes with the global `[mcp].auto_deny`, which is
//!   still checked first and always wins. Deny-by-omission applies *only* when
//!   the list is non-empty, so it can never accidentally block everyone.
//! - `budget.daily_max_usd` is a **cap**: the effective daily limit is the
//!   lower of the global limit and the project cap. A project can tighten
//!   the budget, never raise it. A cap of `0`, negative, non-finite, or
//!   absent is ignored.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::Result;
use crate::budget::BudgetConfig;
use crate::security::Ruleset;

/// Filenames recognised as a project profile, checked in this order within
/// each directory during the walk-up.
const PROFILE_FILENAMES: &[&str] = &[".burnwall.yaml", ".burnwall.yml"];

/// A parsed `.burnwall.yaml`. All fields are optional so partial files (just
/// a `budget:` block, just `allow_paths:`, an empty file) parse cleanly.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProjectProfile {
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
    /// MCP servers this project's agents are allowed to reach. Empty / absent
    /// = no restriction (see module docs). A non-empty list turns the MCP
    /// firewall into deny-by-omission: any server not named here is blocked.
    #[serde(default)]
    pub mcp_allowed_servers: Vec<String>,
    #[serde(default)]
    pub budget: ProjectBudget,
}

/// The `budget:` block of a project profile.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProjectBudget {
    /// Per-project daily spend cap in USD. `None` (key absent) = no cap.
    #[serde(default)]
    pub daily_max_usd: Option<f64>,
}

/// Walk up from `start` (inclusive) looking for a project profile file.
/// Returns the path of the *nearest* one — the search stops at the first
/// directory that contains a match — or `None` if none exists up to the
/// filesystem root.
///
/// `start` should be an absolute directory path; `burnwall start` passes the
/// process working directory.
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        for name in PROFILE_FILENAMES {
            let candidate = d.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        dir = d.parent();
    }
    None
}

/// Parse a project profile from the YAML file at `path`.
///
/// An empty file, a comment-only file, or a literal `null` document all
/// parse to [`ProjectProfile::default`] (no rules, no cap) rather than an
/// error — an empty profile is a valid "I have a `.burnwall.yaml` but
/// haven't filled it in yet" state.
pub fn load(path: &Path) -> Result<ProjectProfile> {
    let text = std::fs::read_to_string(path)?;
    // Deserialize through `Option` so an empty/`null` document yields `None`
    // instead of an "invalid type: unit value" error.
    let profile: Option<ProjectProfile> = serde_norway::from_str(&text)?;
    Ok(profile.unwrap_or_default())
}

/// Discover (walk-up from `start`) and load a project profile, if one
/// exists. Returns the resolved path alongside the parsed profile so callers
/// can report which file was applied.
pub fn discover_and_load(start: &Path) -> Result<Option<(PathBuf, ProjectProfile)>> {
    match discover(start) {
        Some(path) => {
            let profile = load(&path)?;
            Ok(Some((path, profile)))
        }
        None => Ok(None),
    }
}

impl ProjectProfile {
    /// Whether a `tools/call` routed to MCP server `server` is permitted by
    /// this project's `mcp_allowed_servers` list.
    ///
    /// Deny-by-omission applies *only* when the list is non-empty: an
    /// absent/empty list means "no per-project restriction" and always
    /// returns `true`, so a user who never sets the field is never blocked.
    /// `server` is matched exactly against the configured names (the same
    /// routed server name the MCP firewall derives from the path).
    pub fn mcp_server_allowed(&self, server: &str) -> bool {
        self.mcp_allowed_servers.is_empty() || self.mcp_allowed_servers.iter().any(|s| s == server)
    }

    /// Layer this profile's path rules onto a base [`Ruleset`]: `deny_paths`
    /// extend the deny list, `allow_paths` extend the exception list.
    pub fn apply_to_ruleset(&self, ruleset: &mut Ruleset) {
        ruleset.deny_paths.extend(self.deny_paths.iter().cloned());
        ruleset.allow_paths.extend(self.allow_paths.iter().cloned());
    }

    /// Apply the project budget cap to a base [`BudgetConfig`]. The effective
    /// daily limit becomes the lower of the existing limit and the project
    /// cap — a project can tighten the budget but never raise it. A global
    /// limit of `0.0` means "unlimited", so any positive cap wins there.
    ///
    /// A cap that is absent, `0`, negative, or non-finite is ignored.
    pub fn apply_to_budget(&self, budget: &mut BudgetConfig) {
        let Some(cap) = self.budget.daily_max_usd else {
            return;
        };
        if !cap.is_finite() || cap <= 0.0 {
            return;
        }
        budget.daily_usd = if budget.daily_usd <= 0.0 {
            cap
        } else {
            budget.daily_usd.min(cap)
        };
    }
}
