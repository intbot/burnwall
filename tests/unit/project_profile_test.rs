//! Tests for the per-project `.burnwall.yaml` profile: YAML parsing,
//! walk-up discovery, and merge-into-runtime semantics.

use std::fs;
use std::path::Path;

use burnwall::budget::BudgetConfig;
use burnwall::config::project::{self, ProjectBudget, ProjectProfile};
use burnwall::security::Ruleset;

fn write(dir: &Path, name: &str, contents: &str) {
    fs::write(dir.join(name), contents).expect("write profile file");
}

// ──────────────────────────── Parsing ────────────────────────────

#[test]
fn parses_spec_example_profile() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".burnwall.yaml",
        "allow_paths:\n  - ./src\n  - ./tests\ndeny_paths:\n  - ./secrets\n  - ./.env\nbudget:\n  daily_max_usd: 10\n",
    );
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile.allow_paths, vec!["./src", "./tests"]);
    assert_eq!(profile.deny_paths, vec!["./secrets", "./.env"]);
    assert_eq!(profile.budget.daily_max_usd, Some(10.0));
}

#[test]
fn parses_profile_with_only_budget_block() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".burnwall.yaml",
        "budget:\n  daily_max_usd: 2.5\n",
    );
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert!(profile.allow_paths.is_empty());
    assert!(profile.deny_paths.is_empty());
    assert_eq!(profile.budget.daily_max_usd, Some(2.5));
}

#[test]
fn parses_profile_with_only_allow_paths() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "allow_paths:\n  - ./vendor\n");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile.allow_paths, vec!["./vendor"]);
    assert!(profile.deny_paths.is_empty());
    assert_eq!(profile.budget.daily_max_usd, None);
}

#[test]
fn budget_block_without_daily_max_is_none() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "budget: {}\n");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile.budget.daily_max_usd, None);
}

#[test]
fn empty_file_is_default_profile() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile, ProjectProfile::default());
}

#[test]
fn comment_only_file_is_default_profile() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "# nothing configured yet\n");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile, ProjectProfile::default());
}

#[test]
fn malformed_yaml_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    // `allow_paths` must be a sequence — an integer is a type error.
    write(dir.path(), ".burnwall.yaml", "allow_paths: 5\n");
    let err = project::load(&dir.path().join(".burnwall.yaml")).unwrap_err();
    assert!(matches!(err, burnwall::config::ConfigError::Yaml(_)));
}

// ──────────── Parsing — mcp_allowed_servers (per-project MCP allowlist) ────────────

#[test]
fn parses_mcp_allowed_servers_when_present() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".burnwall.yaml",
        "mcp_allowed_servers:\n  - filesystem\n  - github\n",
    );
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile.mcp_allowed_servers, vec!["filesystem", "github"]);
}

#[test]
fn parses_mcp_allowed_servers_inline_list() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".burnwall.yaml",
        "mcp_allowed_servers: [filesystem, github]\n",
    );
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert_eq!(profile.mcp_allowed_servers, vec!["filesystem", "github"]);
}

#[test]
fn empty_mcp_allowed_servers_list_deserializes() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "mcp_allowed_servers: []\n");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert!(profile.mcp_allowed_servers.is_empty());
}

#[test]
fn absent_mcp_allowed_servers_defaults_to_empty() {
    // A profile that only sets other fields must still parse — the new field
    // defaults to an empty Vec (no per-project MCP restriction).
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "allow_paths:\n  - ./src\n");
    let profile = project::load(&dir.path().join(".burnwall.yaml")).expect("load");
    assert!(profile.mcp_allowed_servers.is_empty());
    assert_eq!(profile.allow_paths, vec!["./src"]);
}

// ──────────── mcp_server_allowed — deny-by-omission semantics ────────────

#[test]
fn mcp_server_allowed_when_list_absent_permits_anything() {
    let profile = ProjectProfile::default();
    assert!(profile.mcp_server_allowed("filesystem"));
    assert!(profile.mcp_server_allowed("anything"));
}

#[test]
fn mcp_server_allowed_with_list_is_deny_by_omission() {
    let profile = ProjectProfile {
        mcp_allowed_servers: vec!["filesystem".to_string(), "github".to_string()],
        ..Default::default()
    };
    assert!(profile.mcp_server_allowed("filesystem"));
    assert!(profile.mcp_server_allowed("github"));
    assert!(!profile.mcp_server_allowed("shell"));
    // Exact match — not a prefix/substring.
    assert!(!profile.mcp_server_allowed("git"));
}

// ──────────────────────────── Discovery ────────────────────────────

#[test]
fn discover_finds_profile_in_start_dir() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "allow_paths: [./src]\n");
    let found = project::discover(dir.path()).expect("found");
    assert_eq!(found, dir.path().join(".burnwall.yaml"));
}

#[test]
fn discover_walks_up_to_ancestor() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".burnwall.yaml", "deny_paths: [./secrets]\n");
    let nested = root.path().join("a").join("b").join("c");
    fs::create_dir_all(&nested).unwrap();

    let found = project::discover(&nested).expect("found via walk-up");
    assert_eq!(found, root.path().join(".burnwall.yaml"));
}

#[test]
fn discover_returns_nearest_when_multiple_exist() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".burnwall.yaml",
        "budget: {daily_max_usd: 50}\n",
    );
    let child = root.path().join("child");
    fs::create_dir_all(&child).unwrap();
    write(&child, ".burnwall.yaml", "budget: {daily_max_usd: 5}\n");

    // The walk-up stops at the first match — the child's file, not the root's.
    let found = project::discover(&child).expect("found");
    assert_eq!(found, child.join(".burnwall.yaml"));
}

#[test]
fn discover_returns_none_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(project::discover(dir.path()).is_none());
}

#[test]
fn discover_finds_yml_extension() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yml", "allow_paths: [./src]\n");
    let found = project::discover(dir.path()).expect("found .yml");
    assert_eq!(found, dir.path().join(".burnwall.yml"));
}

#[test]
fn discover_and_load_returns_none_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let result = project::discover_and_load(dir.path()).expect("ok");
    assert!(result.is_none());
}

#[test]
fn discover_and_load_returns_path_and_parsed_profile() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".burnwall.yaml", "deny_paths: [./private]\n");
    let (path, profile) = project::discover_and_load(dir.path())
        .expect("ok")
        .expect("some");
    assert_eq!(path, dir.path().join(".burnwall.yaml"));
    assert_eq!(profile.deny_paths, vec!["./private"]);
}

// ──────────────────── Merge — ruleset ────────────────────

#[test]
fn apply_to_ruleset_extends_deny_and_allow_lists() {
    let mut ruleset = Ruleset::default();
    let default_deny_count = ruleset.deny_paths.len();
    assert!(ruleset.allow_paths.is_empty());

    let profile = ProjectProfile {
        allow_paths: vec!["./src".to_string()],
        deny_paths: vec!["./secrets".to_string()],
        ..Default::default()
    };
    profile.apply_to_ruleset(&mut ruleset);

    // Global denies are preserved; the project deny is appended.
    assert_eq!(ruleset.deny_paths.len(), default_deny_count + 1);
    assert!(ruleset.deny_paths.iter().any(|p| p == "~/.ssh"));
    assert!(ruleset.deny_paths.iter().any(|p| p == "./secrets"));
    assert_eq!(ruleset.allow_paths, vec!["./src"]);
}

// ──────────────────── Merge — budget cap ────────────────────

fn budget(daily: f64) -> BudgetConfig {
    BudgetConfig {
        daily_usd: daily,
        monthly_usd: 0.0,
        warn_percent: 80,
        per_session_usd: 0.0,
        per_hour_usd: 0.0,
        enforce_on_plan: false,
        fallback_model: String::new(),
    }
}

fn profile_with_cap(cap: Option<f64>) -> ProjectProfile {
    ProjectProfile {
        budget: ProjectBudget { daily_max_usd: cap },
        ..Default::default()
    }
}

#[test]
fn budget_cap_lower_than_global_wins() {
    let mut cfg = budget(50.0);
    profile_with_cap(Some(10.0)).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 10.0).abs() < 1e-9);
}

#[test]
fn budget_cap_higher_than_global_keeps_global() {
    // A project cap can tighten the budget, never raise it.
    let mut cfg = budget(50.0);
    profile_with_cap(Some(100.0)).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 50.0).abs() < 1e-9);
}

#[test]
fn budget_cap_applies_when_global_unlimited() {
    // Global 0.0 = unlimited, so any positive project cap takes effect.
    let mut cfg = budget(0.0);
    profile_with_cap(Some(10.0)).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 10.0).abs() < 1e-9);
}

#[test]
fn no_budget_cap_leaves_global_unchanged() {
    let mut cfg = budget(50.0);
    profile_with_cap(None).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 50.0).abs() < 1e-9);
}

#[test]
fn zero_or_negative_budget_cap_is_ignored() {
    let mut cfg = budget(50.0);
    profile_with_cap(Some(0.0)).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 50.0).abs() < 1e-9);

    let mut cfg = budget(50.0);
    profile_with_cap(Some(-5.0)).apply_to_budget(&mut cfg);
    assert!((cfg.daily_usd - 50.0).abs() < 1e-9);
}
