//! Phase A tests for v0.6 rule packs — parsing, safe-compile, layering, and
//! the binding security invariants (I2 deny-only, I3 fail-open / engine stays
//! active, I5 bounded resources).

use burnwall::security::{RulePack, Ruleset, SecurityEngine, ViolationKind};

fn engine_with_pack(toml: &str) -> SecurityEngine {
    let pack = RulePack::parse(toml).expect("pack should parse");
    let mut ruleset = Ruleset::default();
    pack.apply_to_ruleset(&mut ruleset);
    SecurityEngine::new(ruleset)
}

#[test]
fn parses_a_valid_pack() {
    let toml = r#"
id = "django"
name = "Django"
version = "1.0.0"

deny_paths = ["/settings/secrets.py"]
deny_commands = ["python manage.py dumpdata"]

[[secret_patterns]]
name = "Django SECRET_KEY"
regex = "SECRET_KEY"
"#;
    let p = RulePack::parse(toml).expect("valid pack");
    assert_eq!(p.id, "django");
    assert_eq!(p.name, "Django");
    assert_eq!(p.version, "1.0.0");
    assert_eq!(p.deny_paths.len(), 1);
    assert_eq!(p.deny_commands.len(), 1);
    assert_eq!(p.secret_patterns.len(), 1);
    assert_eq!(p.rule_count(), 3);
}

#[test]
fn apply_to_ruleset_extends_deny_lists() {
    let toml = r#"
id = "corp"
deny_paths = ["/corp/secrets"]
deny_commands = ["terraform destroy"]
"#;
    let pack = RulePack::parse(toml).unwrap();
    let mut ruleset = Ruleset::default();
    let paths_before = ruleset.deny_paths.len();
    let cmds_before = ruleset.deny_commands.len();
    pack.apply_to_ruleset(&mut ruleset);
    assert_eq!(ruleset.deny_paths.len(), paths_before + 1);
    assert_eq!(ruleset.deny_commands.len(), cmds_before + 1);
}

// ── I2 — deny-only / append-only: a pack can never loosen ──────────────────

#[test]
fn i2_pack_cannot_add_allow_or_toggle_off() {
    // `enabled` / `allow_paths` are NOT RawPack fields → serde ignores them;
    // only `deny_paths` is captured.
    let toml = r#"
id = "evil"
enabled = false
allow_paths = ["~/.ssh"]
deny_paths = ["/myproject/secrets"]
"#;
    let pack = RulePack::parse(toml).expect("parses; forbidden keys ignored");
    assert_eq!(pack.deny_paths, vec!["/myproject/secrets".to_string()]);

    let mut ruleset = Ruleset::default();
    pack.apply_to_ruleset(&mut ruleset);

    // The pack could not flip the master switch or add an allow exception.
    assert!(
        ruleset.enabled,
        "pack must not be able to disable the engine"
    );
    assert!(
        ruleset.allow_paths.is_empty(),
        "pack must not be able to add an allow_paths exception"
    );

    // ~/.ssh is STILL blocked despite the pack's allow_paths attempt.
    let engine = SecurityEngine::new(ruleset);
    assert!(
        engine.scan(br#"{"x": "cat ~/.ssh/id_rsa"}"#).is_some(),
        "a pack must never be able to green-light a denied path"
    );
}

// ── I3 — a bad pack never disables the engine ──────────────────────────────

#[test]
fn i3_malformed_packs_are_rejected() {
    assert!(RulePack::parse("this is not toml {{{").is_none());
    assert!(RulePack::parse("").is_none());
    assert!(RulePack::parse("deny_paths = []").is_none(), "missing id");
    assert!(
        RulePack::parse("id = \"   \"").is_none(),
        "blank id rejected"
    );
}

#[test]
fn i3_rejected_pack_leaves_builtin_scanner_active() {
    // Even after a rejected pack, the built-in engine still blocks.
    assert!(RulePack::parse("garbage").is_none());
    let engine = SecurityEngine::new(Ruleset::default());
    assert!(engine.scan(br#"{"x": "cat ~/.ssh/id_rsa"}"#).is_some());
}

#[test]
fn i3_one_bad_pattern_does_not_sink_the_pack() {
    let toml = r#"
id = "x"

[[secret_patterns]]
name = "bad"
regex = "(unclosed"

[[secret_patterns]]
name = "good"
regex = "MYSECRET-[0-9]{4}"
"#;
    let pack = RulePack::parse(toml).expect("loads despite one bad pattern");
    assert_eq!(pack.secret_patterns.len(), 1);
    assert_eq!(pack.secret_patterns[0].name.as_ref(), "good");
}

// ── I5 — bounded resources ─────────────────────────────────────────────────

#[test]
fn i5_oversized_pack_rejected() {
    let big = format!(
        "id = \"x\"\ndeny_commands = [{}]",
        "\"aaaaaaaa\",".repeat(40_000)
    );
    assert!(big.len() > 256 * 1024, "fixture must exceed the byte cap");
    assert!(RulePack::parse(&big).is_none());
}

#[test]
fn i5_over_count_pack_rejected() {
    let mut s = String::from("id = \"x\"\ndeny_paths = [");
    for _ in 0..2100 {
        s.push_str("\"/p\",");
    }
    s.push(']');
    assert!(s.len() < 256 * 1024, "fixture must be under the byte cap");
    assert!(RulePack::parse(&s).is_none(), "over the rule-count cap");
}

#[test]
fn i5_oversized_regex_is_skipped() {
    let toml = r#"
id = "x"

[[secret_patterns]]
name = "huge"
regex = "a{200000}"
"#;
    let pack = RulePack::parse(toml).expect("pack loads");
    assert!(
        pack.secret_patterns.is_empty(),
        "an oversized regex must be skipped by safe-compile"
    );
}

// ── Layering: pack rules actually take effect through the scanner ──────────

#[test]
fn pack_secret_pattern_blocks_via_engine() {
    let engine = engine_with_pack(
        r#"
id = "corp"

[[secret_patterns]]
name = "Corp token"
regex = "CORP-[A-Z0-9]{10}"
"#,
    );
    let v = engine
        .scan(br#"{"note": "the token is CORP-ABCD123456 ok"}"#)
        .expect("pack pattern should block");
    assert_eq!(v.kind, ViolationKind::Secret);
    assert_eq!(v.matched, "Corp token");
}

#[test]
fn pack_deny_path_blocks_via_engine() {
    let engine = engine_with_pack(
        r#"
id = "corp"
deny_paths = ["/corp/secrets"]
"#,
    );
    assert!(engine
        .scan(br#"{"path": "/corp/secrets/db.json"}"#)
        .is_some());
}

// ── Official bundled packs (Phase B) ───────────────────────────────────────

#[test]
fn official_packs_all_parse() {
    use burnwall::security::packs;
    let ids = packs::official_ids();
    assert!(ids.contains(&"django"));
    assert!(ids.contains(&"react"));
    assert!(ids.contains(&"infrastructure"));
    assert!(ids.contains(&"data-science"));
    for id in ids {
        let pack = packs::load_official(id)
            .unwrap_or_else(|| panic!("bundled official pack '{id}' must parse"));
        assert_eq!(pack.id, id, "pack id must match its registry key");
        assert!(
            pack.rule_count() > 0,
            "official pack '{id}' should carry at least one rule"
        );
    }
}

// ── `rules lint` — registry-acceptance linter ───────────────────────────────

/// The bundled official packs must themselves pass the strict registry lint —
/// this is the gate the `burnwall-rules` CI calls, and it runs here in CI too,
/// so we can never ship an official pack the registry would reject.
#[test]
fn official_packs_pass_lint() {
    use burnwall::security::packs;
    for (id, toml) in packs::OFFICIAL_PACKS {
        let findings = packs::lint(toml);
        assert!(
            packs::lint_is_clean(&findings),
            "official pack '{id}' must lint clean, got: {:?}",
            findings
                .iter()
                .filter(|f| f.severity == packs::LintSeverity::Error)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn lint_rejects_forbidden_and_unknown_keys() {
    use burnwall::security::packs;
    // A loosening key (I2) is an error, not just a warning like the runtime.
    let f = packs::lint("id = \"x\"\nallow_paths = [\"/etc\"]\ndeny_paths = [\"/a\"]\n");
    assert!(f.iter().any(|x| x.code == "forbidden-key"));
    assert!(!packs::lint_is_clean(&f));
    // A surprise key the registry doesn't understand is also an error.
    let f = packs::lint("id = \"x\"\nsurprise = 1\ndeny_paths = [\"/a\"]\n");
    assert!(f.iter().any(|x| x.code == "unknown-key"));
}

#[test]
fn lint_rejects_overbroad_rules() {
    use burnwall::security::packs;
    let overbroad_path = packs::lint("id = \"x\"\ndeny_paths = [\"/.env\"]\n");
    assert!(overbroad_path.iter().any(|x| x.code == "overbroad-path"));

    let overbroad_cmd = packs::lint("id = \"x\"\ndeny_commands = [\"rm\"]\n");
    assert!(overbroad_cmd.iter().any(|x| x.code == "overbroad-command"));

    let overbroad_re = packs::lint(
        "id = \"x\"\n[[secret_patterns]]\nname = \"all\"\nregex = \".*\"\n",
    );
    assert!(overbroad_re.iter().any(|x| x.code == "overbroad-regex"));
}

#[test]
fn lint_rejects_uncompilable_regex() {
    use burnwall::security::packs;
    // An unbalanced group never compiles — registry rejects (runtime would skip).
    let f = packs::lint("id = \"x\"\n[[secret_patterns]]\nname = \"bad\"\nregex = \"(\"\n");
    assert!(f.iter().any(|x| x.code == "bad-regex"));
}

#[test]
fn lint_flags_empty_pack_and_missing_id() {
    use burnwall::security::packs;
    assert!(packs::lint("id = \"x\"\n").iter().any(|x| x.code == "empty-pack"));
    assert!(packs::lint("deny_paths = [\"/a\"]\n")
        .iter()
        .any(|x| x.code == "missing-id"));
}

// ── M-M6 — pack id is used as a filename; reject traversal attempts ─────────

#[test]
fn pack_id_validation_blocks_path_traversal() {
    use burnwall::cli::rules::validate_pack_id;
    // Registry alphabet passes.
    assert!(validate_pack_id("django").is_ok());
    assert!(validate_pack_id("data-science_2").is_ok());
    // Anything that could escape the rules dir (or surprise the FS) fails.
    assert!(validate_pack_id("..\\..\\x").is_err());
    assert!(validate_pack_id("../escape").is_err());
    assert!(validate_pack_id("a/b").is_err());
    assert!(validate_pack_id("a.b").is_err());
    assert!(validate_pack_id("UPPER").is_err());
    assert!(validate_pack_id("").is_err());
    assert!(validate_pack_id("nul:").is_err());
}

#[test]
fn lint_clean_pack_passes_with_only_warnings() {
    use burnwall::security::packs;
    // Valid rules but no name/version → clean (warnings don't fail the gate).
    let f = packs::lint("id = \"corp\"\ndeny_paths = [\"/corp/secrets\"]\n");
    assert!(packs::lint_is_clean(&f), "should pass: {f:?}");
    assert!(f.iter().any(|x| x.severity == packs::LintSeverity::Warning));

    // Fully specified pack → zero findings.
    let full = packs::lint(
        "id = \"corp\"\nname = \"Corp\"\nversion = \"1.0.0\"\ndeny_paths = [\"/corp/secrets\"]\n",
    );
    assert!(full.is_empty(), "fully-specified pack should have no findings: {full:?}");
}
