# Progress

Update this file after every Claude Code session.

## Status: v0.2 in progress (~50%)

- **v0.1**: fully shipped on `main`. 120 tests. Tagged-and-ship ready (no `v0.1.0` tag pushed yet — `[OWNER]` placeholders still in Cargo.toml/LICENSE).
- **v0.2**: active on the `v0.2` branch. 5 feature commits landed, 143 tests passing, `cargo fmt` + `clippy` clean. Roughly half the milestone done.
- **Current branch:** `v0.2`. Both branches pushed to `origin`.

### Fresh-session orientation

- The **v0.2 plan** (replanned after a competitive-research pass) lives in `internal/ROADMAP.md` — `internal/` is gitignored/local-only. It has checkboxes for what's done vs remaining.
- Next planned feature: **per-project security profiles (`.burnwall.yaml`)** — highest-impact remaining v0.2 item.
- Competitive landscape research is in `internal/COMPETITORS.md`.
- User preferences are in the auto-loaded memory files (no `Co-Authored-By` trailer; no meta-commentary about hidden/scrubbed content).

## Session Log

### v0.2 — Stop Wasting My Money (2026-05-13/14, `v0.2` branch)
- [x] Loop detection — `LoopDetector` (per-hash sliding-window + cost-spiral), wired into the proxy pipeline between budget check and forward; `request_hash` column populated
- [x] `burnwall security` command — table + `--json` view of `security_events`
- [x] Pricing freshness warning — `PRICING_LAST_UPDATED` const + `pricing_age_days()`; `status` warns if >30 days old
- [x] `config show --json` — completes `--json` coverage across all commands
- [x] Shell completions — `burnwall completions <shell>` for bash/zsh/fish/powershell/elvish (`clap_complete`)
- [x] Path redaction — `security.log_redact_details` config; storage rows redact the matched-rule detail, 403 response unaffected (D13 mitigation)
- [x] Competitive research pass — ~50 new competitors catalogued in `internal/COMPETITORS.md`; v0.2 replanned in `internal/ROADMAP.md`
- [x] Repo hygiene — relocated internal planning docs to gitignored `internal/`, scrubbed history of strategy-doc content + names, removed `Co-Authored-By` trailers
- [ ] Remaining v0.2 work — see `internal/ROADMAP.md` (per-project profiles, Tier-2 log-file cost tracking, MCP disclaimer, local-time "today", daemon mode + real `stop`, Homebrew formula, README comparison page, positioning copy, Show HN prep)

### Session 0 — Planning (May 2026)
- [x] CLAUDE.md — project rules and structure
- [x] docs/SPEC.md — exact CLI behavior, proxy logic, pricing tables, schemas
- [x] docs/ARCHITECTURE.md — component design, data flow, shared state
- [x] Planning notes — scope, milestones, design rationale
- [x] LICENSE — FSL-1.1-MIT
- [x] Cargo.toml — workspace skeleton with dependencies

### Session 1 — Project Scaffold (2026-05-12)
- [x] Created all 8 module directories under src/ (proxy, providers, security, budget, storage, pricing, config, cli)
- [x] Created mod.rs in each module declaring its sub-modules
- [x] Created empty stub .rs files for every leaf module listed in CLAUDE.md project structure (30 files total)
- [x] Updated src/main.rs to declare all top-level modules with `#![allow(unused)]` for clean dev build
- [x] Verified `cargo build` compiles cleanly (all dependencies resolved, no warnings, no errors)
- [x] Verified `cargo run` executes the stub binary

### Session 1.5 — Rename TokenGuard → Burnwall (2026-05-13)
- [x] Bulk case-sensitive rename across all docs, code, configs (13 files)
- [x] SPEC.md "Pricing Notes" subsection — OpenAI auto-cache 50%, Anthropic 5-min vs 1-hr multipliers, Batch stacking, Opus 4.7 tokenizer warning
- [x] Planning notes updated to reflect the new name
- [x] `cargo clean && cargo build` regenerates Cargo.lock and target artifacts as `burnwall`

### Session 10 — Polish and Release (2026-05-13)
- [x] `.github/workflows/ci.yml` — matrix build+test on ubuntu / macOS / windows; separate `rustfmt --check` and `clippy --all-targets -D warnings` jobs; `Swatinem/rust-cache@v2` for fast incremental CI
- [x] `.github/workflows/release.yml` — per-target release jobs for `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`; `.tar.gz` on Unix / `.zip` on Windows; auto-publishes to GitHub Release on `v*` tag push with generated notes; manual-trigger via `workflow_dispatch`
- [x] aarch64-linux deliberately omitted from v0.1 (needs `cross` setup) — tracked in CHANGELOG
- [x] `CHANGELOG.md` — v0.1 feature list and explicit "not yet" / v0.2 list
- [x] `README.md` — Quick Start updated to reflect actual v0.1 commands (`init --apply`, `config set budget.daily`); install section adds build-from-source steps; aspirational `install.sh` URL replaced with realistic options
- [x] `cargo fmt --all` — applied across the codebase; `cargo fmt --check` clean
- [x] `cargo clippy --all-targets -- -D warnings` — clean after fixing `derivable_impls` on `Config` (replaced manual `Default` impl with `#[derive(Default)]`), `too_many_arguments` on `write_table` (allow-listed — needs the precise per-column data), `field_reassign_with_default` in security tests (use struct-update syntax with `..Default::default()`), `needless_borrows_for_generic_args` in init test
- [x] `cargo build --release` — clean (LTO + opt-level "z" + strip; multi-minute build but no errors)
- [x] Release binary smoke-test with `BURNWALL_DATA_DIR` sandbox: `--version`, `config show`, `status` (empty + populated), `history` all produce correct output
- [x] `cargo test` final — 120/120 passing across 10 named suites
- [x] PROGRESS, README, CHANGELOG aligned for v0.1.0 tag

### Session 9 — Config and Init (2026-05-13)
- [x] `src/cli/init.rs` — `Shell` enum (zsh/bash/fish/powershell) with `detect()`, `rc_path()`, `export_lines(proxy_url)`; `detect_tools()` checks PATH for `claude`/`codex`/`aider`/`opencode`; `binary_in_path` (process PATH) + `binary_in_path_var` (caller-supplied PATH for race-free testing); `append_to_rc` writes a marker-bracketed block once (idempotent on second run); dry-run by default, `--apply` flag commits changes
- [x] PowerShell rc auto-edit deliberately deferred (signed-script edge cases) — falls back to printing instructions
- [x] `src/cli/stop.rs` — informational stub for v0.1 (foreground-only); real PID-aware stop lands in v0.2 with daemon mode
- [x] `src/cli/start.rs` — now loads `~/.burnwall/config.toml` via `config::load_or_default`; builds `BudgetTracker` and `SecurityEngine` from the user config; `--port` and `--host` flags became `Option<T>` and override config when present
- [x] `src/cli/mod.rs` — added `Init` and `Stop` subcommands
- [x] `tests/integration/init_test.rs` — 11 tests: shell rc-path conventions, export-line syntax for each shell, race-free binary lookup against an isolated PATH, fake-binary detection, idempotent rc-file append (marker check + creates parent dirs), full CLI dry-run/apply via `assert_cmd` + `BURNWALL_DATA_DIR`, `stop` message, end-to-end "config set then start picks it up" via runtime conversion
- [x] `cargo test` — 120/120 passing (11 init + 12 config + 9 cli + 6 pipeline + 16 budget + 22 security + 12 storage + 9 parser + 15 pricing + 8 proxy)

### Session 8 — CLI Commands (2026-05-13)
- [x] `src/storage/models.rs` — `ModelBreakdown` (per-provider/model aggregates) with `cache_hit_rate()`; `DailyTotal` extended with `cache_hit_rate`
- [x] `src/storage/repository.rs` — `breakdown_for_date`, `request_count_for_date`, `blocked_count_for_date`, `security_event_count_for_date`; `daily_totals` now computes hit rate via SQL
- [x] `src/storage/mod.rs` + `src/config/mod.rs` — `BURNWALL_DATA_DIR` env var override on `data_dir()` and `default_path()`, so the binary-under-test in CLI integration tests can sandbox to a tempdir
- [x] `src/config/types.rs` — `Config` mirroring SPEC's TOML schema (proxy, budget, security, loop_detection, logging) with serde derives, defaults via `#[serde(default)]`, plus `From<&BudgetConfig>` / `From<&SecurityConfig>` to runtime types
- [x] `src/config/mod.rs` — `load_or_default(path)`, atomic `save(path, &config)` (write-tmp-then-rename), `set_dotted_key(cfg, "budget.daily", "20")` with type-safe parsing for numbers / strings / booleans / CSV lists; `ConfigError` thiserror variants for unknown key + invalid value
- [x] `src/cli/status.rs` — table view (date header, per-model breakdown, budget %, security count, cache savings) plus `--json` mode
- [x] `src/cli/history.rs` — last-N-days table with totals row + monthly projection plus `--json` mode
- [x] `src/cli/config_cmd.rs` — `config show` (loads or defaults, pretty-prints TOML) and `config set <key> <value>` (loads, mutates, atomically writes)
- [x] `src/cli/mod.rs` — added `Status`, `History`, `Config` subcommands and dispatch
- [x] `tests/unit/config_test.rs` — 12 tests: defaults, missing-file falls back to defaults, save/load roundtrip, parent-dir auto-create, all set-dotted-key variants (numeric/string/boolean/CSV), unknown-key + invalid-value errors, runtime-type conversions
- [x] `tests/integration/cli_test.rs` — 9 end-to-end tests via `assert_cmd` + `predicates` + `BURNWALL_DATA_DIR`-sandboxed tempdir: `status` table + `--json`, empty-DB fallback, `history` table + `--json`, `config show` defaults when no file, `config set` writes file + persists across invocations, unknown key + invalid value errors
- [x] `cargo test` — 109/109 passing

### Session 7 — Wire Everything Together (2026-05-13)
- [x] `src/providers/anthropic.rs` — added `parse_sse` and `parse_any`; SSE parser handles `message_start` (input tokens, cache_*) + `message_delta` (output tokens), max-aggregates output across deltas
- [x] `src/providers/openai.rs` — same: `parse_sse` finds the chunk with non-empty `usage`, skips `[DONE]` sentinel
- [x] `src/proxy/streaming.rs` — added `tee_stream` adapter; spawns a tokio task that clones each `Bytes` chunk (cheap, refcounted) — one copy to client via `mpsc::unbounded`, one accumulated; on stream end calls `on_complete(Vec<Bytes>)` for parsing+recording. Survives client disconnect (keeps draining upstream)
- [x] `src/proxy/mod.rs` — `AppState` expanded with `Arc<SecurityEngine>`, `Arc<BudgetTracker>`, `Arc<Storage>`; `AppState::new` and `with_defaults` constructed for tests with in-memory storage
- [x] `src/proxy/handler.rs` — full pipeline: route → read body → security scan (→ 403 + `security_events` row + blocked `requests` row on hit) → budget check (→ 429 + blocked row on Exceeded; tracing warn on Warn; pass on Ok) → forward
- [x] `src/proxy/forwarding.rs` — refactored signature to take method/uri/headers/body separately; tee callback parses via `parse_any`, computes cost via pricing, inserts `requests` row + bumps budget counter
- [x] Error JSON now matches SPEC: `{"error":{"type":"<security_blocked|budget_exceeded|proxy_error>","message":"..."}}`
- [x] `src/cli/start.rs` — `burnwall start` command with `--port`, `--host`, `--upstream-anthropic`, `--upstream-openai` flags; opens `Storage::open_default()`, hydrates budget from today's total, prints SPEC-formatted banner
- [x] `src/cli/mod.rs` — clap `Cli` parser with `Command::Start`; `Cli::dispatch()` async entry point
- [x] `src/main.rs` — `#[tokio::main]` + `Cli::parse().dispatch().await`
- [x] `tests/integration/pipeline_test.rs` — 6 end-to-end tests via `wiremock`: safe Anthropic request records cost ($0.0105), safe OpenAI with cache records cost ($0.00672), security violation returns 403 + writes `security_events` row + blocked `requests` row, budget exceeded returns 429 + blocked row + upstream never hit (`.expect(0)`), SSE streaming response is tee-parsed (input/cache_read from `message_start`, output from `message_delta`), budget warn state still forwards
- [x] `cargo test` — 88/88 passing (6 pipeline + 16 budget + 22 security + 12 storage + 9 parser + 15 pricing + 8 proxy)
- [x] `cargo run -- --help` and `cargo run -- start --help` print correct clap-generated help

### Session 6 — Budget Enforcement (2026-05-13)
- [x] `src/budget/limits.rs` — `BudgetConfig` (daily / monthly / warn_percent; `0.0` means unlimited per SPEC convention), `BudgetStatus` enum (`Ok` / `Warn { spent, limit, percent }` / `Exceeded { spent, limit }`), pure `check_daily()` matching SPEC step 4 (`>=` daily blocks, `>=` warn% warns but forwards)
- [x] `src/budget/mod.rs` — `BudgetTracker` with `AtomicU64` storing **microcents (10⁻⁸ USD)** rather than cents — sub-cent precision matters: 1000 gpt-5.4-mini requests at 0.005¢ each must reach 5¢, not round to zero
- [x] `record()` clamps NaN/Inf/negative inputs to avoid counter corruption
- [x] `hydrate_for_date(storage, date)` — replaces (not adds to) counter from `Storage::total_cost_for_date()`; caller picks UTC vs local; date-agnostic API matches the storage convention
- [x] `reset()` zeroes the counter for the midnight rollover (caller schedules)
- [x] Lock-free hot path: `today_spent()` and `record()` are wait-free atomic ops, sub-microsecond — meets SPEC's "sub-ms proxy overhead" budget
- [x] Race window per ARCHITECTURE.md: small overshoot under high concurrency is accepted in exchange for no per-request locking
- [x] `loop_detector.rs` — left as empty stub (v0.2 feature)
- [x] `tests/integration/budget_test.rs` — 16 tests: pure `check_daily` boundary cases (under / at-warn / at-limit / over-limit / unlimited zero-config), tracker basics (start / accumulate / clamp NaN+Inf+negative / sub-cent precision over 1000 inserts / Ok→Warn→Exceeded transition / reset), hydration (loads today's total / zero on empty / replaces stale value), and an 8-thread × 10k-record concurrency test proving no cost is lost
- [x] `cargo test` — 82/82 passing (16 budget + 22 security + 12 storage + 9 parser + 15 pricing + 8 proxy)

### Session 5 — Security Engine (2026-05-13)
- [x] `src/security/rules.rs` — `Ruleset` with `DEFAULT_DENY_PATHS`, `DEFAULT_DENY_COMMANDS`, `NETWORK_MOUNT_NEEDLES`; matching primitives `path_matches`, `command_matches`, `mount_matches`
- [x] Path matching strategy — for `~/`-prefixed rules, match the form `/<rest>` (Unix), `~/<rest>` (literal tilde), and `\<rest-backslashes>` (Windows). Catches expanded forms (`/Users/developer/.ssh/...`) without needing the actual username
- [x] `src/security/secrets.rs` — `LazyLock<Vec<SecretPattern>>` with 6 regex patterns (AWS access key, private key header, GitHub PAT, OpenAI API key, Anthropic API key, Slack token). Pattern name reported, raw secret never logged
- [x] `src/security/scanner.rs` — schema-agnostic deep walk of `serde_json::Value`; visits every string leaf; first-violation-wins (proxy blocks on any one). Order: paths → commands → mounts → secrets
- [x] `src/security/mod.rs` — `SecurityEngine` (holds `Ruleset`, `scan(body)` returns `Option<Violation>`); `ViolationKind` enum mapped to SPEC's `event_type` strings (`path_blocked` / `command_blocked` / `mount_blocked` / `secret_detected`); human-readable `Violation::message()`
- [x] Fail-open: non-JSON bodies return `None` (forward) by design
- [x] `tests/integration/security_test.rs` — 22 tests: both fixtures, each rule family (paths in tilde/Unix/Windows forms, commands, all 4 mount needles, all secret patterns), disable toggles for mounts/secrets, deeply nested JSON, event-type mapping, message formatting
- [x] `cargo test` — 66/66 passing (22 security + 12 storage + 9 parser + 15 pricing + 8 proxy)

### Session 4 — SQLite Storage (2026-05-13)
- [x] Recorded the SQLite at-rest encryption decision (no SQLCipher in v0.1 — storage is metadata-only, no keys/prompts; revisit for the team tier)
- [x] Cargo.toml — enabled `chrono` feature on rusqlite (`DateTime<Utc>` ↔ TEXT in RFC 3339)
- [x] `src/storage/models.rs` — `RequestRecord`, `SecurityEvent`, `DailyTotal` plus `RequestRecord::successful()` and `::blocked()` constructors
- [x] `src/storage/mod.rs` — `Storage` (Connection wrapped in std `Mutex`), `open_default()` / `open()` / `open_in_memory()`, embedded SCHEMA (requests + security_events + daily_summary + indexes), `data_dir()` helper, Unix `0700`/`0600` perm hardening (no-op on Windows per default user-profile ACL)
- [x] `src/storage/repository.rs` — `insert_request`, `insert_security_event`, `get_request`, `total_cost_for_date`, `requests_for_date`, `daily_totals(days)`, `security_events_for_date`; all parameterized, no string interpolation; `DATE()` queries work against rusqlite's RFC 3339 timestamps
- [x] `tests/unit/storage_test.rs` — 12 tests: migration (tables exist + idempotent open), full-field roundtrip, blocked-record persistence, aggregate sums by date, oldest-first ordering, multi-day grouping, security event with provider context, file-based persistence across reopens
- [x] `cargo test` — 44/44 passing (12 storage + 9 parser + 15 pricing + 8 proxy)

### Session 3 — Response Parsers + Pricing (2026-05-13)
- [x] `src/providers/mod.rs` — provider-neutral `TokenUsage` (4 buckets: input / output / cache_creation / cache_read), `ParsedResponse`, `ParseError` (thiserror)
- [x] `src/providers/anthropic.rs` — Anthropic Messages API parser; reads `usage.input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `output_tokens`; serde `#[default]` on cache fields so responses without caching parse cleanly
- [x] `src/providers/openai.rs` — OpenAI Chat Completions parser; normalizes `prompt_tokens` (which INCLUDES cached) into `input_tokens` (non-cached) + `cache_read_tokens`; `cache_creation_tokens` is always 0 (no opt-in writes)
- [x] `src/pricing/rates.rs` — `const` rate card for claude-opus-4-7/-6, claude-sonnet-4-6, claude-haiku-4-5, gpt-5.5, gpt-5.4-mini, gpt-5.4; longest-prefix-first ordering so `gpt-5.4-mini-...` matches the mini entry not the base
- [x] `src/pricing/cache_calc.rs` — `cost()`, `cost_without_cache()`, `cache_savings()` (the last two power the "Cache savings today: $X" line in `burnwall status`)
- [x] `src/pricing/mod.rs` — `calculate_cost(model, &usage) -> Option<f64>` convenience; `None` for unknown models (fail-open — don't break the workflow on a pricing miss)
- [x] Date-suffix tolerance: `get_pricing("claude-sonnet-4-6-20250514")` resolves to `claude-sonnet-4-6` rates via prefix match with `-` boundary check (rejects `claude-sonnet-4-6dev`)
- [x] `tests/unit/parser_test.rs` — 9 tests across both providers + the 4 fixture JSON files; covers cached/uncached splits, missing optional fields, invalid JSON, and missing `usage` block
- [x] `tests/unit/pricing_test.rs` — 15 tests covering name normalization (exact / date-stamped / mini-vs-base disambiguation / unrelated-prefix rejection), cost math against hand-computed values for all 4 fixtures, cache-savings consistency, and the convenience API
- [x] `cargo test` — 32/32 passing (9 parser + 15 pricing + 8 proxy)

### Session 2 — Proxy Server (Forward Only) (2026-05-13)
- [x] Added `src/lib.rs` so integration tests can import internal modules; `src/main.rs` slimmed to a stub
- [x] Added `futures-util` dep (Stream adapters for SSE pass-through) and `[[test]]` config to expose `tests/integration/proxy_test.rs`
- [x] `src/proxy/mod.rs` — `AppState`, `run()` for production bind, `serve()` for caller-supplied listener (used by tests)
- [x] `src/proxy/handler.rs` — URL-prefix routing for `/anthropic/*` and `/openai/*`, strict prefix matching (no `/anthropicfoo` false-match), 404/502 error responses with JSON body
- [x] `src/proxy/forwarding.rs` — request forwarding via reqwest; strips RFC 7230 hop-by-hop headers plus `Host` and `Content-Length`; preserves status, method, query string, body
- [x] `src/proxy/streaming.rs` — `UnsyncBoxBody<Bytes, BoxError>` unified body type; `from_stream()` wraps `reqwest::Response::bytes_stream()` for zero-buffer SSE pass-through
- [x] `tests/integration/proxy_test.rs` — 8 wiremock-backed tests: Anthropic POST + auth header, OpenAI POST + bearer auth, query-string preservation, SSE pass-through (content-type + body bytes), 429 upstream error pass-through, 404 unknown route, 502 unreachable upstream, prefix strictness
- [x] `cargo test` — 8/8 passing
- [x] `cargo build` clean, `cargo run` prints stub banner

## Next Steps

Remaining v0.2 work is tracked with checkboxes in `internal/ROADMAP.md`
(gitignored, local-only). Suggested next feature: **per-project security
profiles (`.burnwall.yaml`)** — see that file for the full ordered list
and rationale.

## Bugs / Tech Debt

(None yet — project hasn't started)

## Open Questions

- Exact behavior when streaming response doesn't include usage block (OpenAI without stream_options.include_usage)?
- Should we support multiple concurrent proxy instances (different ports)?
- How to handle Anthropic's 1-hour cache duration vs 5-minute — can we detect which from the request?
