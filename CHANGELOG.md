# Changelog

All notable changes to Burnwall.

## [0.6.5] — 2026-05-26

### Added

- `burnwall mcp-watch` can front **multiple MCP servers** from a single watcher,
  routed by the first path segment. Configure them under `[[mcp.servers]]`; a
  `--upstream` still works as the fallback for unmatched paths.
- **MCP tool approval workflow.** Enforce mode (`mcp.require_approval`, or
  `--require-approval`) holds a `tools/call` to a tool you haven't approved with a
  403 until you approve it; a tool whose definition later changes is reset to
  pending automatically. Manage approvals with `burnwall mcp list`,
  `burnwall mcp approve <server> [tool]`, and `burnwall mcp revoke`. Off by
  default — the watcher stays observe-only until you opt in.
- `burnwall mcp export [--days N] [--format json|csv]` — export the MCP audit log
  (tool calls plus MCP-side security events) as JSON or CSV.
- **Egress / DLP check** (`[security].dlp`, opt-in). Blocks Luhn-valid credit-card
  numbers and US Social Security numbers in outbound payloads, including inside MCP
  tool-call arguments. Reports the category (e.g. "credit card number"), never the
  value.

## [0.6.0] — 2026-05-25

### Added

- **Community security rule packs.** Declarative TOML packs that extend the
  path / command / secret denylist. Bundled official packs ship in the binary:
  `django`, `react`, `infrastructure`, `data-science`. `burnwall rules list`,
  `burnwall rules install <id>`, and `burnwall rules test <pack> <file>` (a
  playground that shows what a pack would block against a sample request).
- **Third-party rule packs** via `burnwall rules add <file>` with
  Trust-On-First-Use: you review exactly what a pack adds, its contents are
  SHA-256-pinned, and any later edit re-prompts for approval. `burnwall rules
  revoke` removes one.
- More built-in secret patterns: Google API key, Google OAuth client secret,
  Stripe live keys, GitHub fine-grained PAT, npm token, SendGrid key.

### Security

- Rule packs are **deny-only / append-only** by construction — a pack can only add
  restrictions, never loosen them, and cannot toggle global switches. User-authored
  regexes are size-capped and compiled with the non-backtracking `regex` engine, so
  a malformed or hostile pattern is skipped rather than able to hang the proxy.

## [0.5.0] — 2026-05-25

### Added

- **MCP firewall.** `burnwall mcp-watch` now inspects `tools/list` responses for
  tool poisoning (injection phrases, hidden/zero-width unicode, smuggled
  paths/commands/secrets) and rug-pulls (a tool's definition silently changing
  after you've seen it). Findings are recorded as security events; responses are
  forwarded byte-for-byte unchanged.
- Cross-tool cost tracking now also reads **OpenCode** and **Aider** session logs,
  alongside Claude Code and Codex.
- `docs/SECURITY_FRAMEWORKS.md` — maps Burnwall's coverage to the OWASP LLM /
  Agentic Top 10 and the EU AI Act (honest about partial coverage).

### Changed

- The `[tools]` config section gained `opencode` and `aider` toggles (default on).

## [0.4.0] — 2026-05-25

### Added

- `burnwall waste` — an advisory report of cost-waste patterns found in your
  local AI session logs, each line annotated with its estimated dollar impact.
  Read-only; it never reads prompt content. Detects prompt-cache starvation,
  flagship-model use on trivial requests, heavy reasoning on routine prompts,
  requests near the context-window limit, runaway context growth within a
  session, and very long sessions. The headline figure is capped at what was
  actually spent. `--days N` and `--json` supported.
- `burnwall explore` — spend broken down by model, by tool, and by workspace
  over a window. `--days N` and `--json` supported.
- Monthly burndown in `burnwall history` — month-to-date spend, an ideal-pace
  line, and an end-of-month projection against the configured monthly budget.
- `burnwall status` shows a one-line teaser of average avoidable spend per day
  when there is any, with a pointer to `burnwall waste`.
- `burnwall config doctor` — prints the effective configuration and flags
  deprecated or unknown keys, out-of-range values, and any safety toggle that
  is turned on. Exits non-zero on an error-level problem.

### Changed

- New `[tools]` config section toggles log scraping per tool (`claude_code`,
  `codex`). It supersedes the old `[log_scrape]` switch, which still works for
  one release as a global on/off.
- New `[waste]` config section with `enabled` (default on) gates the advisory
  engine and the `status` teaser.
- `security.enabled = false` now actually disables request scanning; it was
  previously accepted but ignored.

## [0.3.2] — 2026-05-17

### Fixed

- Security scan no longer fails-open on a request body that starts with
  a UTF-8 BOM (`EF BB BF`). The JSON parser used to reject the BOM and
  the fail-open arm forwarded the request unscanned; the scanner now
  strips a leading BOM before parsing. The same fix lands on
  `extract_model`, the cache-injection rewriter, the cache-savings
  projection, and the MCP `tools/call` parser so they stay consistent.
  Found during pre-launch user-journey testing on Windows.

## [0.3.1] — 2026-05-16

### Changed

- CLI `--help` summary and the library crate doc now match the README
  positioning ("local proxy for AI coding tools"). The CLI summary is
  driven from `Cargo.toml` so the two cannot drift again. No
  functional changes.

## [0.3.0] — 2026-05-16

### Added

- Anthropic prompt-cache auto-injection. When enabled, outbound Messages
  API requests with no existing `cache_control` markers get an
  ephemeral marker added on the system prompt and the first message,
  so the cached read tier applies on subsequent turns. Existing
  markers are always respected and never overridden. Off by default;
  enable via `proxy.cache_injection = true` in config or with
  `burnwall start --rewrite-anthropic-cache`. The startup banner
  shows whether injection is on.
- "Would-have-cached" projection. When injection is off,
  `burnwall status` reports a per-day USD estimate of the savings
  you would have captured if it had been on. Surfaced as a line in
  the table view and a `projected_cache_savings_usd` field in
  `--json` output.
- `burnwall mcp-watch <upstream>` — pass-through proxy in front of an
  upstream MCP HTTP server. Forwards every request unchanged, streams
  responses back, and records JSON-RPC `tools/call` invocations
  (tool name, request id, upstream HTTP status) to a new `mcp_events`
  table. Argument payloads are deliberately not stored — they can
  contain prompt content. `--port` and `--host` flags are available
  for binding; defaults are `127.0.0.1:4101`.
- Security denylist extended to MCP. `burnwall mcp-watch` runs every
  request body through the same security engine the LLM proxy uses,
  so denied paths, commands, network mounts, and secret patterns are
  blocked when they appear inside `tools/call` arguments. A violation
  returns 403, never forwards to the upstream MCP server, and writes
  a `security_events` row with `provider = "mcp"` and the tool name —
  `burnwall security` shows these alongside LLM-side blocks. The
  per-project `.burnwall.yaml` profile (including `allow_paths`
  exceptions) applies too.
- `burnwall status` carries a count line for MCP `tools/call`
  invocations recorded today when the count is non-zero.

## [0.2.0] — 2026-05-16

### Added

- Background daemon mode. `burnwall start --daemon` runs the proxy in
  the background and writes a PID file under the data directory; the
  file is removed on graceful shutdown and stale files self-clean on
  sight. A second `start` against a live daemon refuses cleanly.
- `burnwall stop` now actually terminates a running daemon (graceful
  shutdown on Unix; immediate stop on Windows, safe because each
  storage write is its own transaction).
- Loop detector. Runaway agents that keep firing the same request, or
  burn cost faster than a configurable rate, get cut off with a 429
  before they drain the budget.
- `burnwall security` command — table or `--json` view of blocked
  requests with rule, provider, model, and timestamp.
- Per-project security profiles via `.burnwall.yaml`, discovered by
  walk-up from the current working directory. Supports `allow_paths`
  exceptions, additional `deny_paths`, and a per-project
  `budget.daily_max_usd` cap (can only tighten the global limit).
- Cross-tool cost tracking for tools that don't go through the proxy.
  `burnwall status` aggregates from local Claude Code and Codex CLI
  session logs alongside proxied traffic, with a combined-total line
  and a separate `log_scrape` key in `--json` output. Read-only — no
  database writes from log scraping.
- Local-time "today". `status`, `history`, and `security` now bucket
  by your local calendar day; timestamps are still stored in UTC
  internally. Fixes the off-by-one where late-UTC-day `status` showed
  an empty bucket.
- Pricing data freshness warning — `burnwall status` flags when the
  embedded rate card is more than 30 days old.
- Shell completions. `burnwall completions <shell>` emits scripts for
  bash, zsh, fish, powershell, and elvish.
- Path redaction in storage: `security.log_redact_details` redacts the
  matched-rule detail in `security_events` rows while leaving the 403
  response unaffected (D13 mitigation).
- `--json` output is now consistent across every command, including
  `config show`.
- README documents the scope of what Burnwall guards: it sits on the
  LLM API path, and MCP traffic is intentionally out of scope for
  this milestone. `burnwall status` carries a one-line scope footer.

### Changed

- Headline copy on the README and `Cargo.toml` description now leads
  with "local proxy for AI coding tools."

## [0.1.0] — initial feature set

### Added

- HTTP reverse proxy on `localhost:4100` routing `/anthropic/*` to
  `api.anthropic.com` and `/openai/*` to `api.openai.com`. SSE streaming
  responses pass through unmodified.
- Provider response parsers (Anthropic, OpenAI) for both non-streaming and
  SSE-streaming responses with cache-aware token accounting.
- Pricing database for Anthropic Opus/Sonnet/Haiku 4.x and OpenAI gpt-5.x;
  date-suffix-tolerant model lookup.
- Cache-aware cost calculator (`cost`, `cost_without_cache`, `cache_savings`).
- SQLite storage (`~/.burnwall/burnwall.db`) for `requests`,
  `security_events`, and `daily_summary`. `0700`/`0600` permissions on
  Unix; user-profile ACL on Windows. Unencrypted on disk by design — it
  holds only metadata (no API keys, no prompt content).
- Security engine — schema-agnostic JSON walker matching denied paths
  (with `~/`, expanded-Unix, and Windows-UNC tolerance), denied commands,
  network mounts (`/Volumes/`, `\\`, `smb://`, `nfs://`), and secret
  patterns (AWS access key, private key header, GitHub PAT, OpenAI/
  Anthropic/Slack tokens). Fail-open on non-JSON bodies.
- Atomic budget tracker — `AtomicU64` storing **microcents** for sub-cent
  precision (1000 small `gpt-5.4-mini` requests still register correctly).
  Hydrates from storage on startup.
- End-to-end pipeline: route → security check (403 + audit row on hit) →
  budget check (429 on exceeded) → forward → tee response stream → parse
  usage → record cost in storage and budget counter.
- CLI: `burnwall start`, `status`, `history`, `config set/show`, `init`,
  `stop` (v0.1 stub).
- TOML config at `~/.burnwall/config.toml` with `#[serde(default)]` so
  partial files round-trip. `BURNWALL_DATA_DIR` env var override for
  hermetic CLI integration tests.
- GitHub Actions: CI matrix (ubuntu / macOS / windows; build + test +
  rustfmt + clippy) and release workflow (per-target archives, GitHub
  Release with auto-generated notes on `v*` tag push).
