# Changelog

All notable changes to Burnwall.

## [0.9.2] — 2026-05-28

### Added

- **"Use Burnwall with anything" cookbook** (`docs/INTEGRATIONS.md`) — one-line
  base-URL recipes to put Burnwall in front of your coding tools, agent SDKs, and
  any OpenAI-/Anthropic-compatible gateway (e.g. OpenRouter). Burnwall runs *in
  front of* your existing setup; nothing else changes.
- **Independent audit verification.** `burnwall audit export --format json` emits a
  self-contained, signed receipt bundle, and `tools/verify_receipts.py` re-walks the
  hash chain and verifies every Ed25519 signature **without trusting the Burnwall
  binary**. `docs/COMPLIANCE.md` maps the receipts to EU AI Act Art. 12 / ISO 42001
  A.6.2.8 / SOC 2 / NIST AI RMF (as *evidence*, not certification).
- **MCP registry manifest** (`packaging/mcp/server.json`) + `docs/MCP_REGISTRY.md`
  so the local MCP firewall can be listed/discovered.
- **OpenSSF Scorecard CI** (supply-chain trust signal) and a clearer
  "100% local, zero telemetry" README headline.

## [0.9.1] — 2026-05-28

### Added

- **`burnwall cost-per-pr [--base main] [--json]`** — approximate cost of the
  current git branch / PR, by attributing local cross-tool session-log spend to the
  branch's active window (oldest commit on `base..HEAD`). Local + git metadata only;
  never reads prompt content. Approximate (time-bucketed) and labelled as such.
- **MCP permission auto-policy** — `[mcp].auto_approve` and `[mcp].auto_deny` glob
  lists (matched against `"<server>/<tool>"`). Auto-deny always blocks; auto-approve
  skips the approval gate in enforce mode — cutting approval fatigue. Both opt-in.
- **VS Code inline panel** — the status-bar item now opens a panel
  (`Burnwall: Open Panel`) summarising cost-by-model, security blocks, and MCP tools
  from the local CLI JSON.
- **Soft budget alert** — `burnwall status` shows a non-blocking heads-up once
  today's spend crosses the configured warn threshold but is still under the hard
  daily limit.

## [0.9.0] — 2026-05-28

### Added

- **VS Code extension** (`editor/vscode/`) — a status-bar item showing today's
  spend, cache hit rate, and blocked-request count, read from your local
  `burnwall status --json`. Click it for the full breakdown; when the CLI isn't
  installed it links to the install instructions. Works in Cursor, Windsurf, and
  VSCodium too. No data leaves your machine.
- **Signed remote rule packs.** `burnwall rules fetch <url>` downloads a rule
  pack and its detached Ed25519 signature and installs it **only** if the
  signature verifies against a key you trust in `[rules].publishers`. The
  publisher side is `burnwall rules keygen` (make a keypair) and
  `burnwall rules sign` (sign a pack); `burnwall rules verify` checks a local
  pack + signature. A fetched pack is parsed under the same deny-only /
  append-only rules as any other pack — it can only ever add restrictions.

## [0.8.0] — 2026-05-28

### Added

- **Cryptographic audit receipts** — `burnwall audit seal` walks the request and
  security-event logs and appends, for each action, a signed link in a hash
  chain: a SHA-256 of the source row's contents, chained into the previous
  receipt, then signed with a local Ed25519 key (generated on first use).
  `burnwall audit verify` re-walks the chain and re-derives every hash from the
  live rows, so any edit, deletion, or reordering — of a receipt *or* the
  underlying row — is detected, and the chain can't be forged without the key.
  Tamper-evident, metadata-only proof of what an agent did and was blocked from.
- **CycloneDX AI Bill of Materials** — `burnwall audit aibom [--days N]` exports
  a CycloneDX 1.6 BOM for the window: models as components, MCP servers as
  services, totals in metadata. Machine-readable, audit-grade session record.
- **SARIF export** — `burnwall audit sarif [--days N]` emits security blocks as
  SARIF 2.1.0, ready to upload to GitHub code scanning (the Security tab) with
  no custom integration.
- **`burnwall report [--days N] [--format text|json|csv]`** — a shareable
  weekly/monthly summary (spend, activity, top models, security blocks), and
  **`burnwall audit export [--format json|csv]`** to dump the receipt log.

All of the above are metadata only — they never read or store prompt content —
and read-only against the existing logs.

## [0.7.0] — 2026-05-27

### Added

- **Same-model endpoint failover + circuit breaking** (`[resilience]`, opt-in).
  When an upstream is unreachable or returns a 5xx, Burnwall reroutes the same
  request to the next configured endpoint for that provider (e.g. a Bedrock or
  Vertex base URL for a Claude/Gemini model) — the request shape is identical,
  so it is a transparent reroute, not a translation. A per-endpoint circuit
  breaker (`failure_threshold`, `cooldown_seconds`) stops hammering a dead
  endpoint and lets it recover with a half-open probe. Off by default — a single
  upstream and verbatim 5xx pass-through is unchanged until you configure it.
- **`burnwall metrics [--days N] [--json]`** — per-model latency (p50/p95),
  error rate, and throughput, computed locally from the request log. The local
  answer to hosted LLM observability. Metadata only — no prompt content. The
  proxy now records each forwarded request's upstream latency and HTTP status.
- **`burnwall digest [--days N] [--json]`** — an Agent Bill of Materials for a
  window: which models ran and what they cost, which MCP servers/tools were
  touched, how many tool calls were made, which security checks fired, and total
  turns. Assembled from existing metadata; never reads prompt content.
- **OpenTelemetry GenAI spans** (`[observability].otel_spans`, opt-in). Each
  forwarded request emits one span following the OTel GenAI semantic conventions
  (`gen_ai.*`) as line-delimited JSON to a local file (`otel_file`). Payload-free
  and file-only — no network export, consistent with Burnwall's zero-telemetry
  stance. Interop without leaking prompts.
- **Google Gemini support** — `/google/*` route to the Gemini API, a
  `generateContent` + SSE response parser (`usageMetadata` token accounting with
  cached-content split and thinking-token folding), and pricing for
  `gemini-2.5-pro`, `gemini-2.5-flash`, and `gemini-2.0-flash`.

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
