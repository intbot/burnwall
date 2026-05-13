# Changelog

All notable changes to Burnwall.

## [Unreleased] — v0.1 in development

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
  Unix; user-profile ACL on Windows. Unencrypted on disk by design (see
  D13 in `docs/DECISIONS.md`).
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

### Not yet (planned for v0.2+)

- Loop detection (request hashing + exponential backoff)
- Background daemon mode + real `burnwall stop`
- VS Code / Cursor extension
- TZ-aware "today" (currently UTC; SPEC §"daily reset" is local-time)
- aarch64-linux release artifact (needs cross-build setup)
- Path redaction in `security_events.details`
