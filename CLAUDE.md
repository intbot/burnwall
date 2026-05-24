# Burnwall

**AI agent firewall that also saves you money.**

A cross-platform local proxy that intercepts AI API calls, enforces security policies, tracks real costs (including caching), detects runaway loops, and enforces budget limits. Single binary. Zero telemetry. 100% local.

## Positioning

Lead with SECURITY. Cost tracking is the hook that gets people to install it; security is why they keep it running. No other tool combines cost + security + cross-tool + single binary for individual developers.

## Tech Stack

- **Language:** Rust (latest stable edition)
- **Async runtime:** Tokio
- **HTTP proxy:** Hyper + Tower
- **CLI framework:** Clap v4 (derive API)
- **Storage:** SQLite via rusqlite (bundled)
- **Config:** TOML via toml crate
- **Logging:** tracing + tracing-subscriber
- **Serialization:** serde + serde_json
- **Cross-platform targets:** x86_64 + aarch64 for macOS, Windows, Linux

## Architecture

```
[AI Tool] → HTTP request → [Burnwall Proxy :4100]
                                    │
                          ┌─────────┼──────────┐
                          │   SECURITY CHECK    │
                          │  (scan tool_use     │
                          │   blocks for blocked│
                          │   paths/commands)    │
                          └─────────┬──────────┘
                                    │ pass/block
                          ┌─────────┼──────────┐
                          │   BUDGET CHECK      │
                          │  (daily limit)      │
                          └─────────┬──────────┘
                                    │ pass/block
                          ┌─────────┼──────────┐
                          │   FORWARD REQUEST   │
                          │  → real provider API│
                          └─────────┬──────────┘
                                    │ response
                          ┌─────────┼──────────┐
                          │   PARSE RESPONSE    │
                          │  (extract usage,    │
                          │   calc real cost    │
                          │   with caching)     │
                          └─────────┬──────────┘
                                    │
                          ┌─────────┼──────────┐
                          │   STORE IN SQLITE   │
                          └─────────┬──────────┘
                                    │
                          [Return response unchanged]
```

## Key Principles

- **Zero network calls** except forwarding to AI providers
- **No telemetry**, no analytics, no phone-home, ever
- **Never modify API responses** — read-only inspection on the response path
- **Never log prompt content or API keys** to disk — only metadata (model, tokens, cost, timestamp)
- **Security rules evaluated BEFORE forwarding** — blocked requests never leave the machine
- **Sub-5ms proxy overhead** — users should not feel the proxy exists
- **Fail-open by default** — if parsing fails, forward the request anyway and log the error
- **Works offline** (except the forwarding itself)

## Project Structure

```
src/
  main.rs                  — CLI entry point (clap)
  proxy/
    mod.rs                 — Proxy server setup (hyper + tower)
    handler.rs             — Request/response handler pipeline
    forwarding.rs          — Forward requests to upstream providers
    streaming.rs           — SSE/streaming response handling
  providers/
    mod.rs                 — Provider trait and registry
    anthropic.rs           — Anthropic Messages API parser
    openai.rs              — OpenAI Chat Completions API parser
    google.rs              — Google Gemini API parser (future)
  security/
    mod.rs                 — Security engine orchestrator
    rules.rs               — Rule types and matching logic
    scanner.rs             — Scan request bodies for violations
    secrets.rs             — Detect API keys/credentials in payloads
  budget/
    mod.rs                 — Budget enforcement logic
    limits.rs              — Daily/monthly limit checking
    loop_detector.rs       — Detect runaway agent loops
  storage/
    mod.rs                 — SQLite setup and migrations
    repository.rs          — Query/insert operations
    models.rs              — Database row types
  pricing/
    mod.rs                 — Pricing database and calculator
    rates.rs               — Per-model, per-token-type rates
    cache_calc.rs          — Cache-aware cost calculation
  config/
    mod.rs                 — TOML config loading and defaults
    types.rs               — Config struct definitions
  cli/
    mod.rs                 — CLI command definitions
    start.rs               — `burnwall start` command
    stop.rs                — `burnwall stop` command
    status.rs              — `burnwall status` command
    history.rs             — `burnwall history` command
    config_cmd.rs          — `burnwall config` command
    init.rs                — `burnwall init` (auto-detect + setup)
tests/
  fixtures/                — Real (sanitized) API response JSON files
    anthropic_cached.json
    anthropic_uncached.json
    anthropic_streaming.json
    openai_cached.json
    openai_uncached.json
    request_with_tool_use.json
    request_with_blocked_path.json
  integration/
    proxy_test.rs
    security_test.rs
    budget_test.rs
  unit/
    pricing_test.rs
    parser_test.rs
```

## Code Style

- Use `thiserror` for error types, `anyhow` in main/CLI only
- Prefer `Arc<T>` for shared state across async handlers, avoid `Mutex` where possible (use `DashMap` or atomics)
- All proxy handlers are async
- Use `bytes::Bytes` for zero-copy request/response body handling
- Structured logging: `tracing::info!`, `tracing::warn!`, `tracing::error!` — never `println!`
- Integration tests use a mock HTTP upstream — NO dependency on real AI APIs in CI
- Unit tests use fixtures from `tests/fixtures/`
- One `cargo test` runs everything offline

## Provider API Response Formats

### Anthropic (Messages API)
```json
{
  "usage": {
    "input_tokens": 500,
    "output_tokens": 200,
    "cache_creation_input_tokens": 8000,
    "cache_read_input_tokens": 45000
  }
}
```

### OpenAI (Chat Completions API)
```json
{
  "usage": {
    "prompt_tokens": 500,
    "completion_tokens": 200,
    "prompt_tokens_details": {
      "cached_tokens": 400
    }
  }
}
```

## Security Scanning

Scan `tool_use` / `function_call` blocks in the REQUEST body (before forwarding) for:
- File paths matching deny list (e.g., `~/.ssh`, `~/.aws`, `/etc/passwd`)
- Network mount paths (`/Volumes/`, `\\server\share`, SMB/NFS)
- Blocked commands (`rm -rf`, `chmod 777`, `curl` to unknown domains)
- Patterns that look like API keys or credentials being exfiltrated

## Important Notes for Claude Code Sessions

- Read `docs/SPEC.md` for exact CLI behavior and output formats
- Read `docs/ARCHITECTURE.md` for component design and data flow
- Work in focused, scoped sessions — one component at a time
- Write tests FIRST for any new parser or calculator logic
- Never add any form of telemetry or network call beyond API forwarding
