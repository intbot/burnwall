# Burnwall Architecture

## System Overview

Burnwall is a local HTTP reverse proxy that sits between AI coding tools and their API providers. It inspects requests for security violations, enforces budget limits, forwards clean requests to providers, parses responses for usage data, and stores cost metrics locally.

## Core Design Principles

### 1. Transparent Proxy
The AI tool doesn't know Burnwall exists (beyond the base URL change). Requests and responses pass through unmodified. Burnwall only reads — it never rewrites API responses.

### 2. Request-Side Security, Response-Side Analytics
- **Before forwarding:** scan request body for security violations → block if needed
- **After receiving response:** parse usage block → calculate cost → store in DB
- These are separate concerns and should be separate modules

### 3. Fail-Open
If any part of Burnwall's logic fails (parsing, DB write, pricing lookup), the request/response still flows through. We never break the user's workflow. Log the error and move on.

### 4. Zero Allocation on the Hot Path (where possible)
The proxy adds latency to every API call. Use `bytes::Bytes` for zero-copy body handling. Parse JSON lazily — only look for the fields we need, don't deserialize the entire response. For streaming responses, only parse the final chunk.

## Component Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI (clap)                        │
│  start │ stop │ status │ history │ config │ init     │
└────────────┬────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────┐
│                 Proxy Server (hyper)                  │
│                                                      │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │ Router   │→ │ Security  │→ │ Budget           │  │
│  │ (path    │  │ Engine    │  │ Enforcer         │  │
│  │ matching)│  │           │  │                  │  │
│  └──────────┘  └───────────┘  └────────┬─────────┘  │
│                                        │             │
│  ┌─────────────────────────────────────▼──────────┐  │
│  │              Forwarder                          │  │
│  │  (forward to upstream, handle streaming)        │  │
│  └─────────────────────────────────────┬──────────┘  │
│                                        │             │
│  ┌─────────────────────────────────────▼──────────┐  │
│  │           Response Parser                       │  │
│  │  ┌─────────────┐  ┌──────────────────────────┐  │  │
│  │  │ Anthropic   │  │ OpenAI                   │  │  │
│  │  │ Parser      │  │ Parser                   │  │  │
│  │  └─────────────┘  └──────────────────────────┘  │  │
│  └─────────────────────────────────────┬──────────┘  │
│                                        │             │
│  ┌──────────────┐  ┌──────────────────▼──────────┐  │
│  │ Pricing DB   │← │ Cost Calculator             │  │
│  │ (rates.toml) │  │ (cache-aware)               │  │
│  └──────────────┘  └──────────────────┬──────────┘  │
│                                        │             │
│  ┌─────────────────────────────────────▼──────────┐  │
│  │           Storage (SQLite)                      │  │
│  │  requests │ security_events │ daily_summary     │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Shared State

The proxy server needs shared state across async request handlers:

```rust
struct AppState {
    config: Arc<Config>,                    // Immutable after startup
    storage: Arc<Storage>,                  // SQLite with connection pool
    pricing: Arc<PricingDatabase>,          // Immutable rate table
    budget_tracker: Arc<BudgetTracker>,     // Atomic counters for daily spend
    security_engine: Arc<SecurityEngine>,   // Immutable rule set
    http_client: reqwest::Client,           // Shared HTTP client for forwarding
}
```

Use `Arc<T>` for immutable shared state. The `BudgetTracker` uses `AtomicU64` (storing cents as u64) for lock-free daily spend tracking. SQLite writes use a single writer connection (SQLite's default — one writer, many readers).

## Request Routing

Route based on URL path prefix:

```
/anthropic/v1/messages     → https://api.anthropic.com/v1/messages
/openai/v1/chat/completions → https://api.openai.com/v1/chat/completions
/google/v1beta/models/...  → https://generativelanguage.googleapis.com/v1beta/models/...
```

Each provider's upstream base URL is overridable via `burnwall start`
(`--anthropic-url` / `--openai-url` / `--google-url`).

Strip the provider prefix, forward everything else (path, query params, headers, body) unchanged.

## Streaming Architecture

AI API responses are often streamed via Server-Sent Events (SSE). The proxy must:

1. **Start forwarding immediately** — don't buffer the full response
2. **Tee the stream** — send chunks to the client AND to an internal parser
3. **Parse the final chunk** — extract usage data
4. **Log after stream ends** — write to SQLite once usage is known

```
Upstream SSE → [chunk 1] → forward to client
              [chunk 2] → forward to client
              [chunk 3] → forward to client
              ...
              [final chunk with usage] → forward to client + parse usage → store
```

For Anthropic: the `message_stop` event followed by usage in the `message_delta` event.
For OpenAI: the final chunk with `"finish_reason": "stop"` and `usage` field (when `stream_options.include_usage` is true).
For Google: `usageMetadata` on the final `streamGenerateContent` chunk — the cached-content split comes from `cachedContentTokenCount`, and thinking tokens fold into output.

If the stream doesn't include usage data (some configurations), estimate from token counting or log as "unknown cost."

## Security Engine Design

The security engine scans the JSON request body before forwarding. It does NOT need to understand the full API schema — it pattern-matches on known fields:

### Anthropic tool_use scanning:
```json
{
  "content": [
    {
      "type": "tool_use",
      "name": "bash",
      "input": {
        "command": "cat ~/.ssh/id_rsa"    // ← scan this
      }
    }
  ]
}
```

### OpenAI function_call scanning:
```json
{
  "tool_calls": [
    {
      "function": {
        "name": "execute_command",
        "arguments": "{\"command\": \"cat ~/.ssh/id_rsa\"}"  // ← scan this
      }
    }
  ]
}
```

The scanner does a deep traversal of the JSON looking for string values that match deny patterns. On the LLM proxy path it is **context-aware**: command-shaped rules (denied paths, denied commands, network mounts, destructive commands, exfil techniques) apply only inside tool-call argument subtrees — Anthropic `tool_use.input`, OpenAI `tool_calls` / `function_call` arguments, Gemini `functionCall`. Prose (the system prompt, chat text, tool definitions, tool results) can legitimately *mention* `~/.ssh` or `rm -rf` — project docs describing a deny list, a conversation about backups — and must not be blocked for it. Data-shaped rules (secret detection, DLP) still apply to **every** string leaf, since a credential or card number is worth blocking wherever it sits in the payload.

MCP `tools/call` bodies keep the strict whole-body semantics: there, the entire payload *is* a tool invocation, so any string value containing a denied path or command triggers a block.

### Pattern Matching Strategy:
- **Path matching:** Expand `~` to actual home dir, normalize paths, check against deny list
- **Command matching:** Simple substring/regex matching on known dangerous patterns
- **Secret detection:** Regex for AWS keys (`AKIA...`), private key headers (`-----BEGIN`), common API key formats
- **Network mounts:** Check for `/Volumes/`, `\\\\`, `smb://`, `nfs://` prefixes

## Budget Tracking

### In-Memory (fast, approximate):
- `AtomicU64` storing today's spend in cents
- Checked on every request before forwarding
- Reset at midnight (local time)

### SQLite (accurate, persistent):
- Every request logged with exact cost
- `daily_summary` table updated periodically
- Used by `burnwall status` and `burnwall history` commands
- On startup, load today's total from SQLite into the atomic counter

### Budget Enforcement:
1. Read atomic counter
2. If >= daily_limit → return 429 immediately (sub-millisecond)
3. After response parsed → add cost to atomic counter + write to SQLite

This means there's a small race window where concurrent requests might slightly exceed the budget. This is acceptable — the alternative (locking) adds latency to every request.

## Data Directory

All Burnwall data lives in `~/.burnwall/`:

```
~/.burnwall/
  config.toml          — user configuration
  burnwall.db        — SQLite database
  burnwall.log       — log file (when running as daemon)
  burnwall.pid       — PID file (when running as daemon)
  pricing.toml         — user pricing overrides (optional)
  otel-spans.jsonl     — OTel GenAI spans (only if [observability].otel_spans)
```

On Windows: `%USERPROFILE%\.burnwall\`

## v0.7 Components

Three additions layer onto the pipeline above without changing the
read-only, fail-open contract:

### Provider Parsers — Google Gemini
`providers/google.rs` parses `generateContent` / `streamGenerateContent`
responses, reading token counts from `usageMetadata` (cached-content split,
thinking tokens folded into output). Pricing covers `gemini-2.5-pro`,
`gemini-2.5-flash`, and `gemini-2.0-flash`. The `/google/*` route forwards to
`generativelanguage.googleapis.com`.

### Observability (`observe/`)
Two metadata-only consumers of the request log:

- **`burnwall metrics`** aggregates per-request upstream latency (now recorded
  alongside HTTP status on the response path) into per-model p50/p95, error
  rate, and throughput.
- **`burnwall digest`** assembles an Agent Bill of Materials for a window —
  models + cost, MCP servers/tools, tool-call counts, security checks fired,
  turns — from existing rows.
- **OpenTelemetry GenAI spans** (`observe/otel.rs`): when
  `[observability].otel_spans` is on, each forwarded request emits one
  `gen_ai.*` span as line-delimited JSON to a local file. Payload-free and
  file-only — no network export, consistent with the zero-telemetry stance.

None of these read prompt content.

### Resilience (`proxy/resilience.rs`)
Opt-in same-model endpoint failover plus a per-endpoint circuit breaker. When
`[resilience]` is enabled and the primary upstream is unreachable or returns
5xx, the forwarder retries the identical request against the next configured
endpoint for that provider, skipping endpoints whose circuit is open. A
`CircuitBreaker` (`DashMap`-backed, in-memory) counts consecutive failures;
at `failure_threshold` the endpoint opens for `cooldown_seconds`, after which
one half-open probe decides whether it closes or re-opens. State is in-memory
only — a restart starts clean. Off by default: a single upstream with verbatim
5xx pass-through is unchanged until configured.

## v0.8 Components

### Audit & compliance (`audit/`)
Local, metadata-only audit and compliance artifacts built on the existing
request + security logs. Read-only — they never read prompt content.

- **Cryptographic audit receipts** (`audit/mod.rs`): `burnwall audit seal`
  appends, for each not-yet-sealed `requests` / `security_events` row (in
  chronological order), a signed link in a hash chain. `content_hash` =
  SHA-256 over the source row's canonical text; `hash` = SHA-256(prev_hash ‖
  content_hash); `signature` = Ed25519 over `hash`. The key lives at
  `~/.burnwall/audit_ed25519.key` (0600, generated on first use). Receipts
  go in a new `audit_receipts` table with `UNIQUE(source, source_id)`, so
  sealing is idempotent. `verify` re-walks the chain and re-derives each
  `content_hash` from the live row, so edits/deletions/reorders of either a
  receipt or a sealed source row are detected, and the chain can't be extended
  without the key. **Seal-on-demand, not on the hot path** — the proxy is
  untouched, preserving its latency budget; you seal periodically or before an
  audit.
- **CycloneDX AIBOM** (`audit/aibom.rs`): renders the shared `observe::digest`
  `Digest` as a CycloneDX 1.6 BOM (models → components, MCP servers → services).
- **SARIF export** (`audit/sarif.rs`): renders `security_events` as a SARIF
  2.1.0 run (one rule per event type, one result per block) for GitHub code
  scanning.
- **`burnwall report`** (`cli/report.rs`): a shareable period summary rendered
  from the same `Digest`, in text / JSON / CSV.
