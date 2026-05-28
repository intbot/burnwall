# Burnwall Specification

## Scope

This spec describes Burnwall's CLI commands, proxy behavior, security engine,
and storage schema.

---

## CLI Commands

### `burnwall init`

Auto-detect installed AI tools and configure environment variables.

```
$ burnwall init

🔍 Detecting AI tools...
  ✓ Claude Code found
  ✓ Codex CLI found
  ✗ Aider not found

🔧 Configuring environment...
  → Added ANTHROPIC_BASE_URL=http://localhost:4100/anthropic to ~/.zshrc
  → Added OPENAI_BASE_URL=http://localhost:4100/openai to ~/.zshrc

🛡️ Default security rules applied:
  → Blocking access to: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube
  → Blocking commands: rm -rf /, chmod 777

💰 Default budget: $50/day (change with `burnwall config set budget.daily <amount>`)

✅ Setup complete. Run `source ~/.zshrc` then `burnwall start`.

What's your primary goal?
  [1] Track AI costs
  [2] Set budget limits
  [3] Security / access control
  [4] All of the above
> (stored locally in ~/.burnwall/config.toml, never sent anywhere)
```

**Detection logic:**
- Claude Code: check if `claude` binary exists in PATH
- Codex CLI: check if `codex` binary exists in PATH
- Aider: check if `aider` binary exists in PATH
- OpenCode: check if `opencode` binary exists in PATH

**Shell detection:**
- Check `$SHELL` env var
- Support: zsh (~/.zshrc), bash (~/.bashrc), fish (~/.config/fish/config.fish)
- On Windows: set system environment variables via PowerShell

### `burnwall start`

Start the proxy daemon.

```
$ burnwall start

🛡️ Burnwall v0.1.0
   Proxy: http://localhost:4100
   Config: ~/.burnwall/config.toml
   Database: ~/.burnwall/burnwall.db

   Routes:
     /anthropic/* → api.anthropic.com
     /openai/*    → api.openai.com

   Security: 4 deny rules active
   Budget: $50.00/day

   Ready. All API calls are being tracked.
```

**Behavior:**
- Starts HTTP server on `localhost:4100` (configurable via `--port`)
- Runs in foreground by default
- `--daemon` flag runs as background process, writes PID to `~/.burnwall/burnwall.pid`
- Exits gracefully on SIGINT/SIGTERM
- If port is already in use, print helpful error message

### `burnwall stop`

Stop the background proxy daemon.

```
$ burnwall stop
Stopped Burnwall (PID 12345).
```

### `burnwall status`

Show current spend summary.

```
$ burnwall status

📊 Today (May 11, 2026)
   Total: $12.47 across 84 requests

   Provider / Model                   Cost      Requests  Cache Hit
   ─────────────────────────────────────────────────────────────────
   anthropic/claude-sonnet-4-6       $8.20      62        73%
   anthropic/claude-haiku-4-5        $0.92      18        91%
   openai/gpt-5.4                    $3.35      4         45%

   💰 Budget: $12.47 / $50.00 (24.9%)
   🛡️ Security: 2 blocked attempts
   🔄 Loops: 1 detected and killed

   Cache savings today: $47.82
   (without caching, today would have cost $60.29)
```

**Data source:** Query SQLite for today's records, grouped by provider+model.

**Cache hit rate calculation:**
```
cache_hit_rate = cache_read_tokens / (cache_read_tokens + input_tokens + cache_creation_tokens)
```

**Cache savings calculation:**
```
savings = (cache_read_tokens × base_input_price) - (cache_read_tokens × cache_read_price)
```

### `burnwall history [--days N]`

Show historical spend. Default: 7 days.

```
$ burnwall history

📅 Last 7 days
   Date          Cost       Requests   Cache    Blocked
   ────────────────────────────────────────────────────
   May 11        $12.47     84         73%      2
   May 10        $28.91     156        68%      0
   May 9         $7.23      41         82%      1
   May 8         $45.02     203        45%      5
   May 7         $19.88     98         71%      0
   May 6         $31.44     167        62%      3
   May 5         $22.10     121        77%      1
   ────────────────────────────────────────────────────
   Total         $167.05    870        avg 68%  12

   Estimated monthly (at this rate): $715.93
```

Flags:
- `--days N` — show N days (default 7)
- `--json` — output as JSON
- `--model` — break down by model per day

### `burnwall metrics [--days N] [--json]`

Per-model latency percentiles, error rate, and throughput — computed locally
from the request log. The local answer to hosted LLM observability. Metadata
only; never reads prompt content. Default window: 7 days.

```
$ burnwall metrics

📈 Latency & reliability (last 7 days)

   Provider / Model                  Reqs    Errs       p50       p95     Err%   Req/day
   ──────────────────────────────────────────────────────────────────────────────────
   anthropic/claude-sonnet-4-6        428      3     842ms    3180ms     0.7%      61.1
   openai/gpt-5.4                      96      5     510ms    1920ms     5.2%      13.7
   google/gemini-2.5-pro              140      0     690ms    2450ms     0.0%      20.0
```

**Data source:** per-request upstream latency (ms) and HTTP status recorded on
the response path. `p50`/`p95` are percentiles over latency samples in the
window; `Err%` is the share of requests with a 4xx/5xx status; `Req/day` is the
request count divided by the window in days. Empty window prints a hint to route
a request through the proxy first.

Flags:
- `--days N` — window in days (default 7, floored at 1)
- `--json` — emit `{ "days", "models": [ { provider, model, requests, errors,
  error_rate, p50_ms, p95_ms, throughput_per_day } ] }`

### `burnwall digest [--days N] [--json]`

An Agent Bill of Materials for a window: which models ran and what they cost,
which MCP servers/tools were touched, how many tool calls were made, which
security checks fired, and total turns. Assembled entirely from existing
metadata rows — never reads prompt content. Default window: 7 days.

```
$ burnwall digest

🧾 Agent Bill of Materials (last 7 days)

   Turns:      664 requests (8 blocked)
   Total cost: $241.07

   Models:
     anthropic/claude-sonnet-4-6        428 req   $198.40
     openai/gpt-5.4                      96 req    $31.22
     google/gemini-2.5-pro              140 req    $11.45

   MCP tool calls: 52 (4 distinct tools)
   MCP tools advertised:
     filesystem/read_file (approved)
     filesystem/write_file (pending)

   Security checks fired: 8
     path_blocked: 6
     secret_detected: 2
   Distinct targets touched: 5
```

Flags:
- `--days N` — window in days (default 7)
- `--json` — emit the same structure as the table (days, turns, blocked,
  total_cost_usd, models, mcp_tool_calls, distinct_mcp_tools, mcp_tools,
  security_by_type, distinct_targets)

### `burnwall report [--days N] [--format text|json|csv]`

A shareable period summary (default window: 30 days): spend, request/blocked
activity, top models by cost, and security blocks by type. Built from the same
metadata as `digest`; never reads prompt content. `--format csv` emits the
per-model spend rows; `--format json` the full structure.

### `burnwall audit <subcommand>`

Cryptographic audit receipts and compliance exports (all metadata only).

- `burnwall audit seal` — walk the request + security-event logs and append, in
  chronological order, a signed link in a hash chain for each not-yet-sealed
  action. Each receipt stores a SHA-256 of the source row's canonical contents
  (`content_hash`), chained as `hash = SHA-256(prev_hash ‖ content_hash)`, and
  signed with a local Ed25519 key at `~/.burnwall/audit_ed25519.key` (generated
  0600 on first use). Idempotent — already-sealed rows are skipped.
- `burnwall audit verify` — re-walk the chain: check every hash link, re-derive
  each `content_hash` from the live source row, and verify each Ed25519
  signature. Prints the public key. Exits non-zero if the chain is tampered
  (a receipt or a sealed row was edited, deleted, or reordered).
- `burnwall audit export [--format json|csv]` — dump the receipt log.
- `burnwall audit aibom [--days N]` — export a CycloneDX 1.6 AI Bill of
  Materials for the window (models as components, MCP servers as services).
- `burnwall audit sarif [--days N]` — export security blocks as SARIF 2.1.0
  for GitHub code scanning.

```
$ burnwall audit seal
🔏 Sealed 2 new receipts into the audit chain.
   Public key: 85369a5c3c6f586823d45c9d182e1e177598dae37b0c7791f65c1aa7cb68bec7

$ burnwall audit verify
✅ Audit chain intact — 2 receipts verified.
   Public key: 85369a5c3c6f586823d45c9d182e1e177598dae37b0c7791f65c1aa7cb68bec7
```

### `burnwall config set <key> <value>`

Set configuration values.

```
$ burnwall config set budget.daily 20
✅ Daily budget set to $20.00

$ burnwall config set security.deny_paths "~/.ssh,~/.aws,~/.gnupg"
✅ Deny paths updated (3 entries)

$ burnwall config set security.deny_commands "rm -rf,chmod 777"
✅ Deny commands updated (2 entries)
```

### `burnwall config show`

Show current configuration.

```
$ burnwall config show

[proxy]
port = 4100
host = "127.0.0.1"

[budget]
daily = 50.0
warn_percent = 80

[security]
deny_paths = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube"]
deny_commands = ["rm -rf /", "chmod 777"]
detect_secrets = true
block_network_mounts = true

[loop_detection]
enabled = true
max_identical_requests = 5
window_seconds = 300
max_cost_per_window = 2.0
```

---

## Proxy Behavior

### Request Flow (detailed)

```
1. RECEIVE request from AI tool on localhost:4100
2. IDENTIFY provider from URL path:
     /anthropic/*  → Anthropic Messages API
     /openai/*     → OpenAI Chat Completions API
     /google/*     → Google Gemini API (generateContent)
3. SECURITY CHECK (request body):
   a. Parse JSON body
   b. Scan for tool_use / function_call blocks
   c. For each tool call:
      - Check file paths against deny_paths list
      - Check commands against deny_commands list
      - Check for network mount paths (/Volumes/, \\, smb://, nfs://)
      - Check for secret patterns (AWS keys, API tokens, private keys)
   d. If ANY rule matches:
      - Return HTTP 403 with JSON error body:
        {"error": {"type": "security_blocked", "message": "Burnwall blocked: attempted read of ~/.ssh/id_rsa"}}
      - Log blocked event to SQLite
      - Print warning to terminal: 🛡️ BLOCKED: ...
      - Do NOT forward the request
4. BUDGET CHECK:
   a. Query today's total spend from SQLite
   b. If >= daily_limit:
      - Return HTTP 429 with JSON error body:
        {"error": {"type": "budget_exceeded", "message": "Daily budget of $20.00 exceeded ($20.47 spent)"}}
      - Log event
      - Print warning: 💰 BUDGET EXCEEDED: ...
   c. If >= warn_percent of daily_limit:
      - Print warning: ⚠️ Budget 85% used ($17.02/$20.00)
      - Still forward the request
5. FORWARD request to real provider:
   a. Rewrite URL: strip /anthropic, /openai, or /google prefix
   b. Forward all headers unchanged (including auth)
   c. Forward body unchanged
   d. For streaming (SSE) responses: pipe through, parse final usage chunk
   e. For non-streaming: buffer response, parse usage
   f. [v0.7] If `[resilience]` is enabled and the upstream is unreachable or
      returns 5xx, retry the SAME request against the next configured endpoint
      for that provider (skipping endpoints whose circuit breaker is open).
      The request shape is identical — a transparent reroute, not a translation.
6. PARSE response usage block:
   a. Extract token counts by type (input, cached, output, cache_write)
   b. Look up model in pricing database
   c. Calculate real cost with cache-aware pricing
7. LOOP DETECTION [v0.2]:
   a. Hash first 200 chars of request content
   b. Check if same hash appeared N+ times in last M seconds
   c. If loop detected: block with 429, exponential backoff
8. STORE in SQLite:
   - timestamp, provider, model, input_tokens, cache_creation_tokens,
     cache_read_tokens, output_tokens, cost_usd, blocked (bool),
     block_reason, session_id (from request header if available)
   - [v0.7] upstream latency (ms) and HTTP status — metadata only, feeds
     `burnwall metrics`. If `[observability].otel_spans` is on, also emit one
     OpenTelemetry GenAI span (`gen_ai.*`) as a line of JSON to `otel_file`.
9. RETURN response unchanged to AI tool
```

### Streaming (SSE) Handling

Many AI tools use streaming responses (`stream: true`). The proxy must:
1. Forward SSE chunks as they arrive (don't buffer the whole response)
2. Parse the FINAL chunk which contains the usage block
3. Calculate cost from the final usage block
4. Log to SQLite after the stream completes

For Anthropic streaming, the usage is in the `message_delta` event with `stop_reason`.
For OpenAI streaming, usage is in the final chunk when `stream_options.include_usage` is set, or must be estimated from token counting.

### Error Handling

- If request body is not valid JSON → forward anyway (might be a non-chat endpoint)
- If response parsing fails → log error, still return response unchanged
- If SQLite write fails → log error, don't crash, keep proxying
- If upstream provider is unreachable → return 502 with helpful message
  (with `[resilience]` enabled, only after every configured endpoint for that
  provider has failed or has an open circuit)
- If upstream returns error → forward error unchanged, still log the attempt

---

## Pricing Database

### Anthropic Models (as of May 2026)

| Model | Input ($/MTok) | Cache Write ($/MTok) | Cache Read ($/MTok) | Output ($/MTok) |
|-------|---------------|---------------------|--------------------|-----------------| 
| claude-opus-4-7 | 5.00 | 6.25 (1.25x) | 0.50 (0.10x) | 25.00 |
| claude-opus-4-6 | 5.00 | 6.25 (1.25x) | 0.50 (0.10x) | 25.00 |
| claude-sonnet-4-6 | 3.00 | 3.75 (1.25x) | 0.30 (0.10x) | 15.00 |
| claude-haiku-4-5 | 1.00 | 1.25 (1.25x) | 0.10 (0.10x) | 5.00 |

Note: 1-hour cache duration is 2x base input (instead of 1.25x). Detect from cache_control in request.

### OpenAI Models (as of May 2026)

| Model | Input ($/MTok) | Cached Input ($/MTok) | Output ($/MTok) |
|-------|---------------|-----------------------|-----------------|
| gpt-5.5 | 2.00 | 1.00 (0.50x) | 10.00 |
| gpt-5.4 | 1.25 | 0.625 (0.50x) | 10.00 |
| gpt-5.4-mini | 0.15 | 0.075 (0.50x) | 0.60 |

Note: OpenAI caching is automatic (50% discount on cached tokens). No write premium.

### Google Gemini Models (as of May 2026)

| Model | Input ($/MTok) | Cached Input ($/MTok) | Output ($/MTok) |
|-------|---------------|-----------------------|-----------------|
| gemini-2.5-pro | 1.25 | 0.3125 (0.25x) | 10.00 |
| gemini-2.5-flash | 0.30 | 0.075 (0.25x) | 2.50 |
| gemini-2.0-flash | 0.10 | 0.025 (0.25x) | 0.40 |

Note: Gemini caching is implicit — there is no cache-write cost on the response
path. Token accounting comes from `usageMetadata` (the cached-content split is
read from `cachedContentTokenCount`; thinking tokens fold into output).

### Pricing Update Strategy

Prices are embedded in the binary as a TOML file. Users can override with a local
`~/.burnwall/pricing.toml` file. We publish pricing updates as new releases.
The `burnwall status` command shows a warning if pricing data is >30 days old.

### Pricing Notes

- **OpenAI caching is automatic** (no opt-in). Cached tokens are 50% of the base input price (not 90% like Anthropic).
- **Anthropic has two cache durations:** 5-min (1.25× write) and 1-hour (2× write). Reads are 0.1× base for both.
- **Cache multipliers stack with Batch API discounts** — apply Batch discount on top of cached-token rate.
- **Opus 4.7 shipped a new tokenizer** that produces up to 35% more tokens for the same text. Same per-token price, but higher effective cost — a stealth price increase versus Opus 4.6.
- **Warning:** `pricing.toml` should be checked monthly. The CLI must show a warning if pricing data is >30 days old (see Pricing Update Strategy above).

---

## SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    provider TEXT NOT NULL,           -- 'anthropic', 'openai', 'google'
    model TEXT NOT NULL,              -- 'claude-sonnet-4-6', 'gpt-5.4', etc.
    input_tokens INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0.0,
    blocked INTEGER NOT NULL DEFAULT 0,     -- boolean: 0 or 1
    block_reason TEXT,                       -- null if not blocked
    session_id TEXT,                          -- from request headers if available
    request_hash TEXT                         -- [v0.2] for loop detection
);

CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_provider_model ON requests(provider, model);
CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(blocked);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,         -- 'path_blocked', 'command_blocked', 'secret_detected', 'mount_blocked'
    details TEXT NOT NULL,            -- what was blocked (path, command, etc.)
    provider TEXT,
    model TEXT
);

CREATE TABLE IF NOT EXISTS daily_summary (
    date TEXT PRIMARY KEY,            -- 'YYYY-MM-DD'
    total_cost REAL NOT NULL DEFAULT 0.0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_blocked INTEGER NOT NULL DEFAULT 0,
    cache_savings REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## Config File Format

Location: `~/.burnwall/config.toml`

```toml
[proxy]
port = 4100
host = "127.0.0.1"

[budget]
daily = 50.0           # dollars
monthly = 0.0          # 0 = no monthly limit
warn_percent = 80      # warn at this % of daily limit

[security]
enabled = true
deny_paths = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.config/gcloud",
    "/etc/passwd",
    "/etc/shadow",
]
deny_commands = [
    "rm -rf /",
    "rm -rf ~",
    "chmod 777",
    ":(){ :|:& };:",
]
block_network_mounts = true    # block /Volumes/*, \\server\share, smb://, nfs://
detect_secrets = true          # scan for API keys, private keys in outbound payloads
dlp = false                    # opt-in egress check: Luhn-valid card numbers, US SSNs

[loop_detection]
enabled = true
max_identical_requests = 5     # same hash N times in window → block
window_seconds = 300           # 5 minute window
max_cost_per_window = 2.0      # $2 in 5 min → flag as loop

[logging]
level = "info"                 # trace, debug, info, warn, error
file = "~/.burnwall/burnwall.log"

[mcp]
require_approval = false       # enforce: block tools/call to unapproved tools

# One watcher can front several MCP servers, routed by the first path
# segment (`/<name>/...` → that server's upstream, prefix stripped).
[[mcp.servers]]
name = "filesystem"
upstream = "http://localhost:8090"

[resilience]
enabled = false               # off by default: single upstream, verbatim 5xx
failure_threshold = 3          # consecutive failures before a circuit opens
cooldown_seconds = 30          # how long an open circuit stays open before a probe

# Per-provider ordered fallback endpoints. The primary upstream is tried first;
# these are tried after it, in order, on a connection error or 5xx.
[[resilience.endpoints]]
provider = "anthropic"         # 'anthropic' | 'openai' | 'google'
urls = ["https://bedrock.example.com"]

[observability]
otel_spans = false             # emit one OTel GenAI span per request (file-only)
otel_file = ""                 # span file; empty → <data dir>/otel-spans.jsonl
```

`burnwall mcp` manages the MCP tool-approval workflow and audit log:

- `burnwall mcp list [--json]` — every `(server, tool)` seen, with its approval
  state (`pending` / `approved`).
- `burnwall mcp approve <server> [tool]` — approve one tool, or every tool of a
  server. In enforce mode a `tools/call` to a tool that is not approved is held
  with a 403 until you approve it; a tool whose definition later changes is
  reset to `pending` automatically.
- `burnwall mcp revoke <server> [tool]` — return a tool (or a server) to
  `pending`.
- `burnwall mcp export [--days N] [--format json|csv]` — portable record of MCP
  tool-call activity and MCP-side security events.

---

## v0.2 Additions (Week 3-4)

- Loop detection (request content hashing, exponential backoff)
- `burnwall security` command to view blocked attempts
- Security profile YAML files per project:
  ```yaml
  # .burnwall.yaml in project root
  allow_paths:
    - ./src
    - ./tests
  deny_paths:
    - ./secrets
    - ./.env
  budget:
    daily_max_usd: 10
  ```


