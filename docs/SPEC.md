# Burnwall Specification

## Version Scope

This spec covers **v0.1** (CLI + proxy) through **v0.3** (VS Code extension).
Features marked [v0.2], [v0.3], etc. are out of scope for the initial release.

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
   a. Rewrite URL: strip /anthropic or /openai prefix
   b. Forward all headers unchanged (including auth)
   c. Forward body unchanged
   d. For streaming (SSE) responses: pipe through, parse final usage chunk
   e. For non-streaming: buffer response, parse usage
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

[loop_detection]
enabled = true
max_identical_requests = 5     # same hash N times in window → block
window_seconds = 300           # 5 minute window
max_cost_per_window = 2.0      # $2 in 5 min → flag as loop

[logging]
level = "info"                 # trace, debug, info, warn, error
file = "~/.burnwall/burnwall.log"
```

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

## v0.3 Additions (Week 5-6)

- VS Code extension: status bar item showing `💰 $7.23 | 📊 81% cache | 🛡️ 1 blocked`
- Extension reads from SQLite database, polls every 5 seconds
- Click status bar → output channel with detailed breakdown
- Extension auto-detects if CLI is running, prompts to install if not

## v0.4 Additions (future)

- Google Gemini API support
- Community security rule profiles
- Context compression (experimental)
- Smart model routing (experimental)

## v0.5 Additions (future)

- Cloud dashboard for teams (paid tier)
- Team-wide spend visibility
- Centralized security policy enforcement
- SSO and audit log exports
