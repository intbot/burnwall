# 🛡️ Burnwall

**Track what your AI coding agent costs. Block what it shouldn't touch.**

Burnwall is a local proxy for AI coding tools — Claude Code, Codex CLI, Aider, OpenCode, Cline. It combines cache-aware cost accounting, path-and-command security checks on every tool call, cross-tool spend aggregation, and zero telemetry — without sending your prompts to a SaaS dashboard.

If you've ever woken up to a four-figure API bill from an agent loop, or wondered whether your agent has been quietly `cat`-ing `~/.ssh/id_rsa` into the context window: Burnwall is the seatbelt.

```
$ burnwall start
🛡️ Burnwall v0.1.0
   Proxy: http://localhost:4100
   Security: 4 deny rules active
   Budget: $50.00/day
   Ready.
```

## Why Burnwall?

### 🔒 Security
Your AI agent can read your SSH keys, AWS credentials, and network drives. Most developers don't know this until it's too late. Burnwall scans every API request and blocks dangerous file access, commands, and secret exfiltration before they leave your machine.

### 💰 Real Cost Tracking
AI providers have complex pricing with cache tiers, write premiums, and stealth tokenizer changes. Burnwall reads the actual usage data from API responses and calculates real costs — not estimates. See exactly where your money goes, with cache savings highlighted.

### 🛑 Budget Enforcement
Set a daily limit. Burnwall blocks API calls when you hit it. No more surprise $1,400 bills.

### 🔄 Loop Detection
Detect and kill runaway agents that repeat the same request, burning tokens at 20+ requests per minute.

## Quick Start

```bash
# Auto-detect and configure your AI tools (dry-run; --apply to commit)
burnwall init --apply

# Start the proxy (foreground; Ctrl-C to stop)
burnwall start

# In another terminal: check today's spend
burnwall status

# Last 7 days, with JSON output for piping into jq:
burnwall history --json | jq '.rows[] | {date, total_cost_usd}'

# Tighten the daily budget to $20
burnwall config set budget.daily 20
```

## Install

Prebuilt binaries (after a release tag is pushed, the GitHub Actions
release workflow publishes per-platform archives):

- macOS arm64 / x86_64
- Linux x86_64
- Windows x86_64

```bash
# From source (requires Rust toolchain ≥ 1.80):
git clone https://github.com/[OWNER]/burnwall && cd burnwall
cargo build --release
./target/release/burnwall --help

# Or once published:
cargo install burnwall
```

## How It Works

Burnwall runs as a local HTTP proxy. You point your AI tools at it via environment variables:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4100/anthropic
export OPENAI_BASE_URL=http://localhost:4100/openai
```

Every API call flows through Burnwall:

```
[Your AI Tool] → [Burnwall :4100] → [Provider API]
                       │
                  ✓ Security check (block dangerous requests)
                  ✓ Budget check (enforce daily limits)
                  ✓ Cost tracking (parse real usage with caching)
                  ✓ Store metrics (local SQLite)
```

Responses are **never modified** — Burnwall reads them, logs the cost, and passes them through unchanged.

## Scope: What Burnwall Guards

Burnwall sits on the **LLM API path** — the HTTP traffic between your AI tool and Anthropic/OpenAI. Security scanning, budget enforcement, and cost tracking all operate on that traffic.

It does **not** intercept **MCP** (Model Context Protocol) traffic. When your agent calls an MCP server's tools, that traffic flows through your AI tool directly — Burnwall never sees it, so it can't scan or block it. MCP-layer protection is a separate concern; dedicated MCP-firewall tools exist and run cleanly alongside Burnwall.

## Supported Tools

| Tool | Support | Configuration |
|------|---------|---------------|
| Claude Code | ✅ Full | `ANTHROPIC_BASE_URL` |
| Codex CLI (API key mode) | ✅ Full | `OPENAI_BASE_URL` |
| Aider | ✅ Full | `--openai-api-base` |
| OpenCode | ✅ Full | Settings |
| Cline | ✅ Full | Extension settings |
| Continue | ✅ Full | Extension settings |
| Cursor (BYOK mode) | ✅ Full | API key settings |
| Cursor (internal credits) | ❌ | Not interceptable |
| GitHub Copilot | ❌ | Not interceptable |

## Security Rules

Default rules block access to sensitive paths and dangerous commands:

```toml
# ~/.burnwall/config.toml
[security]
deny_paths = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube"]
deny_commands = ["rm -rf /", "chmod 777"]
block_network_mounts = true    # /Volumes/*, \\server\share
detect_secrets = true          # AWS keys, private keys, API tokens
```

When a rule triggers:
```
🛡️ BLOCKED: Agent attempted to read ~/.ssh/id_rsa
   Provider: anthropic | Model: claude-sonnet-4-6
   Request returned 403 — file was never accessed.
```

## Cost Output

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
   Cache savings today: $47.82
```

## Privacy

- **100% local.** No data ever leaves your machine (except API forwarding).
- **Zero telemetry.** No analytics, no phone-home, no tracking. Ever.
- **No prompt logging.** Only metadata is stored (model, tokens, cost, timestamp).
- **No API key storage.** Keys pass through in headers and are never written to disk.
- **Open source.** Audit the code yourself.

## License

[FSL-1.1-MIT](LICENSE) — Functional Source License. Full source available. Free to use, modify, and self-host. Cannot be redistributed as a competing commercial product. Converts to MIT after 2 years.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

*Built with Rust. No telemetry. No compromises.*
