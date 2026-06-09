# 🛡️ Burnwall

**Track what your AI coding agent costs. Block what it shouldn't touch.**

**100% local. Zero telemetry.** No data leaves your machine except the API call you already make. Burnwall is a single binary that runs *in front of* your existing tools — not a hosted gateway your traffic routes through.

Burnwall is a local proxy for AI coding tools — Claude Code, Codex CLI, Aider, OpenCode, Cline. It combines cache-aware cost accounting, path-and-command security checks on every tool call, cross-tool spend aggregation, and zero telemetry — without sending your prompts to a SaaS dashboard.

**Works with** Claude Code, Cursor, Codex, Aider, OpenRouter, and any OpenAI/Anthropic-compatible gateway — point its base URL at Burnwall. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

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

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/intbot/burnwall/main/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/intbot/burnwall/main/install.ps1 | iex
```

The installers detect your OS and architecture, download the right
release archive from GitHub, drop the `burnwall` binary in a per-user
location (`~/.local/bin` on Unix, `%USERPROFILE%\.burnwall\bin` on
Windows), and print a PATH hint if needed. Override the install dir
with `BURNWALL_INSTALL_DIR=…` or pin a version with
`BURNWALL_VERSION=0.3.1`.

### Homebrew

```bash
brew tap intbot/burnwall
brew install burnwall
```

Works on macOS (arm64 + x86_64) and Linuxbrew.

### Manual download

Prebuilt archives for every release are at
<https://github.com/intbot/burnwall/releases>:

- `burnwall-aarch64-apple-darwin.tar.xz` — macOS Apple Silicon
- `burnwall-x86_64-apple-darwin.tar.xz` — macOS Intel
- `burnwall-aarch64-unknown-linux-gnu.tar.xz` — Linux arm64
- `burnwall-x86_64-unknown-linux-gnu.tar.xz` — Linux x86_64
- `burnwall-x86_64-pc-windows-msvc.zip` — Windows x86_64

Extract and put the `burnwall` binary anywhere on your `PATH`.

### For Rust developers

```bash
cargo install burnwall                                         # from crates.io
git clone https://github.com/intbot/burnwall && cd burnwall && cargo build --release   # from source
```

### Verify your download

Every release binary carries a GitHub Artifact Attestation (Sigstore keyless
build provenance, SLSA Build L2) — proof it was built from this repo's CI, not
swapped out. Verify before trusting a binary in your traffic path:

```bash
gh attestation verify burnwall-x86_64-unknown-linux-gnu.tar.xz --repo intbot/burnwall
```

Each release also ships per-file `.sha256` checksums and a combined `sha256.sum`:

```bash
sha256sum --ignore-missing -c sha256.sum
```

See [`SECURITY.md`](SECURITY.md) for the full integrity + TLS-handling statement.

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

### Defense-in-depth, not a silver bullet

Security rules are evaluated **before the request leaves your machine** — a
blocked request never reaches the provider. That's the point: it's another layer
that holds even when a tool's own approval prompt, allowlist, or sandbox is
bypassed (and those have been, repeatedly). Burnwall doesn't claim you're under
attack; it claims that *if* a prompt-injected agent tries to read `~/.ssh` or
pipe a secret to the network, the rule fires locally first. Pair it with your
tool's native controls — it's designed to complement them, not replace them.

## Scope: What Burnwall Guards

Burnwall sits on the **LLM API path** — the HTTP traffic between your AI tool and Anthropic/OpenAI. Security scanning, budget enforcement, and cost tracking all operate on that traffic.

The LLM-path proxy does **not** automatically see **MCP** (Model Context Protocol) traffic — that flows from your AI tool to MCP servers directly. For that layer, Burnwall ships a dedicated **MCP firewall** you put in front of your MCP servers (`burnwall mcp-watch`): it detects tool-poisoning and "rug-pull" (silent post-approval redefinition) attacks and enforces an approval workflow. Run it alongside the main proxy for end-to-end coverage.

### The coverage boundary

Burnwall protects the traffic that **flows through it**. It does not man-in-the-middle TLS — it forwards via base-URL routing — so a tool that talks to a provider over a path the base URL can't redirect is simply not visible to it. By design, no proxy that avoids TLS interception can see that traffic.

In practice:

- **Routable, fully protected:** Claude Code (including on a Pro/Max subscription), Codex CLI in **API-key mode**, Aider, OpenCode, and other tools that honor `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` or an equivalent API-base setting.
- **Not routable, bypasses entirely:** Codex CLI signed in with **ChatGPT login**, which talks to the ChatGPT backend over OAuth. Codex in **API-key mode** routes through Burnwall and can be protected — but it bills per-token instead of your flat subscription, so weigh the cost trade-off before switching.

So you're never left guessing, Burnwall tells you which of your installed tools are actually behind the firewall: `burnwall init` warns at setup if a tool is in a bypassing mode, and `burnwall status` (and `burnwall watch`) show a per-tool **Coverage** readout — *protected*, *installed but unseen*, or *bypasses*.

## Supported Tools

| Tool | Support | Configuration |
|------|---------|---------------|
| Claude Code | ✅ Full | `ANTHROPIC_BASE_URL` |
| Codex CLI (API key mode) | ✅ Full | `OPENAI_BASE_URL` |
| Codex CLI (ChatGPT login) | ❌ | Not interceptable (OAuth backend) |
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

## Trust & privacy

Burnwall sits in your API traffic path, so it earns that position by being
verifiable, not by asking for trust:

- **100% local.** No data ever leaves your machine except the API forwarding you
  asked for. Works offline (apart from the forwarding itself).
- **Zero telemetry.** No analytics, no phone-home, no tracking. Ever.
- **No prompt logging.** Only metadata is stored (model, tokens, cost, timestamp).
- **No API key storage.** Keys pass through in headers and are never written to disk.
- **Read-only on responses.** Burnwall inspects responses to compute cost and
  **never modifies them** — your tool gets the provider's bytes unchanged.
- **Single binary, signed releases.** Install from a checksummed, signed release
  (or `cargo install` from source). No background services you didn't ask for.
- **Open source.** The "no network calls except forwarding" claim is auditable —
  read the proxy code yourself.

## Terms of service

Burnwall is a **transparent proxy for your own API traffic** — it carries the
requests you were already sending, using *your own* API key, to the official
`api.anthropic.com` / `api.openai.com` endpoints. It does **not**:

- repackage a Pro/Max subscription or OAuth session into API traffic, and
- pool keys or rotate accounts to get around provider rate limits.

Requests are forwarded **unchanged**, with one opt-in exception: Anthropic
prompt-cache markers, off by default and enabled only via `proxy.cache_injection`.
Responses are never modified (see *How It Works*). In short — Burnwall instruments
the traffic you already send; it doesn't change your relationship with the provider.

## License

[FSL-1.1-MIT](LICENSE) — Functional Source License. Full source available. Free to use, modify, and self-host. Cannot be redistributed as a competing commercial product. Converts to MIT after 2 years.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

*Built with Rust. No telemetry. No compromises.*
