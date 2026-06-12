# Use Burnwall with anything

Burnwall is a **local proxy**: your AI coding agent points its API base URL at
Burnwall (`http://localhost:4100`), Burnwall enforces security + budget and tracks
cost, then forwards to the real provider — or to any **OpenAI- or
Anthropic-compatible** gateway you already use. It runs *in front of* your existing
setup; nothing else changes, and no data leaves your machine beyond the API call you
already make.

Start the proxy:

```
burnwall start            # listens on http://localhost:4100
```

Routes: `/anthropic/*`, `/openai/*`, `/google/*`. Your agent's `Authorization` /
`x-api-key` header is forwarded unchanged to the upstream.

## Point an agent or SDK at Burnwall

Most tools and SDKs honour an HTTP base-URL override — usually a single environment
variable. Set it to the matching Burnwall route:

| Tool / SDK | Set | To |
|---|---|---|
| Claude Code / Anthropic SDK / Claude Agent SDK | `ANTHROPIC_BASE_URL` | `http://localhost:4100/anthropic` |
| Codex CLI / OpenAI SDK / OpenAI Agents SDK | `OPENAI_BASE_URL` (or `OPENAI_API_BASE`) | `http://localhost:4100/openai` |
| Google Gemini SDK / ADK | Gemini base URL | `http://localhost:4100/google` |
| LangChain / CrewAI / LlamaIndex | the model's `base_url` | the route for that provider above |
| Cursor / Windsurf / Aider / OpenCode | the tool's "custom API base / OpenAI-compatible URL" setting | the matching route |

The keys stay yours — Burnwall passes the auth header straight through to the
upstream and never logs it.

## Put Burnwall in front of a gateway/router

Already routing through an OpenAI-compatible gateway, router, or proxy? Point
Burnwall's *upstream* at it and keep the local firewall + budget on top:

```
# OpenRouter (OpenAI-compatible): agent → Burnwall → OpenRouter → models
burnwall start --upstream-openai https://openrouter.ai/api/v1
# point the agent at http://localhost:4100/openai with your OpenRouter key
```

```
# Any OpenAI-compatible gateway/proxy (self-hosted or hosted):
burnwall start --upstream-openai https://your-gateway.example/v1
```

```
# Any Anthropic-compatible upstream:
burnwall start --upstream-anthropic https://your-upstream.example
```

To make the chain permanent (no flag on every start), set it in config instead:

```
burnwall config set upstreams.openai https://your-gateway.example/v1
burnwall config set upstreams.anthropic https://your-upstream.example
# back to the provider's own API:
burnwall config set upstreams.openai ""
```

A `--upstream-*` flag passed to `burnwall start` still wins over the config value
for that run.

The upstream URL is **your config**, not something a request can change. Burnwall
forwards your request unchanged and adds, on the local side: blocking dangerous
file-path / command / secret-exfiltration tool calls before they leave the machine,
hard daily/monthly budget stops, runaway-loop detection, and one local cost view
across every tool — none of which a hosted router can do for you.

## Failover to multiple upstreams

If you run more than one base URL for a provider, configure `[resilience]` so
Burnwall retries the same request against the next endpoint on a connection error
or 5xx. Run `burnwall config show` to see the `[resilience]` section.

## Teach your agent about Burnwall (skills)

Coding agents work better with the firewall when they understand it. One command
installs a short, burnwall-owned guide where your agent discovers it:

```
burnwall skills install            # Claude Code + Codex (whichever are present)
burnwall skills show               # print the guide without writing anything
burnwall skills uninstall          # remove it cleanly
```

- **Claude Code** gets `~/.claude/skills/burnwall/SKILL.md` — new sessions pick
  it up automatically.
- **Codex CLI** gets a marker-delimited section in `~/.codex/AGENTS.md`;
  reinstalls replace it in place and never touch your own content.

With the guide installed, the agent can answer spend and budget questions from
`burnwall status --json`, explain a security block by reading the block message
and `burnwall security --json`, and run `burnwall scan` on config files. The
guide's one hard rule: the agent must **never weaken protection itself** — no
`allow-once`, no `pause`, no security config edits. Anything state-changing is
suggested to you, never run. A blocked request may be exactly the action
Burnwall exists to stop, so that call stays human-only.

## Scan agent configs in CI (GitHub Action)

`burnwall scan` is a **file mode** — no proxy, no live traffic. It checks agent
instruction files (`CLAUDE.md`, `.cursorrules`, `.mcp.json`, anything under
`.claude/` and friends) for two high-confidence problems:

- a **committed credential** (a real key pattern in a tracked file), and
- **invisible Unicode characters** hidden inside ASCII text — the way hidden
  instructions get smuggled into agent config files via an innocent-looking PR.

Prose that merely *mentions* a dangerous command or sensitive path is never
flagged — config files are documentation, and Burnwall only reports what it is
confident about.

One step in any workflow uploads findings to the repository's Security tab:

```yaml
permissions:
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v4
  - uses: intbot/burnwall/.github/actions/burnwall-scan@main
```

Inputs: `paths` (default `.`), `all-files` (scan every text file, default
`false`), `fail-on-findings` (also fail the job, default `false`),
`upload-sarif` (default `true`), `burnwall-version` (default `latest`).

Locally, the same scan runs as:

```
burnwall scan                       # agent configs under the current directory
burnwall scan path/to/repo --all-files --fail-on-findings
burnwall scan --sarif report.sarif  # SARIF 2.1.0 for any code-scanning tool
```
