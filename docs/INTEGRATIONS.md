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

The upstream URL is **your config**, not something a request can change. Burnwall
forwards your request unchanged and adds, on the local side: blocking dangerous
file-path / command / secret-exfiltration tool calls before they leave the machine,
hard daily/monthly budget stops, runaway-loop detection, and one local cost view
across every tool — none of which a hosted router can do for you.

## Failover to multiple upstreams

If you run more than one base URL for a provider, configure `[resilience]` so
Burnwall retries the same request against the next endpoint on a connection error
or 5xx. See `docs/SPEC.md`.
