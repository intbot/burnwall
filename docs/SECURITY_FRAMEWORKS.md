# Security Frameworks Mapping

This document maps Burnwall's controls to widely-referenced AI security
frameworks. It is a transparency aid for users who track their tooling against
these frameworks — **not** a certification, audit, or claim of full coverage.

Burnwall is a local, single-machine guardrail that sits on the network path
between an AI coding tool and the model provider. It inspects requests before
they leave the machine, enforces budget limits, and records what it saw to a
local database. It does not modify model responses, and it never reads or logs
prompt content (only metadata: model, token counts, cost, timestamps, and the
specific rule that matched).

Each entry below states **what Burnwall does** and, just as importantly,
**what it does not do**, so the boundaries are clear.

## OWASP Top 10 for LLM Applications

| ID | Risk | How Burnwall helps | Not covered |
|----|------|--------------------|-------------|
| LLM01 | Prompt Injection | Scans advertised MCP tool definitions for injected instructions (hidden-unicode text, "ignore previous instructions"–style phrases) and flags them. | Cannot detect injection inside prompt content it deliberately never reads; this is a partial, tool-surface control only. |
| LLM02 | Sensitive Information Disclosure | Detects credential/secret patterns (API keys, private-key headers, tokens) in outbound request bodies and blocks the request before it leaves the machine. | Pattern-based; novel or encoded secrets can evade it. |
| LLM06 | Excessive Agency | Blocks tool-use requests that touch denied filesystem paths, run denied commands, or reach network mounts; daily budget limits and loop detection cap runaway autonomous activity. | Does not sandbox the agent process itself; enforcement is at the API path. |
| LLM08 | Excessive/Unbounded Consumption | Hard daily budget enforcement (requests over the limit are refused) plus runaway-loop detection. | Limits are per-machine; it is not an org-wide quota system. |
| LLM10 | Unbounded Resource Use | Cache-aware cost accounting and budget limits make consumption visible and enforceable. | — |

## OWASP Top 10 for Agentic Applications

| Area | How Burnwall helps | Not covered |
|------|--------------------|-------------|
| Tool misuse / unsafe tool calls | Inspects tool-use blocks for denied paths, commands, mounts, and secret patterns before forwarding. | — |
| Tool/MCP supply-chain integrity | Fingerprints each MCP tool a server advertises and flags silent post-approval definition changes ("rug pulls"); flags poisoned tool descriptions. | Best-effort change tripwire; not a cryptographic attestation of tool provenance. |
| Resource exhaustion / cost runaway | Budget enforcement and loop detection. | — |
| Auditability | All blocks and flags are written to a local, queryable event log. | Local only; no centralized aggregation. |

## EU AI Act (selected obligations)

The EU AI Act places obligations on providers and deployers of certain AI
systems. Burnwall is infrastructure a deployer can use to help meet some of
them; it does not, by itself, make any system compliant.

- **Record-keeping / logging** — Burnwall keeps a local, timestamped log of
  security events and usage metadata that can support an audit trail.
- **Human oversight** — Burnwall surfaces what an agent attempted (blocked
  actions, flagged tools) so a human can review and intervene.
- **Transparency** — Burnwall performs zero telemetry and makes no network
  calls except forwarding to the configured model provider; its behavior is
  fully local and inspectable.

## Standards referenced

- OWASP Top 10 for LLM Applications — <https://genai.owasp.org/>
- OWASP Top 10 for Agentic Applications — <https://genai.owasp.org/>
- MITRE ATLAS (adversarial ML threat knowledge base) — <https://atlas.mitre.org/>
- EU AI Act — <https://artificialintelligenceact.eu/>

## Scope and honesty note

Burnwall is one layer of defense. The current consensus is that prompt
injection cannot be fully solved by any single tool, so Burnwall is designed to
sit alongside the model provider's own controls (permission prompts,
sandboxing) and good operational practice — not to replace them. Where a
control above is marked "partial," treat it as a useful tripwire, not a
guarantee.
