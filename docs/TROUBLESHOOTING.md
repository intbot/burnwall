# Troubleshooting

Burnwall is local-only and stores zero telemetry, so it can't phone home and we
can't see your machine. Instead, every problem has a command that explains
itself. Start here:

```bash
burnwall doctor          # one-glance health check + the fix for what's wrong
```

If you're about to file a bug, attach a redacted, metadata-only bundle (it's
self-scanned for secrets before it's written, and nothing is sent anywhere):

```bash
burnwall doctor --export
```

---

## Symptom → fix

| Symptom | What it means | Do this |
|---|---|---|
| Requests fail with **connection refused** | Your tool is routed at the proxy, but the proxy isn't answering on that port | `burnwall recover` to get unstuck now, then `burnwall start`. Open a **new shell** so it re-routes. |
| Status line says **`DIRECT (unprotected)`** | This shell isn't routed through Burnwall — traffic is going straight to the provider with no scanning or cost capture | `burnwall doctor` — it tells you whether that's a misconfiguration or your own choice, and the exact fix |
| Status line says **`DIRECT (unprotected) — run burnwall doctor`** | Routing **is** configured, but this shell fell through to direct (the proxy was down when the shell launched, or the shell predates routing) | `burnwall doctor --fix` (starts the proxy if it's down), then open a **new shell** |
| Status line says **`PROXY DOWN`** | This shell is routed, but the proxy process died | `burnwall start`, then check `burnwall status` |
| Status line says **`PAUSED (unprotected)`** | You ran `burnwall pause` — everything relays unchecked until the window ends | `burnwall resume` to restore protection now (it also auto-expires) |
| A request was **unexpectedly blocked** (403 / an `x-burnwall-blocked` header) | A security rule matched the tool call before it left your machine | `burnwall security --days 7` to find the event id, then `burnwall explain <id>`. If it's a false positive: `burnwall allow-once`. See [RULES.md](RULES.md). |
| **Numbers look wrong**, or you want your data elsewhere | — | `burnwall export --format csv` (or `json`) — your rows, on your machine |
| Status line **tokens/context don't move** while your agent runs sub-agents | Expected — see ["Tokens freeze during sub-agents"](#tokens-freeze-during-sub-agents) below | Nothing to fix; the plan/cost segments still track the real traffic |
| **Pricing looks stale** | The bundled rate card is old | Upgrade Burnwall (`burnwall upgrade`); `burnwall doctor` warns when pricing is >30 days old |

---

## "Running, but unprotected"

The most confusing state is a configured-but-unprotected one: you set up
routing, yet a shell is going direct. There are two causes, and Burnwall tells
them apart so it only nags when it's actually a problem:

- **Unintended** — routing is enabled, but the proxy was down when this shell
  started (so the env didn't route), or the shell predates routing.
  `burnwall doctor` reports this as `⚠ UNPROTECTED`, and `burnwall doctor --fix`
  starts the proxy when that's the issue.
- **By choice** — you ran `burnwall disable-routing`, or never set routing up.
  `burnwall doctor` reports this as a `•` note, **not** a warning, and `--fix`
  will not override it — it just tells you the command to turn protection back
  on (`burnwall enable-routing`).

One thing no command can do for you: environment variables are fixed when a
shell launches, so a shell that started unprotected stays unprotected until you
open a **new** one (or restart your AI tool). `burnwall doctor` says so rather
than pretend otherwise.

---

## Tokens freeze during sub-agents

When your AI tool spins up sub-agents, the status line's token counters (`↑ ↓`)
and context gauge (`ctx`) stop moving until the sub-agents finish. That's
correct, not a bug:

- Those two segments come from **the tool's own report of your main
  conversation** — and your conversation genuinely isn't growing while a
  sub-agent works in its own, separate context window. The `ctx` gauge answers
  "how full is *my* conversation" (the number you act on when deciding to
  compact), so it must not count sub-agent context.
- The traffic is still fully metered and scanned: every sub-agent API call goes
  through the proxy, so the **plan headroom (`5h`/`7d`), spend, and block
  count keep moving** — that's your live signal that work is happening.
- Surfaces fed from the database rather than the tool (`burnwall watch`, the
  editor status bar) don't freeze at all.

---

## Where your data lives

Everything is local, in a single directory under your home:

```
~/.burnwall/
  burnwall.db        # all metadata: cost, tokens, security events (one SQLite file)
  config.toml        # your settings
```

- **Back up** by copying `burnwall.db` — that one file is your whole history.
- **Export** a portable copy with `burnwall export --format csv|json`.
- The database holds **metadata only** — model, tokens, cost, timestamps, and
  redacted security-event matches. No prompt content, no API keys.

---

## Filing a bug

1. Reproduce the problem.
2. Run `burnwall doctor --export`. It writes a redacted, metadata-only bundle and
   self-scans it for secrets before writing — if anything secret-shaped survived,
   it refuses to write rather than risk a leak.
3. Review the file (it's plain text), then attach it to a new issue. The bug
   report template asks for it up front.
