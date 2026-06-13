# Security rules

Every block Burnwall raises has a stable **rule id** (the same token you see in
`burnwall security`, in logs, and in an `x-burnwall-blocked` header). This page
is the reference for what each rule guards against and how to proceed when it's
a false positive.

You don't need this page to get an answer in the moment — the CLI carries the
same text:

```bash
burnwall security --days 7     # list recent blocks and their ids
burnwall explain <id>          # what fired, why, and how to proceed
```

Each rule below is anchored by its id, so a `/rules/<id>` reference resolves to
the matching `#<id>` section here.

When something is a genuine false positive, the escape hatches all act on the
**running** proxy — no restart of the proxy or your AI tool:

```bash
burnwall allow-once    # let just the NEXT request through, then auto-restore
burnwall pause 5m      # relay everything unchecked for a bounded window
```

---

## canary_triggered
**Canary tripwire fired**

- **Why:** A credential you planted as bait (`security.canaries`) appeared in an
  outbound payload. It has no legitimate use, so any request carrying it is an
  exfiltration signal.
- **How to proceed:** This is almost never a false positive. If you deliberately
  sent the canary, remove it from `security.canaries` or run the one call with
  `burnwall allow-once`.

## destructive_blocked
**Catastrophic command**

- **Why:** A tool call carried a data-loss-grade command (recursive force-delete,
  disk wipe, destructive SQL), detected by shape rather than a literal string.
- **How to proceed:** If you really intend it, narrow the command, or allow the
  single call with `burnwall allow-once`. Prefer scoping the destructive action
  to an explicit path.

## exfil_blocked
**Data-exfiltration technique**

- **Why:** A tool call matched a command-shaped exfiltration pattern (e.g. a
  secret piped to the network, DNS exfiltration).
- **How to proceed:** If the network call is legitimate, run it outside the agent
  or use `burnwall allow-once` for the single request. Review what was being sent
  first.

## secret_detected
**Secret / credential in payload**

- **Why:** The request body contained something matching a known credential
  pattern (API key, token, private-key header). Sending it to a model would leak
  it.
- **How to proceed:** Remove the credential from what the agent is about to send.
  If it is a false positive (a fake/example key), allow the single call with
  `burnwall allow-once`.

## dlp_blocked
**PII / data exfiltration**

- **Why:** The payload matched a data-loss pattern (card number, SSN). This is
  egress/DLP protection against sensitive data leaving in a prompt.
- **How to proceed:** Strip the sensitive value, or allow the single call with
  `burnwall allow-once` if it is test data. Consider whether the value belongs in
  a prompt at all.

## misdirection_blocked
**Credential sent to the wrong provider**

- **Why:** A recognized provider credential was being forwarded to a different
  provider's endpoint (e.g. an OpenAI key in a body bound for the Anthropic
  upstream).
- **How to proceed:** Point the tool at the correct provider, or disable
  `security.block_credential_misdirection` if this routing is intentional.

## obfuscation_blocked
**Invisible-character obfuscation**

- **Why:** A tool-call argument was dense with zero-width / invisible Unicode —
  content being hidden from filters and from your own review (instruction
  smuggling).
- **How to proceed:** Inspect the source of the tool call; this usually means a
  poisoned input. Only `allow-once` if you understand why the hidden characters
  are there.

## command_blocked
**Dangerous command**

- **Why:** A tool call tried to run a command on the deny list (e.g. `chmod 777`,
  a fork bomb, `curl` to an unknown host).
- **How to proceed:** Adjust the command, relax the rule in config if it is a
  legitimate workflow, or `burnwall allow-once` for the single call.

## path_blocked
**Denied-path access**

- **Why:** A tool call referenced a protected path (`~/.ssh`, `~/.aws`,
  `/etc/passwd`, …). Reading or writing it from an agent is how credentials and
  keys leak.
- **How to proceed:** If the access is intended and safe, allow the single call
  with `burnwall allow-once`, or remove the path from the deny list in config.

## mount_blocked
**Network-mount access**

- **Why:** A tool call touched a network mount (`/Volumes/`, an SMB/NFS share).
  Agent access to network storage is a common data-egress path.
- **How to proceed:** Copy what you need locally, or allow the single call with
  `burnwall allow-once` if the mount access is deliberate.

---

## Anything else

An id Burnwall doesn't have a specific card for (a newer rule, or one authored
in a rule pack) falls back to a generic block. Run `burnwall security --days 7`
to see recent blocks, or `burnwall allow-once` to let the next request through
unchecked.
