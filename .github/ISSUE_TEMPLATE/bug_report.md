---
name: Bug report
about: Something isn't working as expected
title: ""
labels: bug
assignees: ""
---

<!--
Burnwall stores zero telemetry and is local-only, so we can't see your machine.
The single most useful thing you can attach is a redacted diagnostic bundle:

    burnwall doctor --export

It is metadata-only (no prompts, no API keys, no raw paths) and self-scans for
secrets before writing — if anything secret-shaped survived, it refuses to write
rather than risk a leak. Review the file, then paste it below.
-->

## What happened

A clear description of the problem.

## What you expected

What you expected to happen instead.

## Steps to reproduce

1.
2.
3.

## Diagnostic bundle

Paste the output of `burnwall doctor --export` (it's redacted + self-scanned):

```
(paste here)
```

## Environment

- Burnwall version: <!-- `burnwall --version` -->
- OS / arch:
- AI tool(s) involved: <!-- Claude Code, Codex CLI, Aider, … -->

## Anything else

Logs, screenshots, or context. Please don't paste API keys or prompt content —
the `doctor --export` bundle already excludes them.
