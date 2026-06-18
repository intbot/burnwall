# Security

Burnwall sits in your AI API traffic path, so its own integrity matters as much
as the rules it enforces. This document states what we do to be verifiable, how
TLS is handled, and how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than a public
issue. We aim to acknowledge within a few days.

## Self-integrity: verify what you run

- **Build provenance (SLSA Build L2).** Every released binary carries a GitHub
  Artifact Attestation — Sigstore keyless provenance proving it was built from
  this repository's CI. There is no long-lived signing key to leak.
  ```bash
  gh attestation verify burnwall-x86_64-unknown-linux-gnu.tar.xz --repo intbot/burnwall
  ```
- **Checksums.** Each release ships per-file `.sha256` and a combined
  `sha256.sum`:
  ```bash
  sha256sum --ignore-missing -c sha256.sum
  ```
- **Supply-chain hygiene.** The repository runs OpenSSF Scorecard in CI. The
  install one-liners are served over HTTPS only; package-manager installs
  (Homebrew, `cargo install`, `cargo binstall`) are the recommended trusted
  paths, and the npm wrapper publishes with provenance when that channel is
  enabled.
- **Open source.** The proxy, scanner, and pricing logic are auditable — the
  "no network calls except forwarding" claim below can be checked in the code.

## How Burnwall handles your traffic (TLS & data)

A proxy that terminates or weakens TLS would be a liability. Burnwall does not:

- **TLS is validated, never weakened.** Upstream connections use `rustls`
  (`rustls-tls`, with native-TLS disabled) and validate the provider's
  certificate like a browser would. Burnwall never disables certificate
  validation (no `danger_accept_invalid_certs`) and never injects or installs a
  root CA. There is a guard test (`tests/unit/tls_integrity_test.rs`) asserting
  these never appear in the source.
- **Responses are read-only.** Burnwall inspects responses to compute cost and
  **never modifies them** — your tool receives the provider's bytes unchanged.
- **No plaintext secrets at rest.** API keys pass through in headers and are
  never written to disk. Prompt/response **content is never logged** — only
  metadata (model, token counts, cost, timestamp).
- **Local only, zero telemetry.** No data leaves your machine except the API
  forwarding you configured. No analytics, no phone-home.
- **Fail-open.** If a request body can't be parsed, Burnwall forwards it rather
  than break your workflow — it never silently drops your traffic.

## Kill switch

If anything ever misbehaves, `burnwall pause` flips the *running* proxy into a
pure relay (no scanning, no budget checks, no storage) and auto-restores after
5 minutes — `burnwall resume` restores it early, and `burnwall allow-once`
relays just the next request. `burnwall self-rollback <version>` reinstalls a
prior release.

## Scope

Burnwall reduces risk; it is not a guarantee. Run it as one layer of
defense-in-depth alongside your tool's native permissions/sandbox and least-
privilege credentials — not as a replacement for them.
