# Compliance & audit evidence

Burnwall produces **local, metadata-only, tamper-evident** records of what an AI
agent did and was blocked from — useful as *evidence* for AI-governance frameworks.
It is **not** a compliance product and does not make you compliant on its own; it
furnishes artifacts an auditor or underwriter can verify.

## The artifacts

- **Audit receipts** (`burnwall audit seal` / `verify`) — Ed25519-signed,
  hash-chained, metadata-only records of every forwarded/blocked action. Each
  receipt hashes the source row's contents, so `verify` detects edits to the
  underlying data, and the chain detects insertion/deletion/reordering.
- **CycloneDX AI-BOM** (`burnwall audit aibom`) — machine-readable session bill of
  materials (models, MCP servers, security activity).
- **SARIF** (`burnwall audit sarif`) — security blocks for GitHub code scanning.
- **OWASP / EU-AI-Act mapping** — see `docs/SECURITY_FRAMEWORKS.md`.

None of these contain prompt content.

## Framework mapping (evidence, not certification)

| Framework / control | What it asks for | Burnwall artifact |
|---|---|---|
| **EU AI Act, Art. 12** (record-keeping / automatic logging) | Automatic, traceable logs of system events over the lifecycle | Audit receipts (`seal`) — signed, chained, per-action |
| **EU AI Act, Art. 19 / 26** (log retention) | Keep logs (≥6 months for deployers) | Retained receipt chain; `audit verify` reports count + oldest sealed date |
| **ISO/IEC 42001, A.6.2.8** (AI event logging) | Immutable, attributable who/what/when records | Audit receipts + `verify` |
| **SOC 2** (CC-series: logging, change/integrity) | Tamper-evident activity + control-enforcement evidence | Receipts (forward/block) + SARIF security events |
| **NIST AI RMF** (Measure/Manage) | Evidence that runtime controls operated | Blocked-action receipts + security events |

Honest caveat: Burnwall is a deployer-side control plane, so it provides
*proof-of-controls evidence*, not full compliance with any framework.

## Independent verification (no Burnwall required)

`burnwall audit export --format json` emits a self-contained bundle:

```json
{
  "public_key": "<hex Ed25519 verifying key>",
  "count": <n>,
  "receipts": [
    {
      "seq": 1, "sealed_at": "...", "source": "request|security_event",
      "source_id": 1, "timestamp": "...", "action": "forward|block|security",
      "provider": "...", "model": "...", "detail": "...",
      "content_hash": "<sha256 hex of the source row>",
      "prev_hash": "<hex>", "hash": "<sha256(prev_hash \\n content_hash) hex>",
      "signature": "<ed25519(hash) hex>"
    }
  ]
}
```

A third party (auditor/underwriter) can re-walk the chain and verify every
signature **without trusting the Burnwall binary** using `tools/verify_receipts.py`:

```
burnwall audit export --format json > receipts.json
python tools/verify_receipts.py receipts.json
# → OK — N receipt(s) verified against <pubkey>…   (or TAMPERED at seq X)
```

The external verifier checks the chain links + signatures from the export alone
(proving the exported receipts weren't forged, reordered, edited, or deleted after
export). Re-deriving each `content_hash` from the *live* source rows — proving the
underlying data hasn't changed — is what `burnwall audit verify` does locally.
