#!/usr/bin/env python3
"""Independently verify a Burnwall audit-receipt export — no Burnwall required.

    burnwall audit export --format json > receipts.json
    python tools/verify_receipts.py receipts.json

Re-walks the Ed25519 hash chain in the export and verifies every signature
against the embedded public key. This proves the exported receipts were not
forged, reordered, edited, or deleted after export — without trusting the
burnwall binary. (Re-deriving each content_hash from the live source rows —
proving the underlying data is unchanged — is `burnwall audit verify`'s job.)

Chain definition (must match src/audit/mod.rs):
    hash = SHA-256( prev_hash_hex || "\\n" || content_hash_hex )   # ASCII bytes
    signature = Ed25519(hash_hex_bytes)                            # over the hex string
    genesis prev_hash = 64 zeros

Requires: pip install cryptography
Exit code: 0 = intact, 1 = tampered, 2 = usage/format error.
"""

import hashlib
import json
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    sys.exit("error: needs `pip install cryptography`")

GENESIS = "0" * 64


def fail(seq, why):
    print(f"TAMPERED at seq {seq}: {why}", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("usage: verify_receipts.py <export.json>", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)

    pub_hex = data.get("public_key")
    if not pub_hex:
        print("error: export has no public_key", file=sys.stderr)
        sys.exit(2)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

    receipts = sorted(data.get("receipts", []), key=lambda r: r["seq"])
    prev = GENESIS
    for r in receipts:
        if r["prev_hash"] != prev:
            fail(r.get("seq"), "broken chain link (a receipt was inserted, deleted, or reordered)")
        digest = hashlib.sha256()
        digest.update(prev.encode("ascii"))
        digest.update(b"\n")
        digest.update(r["content_hash"].encode("ascii"))
        if digest.hexdigest() != r["hash"]:
            fail(r.get("seq"), "hash does not match its contents")
        try:
            pub.verify(bytes.fromhex(r["signature"]), r["hash"].encode("ascii"))
        except InvalidSignature:
            fail(r.get("seq"), "signature does not verify (forged or wrong key)")
        prev = r["hash"]

    print(f"OK — {len(receipts)} receipt(s) verified against {pub_hex[:16]}…")


if __name__ == "__main__":
    main()
