#!/usr/bin/env python3
"""Check a signed answer from a ScamMap server. Prints VALID or INVALID.

    python tools/verify_attestation.py LOOKUP_JSON KEY [--value VALUE]

LOOKUP_JSON  a file holding a GET /lookup answer (or just its "attestation" object); "-" reads stdin
KEY          the server's public key: a file holding the GET /attestation/key answer, or the base64 key itself
--value      also check that the answer is about this value (any format: +91 98765 43210, 09876543210, ...)

Pin the key you trust (its key_id) out of band: fetching it from the same server only proves the
answer and the key match. VALID proves which server said what and when (by the server's own clock),
not that the verdict is right. Exit code: 0 VALID, 1 INVALID, 2 the input could not be read.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # run from anywhere in the repo

from app.attestation import key_id_for, value_sha256, verify  # noqa: E402


def read_key(arg: str) -> bytes:
    p = Path(arg)
    text = p.read_text(encoding="utf-8").strip() if p.is_file() else arg.strip()
    if text.startswith("{"):
        info = json.loads(text)
        key = base64.b64decode(info["public_key"], validate=True)
        if "key_id" in info and info["key_id"] != key_id_for(key):
            raise ValueError("the key file's key_id does not match its public key")
        return key
    return base64.b64decode(text, validate=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check a signed ScamMap answer. Prints VALID or INVALID.")
    ap.add_argument("lookup_json")
    ap.add_argument("key")
    ap.add_argument("--value", help="the value you asked about, to check the answer is about it")
    args = ap.parse_args(argv)
    try:
        raw = sys.stdin.read() if args.lookup_json == "-" else Path(args.lookup_json).read_text(encoding="utf-8")
        doc = json.loads(raw)
        key = read_key(args.key)
        if len(key) != 32:
            raise ValueError("an Ed25519 public key is 32 bytes")
    except (OSError, ValueError, KeyError, binascii.Error) as e:      # JSONDecodeError is a ValueError
        print(f"cannot read input: {e}", file=sys.stderr)
        return 2
    att = doc.get("attestation", doc) if isinstance(doc, dict) else None
    reason = None
    if not verify(att, key):
        reason = "the signature does not match these fields and this key"
    elif args.value is not None:
        from app.engine.normalise import InvalidIdentifier, normalise
        try:
            if value_sha256(normalise(att["type"], args.value)) != att["value_sha256"]:
                reason = "the answer is about a different value"
        except InvalidIdentifier:
            reason = f"{args.value!r} is not a valid {att['type']}"
    if reason:
        print("INVALID")
        print(reason, file=sys.stderr)
        return 1
    print("VALID")
    print(f"key {att['key_id']} · issued {att['issued_at']} · {att['type']} · {att['verdict']} · "
          f"{att['voices']} voices, {att['report_count']} reports · rules {att['config']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
