"""Signed answers: every /lookup answer carries an Ed25519 signature (an "attestation").

A bank or insurer can check that an answer came from this ScamMap server, and when the server says
it gave it. It proves who said what and when, not that the verdict is right.

The key needs no new secret: seed = HMAC-SHA256(key=TRUST_SALT, msg="scammap-attestation-v1").
The same TRUST_SALT gives the same key after every restart. Never log the seed or the salt.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

IST = timezone(timedelta(hours=5, minutes=30))
DOMAIN = b"scammap-attestation-v1"
VERSION = 1
# The signed fields, besides "sig". The signature covers every field of the attestation except "sig".
FIELDS = ("v", "key_id", "issued_at", "type", "value_sha256", "verdict", "voices", "report_count", "config")


def canonical_json(obj: dict) -> bytes:
    """Sorted keys, no spaces, UTF-8: the exact bytes that are signed (and must be rebuilt to verify)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id_for(public_key: bytes) -> str:
    """First 8 hex characters of SHA-256 of the raw 32-byte public key."""
    return hashlib.sha256(public_key).hexdigest()[:8]


def value_sha256(canonical_value: str) -> str:
    return hashlib.sha256(canonical_value.encode("utf-8")).hexdigest()


class Signer:
    """Holds the signing key. Only the public half ever leaves this object."""

    __slots__ = ("_key", "public_key", "key_id")

    def __init__(self, trust_salt: str):
        if not trust_salt:
            raise ValueError("trust_salt is required")
        self._key = SigningKey(hmac.new(trust_salt.encode("utf-8"), DOMAIN, hashlib.sha256).digest())
        self.public_key = bytes(self._key.verify_key)
        self.key_id = key_id_for(self.public_key)

    def __repr__(self) -> str:  # never the seed
        return f"Signer(key_id={self.key_id!r})"

    def key_info(self) -> dict:
        return {"alg": "Ed25519", "key_id": self.key_id,
                "public_key": base64.b64encode(self.public_key).decode("ascii")}

    def attest(self, *, itype: str, canonical_value: str, verdict: str, voices: int, report_count: int,
               config: str, now: datetime) -> dict:
        body = {"v": VERSION, "key_id": self.key_id,
                "issued_at": now.astimezone(IST).isoformat(timespec="seconds"),
                "type": itype, "value_sha256": value_sha256(canonical_value), "verdict": verdict,
                "voices": voices, "report_count": report_count, "config": config}
        body["sig"] = base64.b64encode(self._key.sign(canonical_json(body)).signature).decode("ascii")
        return body


def verify(attestation: object, public_key: bytes) -> bool:
    """True only when the signature over every other field is good for this public key, the key_id is
    this key's, and the version is 1. Any changed, added or removed field makes it False."""
    if not isinstance(attestation, dict) or not all(k in attestation for k in FIELDS + ("sig",)):
        return False
    if attestation["v"] != VERSION or attestation["key_id"] != key_id_for(public_key):
        return False
    try:
        sig = base64.b64decode(attestation["sig"], validate=True)
        signed = canonical_json({k: v for k, v in attestation.items() if k != "sig"})
        VerifyKey(public_key).verify(signed, sig)
        return True
    except (BadSignatureError, binascii.Error, ValueError, TypeError):
        return False
