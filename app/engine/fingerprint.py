"""Keyed fingerprints of notes and reporter identity (BUILD_SPEC sections 6.2 and 10).

The note text, the raw reporter_id and the raw ip_prefix never leave these functions.
What is kept: a keyed hash of the note's words, keyed 32-bit hashes of each word and each
pair of adjacent words (for the near-duplicate test), the word count, and keyed hashes of
the reporter and network. Without TRUST_SALT none of these can be reversed by guessing.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import unicodedata
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NoteFP:
    note_hash: Optional[str]
    shingles: frozenset
    ntok: int


EMPTY_NOTE = NoteFP(None, frozenset(), 0)


def derive_key(salt: str) -> bytes:
    return hashlib.sha256(("scammap-v1:" + salt).encode()).digest()


def identity_hash(key: bytes, kind: str, value: str) -> str:
    """HMAC-SHA256 cut to 16 bytes (32 hex characters)."""
    return hmac.new(key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:32]


def _tokens(text: str) -> list:
    """NFKC, lower case, keep letters and combining marks (so Hindi matras survive),
    everything else is a separator. Digits are dropped, so numbers in notes are never kept."""
    s = unicodedata.normalize("NFKC", text).lower()
    return "".join(ch if unicodedata.category(ch)[0] in "LM" else " " for ch in s).split()


def _h32(key: bytes, s: str) -> int:
    return int.from_bytes(hmac.new(key, s.encode(), hashlib.sha256).digest()[:4], "big")


def note_fingerprint(note: object, key: bytes, max_chars: int = 500) -> NoteFP:
    if not isinstance(note, str):
        return EMPTY_NOTE
    toks = _tokens(note[:max_chars])
    if not toks:
        return EMPTY_NOTE
    joined = " ".join(toks)
    note_hash = hmac.new(key, b"note:" + joined.encode(), hashlib.sha256).hexdigest()[:32]
    shingles = {_h32(key, "u:" + t) for t in toks}
    shingles.update(_h32(key, "b:" + a + " " + b) for a, b in zip(toks, toks[1:]))
    return NoteFP(note_hash, frozenset(shingles), len(toks))


def network_prefix(value: object) -> Optional[str]:
    """'103.21.58.7' and '103.21.58' both give '103.21.58'; IPv6 gives the /64.
    Anything else is used as given (trimmed, lower case, at most 64 characters)."""
    if value is None:
        return None
    s = str(value).strip().lower()[:64]
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return s
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:3])
    return ":".join(ip.exploded.split(":")[:4])
