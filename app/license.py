"""Licence module: Ed25519 signature verification, gate, state management.

BUILD_SPEC section 9. The public key is a constant. The private key never
appears here, in Git, in a prompt or in a log.
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

logger = logging.getLogger("scammap.license")

# ── public key (paste from tools/gen_keys.py) ────────────────────────────────
# This is the VERIFY (public) key. The signing (private) key lives outside the
# repo, outside every agent's view, outside every prompt.
LICENSE_PUBLIC_KEY_B64 = "zSWH+N1Ir3IfmM/4YpGsXTqHZNR/CgYxDmlZhf40xbA="

# Paths exempt from the licence gate (section 9.2)
EXEMPT_PATHS = frozenset({"/health", "/license"})
# Static file prefix is also exempt
STATIC_PREFIX = "/static"


class LicenseState:
    """In-memory licence state. Thread-safe for reads (one uvicorn worker)."""

    def __init__(self):
        self.licensee: str | None = None
        self.expires_at: datetime | None = None
        self.raw_json: str | None = None
        self._latest_clock: datetime | None = None
        self._verify_key: VerifyKey | None = None
        if LICENSE_PUBLIC_KEY_B64:
            self._verify_key = VerifyKey(base64.b64decode(LICENSE_PUBLIC_KEY_B64))

    def set_public_key(self, key_b64: str):
        """Set the public key (used once at startup or in tests)."""
        self._verify_key = VerifyKey(base64.b64decode(key_b64))

    # ── gate ─────────────────────────────────────────────────────────────
    def is_valid(self, now: datetime) -> bool:
        """True when the licence is present, not expired, and the clock is not
        rolled back beyond the 2-minute tolerance."""
        if self.expires_at is None:
            return False
        if now >= self.expires_at:
            return False
        if self._latest_clock is not None:
            if now < self._latest_clock - timedelta(minutes=2):
                return False
        return True

    def status(self, now: datetime) -> str:
        if self.expires_at is None:
            return "none"
        if self._latest_clock is not None and now < self._latest_clock - timedelta(minutes=2):
            return "clock_rollback"
        if now >= self.expires_at:
            return "expired"
        return "valid"

    def seconds_remaining(self, now: datetime) -> float:
        if self.expires_at is None:
            return 0
        return max(0, (self.expires_at - now).total_seconds())

    # ── update the clock guard ───────────────────────────────────────────
    def update_clock(self, now: datetime):
        """Track the latest time we have seen. Called periodically (every 30 s)
        and at startup."""
        if self._latest_clock is None or now > self._latest_clock:
            self._latest_clock = now

    def set_latest_clock(self, dt: datetime | None):
        """Restore from the database at startup."""
        self._latest_clock = dt

    # ── verify and install ───────────────────────────────────────────────
    def verify_and_install(self, data: dict) -> tuple[bool, str]:
        """Verify the signature and install the licence. Returns (ok, error_or_empty)."""
        if self._verify_key is None:
            return False, "INVALID_LICENSE"

        licensee = data.get("licensee")
        expires_at_str = data.get("expires_at")
        signature_b64 = data.get("signature")

        if not isinstance(licensee, str) or not licensee.strip():
            return False, "INVALID_LICENSE"
        if not isinstance(expires_at_str, str) or not expires_at_str.strip():
            return False, "INVALID_LICENSE"
        if not isinstance(signature_b64, str) or not signature_b64.strip():
            return False, "INVALID_LICENSE"

        # Parse expires_at
        try:
            expires_at = _parse_iso(expires_at_str)
        except (ValueError, TypeError):
            return False, "INVALID_LICENSE"

        # Verify signature: signed message = licensee + \n + expires_at (exact strings)
        message = (licensee + "\n" + expires_at_str).encode("utf-8")
        try:
            sig_bytes = base64.b64decode(signature_b64)
        except Exception:
            return False, "INVALID_LICENSE"

        try:
            self._verify_key.verify(message, sig_bytes)
        except (BadSignatureError, Exception):
            return False, "INVALID_LICENSE"

        # Install
        self.licensee = licensee
        self.expires_at = expires_at
        self.raw_json = json.dumps(data)
        return True, ""

    def to_get_response(self, now: datetime) -> dict:
        """GET /license reply."""
        st = self.status(now)
        return {
            "licensee": self.licensee or "",
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": st,
            "valid": st == "valid",
            "seconds_remaining": round(self.seconds_remaining(now), 1),
        }


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 datetime with offset."""
    # Python 3.11+ datetime.fromisoformat handles offsets
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        # Assume IST if naive
        from app.engine.timeutil import IST
        dt = dt.replace(tzinfo=IST)
    return dt
