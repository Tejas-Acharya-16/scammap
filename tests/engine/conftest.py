import itertools
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.engine import IST, Engine, Registry  # noqa: E402

NOW = datetime(2026, 11, 1, 10, 0, tzinfo=IST)
_counter = itertools.count(1)


@pytest.fixture(scope="session")
def registry():
    return Registry.from_dir(ROOT / "app" / "data")


@pytest.fixture
def engine(registry):
    return Engine(registry, salt="unit-test-salt-01")


def body(**over):
    """A valid report in the brief's shape; override any field."""
    n = next(_counter)
    b = {
        "report_id": f"rep_{n:06d}",
        "occurred_at": (NOW - timedelta(hours=2)).isoformat(),
        "reported_at": (NOW - timedelta(hours=1)).isoformat(),
        "reporter_id": f"r_{n:08x}",
        "ip_prefix": f"10.{n % 250}.{(n // 250) % 250}",
        "channel": "Phone call",
        "scam_type": "digital-arrest",
        "identifier_type": "phone",
        "identifier_value": "+91 90000 00001",
        "pincode": "560102",
        "locality": "HSR Layout",
        "city": "Bengaluru",
        "note": f"video call from a man in police uniform asked for money number {n} " + "abcdefghij"[n % 10] * 3,
        "has_screenshot": False,
        "amount_lost_inr": 0,
    }
    b.update(over)
    return b


def own_words(i):
    """Distinct personal notes (no shared text between i values)."""
    vocab = ["arre", "bhai", "police", "wala", "video", "call", "parcel", "drugs", "paisa", "maanga",
             "darr", "gaya", "officer", "bola", "arrest", "hoga", "bank", "account", "freeze", "turant"]
    rng = __import__("random").Random(i * 7919)
    return " ".join(rng.choice(vocab) + str(rng.randint(0, 9) * "x") for _ in range(9))
