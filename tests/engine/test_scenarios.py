"""The attack table as a test (AT-1.1 to AT-1.6, AT-3.x, AT-3.5). Fewer seeds than the full table.
Known limits (section 6.5) are expected failures, so the table stays honest."""
import pytest

from app.engine import TrustConfig
from tests.engine.scenarios import (ALERT_ROWS, LOOKUP_ROWS, TRICKS, alert_case, alert_ok, judge,
                                    map_windows_ok, run_lookup_table)

CFG = TrustConfig()
SEEDS = 10


@pytest.fixture(scope="module")
def table():
    return run_lookup_table(CFG, SEEDS)


@pytest.mark.parametrize("name,desc,want,limit", LOOKUP_ROWS, ids=[r[0] for r in LOOKUP_ROWS])
def test_lookup_rows(table, name, desc, want, limit):
    rate, susp = table[name]
    verdict = judge(want, rate, susp, limit)
    if limit:
        pytest.xfail(f"known limit (BUILD_SPEC 6.5): {desc}, KNOWN_SCAM rate {rate:.0%}")
    assert verdict == "PASS", f"{desc}: KNOWN_SCAM rate {rate:.0%}"


@pytest.mark.parametrize("name,desc,want", ALERT_ROWS, ids=[r[0] for r in ALERT_ROWS])
def test_alert_rows(name, desc, want):
    for seed in range(4):
        alerts, _ = alert_case(CFG, name, seed)
        assert alert_ok(want, alerts), f"{desc}, seed {seed}: {alerts}"


@pytest.mark.parametrize("trick", TRICKS)
def test_tricks_raise_no_alert(trick):
    if trick == "F4":
        pytest.xfail("known limit: 40 friends with their own varied words look like a real wave")
    for seed in range(4):
        alerts, _ = alert_case(CFG, "trick:" + trick, seed)
        assert alerts == [], f"{trick}, seed {seed}: {alerts}"


def test_map_windows():
    assert map_windows_ok(CFG)
