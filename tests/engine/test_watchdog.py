"""AI campaign watchdog: loads, explains, stays advisory. Synthetic data only."""
import json
import random
from datetime import timedelta

import pytest

from app.engine import TrustConfig
from app.engine.watchdog import FEATURES, MODEL_PATH, SIGNALS, Watchdog, features
from tests.engine import scenarios as sc

ALLOWED_TEXT = {phrase for pair in SIGNALS.values() for phrase in pair}


def world(seed):
    w = sc.World(random.Random(seed), TrustConfig())
    w.background()
    return w


def look(w, number):
    return w.engine.lookup("phone", number, sc.NOW)[1]


def test_model_file_matches_the_code_and_every_weight_is_zero_or_positive():
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    assert tuple(model["features"]) == FEATURES
    assert len(model["weights"]) == len(model["mean"]) == len(model["std"]) == len(FEATURES)
    assert all(w >= 0 for w in model["weights"])          # no signal can count the "wrong" way
    assert model["held_out"]["auc"] > 0.85                # in our simulator, on worlds it never saw
    assert Watchdog.load() is not None


@pytest.mark.parametrize("name", ["F5", "F6", "F7", "F10", "F9", "F1", "K2"])
def test_flags_rings_the_rules_already_stop(name):
    w = world(11)
    a = look(w, sc.scenario(w, name))["ai_watchdog"]
    assert a["level"] == "high" and a["advisory"] is True and a["signals"], a


@pytest.mark.parametrize("name", ["R1", "R2", "R5", "R8", "R14", "J1", "J3"])
def test_quiet_on_real_waves(name):
    w = world(12)
    a = look(w, sc.scenario(w, name))["ai_watchdog"]
    assert a["level"] == "low" and a["signals"], a


def test_flags_backdated_reports_that_the_rules_let_through():
    w = world(13)
    rng = w.rng
    target = "+91 90000 48123"
    for _ in range(12):
        filed = sc.NOW - rng.uniform(0.05, 1) * sc.H
        w.report(target, sc.NOW - rng.uniform(0.5, 5) * sc.D, rng.choice(sc.AREAS), "job-offer",
                 sc.free_note(rng), sc.new_rid(rng), sc.new_prefix(rng), reported=filed)
    r = look(w, target)
    assert r["verdict"] == "KNOWN_SCAM"                    # the rules alone: a gap, shown honestly
    assert r["ai_watchdog"]["level"] == "high"
    assert "backdated+" in r["ai_watchdog"]["signal_codes"]


def test_one_bulk_stamp_is_not_backdating():
    """Test tools often stamp every report with the same reported_at. That is not a ring."""
    w = world(14)
    rng = w.rng
    target = "+91 90000 48124"
    stamp = sc.NOW - 10 * timedelta(minutes=1)
    for _ in range(10):
        w.report(target, sc.NOW - rng.uniform(0.5, 9) * sc.D, rng.choice(sc.AREAS), "job-offer",
                 sc.free_note(rng), sc.new_rid(rng), sc.new_prefix(rng), reported=stamp)
    r = look(w, target)
    assert "backdated+" not in r["ai_watchdog"]["signal_codes"]
    assert r["ai_watchdog"]["level"] == "low", r["ai_watchdog"]


def test_never_changes_any_answer():
    """Every catalogue scenario, looked up with and without the watchdog: identical apart from the field."""
    w = world(15)
    numbers = [sc.scenario(w, name) for name, *_ in sc.LOOKUP_ROWS]
    with_ai = [look(w, n) for n in numbers]
    model, w.engine.watchdog = w.engine.watchdog, None
    without = [look(w, n) for n in numbers]
    w.engine.watchdog = model
    for a, b in zip(with_ai, without):
        assert b["ai_watchdog"] is None
        assert {k: v for k, v in a.items() if k != "ai_watchdog"} == {k: v for k, v in b.items() if k != "ai_watchdog"}


def test_says_nothing_under_three_reports_or_without_a_model(tmp_path):
    w = world(16)
    rng = w.rng
    n = "+91 90000 48125"
    for _ in range(2):
        w.report(n, sc.NOW - rng.uniform(1, 3) * sc.D, "560102", "job-offer", sc.free_note(rng),
                 sc.new_rid(rng), sc.new_prefix(rng))
    assert look(w, n)["ai_watchdog"] is None
    assert look(w, "+91 90000 48126")["ai_watchdog"] is None          # no reports at all
    assert Watchdog.load(tmp_path / "missing.json") is None
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert Watchdog.load(tmp_path / "bad.json") is None


def test_output_holds_only_fixed_words_and_numbers():
    """Privacy: the opinion is a score, a level and phrases from a fixed list. Nothing from a report."""
    w = world(17)
    for name in ("F5", "R2", "F13", "J2"):
        a = look(w, sc.scenario(w, name))["ai_watchdog"]
        assert set(a) == {"coordinated", "level", "signals", "signal_codes", "model", "advisory"}
        assert isinstance(a["coordinated"], float) and 0 <= a["coordinated"] <= 1
        assert set(a["signals"]) <= ALLOWED_TEXT
        assert all(c[:-1] in FEATURES and c[-1] in "+-" for c in a["signal_codes"])


def test_ignores_how_many_reports_there_are():
    """The same pattern at 6 and at 30 reports gets a similar score: size is not a feature."""
    assert not any("count" in f or "reports" in f for f in FEATURES)
    w = world(18)
    rng = w.rng
    scores = []
    for size, n in ((6, "+91 90000 48127"), (30, "+91 90000 48128")):
        for _ in range(size):
            w.report(n, sc.NOW - rng.uniform(0.5, 10) * sc.D, rng.choice(sc.AREAS), "job-offer",
                     sc.free_note(rng), sc.new_rid(rng), sc.new_prefix(rng))
        scores.append(look(w, n)["ai_watchdog"]["coordinated"])
    assert abs(scores[0] - scores[1]) < 0.25, scores
