"""The Scam Arena (POST /arena/attack, POST /arena/redteam, GET /arena): a judge plays the attacker.

Every attack runs on a fresh in-memory sandbox engine; nothing touches the live engine or the database.
Cases 1 to 11 are the acceptance list from the task. The expected outcomes come from the task, not from
running the code. Synthetic data only.
"""
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
ARENA = ROOT / "app" / "static" / "arena.html"
PLAN = {"target": "unlisted", "reports": 40, "accounts": 40, "networks": 40, "areas": 1, "hours": 1,
        "words": "own", "backdate": False}
FIELDS = {"verdict", "report_count", "voices", "burst_counted_as_one", "rules", "ai_watchdog", "alerts_raised",
          "map_moved", "bill", "outcome", "note"}
NETWORK = re.compile(r"\b10\.\d{1,3}\.\d{1,3}\b")            # a 10.x.y network written anywhere
CASES = {
    1: dict(target="verified", reports=40, accounts=40, networks=40, words="own", areas=1, hours=1),
    2: dict(reports=22, accounts=22, networks=1, areas=1, hours=3, words="own"),
    3: dict(reports=6, accounts=1, networks=6, areas=1, hours=1, words="own"),
    4: dict(reports=40, accounts=40, networks=40, areas=1, hours=1, words="copy"),
    5: dict(reports=12, accounts=12, networks=12, areas=6, hours=1, words="own", backdate=True),
    6: dict(reports=11, accounts=11, networks=11, areas=11, hours=1, words="own"),
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def plan(**kw):
    return {**PLAN, **kw}


def attack(client, **kw):
    r = client.post("/arena/attack", json=plan(**kw))
    assert r.status_code == 200, r.text
    body = r.json()
    assert FIELDS <= set(body), set(body)
    return body


def install(client, name):
    assert client.post("/license", json=json.loads((ROOT / "licenses" / name).read_text(encoding="utf-8"))).status_code == 200


# ------------------------------------------------------------------ cases 1 to 6
def test_1_forty_friends_against_the_verified_bakery_are_caught(client):
    r = attack(client, **CASES[1])
    assert r["verdict"] == "VERIFIED_BUSINESS" and r["outcome"] == "caught", r
    assert r["report_count"] == 40
    assert any("verified" in s for s in r["rules"]), r["rules"]


def test_2_twenty_two_accounts_on_one_network(client):
    r = attack(client, **CASES[2])
    assert r["verdict"] != "KNOWN_SCAM" and r["outcome"] == "caught", r
    assert any("network" in s for s in r["rules"]), r["rules"]
    assert r["voices"] == 1


def test_3_one_account_six_times(client):
    r = attack(client, **CASES[3])
    assert r["verdict"] != "KNOWN_SCAM" and r["outcome"] == "caught", r
    assert any("account" in s for s in r["rules"]), r["rules"]


def test_4_forty_pasted_copies_in_one_hour(client):
    r = attack(client, **CASES[4])
    assert r["verdict"] != "KNOWN_SCAM" and r["outcome"] == "caught", r
    assert any("text" in s for s in r["rules"]), r["rules"]


def test_5_backdated_ring_beats_the_rules_and_the_ai_flags_it(client):
    r = attack(client, **CASES[5])
    print("\ncase 5:", r["verdict"], r["ai_watchdog"] and r["ai_watchdog"]["level"], r["outcome"])
    assert r["outcome"] == "beat_rules_ai_flagged", (r["verdict"], r["ai_watchdog"])


def test_6_eleven_friends_in_eleven_areas_beat_the_rules(client):
    r = attack(client, **CASES[6])
    level = r["ai_watchdog"] and r["ai_watchdog"]["level"]
    print("\ncase 6:", r["verdict"], level, r["outcome"])
    assert r["verdict"] == "KNOWN_SCAM", r
    assert r["outcome"] == ("beat_rules_ai_flagged" if level in ("high", "medium") else "beat_both")
    if r["outcome"] == "beat_both":
        assert "known limit" in r["note"] and "disputes" in r["note"], r["note"]


def test_7_tricks_one_to_four_raise_no_alert_and_do_not_move_the_map(client):
    for case in (1, 2, 3, 4):
        r = attack(client, **CASES[case])
        assert r["alerts_raised"] == [], (case, r["alerts_raised"])
        assert r["map_moved"]["added"] == 0, (case, r["map_moved"])


def test_outcome_follows_the_verdict_and_the_ai_level(client):
    for case in CASES.values():
        r = attack(client, **case)
        flagged = bool(r["ai_watchdog"]) and r["ai_watchdog"]["level"] in ("high", "medium")
        want = "caught" if r["verdict"] != "KNOWN_SCAM" else "beat_rules_ai_flagged" if flagged else "beat_both"
        assert r["outcome"] == want, (case, r["verdict"], r["ai_watchdog"], r["outcome"])
        assert r["voices"] <= r["report_count"] == case["reports"]


def test_the_bill_counts_what_the_attacker_spent(client):
    r = attack(client, **CASES[6])
    assert r["bill"] == {"fake_accounts": 11, "networks": 11, "areas": 11, "hours": 1.0, "people_needed": 11}
    r = attack(client, **CASES[3])
    assert r["bill"]["people_needed"] == 1                     # one account can switch networks


# ------------------------------------------------------------------ case 8: never the live data
def test_8_live_reports_and_database_rows_are_unchanged(client):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone(timedelta(hours=5, minutes=30))).isoformat()
    assert client.post("/reports", json={
        "report_id": "arena-live-1", "occurred_at": now, "reported_at": now, "reporter_id": "arena-live-r1",
        "ip_prefix": "192.0.2.0/24", "channel": "Phone call", "scam_type": "digital-arrest",
        "identifier_type": "phone", "identifier_value": "+91 90000 64444", "pincode": "560102",
        "note": "", "has_screenshot": False, "amount_lost_inr": 0}).status_code == 201
    query = {"type": "phone", "value": "+91 90000 64444"}
    live_before, rows_before = main.ENGINE.stats(), main.app.state.db.all_report_rows()
    lookup_before = {k: v for k, v in client.get("/lookup", params=query).json().items() if k != "attestation"}
    for case in (1, 2, 4, 5, 6):
        attack(client, **CASES[case])
    assert client.post("/arena/redteam", json={"seed": 11}).status_code == 200
    assert main.ENGINE.stats() == live_before
    assert main.app.state.db.all_report_rows() == rows_before and len(rows_before) == 1
    assert {k: v for k, v in client.get("/lookup", params=query).json().items() if k != "attestation"} == lookup_before


# ------------------------------------------------------------------ case 9: bad input
@pytest.mark.parametrize("bad", [
    plan(reports=999), plan(words="x"), {k: v for k, v in PLAN.items() if k != "hours"},
    plan(reports=2), plan(accounts=0), plan(accounts=41), plan(networks=41), plan(areas=0), plan(areas=13),
    plan(hours=0.1), plan(hours=169), plan(target="bank"), plan(backdate="yes"), plan(reports=True),
    plan(reports=10.5), plan(reports="40"), plan(hours="1"), plan(hours=None),
    plan(extra=1), [], "attack", None,
])
def test_9_bad_input_is_400_invalid_params_and_never_echoed(client, bad):
    r = client.post("/arena/attack", json=bad)
    assert r.status_code == 400, (bad, r.text)
    assert r.json() == {"error": "invalid_params"}


def test_9_broken_json_and_bad_red_team_seeds_are_400(client):
    r = client.post("/arena/attack", content=b'{"reports": 999,', headers={"content-type": "application/json"})
    assert r.status_code == 400 and r.json() == {"error": "invalid_params"}
    for bad in ({"seed": "abc"}, {"seed": 1.5}, {"seed": True}, {"seed": 1, "extra": 2}, [1]):
        r = client.post("/arena/redteam", json=bad)
        assert r.status_code == 400 and r.json() == {"error": "invalid_params"}, bad


# ------------------------------------------------------------------ case 10: replies carry no identities
def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield k
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)


def test_10_replies_carry_no_reporter_ids_networks_or_notes(client):
    from app import arena, demo
    note_words = re.compile(r"^(?:(?:%s)+\s*){3,}$" % "|".join(demo.SYL))      # the syllable words planted notes use
    replies = [attack(client, **case) for case in CASES.values()]
    for r in replies:
        assert r["note"] in arena.NOTES.values()                 # the outcome note is a fixed phrase
    replies.append(client.post("/arena/redteam", json={"seed": 3}).json())
    for r in replies:
        t = json.dumps(r)
        assert "r_arena" not in t and not NETWORK.search(t), NETWORK.search(t)
        for key in ('"rid"', '"org"', '"reporter_id"', '"ip_prefix"', '"note_hash"', '"shingles"', '"evidence"'):
            assert key not in t, key
        assert not [s for s in _strings(r) if note_words.match(s)]


# ------------------------------------------------------------------ case 11: the red team
def test_11_red_team_is_fast_and_its_cheapest_plan_replays(client):
    t0 = time.perf_counter()
    r = client.post("/arena/redteam", json={"seed": 7})
    took = time.perf_counter() - t0
    assert r.status_code == 200, r.text
    red = r.json()
    print("\nred team:", {k: red[k] for k in ("tried", "beat_rules", "ai_flagged_of_those", "ms")}, f"{took:.2f} s")
    assert took < 6
    assert 1 <= red["tried"] <= 150 and 0 <= red["ai_flagged_of_those"] <= red["beat_rules"] <= red["tried"]
    best = red["cheapest_beat_rules"]
    assert best, red
    again = attack(client, **best["plan"])
    assert again["outcome"] == best["result"]["outcome"] and again["verdict"] == best["result"]["verdict"] == "KNOWN_SCAM"
    if red["cheapest_beat_both"]:
        both = red["cheapest_beat_both"]
        assert attack(client, **both["plan"])["outcome"] == both["result"]["outcome"] == "beat_both"
        key = lambda p: (p["accounts"], p["networks"], p["areas"], p["hours"])
        assert key(best["plan"]) <= key(both["plan"])           # beating both is never cheaper than beating the rules


def test_red_team_is_deterministic_per_seed(client):
    a = client.post("/arena/redteam", json={"seed": 21}).json()
    b = client.post("/arena/redteam", json={"seed": 21}).json()
    if a["tried"] == b["tried"] == 150:                         # not cut short by the time limit
        assert {k: v for k, v in a.items() if k != "ms"} == {k: v for k, v in b.items() if k != "ms"}


def test_the_same_plan_gives_the_same_answer(client):
    assert attack(client, **CASES[5]) == attack(client, **CASES[5])


# ------------------------------------------------------------------ page, licence, lock
def test_arena_page_is_served_even_when_the_licence_has_expired(client):
    r = client.get("/arena")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.content == ARENA.read_bytes()
    install(client, "expired.json")
    assert client.get("/arena").status_code == 200
    for path, body in (("/arena/attack", PLAN), ("/arena/redteam", {})):
        r = client.post(path, json=body)
        assert r.status_code == 403 and r.json() == {"error": "LICENSE_EXPIRED"}
    install(client, "long.json")


def test_one_sandbox_run_at_a_time(client):
    assert main._DEMO_LOCK.acquire(blocking=False)
    try:
        replies = [client.post("/arena/attack", json=PLAN), client.post("/arena/redteam", json={})]
    finally:
        main._DEMO_LOCK.release()
    for r in replies:
        assert r.status_code == 429 and r.json() == {"error": "busy"}


def test_judge_console_links_to_the_arena_and_the_page_uses_the_shared_theme():
    judge = (ROOT / "app" / "static" / "judge.html").read_text(encoding="utf-8")
    assert 'href="/arena"' in judge and "Play the attacker" in judge
    page = ARENA.read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="/static/theme.css">' in page
    assert "<script src=" not in page                           # no new outside scripts
    for word in ("scammer", "fraud"):
        assert word not in page.lower() and word not in (ROOT / "app" / "arena.py").read_text(encoding="utf-8").lower()
