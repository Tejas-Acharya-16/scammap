"""Rule 5 (v1.2): a coordinated burst counts as one voice. Case raised at checkpoint 1:
one person asks 10 friends, each on their own phone and in their own words, to report a number."""
from datetime import timedelta

from tests.engine.conftest import NOW, body, own_words

H = timedelta(hours=1)
D = timedelta(days=1)
AREAS = ["560102", "560038", "560034", "560066", "560076", "560011"]


def friends(engine, number, n, pin="560102", start=0, spread=H, areas=None):
    for i in range(n):
        b = body(identifier_value=number, note=own_words(start + i),
                 pincode=areas[i % len(areas)] if areas else pin,
                 occurred_at=(NOW - spread * (i + 1) / (n + 1)).isoformat())
        assert engine.handle_report(b, NOW)[0] == 201


def look(engine, number):
    return engine.lookup("phone", number, NOW)[1]


def test_one_person_and_ten_friends_is_held(engine):
    friends(engine, "+91 90000 11111", 11)
    r = look(engine, "+91 90000 11111")
    assert r["verdict"] == "SUSPICIOUS" and r["display_value"] == "90XXXXX111"
    assert r["report_count"] == 11 and r["distinct_reporters"] == 1 and r["evidence"] == []
    assert r["trust"]["burst_voices"] == 11 and r["trust"]["hold"] == "burst_from_new_accounts_in_one_area"
    assert engine.alerts("560102", NOW)[1] == {"alerts": []}
    assert engine.map("560102", None, None, NOW)[1] == {"clusters": []}


def test_same_people_across_areas_is_a_real_wave(engine):
    friends(engine, "+91 90000 11112", 11, areas=AREAS)
    r = look(engine, "+91 90000 11112")
    assert r["verdict"] == "KNOWN_SCAM" and r["trust"]["burst_voices"] == 0 and r["trust"]["hold"] is None


def test_same_area_over_days_is_a_real_wave(engine):
    friends(engine, "+91 90000 11113", 11, spread=3 * D)
    assert look(engine, "+91 90000 11113")["verdict"] == "KNOWN_SCAM"


def test_independent_people_still_confirm(engine):
    friends(engine, "+91 90000 11114", 20)
    for i, pin in enumerate(["560038", "560034", "560066"]):
        b = body(identifier_value="+91 90000 11114", note=own_words(500 + i), pincode=pin,
                 occurred_at=(NOW - (i + 2) * D).isoformat())
        assert engine.handle_report(b, NOW)[0] == 201
    r = look(engine, "+91 90000 11114")
    assert r["verdict"] == "KNOWN_SCAM" and r["distinct_reporters"] == 4
    assert r["trust"]["burst_voices"] == 20 and r["trust"]["hold"] is None


def test_ring_cannot_earn_a_track_record_from_its_own_burst(engine):
    ids = [f"r_ring{i}" for i in range(11)]
    for number, hours_ago in [("+91 90000 11115", 30), ("+91 90000 11116", 2)]:
        for i, rid in enumerate(ids):
            b = body(identifier_value=number, reporter_id=rid, ip_prefix=f"10.77.{i}",
                     note=own_words(hours_ago * 100 + i),
                     occurred_at=(NOW - hours_ago * H + i * timedelta(minutes=3)).isoformat())
            assert engine.handle_report(b, NOW)[0] == 201
    assert look(engine, "+91 90000 11115")["verdict"] == "SUSPICIOUS"
    assert look(engine, "+91 90000 11116")["verdict"] == "SUSPICIOUS"


def test_reporters_with_a_track_record_are_not_merged(engine):
    # three people who each earlier reported a number that others confirmed
    for i in range(3):
        number = f"+91 90000 2220{i}"
        for k in range(3):
            rid = f"r_vet{i}" if k == 0 else f"r_other{i}{k}"
            b = body(identifier_value=number, reporter_id=rid, note=own_words(700 + i * 10 + k),
                     pincode="560038", occurred_at=(NOW - (5 + k) * D).isoformat())
            assert engine.handle_report(b, NOW)[0] == 201
    friends(engine, "+91 90000 11117", 16, start=800)
    for i in range(3):
        b = body(identifier_value="+91 90000 11117", reporter_id=f"r_vet{i}", note=own_words(900 + i),
                 occurred_at=(NOW - (i + 1) * timedelta(minutes=10)).isoformat())
        assert engine.handle_report(b, NOW)[0] == 201
    r = look(engine, "+91 90000 11117")
    assert r["verdict"] == "KNOWN_SCAM" and r["trust"]["burst_voices"] == 16 and r["distinct_reporters"] == 4


def test_small_ring_is_a_known_limit(engine):
    """Seven friends is below the burst size: shown honestly, as in the README's limits."""
    friends(engine, "+91 90000 11118", 7)
    assert look(engine, "+91 90000 11118")["verdict"] == "KNOWN_SCAM"


def test_six_new_people_in_two_hours_still_flip(engine):
    friends(engine, "+91 90000 11119", 6, spread=2 * H)
    assert look(engine, "+91 90000 11119")["verdict"] == "KNOWN_SCAM"
