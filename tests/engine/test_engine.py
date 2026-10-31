"""Engine behaviour against the API rules (BUILD_SPEC sections 3, 5, 7, 8, 12, 13)."""
from datetime import timedelta

import pytest

from app.engine import Engine, Report
from tests.engine.conftest import NOW, body, own_words

H = timedelta(hours=1)
D = timedelta(days=1)


def post(engine, **over):
    return engine.handle_report(body(**over), NOW)


def wave(engine, number, n, **over):
    for i in range(n):
        status, _ = post(engine, identifier_value=number, note=own_words(1000 + i), **over)
        assert status == 201


# ------------------------------------------------------------------ POST /reports
def test_accepts_brief_example_and_merges(engine):
    s1, r1 = post(engine, report_id="rep_000123")
    s2, r2 = post(engine, identifier_value="09000000001")
    assert (s1, s2) == (201, 201)
    assert r1 == {"report_id": "rep_000123", "case_id": r1["case_id"], "merged": False}
    assert r2["merged"] is True and r2["case_id"] == r1["case_id"]
    assert r1["case_id"].startswith("case_") and len(r1["case_id"]) == 15


@pytest.mark.parametrize("over,code", [
    ({"identifier_value": "12345"}, "invalid_identifier"),
    ({"identifier_value": "test"}, "invalid_identifier"),
    ({"identifier_value": ""}, "invalid_identifier"),
    ({"identifier_value": "+91 00000 00000"}, "invalid_identifier"),
    ({"identifier_type": "email"}, "invalid_identifier"),
    ({"pincode": "000000"}, "invalid_pincode"),
    ({"pincode": "999999"}, "invalid_pincode"),
    ({"pincode": "5601"}, "invalid_pincode"),
    ({"occurred_at": "yesterday"}, "invalid_time"),
    ({"occurred_at": "2030-01-01T10:00:00+05:30"}, "invalid_time"),
    ({"occurred_at": None}, "invalid_time"),
    ({"reported_at": "soon"}, "invalid_time"),
])
def test_junk_is_rejected_and_not_stored(engine, over, code):
    status, reply = post(engine, **over)
    assert (status, reply) == (400, {"error": code})
    assert engine.stats()["reports"] == 0


def test_not_an_object(engine):
    assert engine.handle_report(["x"], NOW) == (400, {"error": "invalid_body"})


def test_lenient_on_optional_fields(engine):
    status, _ = post(engine, scam_type="ai-voice-clone", channel="carrier pigeon", note=None,
                     has_screenshot="yes", amount_lost_inr="lots", reported_at=None, pincode=560102)
    assert status == 201
    _, look = engine.lookup("phone", "+91 90000 00001", NOW)
    assert look["scam_type"] == "other"


def test_time_rules(engine):
    assert post(engine, occurred_at=(NOW + 30 * timedelta(minutes=1)).isoformat())[0] == 201   # clock skew
    assert post(engine, occurred_at=(NOW + 2 * H).isoformat())[0] == 400
    assert post(engine, occurred_at=(NOW - 300 * D).isoformat())[0] == 201
    assert post(engine, occurred_at="2026-10-27T18:21:04")[0] == 201                          # naive = IST
    assert post(engine, occurred_at="2026-10-27T12:51:04Z")[0] == 201


def test_retry_counts_once_but_reused_id_from_someone_else_counts(engine):
    b = body()
    s1, first = engine.handle_report(b, NOW)
    s2, again = engine.handle_report(dict(b), NOW)
    assert (s1, s2) == (201, 201)
    assert again == {"report_id": b["report_id"], "case_id": first["case_id"], "merged": True}
    assert engine.stats()["reports"] == 1
    other = dict(b, reporter_id="r_someone_else", ip_prefix="10.200.1")
    assert engine.handle_report(other, NOW)[0] == 201
    assert engine.stats()["reports"] == 2


def test_persist_failure_leaves_memory_unchanged(engine):
    def boom(row):
        raise RuntimeError("db down")
    with pytest.raises(RuntimeError):
        engine.handle_report(body(), NOW, persist=boom)
    assert engine.stats()["reports"] == 0


# ------------------------------------------------------------------ GET /lookup
def test_no_reports(engine):
    status, r = engine.lookup("phone", "+91 90000 99999", NOW)
    assert status == 200 and r["verdict"] == "NO_REPORTS"
    assert r["display_value"] == "90XXXXX999" and r["first_seen"] is None and r["evidence"] == []
    assert r["report_count"] == 0 and r["distinct_reporters"] == 0


def test_lookup_400(engine):
    assert engine.lookup("phone", "12345", NOW) == (400, {"error": "invalid_identifier"})
    assert engine.lookup("fax", "123", NOW) == (400, {"error": "invalid_identifier"})


def test_every_format_same_answer(engine):
    wave(engine, "+91 98765 43210", 5)
    answers = [engine.lookup("phone", v, NOW)[1] for v in
               ["+91 98765 43210", "09876543210", "98765-43210", "919876543210"]]
    assert all(a == answers[0] for a in answers)
    assert answers[0]["verdict"] == "KNOWN_SCAM" and answers[0]["display_value"] == "+919876543210"


def test_known_scam_needs_three_people(engine):
    wave(engine, "+91 90000 00002", 2)
    _, r = engine.lookup("phone", "+91 90000 00002", NOW)
    assert r["verdict"] == "SUSPICIOUS" and r["display_value"] == "90XXXXX002" and r["evidence"] == []
    assert r["first_seen"].endswith("T00:00:00+05:30")        # rounded to the day below 3 people
    wave(engine, "+91 90000 00002", 1)
    _, r = engine.lookup("phone", "+91 90000 00002", NOW)
    assert r["verdict"] == "KNOWN_SCAM" and r["distinct_reporters"] == 3
    assert r["display_value"] == "+919000000002" and len(r["evidence"]) == 3
    assert set(r["evidence"][0]) == {"occurred_at", "channel", "scam_type", "pincode"}


def test_one_person_six_times(engine):
    for i in range(6):
        post(engine, reporter_id="r_same", ip_prefix=f"10.9.{i}", note=own_words(i))
    _, r = engine.lookup("phone", "+91 90000 00001", NOW)
    assert (r["report_count"], r["distinct_reporters"], r["verdict"]) == (6, 1, "SUSPICIOUS")


def test_twenty_two_accounts_one_wifi(engine):
    for i in range(22):
        post(engine, reporter_id=f"r_acc{i}", ip_prefix="103.21.58", note=own_words(i))
    _, r = engine.lookup("phone", "+91 90000 00001", NOW)
    assert r["distinct_reporters"] == 1 and r["verdict"] == "SUSPICIOUS"


def test_forty_friends_same_note(engine):
    for i in range(40):
        post(engine, note="This shop sold me rotten cake and cheated me, total scam!!", identifier_value="+91 90000 00003")
    _, r = engine.lookup("phone", "+91 90000 00003", NOW)
    assert r["verdict"] != "KNOWN_SCAM"


def test_forty_friends_against_the_verified_bakery(engine):
    for i in range(40):
        post(engine, identifier_value="+91 80 4100 2233", note=own_words(i))
    _, r = engine.lookup("phone", "080-4100-2233", NOW)
    assert r["verdict"] == "VERIFIED_BUSINESS" and r["display_value"] == "+918041002233"
    assert r["label"].startswith("Fresh Bakes") and r["evidence"] == []
    _, al = engine.alerts("560102", NOW)
    assert al == {"alerts": []}


@pytest.mark.parametrize("itype,value", [("phone", "1930"), ("phone", "1800 1600"), ("phone", "1860 266 2666"),
                                         ("sender_id", "VM-HDFCBK"), ("sender_id", "KOTAKB"),
                                         ("url", "https://cybercrime.gov.in/Home"), ("url", "sancharsaathi.gov.in"),
                                         ("upi", "FreshBakes@OKAXIS"), ("phone", "+91 80 2553 0190")])
def test_verified_list(engine, itype, value):
    _, r = engine.lookup(itype, value, NOW)
    assert r["verdict"] == "VERIFIED_BUSINESS" and "*" not in r["display_value"] and "X" not in r["display_value"]


def test_lookalike_host_is_not_verified(engine):
    _, r = engine.lookup("url", "https://cybercrime.gov.in.evil.example/login", NOW)
    assert r["verdict"] == "NO_REPORTS"


def test_masks_for_all_four_types_below_three(engine):
    for itype, value, masked in [("upi", "ravi12@okaxis", "r***@okaxis"),
                                 ("url", "http://www.sbi-kyc.in/pay?utm=sms", "sbi***.in/..."),
                                 ("sender_id", "VM-ABCDEF", "AB****")]:
        post(engine, identifier_type=itype, identifier_value=value)
        _, r = engine.lookup(itype, value, NOW)
        assert r["display_value"] == masked and r["evidence"] == []


# ------------------------------------------------------------------ POST /challenges
def test_dispute(engine):
    wave(engine, "+91 90000 00004", 5)
    assert engine.lookup("phone", "+91 90000 00004", NOW)[1]["verdict"] == "KNOWN_SCAM"
    status, reply = engine.handle_challenge({"identifier_type": "phone", "identifier_value": "09000000004",
                                             "claimant_name": "Fresh Bakes", "contact_email": "owner@example.com",
                                             "proof_note": "GST certificate attached."}, NOW)
    assert status == 201 and reply["status"] == "under_review" and reply["challenge_id"].startswith("ch_")
    _, r = engine.lookup("phone", "+91 90000 00004", NOW)
    assert r["challenged"] is True and r["verdict"] == "SUSPICIOUS" and r["display_value"] == "90XXXXX004"
    assert engine.map("560102", None, None, NOW)[1] == {"clusters": []}
    assert engine.handle_challenge({"identifier_type": "phone", "identifier_value": "12345"}, NOW)[0] == 400
    assert engine.handle_challenge({"identifier_type": "phone", "identifier_value": "+91 90000 00005"}, NOW)[0] == 201


# ------------------------------------------------------------------ map and alerts
def test_map_window_and_registry_points(engine, registry):
    for days_old, pin in [(30, "560038"), (8, "560038"), (6, "560034"), (1, "560034")]:
        post(engine, identifier_value=f"+91 90000 1{days_old:04d}", pincode=pin, note=own_words(days_old),
             occurred_at=(NOW - days_old * D).isoformat())
    _, m = engine.map(None, None, None, NOW)
    pins = {c["pincode"]: c for c in m["clusters"]}
    assert "560038" not in pins and pins["560034"]["count"] == 2
    a = registry.areas["560034"]
    assert (pins["560034"]["lat"], pins["560034"]["lng"], pins["560034"]["locality"]) == (a.lat, a.lng, a.area)
    assert set(pins["560034"]) == {"pincode", "locality", "city", "count", "top_scam_type", "severity", "lat", "lng"}
    _, m30 = engine.map(None, "30", None, NOW)
    assert any(c["pincode"] == "560038" for c in m30["clusters"])


def test_map_radius_and_queries(engine):
    post(engine, pincode="560103", note=own_words(1))           # Bellandur, about 3.3 km from HSR Layout
    assert engine.map("560102", 7, 2, NOW)[1] == {"clusters": []}
    assert [c["pincode"] for c in engine.map("560102", 7, 5, NOW)[1]["clusters"]] == ["560103"]
    assert engine.map("12ab", None, None, NOW) == (400, {"error": "invalid_pincode"})
    assert engine.map("123456", None, None, NOW) == (200, {"clusters": []})
    assert engine.alerts("12ab", NOW) == (400, {"error": "invalid_pincode"})
    assert engine.alerts("123456", NOW) == (200, {"alerts": []})


def test_spike_matches_the_brief_example(engine):
    for i in range(14):
        post(engine, identifier_value=f"+91 90000 2{i:04d}", note=own_words(i),
             occurred_at=(NOW - D - (i / 2) * D - H).isoformat())
    for i in range(10):
        post(engine, identifier_value=f"+91 90000 3{i:04d}", note=own_words(100 + i),
             occurred_at=(NOW - (i + 1) * H).isoformat())
    _, a = engine.alerts("560102", NOW)
    spike = [x for x in a["alerts"] if x["type"] == "SPIKE"]
    assert spike == [{"type": "SPIKE", "pincode": "560102", "window": "24h", "count": 10, "baseline_per_day": 2.0}]


def test_normal_area_and_new_type(engine):
    for d in range(1, 21):
        for k in range(2):
            post(engine, identifier_value=f"+91 90000 4{d:02d}{k:02d}", note=own_words(d * 10 + k),
                 occurred_at=(NOW - d * D - k * H).isoformat())
    for k in range(3):
        post(engine, identifier_value=f"+91 90000 5{k:04d}", note=own_words(500 + k),
             occurred_at=(NOW - (k + 1) * H).isoformat())
    assert engine.alerts("560102", NOW)[1] == {"alerts": []}
    post(engine, identifier_value="+91 90000 60000", scam_type="job-offer", note=own_words(900),
         occurred_at=(NOW - H).isoformat())
    _, a = engine.alerts("560102", NOW)
    assert [x["type"] for x in a["alerts"]] == ["NEW_TYPE"] and a["alerts"][0]["scam_type"] == "job-offer"


def test_unknown_type_keeps_its_name_for_new_type(engine):
    post(engine, scam_type="AI Voice Clone", note=own_words(77))
    _, a = engine.alerts("560102", NOW)
    assert a["alerts"][0]["scam_type"] == "ai-voice-clone"


def test_tricks_set_off_no_alerts(engine):
    for i in range(22):
        post(engine, reporter_id=f"r_f{i}", ip_prefix="103.21.58", scam_type="job-offer", note=own_words(i))
    for i in range(6):
        post(engine, identifier_value="+91 90000 70001", reporter_id="r_spam", ip_prefix=f"10.8.{i}",
             scam_type="lottery-prize", note=own_words(40 + i))
    for i in range(40):
        post(engine, identifier_value="+91 90000 70002", scam_type="otp-call", note="pls report this fraud number urgent")
    assert engine.alerts("560102", NOW)[1] == {"alerts": []}
    assert engine.map("560102", None, None, NOW)[1] == {"clusters": []}


# ------------------------------------------------------------------ reset and restart
def test_reset(engine):
    wave(engine, "+91 90000 00006", 4)
    engine.handle_challenge({"identifier_type": "phone", "identifier_value": "+91 90000 00006"}, NOW)
    engine.reset()
    _, r = engine.lookup("phone", "+91 90000 00006", NOW)
    assert r["verdict"] == "NO_REPORTS" and r["challenged"] is False


def test_restart_rebuilds_identically(registry):
    rows, challenges = [], []
    live = Engine(registry, salt="unit-test-salt-01")
    for i in range(5):
        live.handle_report(body(identifier_value="+91 90000 00007", note=own_words(i)), NOW, persist=rows.append)
    live.handle_report(body(identifier_value="+91 90000 00008"), NOW, persist=rows.append)
    live.handle_challenge({"identifier_type": "phone", "identifier_value": "+91 90000 00008"}, NOW,
                          persist=challenges.append)
    again = Engine(registry, salt="unit-test-salt-01")
    assert again.load(rows, challenges) == 6
    for number in ("+91 90000 00007", "+91 90000 00008"):
        assert again.lookup("phone", number, NOW) == live.lookup("phone", number, NOW)
    assert Report.from_row(rows[0]).to_row() == rows[0]


def test_salt_required(registry):
    with pytest.raises(ValueError):
        Engine(registry, salt="")
