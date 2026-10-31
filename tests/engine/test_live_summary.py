"""GET /live/summary: the live scam map's data (areas, top scam types, most reported numbers, alerts)."""
import json
from datetime import timedelta

from tests.engine.conftest import NOW, body, own_words

H = timedelta(hours=1)
D = timedelta(days=1)


def post(engine, **over):
    assert engine.handle_report(body(**over), NOW)[0] == 201


def test_empty(engine):
    st, r = engine.live_summary(NOW)
    assert st == 200 and r["areas"] == [] and r["top_types"] == [] and r["top_numbers"] == []
    assert r["alerts"] == [] and r["total"] == 0 and r["window_days"] == 7


def test_areas_types_and_known_numbers(engine):
    # three different people over three days: KNOWN_SCAM, may be shown in full
    for i, pin in enumerate(["560102", "560034", "560038"]):
        post(engine, identifier_value="+91 90000 31111", pincode=pin, note=own_words(10 + i),
             occurred_at=(NOW - (i + 1) * D).isoformat())
    # two people: SUSPICIOUS, never listed
    for i in range(2):
        post(engine, identifier_value="+91 90000 32222", scam_type="job-offer", note=own_words(20 + i),
             occurred_at=(NOW - (i + 1) * H).isoformat())
    # 10 days old: outside the 7-day window
    post(engine, identifier_value="+91 90000 33333", pincode="560066", note=own_words(30),
         occurred_at=(NOW - 10 * D).isoformat())
    st, r = engine.live_summary(NOW)
    assert st == 200
    assert [n["display_value"] for n in r["top_numbers"]] == ["+919000031111"]
    assert r["top_numbers"][0]["voices"] == 3 and r["known_numbers"] == 1
    pins = {a["pincode"]: a for a in r["areas"]}
    assert "560066" not in pins and pins["560102"]["count"] == 3
    assert {t["scam_type"] for t in r["top_types"]} == {"digital-arrest", "job-offer"}
    assert r["total"] == 5 and r["areas_active"] == 3


def test_verified_and_disputed_numbers_are_never_listed(engine):
    for i in range(40):
        post(engine, identifier_value="+91 80 4100 2233", note=own_words(100 + i),
             occurred_at=(NOW - (i % 5 + 1) * D).isoformat())
    for i in range(4):
        post(engine, identifier_value="+91 90000 34444", note=own_words(200 + i),
             occurred_at=(NOW - (i + 1) * D).isoformat())
    engine.handle_challenge({"identifier_type": "phone", "identifier_value": "+91 90000 34444"}, NOW)
    _, r = engine.live_summary(NOW)
    assert r["top_numbers"] == []


def test_fake_burst_is_not_listed_or_counted(engine):
    for i in range(11):
        post(engine, identifier_value="+91 90000 35555", note=own_words(300 + i),
             occurred_at=(NOW - (i + 1) * timedelta(minutes=5)).isoformat())
    _, r = engine.live_summary(NOW)
    assert r["top_numbers"] == [] and r["areas"] == [] and r["alerts"] == []


def test_nothing_about_reporters(engine):
    post(engine, reporter_id="r_CANARY_live", ip_prefix="10.9.8.7", note="CANARYNOTE " + own_words(1))
    text = json.dumps(engine.live_summary(NOW)[1])
    for bad in ("r_CANARY_live", "10.9.8.7", "CANARYNOTE", '"rid"', '"org"', '"note"'):
        assert bad not in text


def test_window_and_cache_follow_changes(engine):
    post(engine, identifier_value="+91 90000 36666", note=own_words(400))
    first = engine.live_summary(NOW)[1]["total"]
    post(engine, identifier_value="+91 90000 36667", note=own_words(401))
    assert engine.live_summary(NOW)[1]["total"] == first                        # cached for 10 s
    assert engine.live_summary(NOW + timedelta(seconds=11))[1]["total"] == first + 1
    assert engine.live_summary(NOW, "1")[1]["window_days"] == 1
    assert engine.live_summary(NOW + timedelta(seconds=30), "junk")[1]["window_days"] == 7
