"""Privacy canaries (BUILD_SPEC section 10, AT-4.1 engine part). Any failure here is a
disqualification risk: a reporter must never be identifiable from what we store or return."""
import json
from datetime import timedelta

from app.engine import Engine
from tests.engine.conftest import NOW, body

CANARY_REPORTER = "r_CANARY1"
CANARY_PREFIX = "10.9.8.7"
CANARY_NOTE = "CANARYNOTE my own number is 9876501234 call me at home Koramangala 4th block"
FORBIDDEN = [CANARY_REPORTER, "CANARY1", CANARY_PREFIX, "10.9.8", "CANARYNOTE", "canarynote", "9876501234",
             "Koramangala 4th block", "koramangala"]


def _dump(obj) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)


def test_canaries_never_stored_or_returned(registry):
    rows = []
    e = Engine(registry, salt="privacy-test-salt")
    for i in range(4):
        e.handle_report(body(identifier_value="+91 90000 88888", reporter_id=CANARY_REPORTER if i == 0 else f"r_x{i}",
                             ip_prefix=CANARY_PREFIX if i == 0 else f"10.1.{i}", note=CANARY_NOTE if i == 0 else f"words {i} " * 4,
                             occurred_at=(NOW - timedelta(hours=i + 1)).isoformat()),
                        NOW, client_ip="10.9.8.99", persist=rows.append)
    stored = _dump(rows)
    replies = _dump([e.lookup("phone", "+91 90000 88888", NOW), e.map(None, None, None, NOW),
                     e.alerts("560102", NOW), e.stats()])
    internal = _dump([vars(r) for reports in e._reports.values() for r in reports])
    for text in (stored, replies, internal):
        for bad in FORBIDDEN:
            assert bad not in text, bad
    assert "rid" not in replies and "org" not in replies and "note" not in replies


def test_reply_keys_are_aggregate_only(registry):
    e = Engine(registry, salt="privacy-test-salt")
    for i in range(3):
        e.handle_report(body(identifier_value="+91 90000 77777", note=f"distinct note number {i} " * 3), NOW)
    _, r = e.lookup("phone", "+91 90000 77777", NOW)
    assert set(r) <= {"verdict", "report_count", "distinct_reporters", "first_seen", "last_seen", "scam_type",
                      "display_value", "evidence", "challenged", "type", "label", "trust", "ai_watchdog"}
    for item in r["evidence"]:
        assert set(item) == {"occurred_at", "channel", "scam_type", "pincode"}
    # The AI watchdog's opinion (added 1 Nov): a score, a level and phrases from a fixed list only.
    from app.engine.watchdog import SIGNALS
    a = r["ai_watchdog"]
    assert set(a) == {"coordinated", "level", "signals", "signal_codes", "model", "advisory"}
    assert set(a["signals"]) <= {p for pair in SIGNALS.values() for p in pair}
    assert "distinct note" not in _dump(a)


def test_hashes_depend_on_the_secret_salt(registry):
    a = Engine(registry, salt="salt-number-one").prepare(body(reporter_id="r_same", ip_prefix="1.2.3"), NOW).report
    b = Engine(registry, salt="salt-number-two").prepare(body(reporter_id="r_same", ip_prefix="1.2.3"), NOW).report
    assert a.rid != b.rid and a.org != b.org and len(a.rid) == 32


def test_no_location_finer_than_area(registry):
    row = Engine(registry, salt="privacy-test-salt").prepare(
        body(locality="Flat 4B, 12th Cross", city="Bengaluru", lat=12.91, lng=77.64), NOW).report.to_row()
    assert set(row) == {"report_id", "identifier_type", "identifier", "occurred_at", "reported_at", "received_at",
                        "rid", "org", "channel", "scam_type", "scam_type_key", "pincode", "note_hash", "shingles",
                        "ntok", "has_screenshot", "amount_lost_inr"}
    assert "Flat" not in _dump(row) and "12.91" not in _dump(row)
