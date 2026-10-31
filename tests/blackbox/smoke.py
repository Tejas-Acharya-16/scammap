"""Black-box check of a running server against the brief's API rules (BUILD_SPEC section 3).
Standard library only, so it runs anywhere Python does.

    python -m tests.blackbox.smoke URL                  read-only checks, safe on the live server
    python -m tests.blackbox.smoke URL --write          also posts synthetic reports, then POST /admin/reset
                                                        (deletes every report on that server)
    python -m tests.blackbox.smoke URL --licence licenses/expired.json licenses/long.json
                                                        the licence cycle with no restart (row 5)
Exit code 0 only when every check passes. Synthetic numbers only (+91 90000 xxxxx).
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

IST = timezone(timedelta(hours=5, minutes=30))
ROOT = Path(__file__).resolve().parents[2]
RESULTS = []


def call(base, method, path, body=None, timeout=60):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    headers = {"content-type": "application/json"} if data is not None else {}
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    ms = (time.perf_counter() - t0) * 1000
    try:
        js = json.loads(raw or b"null")
    except ValueError:
        js = None
    return status, js, ms


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))


def q(**kw):
    return "?" + urllib.parse.urlencode(kw)


def report(number, rid, prefix, note, pin="560102", typ="digital-arrest", hours_ago=1.0):
    now = datetime.now(IST)
    return {"report_id": "rep_" + uuid.uuid4().hex[:12],
            "occurred_at": (now - timedelta(hours=hours_ago)).isoformat(timespec="seconds"),
            "reported_at": now.isoformat(timespec="seconds"), "reporter_id": rid, "ip_prefix": prefix,
            "channel": "Phone call", "scam_type": typ, "identifier_type": "phone", "identifier_value": number,
            "pincode": pin, "locality": "HSR Layout", "city": "Bengaluru", "note": note,
            "has_screenshot": False, "amount_lost_inr": 0}


def read_only(base):
    print("Read-only checks")
    s, js, ms = call(base, "GET", "/health")
    check("GET /health is 200 {\"ok\": true}", s == 200 and js == {"ok": True}, f"{s} {js}")
    s, js, _ = call(base, "GET", "/license")
    check("GET /license shows who and until when", s == 200 and isinstance(js, dict) and "licensee" in js and "expires_at" in js, f"{s} {js}")
    forms = ["+91 98765 43210", "09876543210", "98765-43210", "919876543210"]
    bodies = [call(base, "GET", "/lookup" + q(type="phone", value=f))[1] for f in forms]
    check("4 ways of typing one number give the same answer", all(b == bodies[0] for b in bodies), str(bodies[0])[:120])
    b = bodies[0] or {}
    need = {"verdict", "report_count", "distinct_reporters", "first_seen", "last_seen", "scam_type", "display_value", "evidence", "challenged"}
    check("lookup reply has every field from the brief", need <= set(b), f"missing {need - set(b)}")
    check("verdict is one of the four exact strings", b.get("verdict") in {"KNOWN_SCAM", "SUSPICIOUS", "NO_REPORTS", "VERIFIED_BUSINESS"}, str(b.get("verdict")))
    unused = "+91 90000 " + "".join(random.choice("0123456789") for _ in range(5))
    s, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=unused))
    check("unreported number is 200 NO_REPORTS (not 404)", s == 200 and js and js.get("verdict") == "NO_REPORTS", f"{s} {js}")
    check("unreported number is masked like 90XXXXX...", js and str(js.get("display_value", "")).startswith("90XXXXX"), str(js and js.get("display_value")))
    for bad in ["12345", "test"]:
        s, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=bad))
        check(f"lookup of junk {bad!r} is 400 with an error code", s == 400 and isinstance(js, dict) and "error" in js, f"{s} {js}")
        check(f"error for {bad!r} does not echo the input", bad not in json.dumps(js or {}), f"{js}")
    s, js, _ = call(base, "GET", "/lookup" + q(type="fax", value="1"))
    check("unknown identifier type is 400", s == 400, f"{s} {js}")
    verified = json.loads((ROOT / "app" / "data" / "verified.json").read_text(encoding="utf-8"))
    bad = []
    for e in verified:
        s, js, _ = call(base, "GET", "/lookup" + q(type=e["type"], value=e["value"]))
        dv = str((js or {}).get("display_value", "XXXXX*"))
        if not (s == 200 and js.get("verdict") == "VERIFIED_BUSINESS" and "XXXXX" not in dv and "*" not in dv):
            bad.append((e["value"], s, js and js.get("verdict")))
    check(f"all {len(verified)} verified values say VERIFIED_BUSINESS, unmasked", not bad, str(bad[:3]))
    s, js, _ = call(base, "GET", "/map" + q(pincode="560102"))
    ok = s == 200 and isinstance(js, dict) and isinstance(js.get("clusters"), list)
    keys = {"pincode", "locality", "city", "count", "top_scam_type", "severity", "lat", "lng"}
    check("GET /map gives {clusters: [...]} with the brief's fields", ok and all(keys <= set(c) for c in js["clusters"]), f"{s} {str(js)[:120]}")
    s, js, _ = call(base, "GET", "/map")
    check("GET /map without a pincode is 200", s == 200, f"{s}")
    s, js, _ = call(base, "GET", "/map" + q(pincode="12ab"))
    check("malformed pincode on /map is 400", s == 400, f"{s} {js}")
    s, js, _ = call(base, "GET", "/alerts" + q(pincode="560102"))
    check("GET /alerts gives {alerts: [...]}", s == 200 and isinstance(js, dict) and isinstance(js.get("alerts"), list), f"{s} {js}")
    s, js, _ = call(base, "GET", "/no-such-route")
    check("unknown route is 404 with a JSON body", s == 404 and isinstance(js, dict), f"{s} {js}")
    s, js, _ = call(base, "POST", "/health", {})
    check("wrong method is 405 with a JSON body", s == 405 and isinstance(js, dict), f"{s} {js}")
    times = [call(base, "GET", "/lookup" + q(type="phone", value="+91 98765 43210"))[2] for _ in range(20)]
    p95 = sorted(times)[18]
    check(f"20 lookups: p50 {statistics.median(times):.0f} ms, p95 {p95:.0f} ms (under 500)", p95 < 500, f"p95 {p95:.0f} ms")


def writes(base):
    print("Write checks (synthetic data; ends with POST /admin/reset)")
    tag = random.randint(10000, 99999)
    n1, n2, n3 = f"+91 90000 {tag:05d}", f"+91 90001 {tag:05d}", f"+91 90002 {tag:05d}"
    s, js, _ = call(base, "POST", "/reports", report(n1, "r_smoke_a", "10.11.1", "fake police video call asked for money urgently"))
    check("valid report is 201 {report_id, case_id, merged}", s == 201 and isinstance(js, dict) and {"report_id", "case_id", "merged"} <= set(js) and js["merged"] is False, f"{s} {js}")
    case1 = js and js.get("case_id")
    s, js, _ = call(base, "POST", "/reports", report(n1.replace(" ", ""), "r_smoke_b", "10.11.2", "my father got the same police uniform video call today"))
    check("second report on the same number merges into the same case", s == 201 and js.get("merged") is True and js.get("case_id") == case1, f"{s} {js}")
    for field, value in [("identifier_value", "12345"), ("identifier_value", "test"), ("pincode", "000000"), ("occurred_at", "yesterday")]:
        body = report(n2, "r_smoke_j", "10.11.3", "junk")
        body[field] = value
        s, js, _ = call(base, "POST", "/reports", body)
        check(f"junk {field}={value!r} is 400 {{error}}", s == 400 and isinstance(js, dict) and "error" in js, f"{s} {js}")
    s, js, _ = call(base, "POST", "/reports", b"{not json")
    check("broken JSON body is 400, not 422", s == 400, f"{s} {js}")
    for i in range(6):
        call(base, "POST", "/reports", report(n2, "r_smoke_spam", f"10.12.{i}", f"spamming the same number again and again round {i}"))
    _, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=n2))
    check("one person x6: distinct_reporters 1, report_count 6, not KNOWN_SCAM",
          js and js.get("distinct_reporters") == 1 and js.get("report_count") == 6 and js.get("verdict") != "KNOWN_SCAM", f"{js}")
    check("under 3 people the number stays masked", js and "XXXXX" in str(js.get("display_value")), f"{js and js.get('display_value')}")
    for i, note in enumerate(["video call from a man in police uniform demanding money",
                              "said a parcel with drugs was in my name and asked me to pay",
                              "fake cyber cell officer kept me on call for two hours"]):
        call(base, "POST", "/reports", report(n3, f"r_smoke_real{i}", f"10.13.{i}", note, hours_ago=2 + i))
    _, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=n3))
    check("3 different people in their own words: KNOWN_SCAM", js and js.get("verdict") == "KNOWN_SCAM", f"{js}")
    check("after 3 people the number is shown in full", js and js.get("display_value") == "+91" + n3.replace(" ", "")[3:], f"{js and js.get('display_value')}")
    ev = (js or {}).get("evidence") or []
    check("evidence has only time, channel, type and area", ev and all(set(e) <= {"occurred_at", "channel", "scam_type", "pincode"} for e in ev), f"{ev[:1]}")
    canary = report(n1, "r_CANARY_9", "10.9.8", "CANARYNOTE call me on 9876501234")
    call(base, "POST", "/reports", canary)
    blob = json.dumps([call(base, "GET", p)[1] for p in ["/lookup" + q(type="phone", value=n1), "/map", "/alerts" + q(pincode="560102")]])
    check("privacy: reporter ID, network and note never come back", not any(x in blob for x in ["r_CANARY_9", "10.9.8", "CANARYNOTE", "9876501234"]))
    s, js, _ = call(base, "POST", "/challenges", {"identifier_type": "phone", "identifier_value": n3, "claimant_name": "Test Shop",
                                                  "contact_email": "owner@example.com", "proof_note": "test"})
    check("POST /challenges is 201 under_review", s == 201 and js.get("status") == "under_review" and "challenge_id" in js, f"{s} {js}")
    _, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=n3))
    check("disputed number: challenged true, never KNOWN_SCAM", js and js.get("challenged") is True and js.get("verdict") != "KNOWN_SCAM", f"{js}")
    s, js, _ = call(base, "POST", "/admin/reset", {})
    check("POST /admin/reset is 200", s == 200, f"{s} {js}")
    _, js, _ = call(base, "GET", "/lookup" + q(type="phone", value=n3))
    check("after reset the number is NO_REPORTS again", js and js.get("verdict") == "NO_REPORTS", f"{js}")


def licence_cycle(base, expired_path, long_path):
    print("Licence cycle (row 5): no restart allowed")
    exp, lng = Path(expired_path).read_bytes(), Path(long_path).read_bytes()
    s, js, _ = call(base, "POST", "/license", exp)
    check("POST an expired licence is accepted", s == 200, f"{s} {js}")
    s, js, _ = call(base, "GET", "/lookup" + q(type="phone", value="1930"))
    check("lookup now 403 {\"error\": \"LICENSE_EXPIRED\"}", s == 403 and js == {"error": "LICENSE_EXPIRED"}, f"{s} {js}")
    for path in ["/map", "/alerts?pincode=560102"]:
        s, js, _ = call(base, "GET", path)
        check(f"GET {path} also 403 while expired", s == 403, f"{s} {js}")
    s, js, _ = call(base, "GET", "/health")
    check("/health still 200 while expired", s == 200, f"{s}")
    s, js, _ = call(base, "GET", "/license")
    check("/license still answers while expired", s == 200, f"{s} {js}")
    t0 = time.perf_counter()
    s, js, _ = call(base, "POST", "/license", lng)
    check("POST the long licence is accepted", s == 200, f"{s} {js}")
    s, js, _ = call(base, "GET", "/lookup" + q(type="phone", value="1930"))
    check(f"lookup works again with no restart ({(time.perf_counter() - t0):.1f} s)", s == 200 and js.get("verdict") == "VERIFIED_BUSINESS", f"{s} {js}")
    s, js, _ = call(base, "POST", "/license", b'{"licensee":"Demo Bank","expires_at":"2099-01-01T00:00:00+05:30","signature":"AAAA"}')
    check("a licence with a forged date is refused with 400", s == 400, f"{s} {js}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--write", action="store_true", help="post synthetic reports, then POST /admin/reset")
    ap.add_argument("--licence", nargs=2, metavar=("EXPIRED_JSON", "LONG_JSON"))
    a = ap.parse_args(argv)
    base = a.url.rstrip("/")
    print(f"Target: {base}  ({datetime.now(IST):%H:%M:%S} IST)")
    s, _, ms = call(base, "GET", "/health", timeout=120)
    print(f"  (first request {ms:.0f} ms; a sleeping free server can take a minute)")
    read_only(base)
    if a.write:
        writes(base)
    if a.licence:
        licence_cycle(base, *a.licence)
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed" + ("" if not failed else "\nFAILED:\n  " + "\n  ".join(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
