#!/usr/bin/env python3
"""Demo script: post 3 reports, look up in 3 formats, check edge cases.

Standard library only. Usage: python tools/demo.py [BASE_URL]
"""
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"


def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def get(path):
    try:
        with urllib.request.urlopen(f"{BASE}{path}") as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def show(label, status, body):
    print(f"\n{'='*60}")
    print(f"{label}  [{status}]")
    print(json.dumps(body, indent=2))


def main():
    now = datetime.now(timezone.utc).isoformat()
    print(f"Demo against {BASE}")
    print(f"Time: {now}")

    # ── Reset first ──────────────────────────────────────────────────────
    status, body = post("/admin/reset", {})
    show("POST /admin/reset", status, body)
    assert status == 200 and body.get("ok") is True, f"reset failed: {status} {body}"

    # ── 3 reports on +91 90000 12345 from 3 different reporters ─────────
    number = "+91 90000 12345"
    reporters = [
        {"id": "demo_reporter_1", "ip": "10.1.1.0", "note": "This person called me pretending to be police and said I had a warrant"},
        {"id": "demo_reporter_2", "ip": "10.2.2.0", "note": "Received a threatening call about a fake arrest warrant from this number"},
        {"id": "demo_reporter_3", "ip": "10.3.3.0", "note": "Caller said I am under digital arrest and demanded money via UPI"},
    ]

    for i, r in enumerate(reporters, 1):
        report = {
            "report_id": f"demo_report_{i}",
            "occurred_at": now,
            "reported_at": now,
            "reporter_id": r["id"],
            "ip_prefix": r["ip"],
            "channel": "Phone call",
            "scam_type": "digital-arrest",
            "identifier_type": "phone",
            "identifier_value": number,
            "pincode": "560102",
            "note": r["note"],
        }
        status, body = post("/reports", report)
        show(f"POST /reports (reporter {i})", status, body)
        assert status == 201, f"report {i} failed: {status} {body}"

    # ── Lookup in 3 formats: same number, different shapes ──────────────
    formats = [
        ("+91 98765 43210", "+91 space format"),
        ("09876543210", "0-prefixed 11-digit"),
        ("98765-43210", "dashed format"),
    ]

    # But first look up the number we reported
    status, body = get(f"/lookup?type=phone&value=%2B91+90000+12345")
    show("Lookup +91 90000 12345 (reported number)", status, body)
    assert status == 200, f"lookup failed: {status}"

    for value, label in formats:
        encoded = urllib.request.quote(value, safe="")
        status, body = get(f"/lookup?type=phone&value={encoded}")
        show(f"Lookup '{value}' ({label})", status, body)
        assert status == 200, f"lookup failed for {value}: {status}"

    # ── Edge cases ──────────────────────────────────────────────────────
    # 12345 → 400 (not a valid phone)
    status, body = get("/lookup?type=phone&value=12345")
    show("Lookup '12345' (expect 400)", status, body)
    assert status == 400, f"expected 400 for 12345, got {status}"

    # 1930 → VERIFIED_BUSINESS (National Cybercrime Helpline)
    status, body = get("/lookup?type=phone&value=1930")
    show("Lookup '1930' (expect VERIFIED_BUSINESS)", status, body)
    assert status == 200, f"1930 lookup failed: {status}"
    assert body.get("verdict") == "VERIFIED_BUSINESS", f"expected VERIFIED_BUSINESS, got {body.get('verdict')}"

    print(f"\n{'='*60}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
