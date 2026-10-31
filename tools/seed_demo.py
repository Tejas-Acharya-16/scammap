#!/usr/bin/env python3
"""Seed demo dataset for Community Scam Map video and demonstrations.

Standard library only.
Usage: python tools/seed_demo.py [BASE_URL]
"""
import json
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"


def post_report(base_url: str, report: dict) -> dict:
    data = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/reports",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


# Note generator ensuring distinct phrasing for each report (>= 3 words)
NOTE_TEMPLATES = [
    "Pretended to be courier delivery agent demanding customs penalty of {amt}",
    "Threatened with immediate digital arrest over fake police warrant call",
    "Sent bogus refund link claiming electricity power will disconnect tonight",
    "Demanded transfer for unpaid road challan before legal action initiated",
    "Impersonated credit card security division asking to verify recent transaction",
    "Posed as income tax official requiring urgent verification fine transfer",
    "Fake parcel detained at airport terminal asking clearance service charge",
    "Demanded instant settlement payment via UPI or warned of bank freeze",
    "Unsolicited job offer asking initial security deposit before joining",
    "Claimed high yield part time task earning with upfront training fee",
    "Urgent notification to submit KYC documents on unfamiliar website portal",
    "Fraudulent lottery prize message requiring processing tax prepayment",
]


class ReporterPool:
    def __init__(self):
        self.counter = 0

    def next_reporter(self):
        self.counter += 1
        a = (self.counter // 250) + 1
        b = (self.counter % 250) + 1
        note_tpl = NOTE_TEMPLATES[(self.counter - 1) % len(NOTE_TEMPLATES)]
        note = note_tpl.format(amt=f"Rs {1500 + (self.counter * 170) % 9000}")
        return {
            "reporter_id": f"r_demo_{self.counter}",
            "ip_prefix": f"10.{a}.{b}",
            "note": f"{note} (case ref {self.counter})",
        }


def make_random_phone(used_numbers: set) -> str:
    while True:
        num = f"+91 90000 {random.randint(10000, 99999)}"
        if num not in used_numbers:
            used_numbers.add(num)
            return num


def main():
    now = datetime.now(IST)
    print(f"Seeding demo data to: {BASE}")
    print(f"Reference time (IST): {now.isoformat()}")

    pool = ReporterPool()
    used_phones = set()
    report_count = 0

    # Summary list of targets to print at the end
    targets = []

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Three numbers with 5 reports each over the last 5 days
    #    (HSR Layout: 560102, Koramangala: 560034, Indiranagar: 560038)
    #    Expected: KNOWN_SCAM
    # ──────────────────────────────────────────────────────────────────────────
    areas = [
        ("560102", "HSR Layout", "digital-arrest"),
        ("560034", "Koramangala", "courier-customs"),
        ("560038", "Indiranagar", "fake-kyc-link"),
    ]

    for pincode, area_name, scam_type in areas:
        phone = make_random_phone(used_phones)
        targets.append({
            "type": "phone",
            "value": phone,
            "verdict": "KNOWN_SCAM",
            "reason": f"5 distinct reporters in {area_name} ({pincode}) over 5 days",
        })
        for day in range(5):
            rep = pool.next_reporter()
            occurred = (now - timedelta(days=4 - day, hours=random.randint(1, 10))).isoformat()
            payload = {
                "report_id": f"rep_ks_{pincode}_{day}",
                "occurred_at": occurred,
                "reported_at": occurred,
                "reporter_id": rep["reporter_id"],
                "ip_prefix": rep["ip_prefix"],
                "channel": "Phone call",
                "scam_type": scam_type,
                "identifier_type": "phone",
                "identifier_value": phone,
                "pincode": pincode,
                "note": rep["note"],
            }
            post_report(BASE, payload)
            report_count += 1

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Two numbers each reported by 2 people (stays SUSPICIOUS, masked)
    # ──────────────────────────────────────────────────────────────────────────
    for i in range(2):
        phone = make_random_phone(used_phones)
        targets.append({
            "type": "phone",
            "value": phone,
            "verdict": "SUSPICIOUS (masked)",
            "reason": "Only 2 reports, below the 3-voice threshold",
        })
        for r_idx in range(2):
            rep = pool.next_reporter()
            occurred = (now - timedelta(days=r_idx + 1, hours=3)).isoformat()
            payload = {
                "report_id": f"rep_susp_{i}_{r_idx}",
                "occurred_at": occurred,
                "reported_at": occurred,
                "reporter_id": rep["reporter_id"],
                "ip_prefix": rep["ip_prefix"],
                "channel": "Phone call",
                "scam_type": "lottery-prize",
                "identifier_type": "phone",
                "identifier_value": phone,
                "pincode": "560102",
                "note": rep["note"],
            }
            post_report(BASE, payload)
            report_count += 1

    # ──────────────────────────────────────────────────────────────────────────
    # 3. One UPI ID and one .example link, each reported by 3 people on different days
    #    Expected: KNOWN_SCAM
    # ──────────────────────────────────────────────────────────────────────────
    upi_id = f"refund.agent{random.randint(100, 999)}@okaxis"
    targets.append({
        "type": "upi",
        "value": upi_id,
        "verdict": "KNOWN_SCAM",
        "reason": "3 distinct reporters on different days",
    })
    for day in range(3):
        rep = pool.next_reporter()
        occurred = (now - timedelta(days=2 - day, hours=2)).isoformat()
        payload = {
            "report_id": f"rep_upi_{day}",
            "occurred_at": occurred,
            "reported_at": occurred,
            "reporter_id": rep["reporter_id"],
            "ip_prefix": rep["ip_prefix"],
            "channel": "UPI request",
            "scam_type": "upi-refund-qr",
            "identifier_type": "upi",
            "identifier_value": upi_id,
            "pincode": "560034",
            "note": rep["note"],
        }
        post_report(BASE, payload)
        report_count += 1

    url_target = f"https://kyc-update-portal{random.randint(10, 99)}.example/verify"
    targets.append({
        "type": "url",
        "value": url_target,
        "verdict": "KNOWN_SCAM",
        "reason": "3 distinct reporters on different days",
    })
    for day in range(3):
        rep = pool.next_reporter()
        occurred = (now - timedelta(days=2 - day, hours=4)).isoformat()
        payload = {
            "report_id": f"rep_url_{day}",
            "occurred_at": occurred,
            "reported_at": occurred,
            "reporter_id": rep["reporter_id"],
            "ip_prefix": rep["ip_prefix"],
            "channel": "SMS or WhatsApp",
            "scam_type": "fake-kyc-link",
            "identifier_type": "url",
            "identifier_value": url_target,
            "pincode": "560038",
            "note": rep["note"],
        }
        post_report(BASE, payload)
        report_count += 1

    # ──────────────────────────────────────────────────────────────────────────
    # 4. In 560102: 2 digital-arrest reports a day for the past 7 days on different numbers,
    #    then 8 today -> triggers SPIKE alert in 560102
    # ──────────────────────────────────────────────────────────────────────────
    # Past 7 days baseline: days 7..1 (2 reports/day = 14 total baseline, baseline/day = 2.0)
    for day_offset in range(1, 8):
        for rep_slot in range(2):
            spike_phone = make_random_phone(used_phones)
            rep = pool.next_reporter()
            occurred = (now - timedelta(days=day_offset, hours=rep_slot * 4 + 2)).isoformat()
            payload = {
                "report_id": f"rep_spike_base_{day_offset}_{rep_slot}",
                "occurred_at": occurred,
                "reported_at": occurred,
                "reporter_id": rep["reporter_id"],
                "ip_prefix": rep["ip_prefix"],
                "channel": "Phone call",
                "scam_type": "digital-arrest",
                "identifier_type": "phone",
                "identifier_value": spike_phone,
                "pincode": "560102",
                "note": rep["note"],
            }
            post_report(BASE, payload)
            report_count += 1

    # Today: 8 reports within the last 12 hours (count >= 5 and count >= 2 * baseline)
    for rep_slot in range(8):
        spike_phone = make_random_phone(used_phones)
        rep = pool.next_reporter()
        occurred = (now - timedelta(hours=1 + rep_slot)).isoformat()
        payload = {
            "report_id": f"rep_spike_today_{rep_slot}",
            "occurred_at": occurred,
            "reported_at": occurred,
            "reporter_id": rep["reporter_id"],
            "ip_prefix": rep["ip_prefix"],
            "channel": "Phone call",
            "scam_type": "digital-arrest",
            "identifier_type": "phone",
            "identifier_value": spike_phone,
            "pincode": "560102",
            "note": rep["note"],
        }
        post_report(BASE, payload)
        report_count += 1

    # ──────────────────────────────────────────────────────────────────────────
    # 5. One job-offer report today in 560034 -> triggers NEW_TYPE alert
    # ──────────────────────────────────────────────────────────────────────────
    new_type_phone = make_random_phone(used_phones)
    rep = pool.next_reporter()
    occurred = (now - timedelta(hours=2)).isoformat()
    payload = {
        "report_id": "rep_new_type_job_0",
        "occurred_at": occurred,
        "reported_at": occurred,
        "reporter_id": rep["reporter_id"],
        "ip_prefix": rep["ip_prefix"],
        "channel": "SMS or WhatsApp",
        "scam_type": "job-offer",
        "identifier_type": "phone",
        "identifier_value": new_type_phone,
        "pincode": "560034",
        "note": rep["note"],
    }
    post_report(BASE, payload)
    report_count += 1

    print(f"\nSuccessfully seeded {report_count} reports into {BASE}")
    print("\nTarget Identifiers & Expected Verdicts:")
    print("=" * 70)
    for t in targets:
        print(f"[{t['type'].upper():5}] {t['value']}")
        print(f"        Expected: {t['verdict']}")
        print(f"        Reason:   {t['reason']}")
    print("=" * 70)
    print("Expected Alerts:")
    print("  - Pincode 560102 (HSR Layout): SPIKE alert (8 reports today vs 2.0/day baseline)")
    print("  - Pincode 560034 (Koramangala): NEW_TYPE alert (scam_type: job-offer)")
    print("=" * 70)


if __name__ == "__main__":
    main()
