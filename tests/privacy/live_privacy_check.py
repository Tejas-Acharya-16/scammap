"""Send two synthetic reports and check live HTTP privacy behavior.

Usage: python tests/privacy/live_privacy_check.py https://scammap-yp1k.onrender.com
Writes the full report beside this script as LIVE_PRIVACY_CHECK.txt.
This script never calls /admin/reset.
"""
from __future__ import annotations

import http.client
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit


IST = timezone(timedelta(hours=5, minutes=30))
MASKED_FIELDS = {"pincode", "locality", "city", "count", "top_scam_type", "severity", "lat", "lng"}
NOTE = "CANARYNOTE verify request from 9123456780"
CANARIES = (
    "r_CANARY_live1",
    "r_CANARY_live2",
    "10.9.8.7",
    "CANARYNOTE",
    "9123456780",
)


def connection_for(url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must use http or https and include a host")
    cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return cls(parsed.hostname, port, timeout=20), parsed.path.rstrip("/")


def request(url: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict, str, dict]:
    conn, prefix = connection_for(url)
    payload = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, prefix + path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        text = raw.decode("utf-8", errors="replace")
        try:
            data = json.loads(text) if text else {}
        except json.JSONDecodeError:
            data = {}
        return response.status, data if isinstance(data, dict) else {}, text, dict(response.getheaders())
    finally:
        conn.close()


def lookup_value(url: str, value: str) -> tuple[int, dict, str, dict]:
    return request(url, "GET", "/lookup?" + urlencode({"type": "phone", "value": value}))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.splitlines()[-1])
        return 2

    target = sys.argv[1].rstrip("/")
    report = [
        "Community Scam Map live privacy check",
        f"Timestamp: {datetime.now(IST).isoformat(timespec='seconds')} IST",
        f"Target host: {urlsplit(target).hostname or 'invalid'}",
        "Synthetic data only. /admin/reset was not called.",
        "Raw reporter IDs, network prefix, note, and canary values are not written to this report.",
        "",
    ]
    response_texts: list[str] = []
    passed = True
    try:
        health_status, _, _, health_headers = request(target, "GET", "/health")
        date_header = next((value for key, value in health_headers.items() if key.casefold() == "date"), None)
        if health_status != 200 or not date_header:
            raise RuntimeError("health response unavailable or missing Date header")
        server_time = parsedate_to_datetime(date_header)
        if server_time.tzinfo is None:
            server_time = server_time.replace(tzinfo=timezone.utc)
        occurred_at = server_time.astimezone(IST).isoformat(timespec="seconds")

        # Find an unused identifier in the documented synthetic range, without clearing data.
        number = None
        candidate_checks = 0
        seed = (server_time.hour * 3600 + server_time.minute * 60 + server_time.second) % 90000
        for offset in range(32):
            suffix = 10000 + ((seed + offset * 7919) % 90000)
            candidate = f"+91 90000 {suffix:05d}"
            status, body, text, _ = lookup_value(target, candidate)
            candidate_checks += 1
            response_texts.append(text)
            if status == 200 and body.get("verdict") == "NO_REPORTS" and body.get("report_count", 0) == 0:
                number = candidate
                break
        if number is None:
            raise RuntimeError("no unused synthetic identifier found in 32 candidates")

        report_statuses = []
        for i, reporter_id in enumerate(("r_CANARY_live1", "r_CANARY_live2"), start=1):
            body = {
                "report_id": f"privacy-live-{uuid.uuid4().hex}",
                "occurred_at": occurred_at,
                "reporter_id": reporter_id,
                "ip_prefix": "10.9.8.7",
                "channel": "Phone call",
                "scam_type": "fake-customer-care",
                "identifier_type": "phone",
                "identifier_value": number,
                "pincode": "560102",
                "locality": "HSR Layout",
                "city": "Bengaluru",
                "note": NOTE,
                "has_screenshot": False,
                "amount_lost_inr": 0,
            }
            status, _, text, _ = request(target, "POST", "/reports", body)
            report_statuses.append(status)
            response_texts.append(text)
            report.append(f"Synthetic report {i}: HTTP {status}")
        passed &= report_statuses == [201, 201]
        report.append(f"Unused-number candidates checked: {candidate_checks}")

        lookup_status, lookup_body, lookup_text, _ = lookup_value(target, number)
        response_texts.append(lookup_text)
        digits = "".join(ch for ch in number if ch.isdigit())
        display = str(lookup_body.get("display_value") or "")
        display_digits = "".join(ch for ch in display if ch.isdigit())
        masked = digits not in display_digits and lookup_body.get("distinct_reporters", 99) <= 2
        report.append(
            f"Lookup: HTTP {lookup_status}; report_count={lookup_body.get('report_count')}; "
            f"distinct_reporters={lookup_body.get('distinct_reporters')}; masked with at most 2 reporters={'PASS' if masked else 'FAIL'}"
        )
        passed &= lookup_status == 200 and masked

        map_status, map_body, map_text, _ = request(target, "GET", "/map?days=7")
        response_texts.append(map_text)
        clusters = map_body.get("clusters") if isinstance(map_body.get("clusters"), list) else []
        map_fields_ok = all(isinstance(cluster, dict) and set(cluster).issubset(MASKED_FIELDS) for cluster in clusters)
        report.append(
            f"Map: HTTP {map_status}; clusters={len(clusters)}; "
            f"area-level fields only={'PASS' if map_fields_ok else 'FAIL'}"
        )
        passed &= map_status == 200 and map_fields_ok

        alerts_status, alerts_body, alerts_text, _ = request(target, "GET", "/alerts")
        response_texts.append(alerts_text)
        report.append(f"Alerts: HTTP {alerts_status}; alerts={len(alerts_body.get('alerts', [])) if isinstance(alerts_body.get('alerts', []), list) else 'invalid'}")
        passed &= alerts_status == 200 and isinstance(alerts_body.get("alerts", []), list)

        all_responses = response_texts
        identifier_canaries = (number, number.replace(" ", ""), number.split(" ", 1)[-1].replace(" ", ""))
        leaked = [value for value in (*CANARIES, *identifier_canaries) if any(value.casefold() in text.casefold() for text in all_responses)]
        # Also check the normalized display field without scanning unrelated response digits.
        number_leaked = digits in display_digits
        no_canaries = not leaked and not number_leaked
        report.append(f"Canary values absent from every response: {'PASS' if no_canaries else 'FAIL'}")
        passed &= no_canaries
        if leaked:
            report.append(f"Leaked canary categories: {len(leaked)} (values withheld)")
        if number_leaked:
            report.append("Full synthetic identifier appeared in a response (value withheld).")
    except Exception as exc:  # Do not echo request bodies, query strings, or canary values.
        report.append(f"CHECK ERROR: {type(exc).__name__}")
        passed = False

    report.extend(["", f"Overall: {'PASS' if passed else 'FAIL'}"])
    output = "\n".join(report) + "\n"
    Path(__file__).with_name("LIVE_PRIVACY_CHECK.txt").write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
