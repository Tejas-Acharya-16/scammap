"""Check live lookup normalization and latency without changing server data.

Usage: python tests/api/live_lookup_check.py https://scammap-yp1k.onrender.com
Writes the full report beside this script as LIVE_LOOKUP_CHECK.txt.
"""
from __future__ import annotations

import http.client
import json
import math
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit


VARIANTS = [
    "+91 98765 43210",
    "09876543210",
    "9876543210",
    "+91-98765-43210",
]
SAMPLES = 100
IST = timezone(timedelta(hours=5, minutes=30))


def connection_for(url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must use http or https and include a host")
    cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return cls(parsed.hostname, port, timeout=20), parsed.path.rstrip("/")


def lookup(conn: http.client.HTTPConnection, prefix: str, value: str, keep_alive: bool) -> tuple[int, dict, bool]:
    path = prefix + "/lookup?" + urlencode({"type": "phone", "value": value})
    was_disconnected = conn.sock is None
    conn.request("GET", path, headers={
        "Accept": "application/json",
        "Connection": "keep-alive" if keep_alive else "close",
    })
    response = conn.getresponse()
    raw = response.read()
    status = response.status
    data = json.loads(raw.decode("utf-8")) if raw else {}
    if not isinstance(data, dict):
        data = {}
    return status, data, was_disconnected


def percentiles(samples: list[float]) -> tuple[float, float, float]:
    ordered = sorted(samples)
    return ordered[math.ceil(0.50 * len(ordered)) - 1], ordered[math.ceil(0.95 * len(ordered)) - 1], ordered[-1]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.splitlines()[-1])
        return 2

    target = sys.argv[1].rstrip("/")
    report: list[str] = [
        "Community Scam Map live lookup check",
        f"Timestamp: {datetime.now(IST).isoformat(timespec='seconds')} IST",
        f"Target host: {urlsplit(target).hostname or 'invalid'}",
        "No data-changing requests were sent.",
        "",
    ]
    passed = True
    try:
        conn, prefix = connection_for(target)
        format_results = []
        for value in VARIANTS:
            status, body, _ = lookup(conn, prefix, value, keep_alive=False)
            format_results.append((value, status, body))
            report.append(
                f"Format {value!r}: HTTP {status}, verdict={body.get('verdict')!r}, "
                f"display_value={body.get('display_value')!r}"
            )
        conn.close()

        statuses_ok = all(status == 200 for _, status, _ in format_results)
        verdicts = {body.get("verdict") for _, _, body in format_results}
        displays = {body.get("display_value") for _, _, body in format_results}
        same_verdict = len(verdicts) == 1
        same_display = len(displays) == 1
        report.extend([
            f"All four responses HTTP 200: {'PASS' if statuses_ok else 'FAIL'}",
            f"Same verdict: {'PASS' if same_verdict else 'FAIL'}",
            f"Same display_value: {'PASS' if same_display else 'FAIL'}",
            "",
        ])
        passed &= statuses_ok and same_verdict and same_display

        fresh_conn_samples: list[float] = []
        fresh_statuses: list[int] = []
        for _ in range(SAMPLES):
            fresh, fresh_prefix = connection_for(target)
            start = time.perf_counter()
            status, _, _ = lookup(fresh, fresh_prefix, VARIANTS[0], keep_alive=False)
            fresh_conn_samples.append(time.perf_counter() - start)
            fresh_statuses.append(status)
            fresh.close()

        keep_conn, keep_prefix = connection_for(target)
        keep_samples: list[float] = []
        keep_statuses: list[int] = []
        physical_connections = 0
        try:
            for _ in range(SAMPLES):
                start = time.perf_counter()
                status, _, reconnected = lookup(keep_conn, keep_prefix, VARIANTS[0], keep_alive=True)
                keep_samples.append(time.perf_counter() - start)
                keep_statuses.append(status)
                physical_connections += int(reconnected)
        finally:
            keep_conn.close()

        for label, samples, statuses in (
            ("New connection each lookup", fresh_conn_samples, fresh_statuses),
            ("One keep-alive client", keep_samples, keep_statuses),
        ):
            p50, p95, maximum = percentiles(samples)
            report.append(
                f"{label} (n={len(samples)}): p50={p50 * 1000:.1f} ms, "
                f"p95={p95 * 1000:.1f} ms, max={maximum * 1000:.1f} ms; "
                f"HTTP 200={statuses.count(200)}/{len(statuses)}; "
                f"p95 under 500 ms={'yes' if p95 < 0.5 else 'no'}"
            )
            passed &= len(samples) == SAMPLES and all(status == 200 for status in statuses) and p95 < 0.5
        report.append(f"Keep-alive physical connections: {physical_connections} (expected 1)")
        passed &= physical_connections == 1
    except Exception as exc:  # Keep errors free of URLs, queries, and input values.
        report.append(f"CHECK ERROR: {type(exc).__name__}")
        passed = False

    report.extend(["", f"Overall: {'PASS' if passed else 'FAIL'}"])
    output = "\n".join(report) + "\n"
    Path(__file__).with_name("LIVE_LOOKUP_CHECK.txt").write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
