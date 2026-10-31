"""Run the one-shot synthetic live report load and save its full transcript.

Usage: python tests/api/live_bulk_load.py

Sends exactly 2,000 POST /reports requests, with at most 16 in flight and no
retries. A lookup probe runs every 0.5 seconds during the upload. Never resets
the server. Results are saved to LIVE_BULK_LOAD.txt next to this script.
"""
from __future__ import annotations

import argparse
import asyncio
import math
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx


IST = timezone(timedelta(hours=5, minutes=30))
TARGET = "https://scammap-yp1k.onrender.com"
REPORT_COUNT = 2_000
CONCURRENCY = 16
TIMEOUT_SECONDS = 30.0
POLL_SECONDS = 0.5
PHONE_BASE = "+91 90000 10000"
WORDS = (
    "parcel", "payment", "verify", "tracking", "update", "secure", "account",
    "delivery", "refund", "alert", "review", "message", "support", "service",
    "confirm", "notice",
)


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct * len(ordered)) - 1)]


def synthetic_note(index: int) -> str:
    """Build a unique five-word note using only the fixed harmless word list."""
    value = index
    selected: list[str] = []
    for _ in range(5):
        selected.append(WORDS[value % len(WORDS)])
        value //= len(WORDS)
    return " ".join(selected)


def report_payload(index: int, occurred_at: str) -> dict[str, object]:
    suffix = 10_000 + index
    third_octet = index // 250
    fourth_octet = index % 250 + 1
    return {
        "report_id": f"bulk-load-{index + 1:04d}",
        "occurred_at": occurred_at,
        "reported_at": occurred_at,
        "reporter_id": f"r_bulk_{index + 1}",
        "ip_prefix": f"10.77.{third_octet}.{fourth_octet}",
        "channel": "SMS or WhatsApp",
        "scam_type": "digital-arrest",
        "identifier_type": "phone",
        "identifier_value": f"+91 90000 {suffix:05d}",
        "pincode": "560102",
        "note": synthetic_note(index),
        "has_screenshot": False,
        "amount_lost_inr": 0,
    }


def server_time_from_headers(headers: httpx.Headers) -> datetime:
    date_header = headers.get("date")
    if not date_header:
        raise RuntimeError("GET /health had no Date header; refusing to start load")
    value = parsedate_to_datetime(date_header)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


async def run(target: str, expected_commit: str) -> int:
    host = urlsplit(target).hostname
    if host != "scammap-yp1k.onrender.com":
        raise ValueError("Refusing to send the live load to an unexpected host")

    timeout = httpx.Timeout(TIMEOUT_SECONDS)
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False) as client:
        health = await client.get(target + "/health")
        if health.status_code != 200:
            raise RuntimeError(f"GET /health returned HTTP {health.status_code}; refusing to start load")
        commit = health.headers.get("x-commit", "")
        if commit != expected_commit:
            raise RuntimeError(
                f"GET /health X-Commit did not match expected {expected_commit}; refusing to start load"
            )
        occurred_at = server_time_from_headers(health.headers).astimezone(IST).isoformat(timespec="seconds")

        statuses: list[int | None] = [None] * REPORT_COUNT
        elapsed: list[float | None] = [None] * REPORT_COUNT
        errors: list[str | None] = [None] * REPORT_COUNT
        lookup_latencies: list[float] = []
        lookup_statuses: list[int | str] = []
        started = time.perf_counter()

        async def post_one(index: int) -> None:
            began = time.perf_counter()
            try:
                response = await client.post(target + "/reports", json=report_payload(index, occurred_at))
                statuses[index] = response.status_code
                elapsed[index] = time.perf_counter() - began
                await response.aread()
            except (httpx.TimeoutException, asyncio.TimeoutError):
                elapsed[index] = time.perf_counter() - began
                errors[index] = "timeout"
            except httpx.HTTPError as exc:
                elapsed[index] = time.perf_counter() - began
                errors[index] = type(exc).__name__

        async def upload() -> None:
            semaphore = asyncio.Semaphore(CONCURRENCY)

            async def bounded(index: int) -> None:
                async with semaphore:
                    await post_one(index)

            await asyncio.gather(*(bounded(index) for index in range(REPORT_COUNT)))

        async def poll_lookups(upload_task: asyncio.Task[None]) -> None:
            lookup_url = target + "/lookup?" + urlencode({"type": "phone", "value": PHONE_BASE})
            while not upload_task.done():
                poll_start = time.perf_counter()
                try:
                    response = await client.get(lookup_url)
                    await response.aread()
                    lookup_statuses.append(response.status_code)
                except (httpx.TimeoutException, asyncio.TimeoutError):
                    lookup_statuses.append("timeout")
                except httpx.HTTPError as exc:
                    lookup_statuses.append(type(exc).__name__)
                lookup_latencies.append(time.perf_counter() - poll_start)
                delay = POLL_SECONDS - (time.perf_counter() - poll_start)
                if delay > 0 and not upload_task.done():
                    await asyncio.sleep(delay)

        upload_task = asyncio.create_task(upload())
        await poll_lookups(upload_task)
        await upload_task
        duration = time.perf_counter() - started

    status_values = [status for status in statuses if status is not None]
    post_timeouts = sum(error == "timeout" for error in errors)
    transport_errors = sum(error is not None and error != "timeout" for error in errors)
    count_201 = sum(status == 201 for status in status_values)
    count_429 = sum(status == 429 for status in status_values)
    count_5xx = sum(status is not None and 500 <= status < 600 for status in status_values)
    timestamp = datetime.now(IST).isoformat(timespec="seconds")
    lines = [
        f"{timestamp} IST | X-Commit: {commit} | synthetic data, our generator",
        "Community Scam Map live bulk-load run",
        f"Target: {TARGET}/reports",
        f"Configuration: reports={REPORT_COUNT}; concurrency={CONCURRENCY}; per-request timeout={TIMEOUT_SECONDS:.0f}s; retries=0",
        "No /admin/reset call was made. Identifiers, reporter IDs, IP prefixes, and notes are synthetic.",
        "Notes are generated only from the fixed harmless word list in live_bulk_load.py.",
        f"Upload duration: {duration:.3f}s",
        f"POST totals: attempted={REPORT_COUNT}; responses={len(status_values)}; 201={count_201}; 429={count_429}; 5xx={count_5xx}; timeouts={post_timeouts}; other transport errors={transport_errors}",
        f"Other HTTP statuses: {sum(status not in (201, 429) and not (500 <= status < 600) for status in status_values)}",
        f"Lookup probe: interval={POLL_SECONDS:.1f}s; samples={len(lookup_latencies)}; HTTP 200={sum(status == 200 for status in lookup_statuses)}; non-200 or errors={len(lookup_statuses) - sum(status == 200 for status in lookup_statuses)}",
    ]
    for label, value in (("p50", percentile(lookup_latencies, 0.50)), ("p95", percentile(lookup_latencies, 0.95)), ("max", max(lookup_latencies) if lookup_latencies else None)):
        lines.append(f"Lookup latency {label}: {'n/a' if value is None else f'{value * 1000:.2f} ms'} (all completed probe requests)")
    lines.extend(["", "Per-report outcomes (request index | HTTP status or error | elapsed ms):"])
    for index in range(REPORT_COUNT):
        state = str(statuses[index]) if statuses[index] is not None else (errors[index] or "no response")
        took = 0.0 if elapsed[index] is None else elapsed[index] * 1000
        lines.append(f"{index + 1:04d} | {state} | {took:.2f}")
    lines.extend(["", "Lookup samples (index | status | elapsed ms):"])
    for index, (latency, status) in enumerate(zip(lookup_latencies, lookup_statuses), start=1):
        lines.append(f"{index:04d} | {status} | {latency * 1000:.2f}")
    output = "\n".join(lines) + "\n"
    output_path = Path(__file__).with_name("LIVE_BULK_LOAD.txt")
    output_path.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if count_201 == REPORT_COUNT and count_429 == 0 and count_5xx == 0 and post_timeouts == 0 and transport_errors == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=TARGET)
    parser.add_argument("--expected-commit", default="b675ed6")
    args = parser.parse_args()
    try:
        return asyncio.run(run(args.base_url.rstrip("/"), args.expected_commit))
    except Exception as exc:
        print(f"LOAD NOT STARTED or CHECK FAILED: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
