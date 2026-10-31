"""The attack table over HTTP, against a running server (the judges' tool works the same way).
Reuses the scenario generators in tests/engine/scenarios.py, but every report is a real POST /reports
and every verdict a real GET /lookup. Times are shifted to the real clock.

    python -m tests.blackbox.attack URL [--seeds 3] [--workers 8]

It starts with POST /admin/reset, so it deletes every report on that server. Synthetic data only.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from tests.engine import scenarios as sc

BASE = ""
DELTA = timedelta(0)


def http(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"content-type": "application/json"} if data else {})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(1.5)
                continue
            return e.code, None
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(1.0)


class HttpWorld(sc.World):
    """Same generators, but reports are collected and sent over HTTP."""

    def __init__(self, rng):
        self.rng = rng
        self.used = set()
        self.bodies = []

    def report(self, number, when, pin, typ, note, rid, prefix, reported=None, itype="phone"):
        rng = self.rng
        self.used.add(number)
        if reported is None:
            reported = min(when + timedelta(minutes=rng.randint(5, 90)), sc.NOW)
        self.bodies.append({
            "report_id": "rep_%012x" % rng.getrandbits(48),
            "occurred_at": (when + DELTA).isoformat(timespec="seconds"),
            "reported_at": (reported + DELTA).isoformat(timespec="seconds"),
            "reporter_id": rid, "ip_prefix": prefix,
            "channel": rng.choice(["Phone call", "SMS or WhatsApp", "UPI request"]),
            "scam_type": typ, "identifier_type": itype, "identifier_value": number,
            "pincode": pin, "locality": "x", "city": "y", "note": note,
            "has_screenshot": False, "amount_lost_inr": 0,
        })


def run(seeds, workers):
    hits = {r[0]: 0 for r in sc.LOOKUP_ROWS}
    susp = {r[0]: 0 for r in sc.LOOKUP_ROWS}
    sent = rejected = 0
    t0 = time.perf_counter()
    for s in range(seeds):
        status, _ = http("POST", "/admin/reset", {})
        if status != 200:
            sys.exit(f"POST /admin/reset failed with {status}; is the licence valid?")
        world = HttpWorld(random.Random(1000 + s))
        world.background()
        targets = {name: sc.scenario(world, name) for name, *_ in sc.LOOKUP_ROWS}
        with ThreadPoolExecutor(workers) as ex:
            codes = list(ex.map(lambda b: http("POST", "/reports", b)[0], world.bodies))
        sent += len(codes)
        rejected += sum(c != 201 for c in codes)
        for name, target in targets.items():
            _, body = http("GET", "/lookup?" + urllib.parse.urlencode({"type": "phone", "value": target}))
            v = (body or {}).get("verdict")
            hits[name] += v == "KNOWN_SCAM"
            susp[name] += v == "SUSPICIOUS"
        print(f"  seed {s + 1}/{seeds}: {len(codes)} reports sent ({time.perf_counter() - t0:.0f} s)")
    http("POST", "/admin/reset", {})
    return {n: (hits[n] / seeds, susp[n] / seeds) for n in hits}, sent, rejected


def main(argv=None):
    global BASE, DELTA
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args(argv)
    BASE = a.url.rstrip("/")
    DELTA = datetime.now(timezone.utc) - sc.NOW
    print(f"Target: {BASE}. This resets the server before and after. Seeds: {a.seeds}")
    res, sent, rejected = run(a.seeds, a.workers)
    print(f"\n{'Scenario':<52} {'Want':<5} {'KNOWN_SCAM':>10}  Result")
    fails = 0
    for name, desc, want, limit in sc.LOOKUP_ROWS:
        rate, s_rate = res[name]
        verdict = sc.judge(want, rate, s_rate, limit)
        fails += verdict == "FAIL"
        print(f"{desc:<52} {want:<5} {rate * 100:9.0f}%  {verdict}")
    print(f"\n{sent} reports sent over HTTP, {rejected} rejected (expected 0). Failures: {fails}.")
    print("Our generators, not the judges' tool. Quote as 'in our tests'.")
    return 1 if fails or rejected else 0


if __name__ == "__main__":
    sys.exit(main())
