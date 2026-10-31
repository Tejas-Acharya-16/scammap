"""Engine speed at judging-day volume (in-process, no network).

    python -m tests.engine.bench [--reports 5000]

Prints p50, p95 and max for lookups, map and alerts, plus the time to rebuild from rows.
The live server adds network time and a slower CPU; measure that with `make perf`.
"""
from __future__ import annotations

import argparse
import random
import statistics
import time

from tests.engine.scenarios import AREAS, NOW, REGISTRY, TYPES, D, World, free_note, new_number, new_prefix, new_rid
from app.engine import Engine, TrustConfig


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", type=int, default=5000)
    args = ap.parse_args(argv)
    rng = random.Random(7)
    world = World(rng, TrustConfig())
    rows = []
    numbers = [new_number(rng) for _ in range(args.reports // 6)]
    t0 = time.perf_counter()
    for i in range(args.reports):
        n = rng.choice(numbers)
        world.engine.handle_report({
            "report_id": f"rep_{i}", "occurred_at": (NOW - rng.uniform(0, 30) * D).isoformat(),
            "reporter_id": new_rid(rng), "ip_prefix": new_prefix(rng), "channel": "Phone call",
            "scam_type": rng.choice(TYPES), "identifier_type": "phone", "identifier_value": n,
            "pincode": rng.choice(AREAS), "note": free_note(rng) if rng.random() < 0.8 else ""},
            NOW, persist=rows.append)
    ingest = time.perf_counter() - t0
    e = world.engine

    def timed(fn, k=300):
        out = []
        for _ in range(k):
            s = time.perf_counter()
            fn()
            out.append((time.perf_counter() - s) * 1000)
        return out

    looks = timed(lambda: e.lookup("phone", rng.choice(numbers), NOW))
    e._counted_cache = None
    cold_map = timed(lambda: (setattr(e, "_counted_cache", None), e.map("560102", 7, 2, NOW)), 20)
    warm_map = timed(lambda: e.map("560102", 7, 2, NOW))
    alerts = timed(lambda: e.alerts(rng.choice(AREAS), NOW))
    t0 = time.perf_counter()
    Engine(REGISTRY, salt="scenario-salt-0001").load(rows)
    rebuild = time.perf_counter() - t0
    print(f"{args.reports} reports on {len(numbers)} numbers; ingest {ingest:.2f} s "
          f"({ingest / args.reports * 1000:.2f} ms each); rebuild from rows {rebuild:.2f} s")
    for name, xs in [("lookup", looks), ("map, after a write", cold_map), ("map", warm_map), ("alerts", alerts)]:
        print(f"{name:<20} p50 {statistics.median(xs):6.2f} ms   p95 {pct(xs, 95):6.2f} ms   max {max(xs):6.2f} ms")


if __name__ == "__main__":
    main()
