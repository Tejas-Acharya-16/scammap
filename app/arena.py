"""Scam Arena: a judge plays the attacker against a sandbox engine (POST /arena/attack, POST /arena/redteam).

Like app/demo.py, every attack runs on a FRESH in-memory Engine with the same code and the same trust config
as the live server. Nothing here reads or writes the live engine or the database. Synthetic data only:
numbers +91 90000 xxxxx, reporter IDs r_arena_N, networks 10.x.y, notes made of random syllables. A reply
holds counts, verdicts, area codes and fixed phrases: never a reporter ID, a network or a note.

The random generator is seeded from the plan, so the same plan always plants the same reports. A plan the
red team found gives the same outcome when a judge replays it with POST /arena/attack.

    from app.arena import parse_plan, attack, redteam
    attack(REGISTRY, ENGINE.config, parse_plan(body))      # one attack, a few milliseconds
    redteam(REGISTRY, ENGINE.config, seed=7)               # 150 random plans, stops at 4 s
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .demo import SYL, Sandbox
from .engine import IST, KNOWN_SCAM, SUSPICIOUS, VERIFIED_BUSINESS, normalise

H = timedelta(hours=1)

KEYS = ("target", "reports", "accounts", "networks", "areas", "hours", "words", "backdate")
TARGETS = ("verified", "unlisted")
WORDS = ("copy", "reword", "own", "empty")
RED_HOURS = (0.25, 0.5, 1.0, 2.0, 3.0, 6.0, 12.0, 24.0, 48.0, 72.0, 120.0, 168.0)
RED_PLANS = 150
RED_BUDGET_S = 4.0
FLAGGED = ("high", "medium")            # AI watchdog levels that count as "flagged"
ATTACK_TYPE = "job-offer"               # new to the attacked areas, so counted fakes would raise NEW_TYPE
BACKGROUND_TYPE = "digital-arrest"

NOTES = {
    "caught": "Caught in this sandbox: the rules kept the number below Known scam.",
    "caught_verified": "Caught in this sandbox: the verified list always wins, so reports cannot make a listed "
                       "business a known scam.",
    "beat_rules_ai_flagged": "You beat the rules in this sandbox, but the AI watchdog flagged the reports for a person "
                             "to review. The AI never changes the verdict.",
    "beat_both": "You beat both layers. This is our known limit: people each in a different area at once look like "
                 "a real wave. The verified list protects listed businesses; disputes protect everyone else.",
}


class InvalidParams(ValueError):
    """Any problem with the request body. The route answers 400 {"error": "invalid_params"} and never says which."""


# ------------------------------------------------------------------ input
def _int(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise InvalidParams
    return v


def parse_plan(body) -> dict:
    """The attack plan, checked. Every field is required, nothing else is allowed, nothing is clamped."""
    if not isinstance(body, dict) or set(body) != set(KEYS):
        raise InvalidParams
    if body["target"] not in TARGETS or body["words"] not in WORDS or not isinstance(body["backdate"], bool):
        raise InvalidParams
    reports = _int(body["reports"], 3, 60)
    hours = body["hours"]
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not math.isfinite(hours) \
            or not 0.25 <= hours <= 168:
        raise InvalidParams
    return {"target": body["target"], "reports": reports, "accounts": _int(body["accounts"], 1, reports),
            "networks": _int(body["networks"], 1, reports), "areas": _int(body["areas"], 1, 12),
            "hours": float(hours), "words": body["words"], "backdate": body["backdate"]}


def parse_seed(body):
    """{} or {"seed": int} -> the seed or None."""
    if not isinstance(body, dict) or not set(body) <= {"seed"}:
        raise InvalidParams
    seed = body.get("seed")
    if seed is None:
        return None
    return _int(seed, 0, 10 ** 12)


def _plan_seed(plan) -> int:
    blob = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return int.from_bytes(hashlib.sha256(blob.encode()).digest()[:8], "big")


# ------------------------------------------------------------------ synthetic reports
def _word(rng):
    return "".join(rng.choice(SYL) for _ in range(rng.randint(2, 4)))


def _words(rng, lo, hi):
    return " ".join(_word(rng) for _ in range(rng.randint(lo, hi)))


def _send(engine, now, value, occurred_h, filed_h, rid, net, pin, note, typ, report_id):
    body = {
        "report_id": report_id,
        "occurred_at": (now - occurred_h * H).isoformat(timespec="seconds"),
        "reported_at": (now - filed_h * H).isoformat(timespec="seconds"),
        "reporter_id": rid, "ip_prefix": net, "channel": "Phone call", "scam_type": typ,
        "identifier_type": "phone", "identifier_value": value, "pincode": pin, "note": note,
        "has_screenshot": False, "amount_lost_inr": 0,
    }
    status, _ = engine.handle_report(body, now)
    if status != 201:
        raise RuntimeError("the sandbox refused a planted report")


def _plant(engine, now, plan, value, pins, rng, tag, rid_base):
    """Plant the attack on `value`. Only `rng` decides times and words, so a plan plants the same reports in
    any sandbox. Report i comes from account i mod A, network i mod K and area i mod Z."""
    base = _words(rng, 12, 16).split()
    shared = " ".join(base)
    for i in range(plan["reports"]):
        if plan["backdate"]:                        # claims calls over 5 days, files them all within `hours`
            occurred_h = rng.uniform(12, 120)
            filed_h = rng.uniform(0.05, max(0.05, min(plan["hours"], occurred_h - 0.05)))
        else:                                       # calls within `hours`, each filed 2 to 40 minutes later
            occurred_h = rng.uniform(0.05, plan["hours"])
            filed_h = max(0.0, occurred_h - rng.randint(2, 40) / 60)
        if plan["words"] == "copy":
            note = shared
        elif plan["words"] == "empty":
            note = ""
        elif plan["words"] == "reword":
            t = base[:]
            for _ in range(rng.randint(1, 3)):
                t[rng.randrange(len(t))] = _word(rng)
            note = " ".join(t)
        else:
            note = _words(rng, 8, 16)
        k = i % plan["networks"]
        _send(engine, now, value, occurred_h, filed_h, "r_arena_%d" % (rid_base + i % plan["accounts"]),
              "10.%d.%d" % (100 + k // 250, 1 + k % 250), pins[i % len(pins)], note, ATTACK_TYPE,
              "rep_arena_%s_%03d" % (tag, i))


def _background(sb, pins, rng, now):
    """A quiet background in the attacked areas: 2 reports a day for 14 days, each on its own number."""
    n = 0
    for pin in pins:
        for d in range(1, 15):
            for _ in range(2):
                n += 1
                occurred_h = d * 24 + rng.uniform(0.05, 20)
                _send(sb.engine, now, sb.number(), occurred_h, occurred_h - 0.2, "r_arena_%d" % (100000 + n),
                      "10.%d.%d" % (rng.randint(0, 99), rng.randint(0, 255)), pin, _words(rng, 8, 16),
                      BACKGROUND_TYPE, "rep_arena_bg_%05d" % n)


# ------------------------------------------------------------------ reading the result
def _classify(verdict, wd) -> str:
    if verdict != KNOWN_SCAM:
        return "caught"
    return "beat_rules_ai_flagged" if wd and wd.get("level") in FLAGGED else "beat_both"


def _groups(rids, edges):
    parent = {r: r for r in rids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        parent[find(a)] = find(b)
    return len({find(r) for r in rids})


def _rules(engine, ikey, reply, cfg) -> list:
    """Plain sentences for the rules that linked these reports. Read-only use of the sandbox engine's own voices:
    for each linked group, which kinds of link joined reports from different accounts."""
    out = []
    if reply.get("label"):
        out.append("This number is on the verified list, so reports cannot make it a known scam.")
    window = None if cfg.org_link_hours is None else timedelta(hours=cfg.org_link_hours)
    same_account = network = copy = reword = False
    for v in engine._voices(ikey):
        per = Counter(r.rid for r in v.reports)
        same_account = same_account or max(per.values()) >= 2
        if len(per) < 2:
            continue
        net_edges = []
        by_org = defaultdict(list)
        for r in v.reports:
            by_org[r.org].append(r)
        for group in by_org.values():
            for attr in ("t", "reported_at"):        # the same two clocks trust.build_voices uses
                seq = sorted((r for r in group if getattr(r, attr) is not None),
                             key=lambda r: (getattr(r, attr), r.report_id))
                for a, b in zip(seq, seq[1:]):
                    if a.rid != b.rid and (window is None or getattr(b, attr) - getattr(a, attr) <= window):
                        net_edges.append((a.rid, b.rid))
        network = network or bool(net_edges)
        after_net = _groups(per, net_edges)
        if after_net > 1:                            # text joined what accounts and networks did not
            by_hash = defaultdict(list)
            for r in v.reports:
                if r.note_hash:
                    by_hash[r.note_hash].append(r.rid)
            text_edges = [(g[0], x) for g in by_hash.values() for x in g[1:] if x != g[0]]
            after_copy = _groups(per, net_edges + text_edges)
            copy = copy or after_copy < after_net
            reword = reword or after_copy > 1
    if same_account:
        out.append("Several reports from one account count as one person.")
    if network:
        out.append("Reports from one network within %g hours count as one person." % cfg.org_link_hours)
    if copy:
        out.append("Copies of one text from %d or more accounts within %g hours count as one voice."
                   % (cfg.note_link_min_reporters, cfg.note_link_window_hours))
    if reword:
        out.append("Lightly reworded copies of one text count as one voice.")
    voices, _, burst = engine._final(ikey)
    if burst:
        merged = next(v for v in voices if v.burst)
        if len({r.pincode for r in merged.reports}) == 1:
            out.append("%d brand-new accounts from one area within %g hours count as one voice until people "
                       "elsewhere confirm it." % (burst, cfg.ring_window_hours))
        else:
            out.append("%d brand-new accounts with no words of their own, arriving within %g hours, count as one "
                       "voice." % (burst, cfg.ring_window_hours))
    if reply["verdict"] == SUSPICIOUS:
        if reply["distinct_reporters"] < cfg.min_voices:
            out.append("Known scam needs %d independent voices; after linking, %d remained."
                       % (cfg.min_voices, reply["distinct_reporters"]))
        elif not burst:
            out.append("Linked groups count once and add no weight, so the number stays below Known scam.")
    return out


def _map_count(engine, pins, now) -> int:
    _, m = engine.map(None, 7, 0, now)
    return sum(c["count"] for c in m["clusters"] if c["pincode"] in pins)


def _alerts(engine, pins, now) -> list:
    out = []
    for pin in pins:
        out += engine.alerts(pin, now)[1]["alerts"]
    return out


# ------------------------------------------------------------------ the two routes
def attack(registry, config, plan, now=None) -> dict:
    """One attack on a fresh sandbox. `plan` must come from parse_plan."""
    now = (now or datetime.now(IST)).replace(microsecond=0)   # whole seconds: the same plan, the same times
    seed = _plan_seed(plan)
    rng = random.Random(seed)
    sb = Sandbox(registry, config, random.Random(seed ^ 0x5EED), now)
    pins = rng.sample(sb.pins[:12], plan["areas"])
    _background(sb, pins, random.Random(seed ^ 0xB6), now)
    map_before, alerts_before = _map_count(sb.engine, pins, now), _alerts(sb.engine, pins, now)
    if plan["target"] == "verified":                           # the first verified phone, as check T1 does
        value = next(c for t, c, _ in registry.verified_items() if t == "phone" and len(c) >= 13)
    else:
        value = sb.number()
    _plant(sb.engine, now, plan, value, pins, rng, "a", 0)
    _, reply = sb.engine.lookup("phone", value, now)
    ikey = "phone:" + normalise("phone", value)                # the key the engine files these reports under
    wd = reply.get("ai_watchdog")
    outcome = _classify(reply["verdict"], wd)
    map_after = _map_count(sb.engine, pins, now)
    raised = [a for a in _alerts(sb.engine, pins, now) if a not in alerts_before]
    for a in raised:
        area = registry.areas.get(a.get("pincode"))
        a["locality"] = area.area if area else None
    return {
        "verdict": reply["verdict"], "display_value": reply["display_value"], "report_count": reply["report_count"],
        "voices": reply["distinct_reporters"], "burst_counted_as_one": (reply.get("trust") or {}).get("burst_voices") or 0,
        "rules": _rules(sb.engine, ikey, reply, config), "ai_watchdog": wd, "alerts_raised": raised,
        "map_moved": {"before": map_before, "after": map_after, "added": map_after - map_before},
        "bill": {"fake_accounts": plan["accounts"], "networks": plan["networks"], "areas": plan["areas"],
                 "hours": plan["hours"], "people_needed": min(plan["accounts"], plan["networks"])},
        "outcome": outcome, "note": NOTES["caught_verified"] if reply["verdict"] == VERIFIED_BUSINESS else NOTES[outcome],
        "config": config.hash(), "live_data_touched": False,
    }


def _random_plan(rng) -> dict:
    reports = rng.randint(3, 60)
    return {"target": "unlisted", "reports": reports, "accounts": rng.randint(1, reports),
            "networks": rng.randint(1, reports), "areas": rng.randint(1, 12), "hours": rng.choice(RED_HOURS),
            "words": rng.choice(WORDS), "backdate": rng.random() < 0.25}


def _cost(item):
    plan, _, k = item
    return plan["accounts"], plan["networks"], plan["areas"], plan["hours"], plan["reports"], k


def redteam(registry, config, seed=None, now=None, plans=RED_PLANS, budget_s=RED_BUDGET_S) -> dict:
    """Our automated attacker: a random search over the same sliders, all plans in one reused sandbox (each on its
    own number with its own accounts), stopping at `budget_s`. The verified list always wins, so it spends every try
    on unlisted numbers. The two cheapest plans are then replayed on fresh sandboxes exactly as /arena/attack would."""
    seed = random.randrange(10 ** 6) if seed is None else seed
    t0 = time.perf_counter()
    now = (now or datetime.now(IST)).replace(microsecond=0)
    gen = random.Random(seed)
    todo = [_random_plan(gen) for _ in range(plans)]
    sb = Sandbox(registry, config, random.Random(seed ^ 0x5EED), now)
    tried, beat = 0, []
    for k, plan in enumerate(todo):
        if time.perf_counter() - t0 >= budget_s:
            break
        rng = random.Random(_plan_seed(plan))
        pins = rng.sample(sb.pins[:12], plan["areas"])
        value = sb.number()
        _plant(sb.engine, now, plan, value, pins, rng, "p%d" % k, (k + 1) * 100)
        _, reply = sb.engine.lookup("phone", value, now)
        tried += 1
        outcome = _classify(reply["verdict"], reply.get("ai_watchdog"))
        if outcome != "caught":
            beat.append((plan, outcome, k))
    flagged = sum(1 for _, o, _ in beat if o == "beat_rules_ai_flagged")
    best_rules = min(beat, key=_cost, default=None)
    best_both = min((b for b in beat if b[1] == "beat_both"), key=_cost, default=None)

    def replay(item):
        return None if item is None else {"plan": item[0], "result": attack(registry, config, item[0], now)}

    return {"seed": seed, "tried": tried, "beat_rules": len(beat), "ai_flagged_of_those": flagged,
            "cheapest_beat_rules": replay(best_rules), "cheapest_beat_both": replay(best_both),
            "ms": round((time.perf_counter() - t0) * 1000), "plans": plans, "budget_s": budget_s,
            "config": config.hash(), "live_data_touched": False}
