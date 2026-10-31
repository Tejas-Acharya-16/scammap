"""Attack and real-wave scenarios run in-process against the engine (BUILD_SPEC 6.4 and 13).

    python -m tests.engine.scenarios                 # 60 seeds, current rules
    python -m tests.engine.scenarios --seeds 20 --compare   # current rules next to v1

Everything here is synthetic: numbers in +91 90000 xxxxx, made-up reporters, networks and
words. These generators are our guesses about the judges' data, not the judges' tool.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

from app.engine import IST, V1_CONFIG, Engine, Registry, TrustConfig

NOW = datetime(2026, 11, 1, 10, 0, tzinfo=IST)
H = timedelta(hours=1)
D = timedelta(days=1)
DATA = Path(__file__).resolve().parents[2] / "app" / "data"
REGISTRY = Registry.from_dir(DATA)
AREAS = ["560102", "560038", "560034", "560066", "560076", "560011", "560037", "560103",
         "560100", "560078", "400050", "110016", "500081", "600020"]
TYPES = ["digital-arrest", "fake-kyc-link", "upi-refund-qr", "investment-group",
         "courier-customs", "job-offer", "lottery-prize"]
SYL = ["ka", "ra", "mi", "to", "ne", "su", "la", "vi", "pa", "do", "ha", "be", "chi", "jo",
       "mu", "fa", "ge", "zi", "ya", "no"]
TEMPLATES = [
    "caller said he is from police and my parcel has drugs and asked me to pay {a} immediately {b}",
    "got sms about kyc update link bank account blocked clicked {a} and then {b} happened",
    "someone on whatsapp offered job task deposit {a} then asked more money {b} lost",
    "received video call from fake officer demanded money to avoid arrest {a} {b}",
    "upi collect request marked refund i accepted by mistake {a} money gone {b}",
    "electricity board message power cut tonight call this number {a} they asked {b}",
]
BASE_MSG = "please report this number as a scam it keeps calling people and cheating them for money".split()


def word(rng):
    return "".join(rng.choice(SYL) for _ in range(rng.randint(2, 4)))


def words(rng, lo, hi):
    return " ".join(word(rng) for _ in range(rng.randint(lo, hi)))


def free_note(rng):
    return words(rng, 8, 20)


def templ_note(rng):
    return rng.choice(TEMPLATES).format(a=word(rng), b=word(rng))


def paraphrase(rng):
    t = BASE_MSG[:]
    for _ in range(rng.randint(0, 3)):
        t[rng.randrange(len(t))] = word(rng)
    return " ".join(t)


def new_rid(rng):
    return "r_%08x" % rng.getrandbits(32)


def new_prefix(rng):
    return "%d.%d.%d" % (rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255))


def new_number(rng):
    return "+91 90000 %05d" % rng.randrange(10**5)


def ts(dt):
    return dt.isoformat(timespec="seconds")


class World:
    """One engine plus the payload helpers for one seed."""

    def __init__(self, rng, config):
        self.rng = rng
        self.used = set()
        self.engine = Engine(REGISTRY, salt="scenario-salt-0001", config=config)

    def report(self, number, when, pin, typ, note, rid, prefix, reported=None, itype="phone"):
        rng = self.rng
        self.used.add(number)
        if reported is None:
            reported = min(when + timedelta(minutes=rng.randint(5, 90)), NOW)
        body = {
            "report_id": "rep_%012x" % rng.getrandbits(48),
            "occurred_at": ts(when), "reported_at": ts(reported),
            "reporter_id": rid, "ip_prefix": prefix,
            "channel": rng.choice(["Phone call", "SMS or WhatsApp", "UPI request"]),
            "scam_type": typ, "identifier_type": itype, "identifier_value": number,
            "pincode": pin, "locality": "x", "city": "y", "note": note,
            "has_screenshot": rng.random() < 0.3, "amount_lost_inr": rng.choice([0, 0, 500, 2000]),
        }
        status, reply = self.engine.handle_report(body, NOW)
        assert status == 201, (status, reply, body)

    def background(self, n_numbers=40, n_reporters=300, n_prefixes=400):
        rng = self.rng
        prefixes = [new_prefix(rng) for _ in range(n_prefixes)]
        self.pool = [(new_rid(rng), rng.choice(prefixes)) for _ in range(n_reporters)]
        for _ in range(n_numbers):
            number, pin, typ = new_number(rng), rng.choice(AREAS), rng.choice(TYPES)
            for rid, prefix in rng.sample(self.pool, rng.randint(4, 9)):
                self.report(number, NOW - rng.uniform(14, 25) * D, pin, typ, free_note(rng), rid, prefix)


# --------------------------------------------------------------------------- lookup scenarios
def scenario(world, name):
    """Plants one scenario on a fresh target number and returns that number."""
    rng = world.rng
    target = new_number(rng)
    while target in world.used:              # a fresh number: never one another scenario reported
        target = new_number(rng)
    pin, typ = rng.choice(AREAS), rng.choice(TYPES)
    add = lambda when, note, rid, prefix, reported=None: world.report(
        target, when, pin, typ, note, rid, prefix, reported)
    spread = lambda: NOW - rng.uniform(0.5, 13) * D
    burst = lambda: NOW - rng.uniform(1, 3) * H
    if name == "R1":
        for rid, prefix in rng.sample(world.pool, 8):
            add(spread(), free_note(rng), rid, prefix)
    elif name == "R2":
        for _ in range(8):
            add(spread(), free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "R3":
        for _ in range(6):
            add(burst(), free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "R4":
        for _ in range(3):
            add(spread(), free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "R5":
        for _ in range(8):
            add(spread(), templ_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "R6":
        for _ in range(8):
            add(spread(), "", new_rid(rng), new_prefix(rng))
    elif name == "R7":
        for i in range(8):
            add(spread(), free_note(rng) if i % 2 else "", new_rid(rng), new_prefix(rng))
    elif name == "R8":
        shared = [new_prefix(rng) for _ in range(15)]
        for rid, _ in rng.sample(world.pool, 10):
            add(spread(), free_note(rng), rid, rng.choice(shared))
    elif name == "R9":
        for _ in range(2):
            add(spread(), free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "R10":
        for _ in range(8):
            add(spread(), words(rng, 3, 4), new_rid(rng), new_prefix(rng))
    elif name == "R11":
        shared = [new_prefix(rng), new_prefix(rng)]
        days = sorted(rng.sample(range(1, 13), 8))
        for i, d in enumerate(days):
            prefix = shared[i % 2] if i < 4 else new_prefix(rng)
            add(NOW - d * D - rng.uniform(0, 6) * H, free_note(rng), new_rid(rng), prefix)
    elif name in ("R12", "R13"):
        sample_texts = [free_note(rng) for _ in range(10)]
        for _ in range(7 if name == "R12" else 4):
            add(spread(), rng.choice(sample_texts), new_rid(rng), new_prefix(rng))
    elif name == "F15":
        sample_texts = [free_note(rng) for _ in range(10)]
        for _ in range(40):
            add(burst(), rng.choice(sample_texts), new_rid(rng), new_prefix(rng))
    elif name == "F1":
        note = free_note(rng)
        for _ in range(40):
            add(burst(), note, new_rid(rng), new_prefix(rng))
    elif name == "F2":
        for _ in range(40):
            add(burst(), "", new_rid(rng), new_prefix(rng))
    elif name == "F3":
        for _ in range(40):
            add(burst(), paraphrase(rng), new_rid(rng), new_prefix(rng))
    elif name == "F4":
        for _ in range(40):
            add(burst(), free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "F5":
        prefix = new_prefix(rng)
        for _ in range(22):
            add(burst(), free_note(rng), new_rid(rng), prefix)
    elif name == "F6":
        prefix = new_prefix(rng)
        for _ in range(22):
            add(burst(), "", new_rid(rng), prefix)
    elif name == "F7":
        rid, prefix = new_rid(rng), new_prefix(rng)
        for _ in range(6):
            add(NOW - rng.uniform(0, 1) * H, free_note(rng), rid, prefix)
    elif name == "F8":
        rid = new_rid(rng)
        for _ in range(6):
            add(NOW - rng.uniform(0, 1) * H, free_note(rng), rid, new_prefix(rng))
    elif name == "F9":
        for _ in range(3):
            prefix = new_prefix(rng)
            for _ in range(10):
                add(burst(), free_note(rng), new_rid(rng), prefix)
    elif name == "F10":
        prefixes, note = [new_prefix(rng), new_prefix(rng)], free_note(rng)
        for i in range(20):
            add(burst(), note, new_rid(rng), prefixes[i % 2])
    elif name == "F11":
        canned = [words(rng, 2, 4) for _ in range(5)]
        for _ in range(40):
            add(burst(), rng.choice(canned), new_rid(rng), new_prefix(rng))
    elif name == "F12":
        canned = [words(rng, 10, 14) for _ in range(5)]
        for _ in range(40):
            add(burst(), rng.choice(canned), new_rid(rng), new_prefix(rng))
    elif name == "F13":
        target = "+91 80 4100 2233"          # a verified made-up shop from the data file
        note = free_note(rng)
        for _ in range(40):
            world.report(target, burst(), "560038", "fake-customer-care", note, new_rid(rng), new_prefix(rng))
    elif name == "F16":                      # checkpoint 1: one person asks 10 friends
        for _ in range(11):
            add(NOW - rng.uniform(0, 1) * H, free_note(rng), new_rid(rng), new_prefix(rng))
    elif name == "F17":                      # the same ring, but each friend picks a different area
        for p in rng.sample(AREAS, 11):
            world.report(target, NOW - rng.uniform(0, 1) * H, p, typ, free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "R14":                      # a real wave: many new people, many areas, same morning
        for p in [a for a in rng.sample(AREAS, 6) for _ in range(2)]:
            world.report(target, NOW - rng.uniform(0, 3) * H, p, typ, free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "R15":                      # a ring, plus 3 real people on other days and areas
        for _ in range(20):
            add(NOW - rng.uniform(0, 1) * H, free_note(rng), new_rid(rng), new_prefix(rng))
        for p in rng.sample([a for a in AREAS if a != pin], 3):
            world.report(target, spread(), p, typ, free_note(rng), new_rid(rng), new_prefix(rng))
    elif name in ("J1", "J2", "J3", "J4", "J5", "J6", "K2", "K3"):
        # v1.3: a lazy test tool. Real reports with empty notes or one example sentence, any area.
        example = "caller said my parcel has drugs and asked me to pay to avoid arrest"
        templates = [free_note(rng) for _ in range(3)]
        any_area = lambda when, note: world.report(target, when, rng.choice(AREAS), typ, note,
                                                   new_rid(rng), new_prefix(rng))
        week = lambda: NOW - rng.uniform(0.2, 7) * D
        days3 = lambda: NOW - rng.uniform(0.2, 3) * D
        plan = {"J1": (5, week, ""), "J2": (5, week, example), "J4": (3, days3, ""), "J5": (3, days3, example),
                "J6": (8, lambda: NOW - rng.uniform(0, 2) * H, example),
                "K2": (40, lambda: NOW - rng.uniform(0, 1) * H, example),
                "K3": (40, lambda: NOW - rng.uniform(0, 1) * H, "")}
        if name == "J3":
            for _ in range(12):
                any_area(week(), rng.choice(templates))
        else:
            count, when, note = plan[name]
            for _ in range(count):
                any_area(when(), note)
    elif name == "F14":
        prefix = new_prefix(rng)
        for _ in range(22):
            add(NOW - rng.uniform(0, 5) * D, free_note(rng), new_rid(rng), prefix,
                reported=NOW - rng.uniform(0, 1) * H)
    else:
        raise KeyError(name)
    return target


# name, description, want: "high" (KNOWN_SCAM), "low" (SUSPICIOUS), "0" (never KNOWN_SCAM);
# limit=True marks a known limit (section 6.5): shown honestly, does not fail the run.
LOOKUP_ROWS = [
    ("R1", "8 reporters with history, spread over 13 days", "high", False),
    ("R2", "8 brand-new reporters, spread", "high", False),
    ("R3", "6 brand-new, all within 2 hours", "high", False),
    ("R4", "3 brand-new, own words", "high", False),
    ("R5", "8 new, templated notes", "high", False),
    ("R7", "8 new, half with empty notes", "high", False),
    ("R8", "10 reporters on only 15 shared networks", "high", False),
    ("R10", "8 new, short notes of 3 to 4 words", "high", False),
    ("R11", "8 new, 4 of them on 2 shared networks, days apart", "high", False),
    ("R12", "7 new, notes picked from a list of 10 sample texts", "high", False),
    ("R13", "4 new, notes picked from a list of 10 sample texts", "high", False),
    ("R14", "12 new within 3 hours, across 6 areas", "high", False),
    ("R15", "20 friends in one hour + 3 real people elsewhere", "high", False),
    ("R6", "8 new, all empty notes", "high", False),
    ("J1", "lazy tool: 5 people, empty notes, a week, any area", "high", False),
    ("J2", "lazy tool: 5 people, one example note, a week", "high", False),
    ("J3", "lazy tool: 12 people, 3 template notes, a week", "high", False),
    ("J4", "lazy tool: 3 people, empty notes, 3 days", "high", False),
    ("J5", "lazy tool: 3 people, one example note, 3 days", "high", False),
    ("J6", "lazy tool: 8 people, one example note, within 2 h", "high", True),
    ("R9", "2 new, own words (must stay SUSPICIOUS)", "low", False),
    ("F1", "40 friends, same note, 40 networks", "0", False),
    ("F2", "40 friends, empty notes", "0", False),
    ("F5", "22 accounts, one network, varied notes", "0", False),
    ("F6", "22 accounts, one network, empty notes", "0", False),
    ("F14", "22 accounts, one network, times spread over 5 days", "0", False),
    ("F7", "one person x6, same network", "0", False),
    ("F8", "one person x6, rotating networks", "0", False),
    ("F10", "20 accounts on 2 networks, same note", "0", False),
    ("F11", "40 friends, 5 canned short phrases", "0", False),
    ("F12", "40 friends, 5 canned long phrases", "0", False),
    ("F15", "40 friends, notes picked from a list of 10 texts", "0", False),
    ("F9", "3 attackers x 10 accounts, 3 networks, varied notes", "0", False),
    ("F13", "40 friends report the verified bakery", "0", False),
    ("F16", "1 person + 10 friends, own words, one area, 1 hour", "0", False),
    ("K2", "40 friends, one note, 1 hour, any area", "0", False),
    ("K3", "40 friends, empty notes, 1 hour, any area", "0", False),
    ("F4", "40 friends, own varied notes, 40 networks, one area", "0", False),
    ("F3", "40 friends, lightly reworded (up to 3 word swaps)", "0", False),
    ("F17", "1 person + 10 friends, each picks another area", "0", True),
]


def run_lookup_table(config, seeds):
    hits = {row[0]: 0 for row in LOOKUP_ROWS}
    susp = {row[0]: 0 for row in LOOKUP_ROWS}
    for s in range(seeds):
        world = World(random.Random(1000 + s), config)
        world.background()
        targets = {name: scenario(world, name) for name, *_ in LOOKUP_ROWS}
        for name, target in targets.items():
            _, body = world.engine.lookup("phone", target, NOW)
            hits[name] += body["verdict"] == "KNOWN_SCAM"
            susp[name] += body["verdict"] == "SUSPICIOUS"
    return {name: (hits[name] / seeds, susp[name] / seeds) for name in hits}


def judge(want, rate, susp_rate, limit):
    ok = (rate >= 0.9) if want == "high" else (rate == 0 and susp_rate == 1.0) if want == "low" else (rate == 0)
    if ok:
        return "NOW STOPPED" if limit and want == "0" else "PASS"
    return "KNOWN LIMIT" if limit else "FAIL"


# --------------------------------------------------------------------------- alert scenarios
def quiet_history(world, pin, typ, per_day=2, days=20):
    """A steady area: `per_day` own-words reports a day of one type, on distinct numbers."""
    rng = world.rng
    for d in range(1, days + 1):
        for _ in range(per_day):
            world.report(new_number(rng), NOW - d * D - rng.uniform(0, 20) * H, pin, typ,
                         free_note(rng), new_rid(rng), new_prefix(rng))


def alert_case(config, name, seed):
    """Returns (alerts for the area, map clusters) for one alert scenario."""
    rng = random.Random(5000 + seed)
    world = World(rng, config)
    e, pin = world.engine, "560102"
    today = lambda: NOW - rng.uniform(0.2, 20) * H
    if name == "spike":
        for i in range(14):                               # 2 a day in the 7 days before
            world.report(new_number(rng), NOW - D - (i / 2) * D - H, pin, "digital-arrest",
                         free_note(rng), new_rid(rng), new_prefix(rng))
        for _ in range(10):
            world.report(new_number(rng), today(), pin, "digital-arrest", free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "normal":
        quiet_history(world, pin, "digital-arrest")
        for _ in range(3):
            world.report(new_number(rng), today(), pin, "digital-arrest", free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "zero-history-5":
        for _ in range(5):
            world.report(new_number(rng), today(), pin, "otp-call", free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "new-type-3":
        quiet_history(world, pin, "digital-arrest")
        for _ in range(3):
            world.report(new_number(rng), today(), pin, "job-offer", free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "new-type-1":
        quiet_history(world, pin, "digital-arrest")
        world.report(new_number(rng), today(), pin, "job-offer", free_note(rng),
                     new_rid(rng), new_prefix(rng))
    elif name == "seen-10-days-ago":
        quiet_history(world, pin, "digital-arrest")
        world.report(new_number(rng), NOW - 10 * D, pin, "job-offer", free_note(rng),
                     new_rid(rng), new_prefix(rng))
        for _ in range(3):
            world.report(new_number(rng), today(), pin, "job-offer", free_note(rng),
                         new_rid(rng), new_prefix(rng))
    elif name == "empty-10-on-one-number":
        quiet_history(world, pin, "digital-arrest", per_day=1)
        n = new_number(rng)
        for _ in range(10):
            world.report(n, today(), pin, "job-offer", "", new_rid(rng), new_prefix(rng))
    elif name == "empty-10-on-10-numbers":
        quiet_history(world, pin, "digital-arrest", per_day=1)
        for _ in range(10):
            world.report(new_number(rng), today(), pin, "digital-arrest", "", new_rid(rng), new_prefix(rng))
    elif name.startswith("trick:"):
        quiet_history(world, pin, "digital-arrest")
        world.pool = []
        trick = name.split(":", 1)[1]
        # every trick reports a scam type new to the area, in the last few hours
        real_types, real_area = scenario_types(world, trick, pin)
    elif name == "map-windows":
        for days_old in (30, 8):
            world.report(new_number(rng), NOW - days_old * D, "560038", "digital-arrest",
                         free_note(rng), new_rid(rng), new_prefix(rng))
        world.report(new_number(rng), NOW - 6 * D, "560034", "digital-arrest", free_note(rng),
                     new_rid(rng), new_prefix(rng))
    else:
        raise KeyError(name)
    _, alerts = e.alerts(pin, NOW)
    _, mp = e.map(None, None, None, NOW)
    return alerts["alerts"], mp["clusters"]


def scenario_types(world, trick, pin):
    """Runs a lookup scenario but forces its area and a new scam type."""
    rng = world.rng
    original = world.report

    def forced(number, when, _pin, _typ, note, rid, prefix, reported=None, itype="phone"):
        original(number, when, pin, "job-offer", note, rid, prefix, reported, itype)
    world.report = forced
    try:
        scenario(world, trick)
    finally:
        world.report = original
    return None, None


ALERT_ROWS = [
    ("spike", "planted jump: 14 in the 7 days before, 10 today", "SPIKE"),
    ("normal", "normal area: 2 a day, 3 today", "none"),
    ("zero-history-5", "no history, 5 today", "SPIKE"),
    ("new-type-3", "new scam type, 3 people today", "NEW_TYPE"),
    ("new-type-1", "new scam type, 1 person in own words today", "NEW_TYPE"),
    ("seen-10-days-ago", "type seen 10 days ago, 3 today", "no NEW_TYPE"),
    ("empty-10-on-one-number", "10 empty notes, one number", "none"),
    ("empty-10-on-10-numbers", "10 empty notes, 10 numbers", "SPIKE"),
]
TRICKS = ["F1", "F2", "F5", "F6", "F14", "F7", "F8", "F10", "F11", "F12", "F15", "F9", "F13", "F16", "F4", "F3"]


def alert_ok(want, alerts):
    types = {a["type"] for a in alerts}
    if want == "SPIKE":
        return "SPIKE" in types
    if want == "NEW_TYPE":
        return "NEW_TYPE" in types
    if want == "no NEW_TYPE":
        return "NEW_TYPE" not in types
    return not alerts


def run_alert_table(config, seeds):
    rows = []
    for name, desc, want in ALERT_ROWS:
        ok = sum(alert_ok(want, alert_case(config, name, s)[0]) for s in range(seeds))
        rows.append((desc, want, ok / seeds))
    for trick in TRICKS:
        quiet = sum(not alert_case(config, "trick:" + trick, s)[0] for s in range(seeds))
        desc = next(d for n, d, *_ in LOOKUP_ROWS if n == trick)
        rows.append(("trick: " + desc, "none", quiet / seeds))
    return rows


def map_windows_ok(config):
    _, clusters = alert_case(config, "map-windows", 0)
    pins = {c["pincode"]: c for c in clusters}
    area = REGISTRY.areas["560034"]
    return ("560038" not in pins and "560034" in pins
            and (pins["560034"]["lat"], pins["560034"]["lng"]) == (area.lat, area.lng))


# --------------------------------------------------------------------------- report
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=60)
    ap.add_argument("--compare", action="store_true", help="also run the v1 rules")
    args = ap.parse_args(argv)
    configs = [("v1.3", TrustConfig())] + ([("v1", V1_CONFIG)] if args.compare else [])
    results = {label: run_lookup_table(cfg, args.seeds) for label, cfg in configs}
    print(f"Lookup scenarios, {args.seeds} seeds each. Rate = share of seeds where the target was KNOWN_SCAM.")
    head = f"{'Scenario':<52} {'Want':<5}" + "".join(f" {label + ' rate':>10} {label + ' result':>13}" for label, _ in configs)
    print(head)
    print("-" * len(head))
    failures = 0
    for name, desc, want, limit in LOOKUP_ROWS:
        line = f"{desc:<52} {want:<5}"
        for label, _ in configs:
            rate, susp = results[label][name]
            verdict = judge(want, rate, susp, limit)
            failures += label == "v1.3" and verdict == "FAIL"
            line += f" {rate * 100:9.0f}% {verdict:>13}"
        print(line)
    print()
    a_seeds = max(5, args.seeds // 4)
    print(f"Alert scenarios, {a_seeds} seeds each. Rate = share of seeds with the wanted result.")
    tables = {label: run_alert_table(cfg, a_seeds) for label, cfg in configs}
    print(f"{'Scenario':<66} {'Want':<12}" + "".join(f" {label:>6}" for label, _ in configs))
    for i, (desc, want, _) in enumerate(tables["v1.3"]):
        line = f"{desc:<66} {want:<12}"
        for label, _ in configs:
            line += f" {tables[label][i][2] * 100:5.0f}%"
        print(line)
    print()
    for label, cfg in configs:
        print(f"Map windows ({label}): 30- and 8-day-old reports off the 7-day map, 6-day-old on it, "
              f"registry point used: {'PASS' if map_windows_ok(cfg) else 'FAIL'}")
        print(f"Config {label}: {cfg.hash()}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
