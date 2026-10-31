"""Sandbox checks for the judge console (GET /judge calls POST /demo/run).

Every check runs on a FRESH in-memory Engine built from the same code and the same trust config as
the live server, so it shows the server's real behaviour, but nothing here reads or writes the live
data. Synthetic data only: numbers +91 90000 xxxxx, made-up reporters (r_demo_...), networks in
10.x.y, notes made of random syllables. The same seed repeats a run; a new seed gives new data.

    from app.demo import run
    result = run(REGISTRY, ENGINE.config, seed=None)      # about 0.1 to 0.5 s
"""
from __future__ import annotations

import json
import random
import secrets
import time
from datetime import datetime, timedelta

from .engine import (IST, KNOWN_SCAM, NO_REPORTS, SUSPICIOUS, VERIFIED_BUSINESS, Engine,
                     normalise)

H = timedelta(hours=1)
D = timedelta(days=1)
M = timedelta(minutes=1)
SYL = ["ka", "ra", "mi", "to", "ne", "su", "la", "vi", "pa", "do", "ha", "be", "chi", "jo",
       "mu", "fa", "ge", "zi", "ya", "no"]
CANARY = {"reporter": "r_CANARY_7f3a", "network": "10.9.8.7", "note_word": "CANARYNOTE",
          "note_phone": "9123456780"}


class Sandbox:
    """One fresh engine and payload helpers. `rows` collects exactly what the server would store."""

    def __init__(self, registry, config, rng, now):
        self.registry, self.rng, self.now = registry, rng, now
        self.engine = Engine(registry, salt="sandbox-" + secrets.token_hex(8), config=config)
        self.rows = []
        self.used = set()
        pins = list(registry.areas)
        self.pins = pins

    # --- synthetic values
    def number(self):
        while True:
            n = "+91 90000 %05d" % self.rng.randrange(10 ** 5)
            if n not in self.used:
                self.used.add(n)
                return n

    def words(self, lo=8, hi=16):
        w = lambda: "".join(self.rng.choice(SYL) for _ in range(self.rng.randint(2, 4)))
        return " ".join(w() for _ in range(self.rng.randint(lo, hi)))

    def rid(self):
        return "r_demo_%08x" % self.rng.getrandbits(32)

    def net(self):
        return "10.%d.%d" % (self.rng.randint(0, 255), self.rng.randint(0, 255))

    # --- API calls on the sandbox engine
    def report(self, value, ago, pin, note=None, rid=None, net=None, typ="digital-arrest", itype="phone"):
        occurred = self.now - ago
        body = {
            "report_id": "rep_demo_%010x" % self.rng.getrandbits(40),
            "occurred_at": occurred.isoformat(timespec="seconds"),
            "reported_at": min(occurred + self.rng.randint(2, 40) * M, self.now).isoformat(timespec="seconds"),
            "reporter_id": rid or self.rid(), "ip_prefix": net or self.net(),
            "channel": "Phone call", "scam_type": typ, "identifier_type": itype,
            "identifier_value": value, "pincode": pin,
            "note": self.words() if note is None else note,
            "has_screenshot": False, "amount_lost_inr": 0,
        }
        return self.engine.handle_report(body, self.now, persist=self.rows.append)

    def look(self, value, itype="phone"):
        return self.engine.lookup(itype, value, self.now)

    def within(self, hours):
        return self.rng.uniform(0.05, hours) * H


def _brief(reply):
    """The fields a judge needs to see from a lookup reply."""
    t = reply.get("trust") or {}
    out = {"verdict": reply.get("verdict"), "display_value": reply.get("display_value"),
           "report_count": reply.get("report_count"), "distinct_reporters": reply.get("distinct_reporters")}
    if t.get("burst_voices"):
        out["burst_counted_as_one"] = t["burst_voices"]
    if reply.get("label"):
        out["label"] = reply["label"]
    return out


def _check(cid, title, how, want, got, ok):
    return {"id": cid, "title": title, "how": how, "want": want, "got": got, "ok": bool(ok)}


# ============================================================================ row 1: fake reports
def _fake_reports(sb):
    rng, out = sb.rng, []
    home = rng.choice(sb.pins[:10])
    biz = [(t, c, label) for t, c, label in sb.registry.verified_items() if t == "phone" and len(c) >= 13]
    if biz:
        _, bakery, label = biz[0]
        for _ in range(40):
            sb.report(bakery, sb.within(1), home)
        st, r = sb.look(bakery)
        out.append(_check("T1", "40 friends gang up on a real, verified bakery",
                          "40 new accounts, 40 networks, each in their own words, within one hour",
                          VERIFIED_BUSINESS, _brief(r), r["verdict"] == VERIFIED_BUSINESS))

    def attack(cid, title, how, make):
        n = sb.number()
        make(n)
        _, r = sb.look(n)
        out.append(_check(cid, title, how, "not " + KNOWN_SCAM, _brief(r), r["verdict"] != KNOWN_SCAM))

    attack("T1b", "40 friends gang up on a shop that is NOT on the verified list",
           "40 new accounts, 40 networks, each in their own words, one area, within one hour",
           lambda n: [sb.report(n, sb.within(1), home) for _ in range(40)])
    attack("T2", "22 accounts on one Wi-Fi",
           "22 new reporter IDs, one network, own words, within 3 hours",
           lambda n, w=sb.net(): [sb.report(n, sb.within(3), home, net=w) for _ in range(22)])
    attack("T3", "One person reports the same number 6 times",
           "one reporter ID, a new network every time, new words every time",
           lambda n, p=sb.rid(): [sb.report(n, sb.within(1), home, rid=p) for _ in range(6)])
    attack("T5", "One person asks 10 friends to report (checkpoint 1)",
           "11 new accounts, own phones and networks, own words, one area, within one hour",
           lambda n: [sb.report(n, sb.within(1), home) for _ in range(11)])
    attack("T6", "40 friends paste the same message",
           "40 new accounts, 40 networks, one shared text, within one hour",
           lambda n, t=sb.words(): [sb.report(n, sb.within(1), home, note=t) for _ in range(40)])
    attack("T7", "40 friends with empty notes",
           "40 new accounts, 40 networks, no text, within one hour",
           lambda n: [sb.report(n, sb.within(1), home, note="") for _ in range(40)])

    before = len(sb.rows)
    junk = ["12345", "test", "0000000000", "1234567890", "", "abc@", "javascript:alert(1)"]
    codes = [sb.report(v, sb.within(1), home)[0] for v in junk]
    out.append(_check("T4", "Junk values are refused", "POST /reports with " + ", ".join(repr(v) for v in junk),
                      "400 for each, nothing stored", {"statuses": codes, "stored": len(sb.rows) - before},
                      all(c == 400 for c in codes) and len(sb.rows) == before))
    return out


# ============================================================================ real waves (rows 1 and 2)
def _real_waves(sb):
    rng, out = sb.rng, []
    home = rng.choice(sb.pins[:10])

    def wave(cid, title, how, make, want):
        n = sb.number()
        make(n)
        _, r = sb.look(n)
        ok = r["verdict"] == want and (want != KNOWN_SCAM or "X" not in r["display_value"])
        if want == SUSPICIOUS:
            ok = ok and "X" in r["display_value"]
        out.append(_check(cid, title, how, want + (" (number shown in full)" if want == KNOWN_SCAM else " (number masked)"),
                          _brief(r), ok))
        return n

    w1 = wave("W1", "3 different people report it", "3 new people, own words, over 6 days",
              lambda n: [sb.report(n, rng.uniform(0.5, 6) * D, home) for _ in range(3)], KNOWN_SCAM)
    wave("W2", "Only 2 people report it", "2 new people, own words, over 3 days",
         lambda n: [sb.report(n, rng.uniform(0.5, 3) * D, home) for _ in range(2)], SUSPICIOUS)
    wave("W3", "A real wave: 12 people in 6 areas, same morning", "12 new people, 2 per area, within 3 hours",
         lambda n: [sb.report(n, sb.within(3), p) for p in rng.sample(sb.pins[:12], 6) for _ in range(2)], KNOWN_SCAM)
    wave("W4", "A ring of 20, then 3 real people elsewhere", "20 friends in one area in one hour; 3 people in other areas on other days",
         lambda n: ([sb.report(n, sb.within(1), home) for _ in range(20)]
                    + [sb.report(n, rng.uniform(1, 6) * D, p) for p in rng.sample([x for x in sb.pins[:12] if x != home], 3)]),
         KNOWN_SCAM)
    return out, w1


# ============================================================================ row 2: lookup
def _lookup(sb, w1):
    out = []
    digits = normalise("phone", w1)[3:]                     # the 10-digit form
    forms = [w1, "0" + digits, digits, "+91-%s-%s" % (digits[:5], digits[5:]), "91" + digits]
    replies = [sb.look(f)[1] for f in forms]
    same = len({(r["verdict"], r["display_value"]) for r in replies}) == 1
    out.append(_check("L1", "The same number written 5 ways gives one answer", "GET /lookup with " + ", ".join(forms),
                      "same verdict and number", [r["verdict"] + " " + r["display_value"] for r in replies], same))
    home = sb.pins[0]
    samples = [("upi", "demo%04d@okaxis" % sb.rng.randrange(10 ** 4)),
               ("url", "https://kyc-update-%04d.example/login?x=1" % sb.rng.randrange(10 ** 4)),
               ("sender_id", "VM-" + "".join(sb.rng.choice("BCDFGHJKLMNPQRSTVWXZ") for _ in range(6)))]
    got = {}
    for itype, value in samples:
        sb.report(value, sb.within(5), home, itype=itype)
        got[itype] = sb.look(value, itype)[1]["display_value"]
    masked = all(("*" in v or "X" in v or "..." in v) for v in got.values())
    out.append(_check("L2", "UPI IDs, links and SMS sender IDs work too, masked below 3 people",
                      "one report each, then GET /lookup", "masked values", got, masked))
    n = sb.number()
    st, r = sb.look(n)
    out.append(_check("L3", "A number nobody reported", "GET /lookup on a fresh number", NO_REPORTS,
                      _brief(r), st == 200 and r["verdict"] == NO_REPORTS))
    st, r = sb.look("12345")
    out.append(_check("L4", "A bad value", "GET /lookup?type=phone&value=12345", "400 invalid_identifier",
                      {"status": st, "body": r}, st == 400 and r == {"error": "invalid_identifier"}))
    times = []
    for _ in range(200):
        t0 = time.perf_counter()
        sb.look(w1)
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    p95 = times[int(len(times) * 0.95) - 1]
    out.append(_check("L5", "Lookup speed inside the engine", "200 lookups on the sandbox engine",
                      "p95 under 50 ms", {"p95_ms": round(p95, 3), "reports_in_sandbox": len(sb.rows)}, p95 < 50))
    return out


# ============================================================================ row 3: map and alerts
def _map_alerts(registry, config, rng, now):
    out = []
    sb = Sandbox(registry, config, rng, now)
    a_spike, a_quiet, a_new, a_map = rng.sample(sb.pins[:10], 4)
    # A: 2 a day for 7 days, then 10 today, each on its own number
    for i in range(14):
        sb.report(sb.number(), D + (i / 2) * D + H, a_spike)
    for _ in range(10):
        sb.report(sb.number(), sb.within(20), a_spike)
    al = sb.engine.alerts(a_spike, now)[1]["alerts"]
    out.append(_check("A1", "A sudden jump raises an alert", "area: 2 reports a day for 7 days, then 10 today",
                      "SPIKE", al, any(a["type"] == "SPIKE" for a in al)))
    # B: a normal day
    for d in range(1, 15):
        for _ in range(2):
            sb.report(sb.number(), d * D + sb.within(20), a_quiet)
    for _ in range(3):
        sb.report(sb.number(), sb.within(20), a_quiet)
    al = sb.engine.alerts(a_quiet, now)[1]["alerts"]
    out.append(_check("A2", "A normal day raises nothing", "area: 2 a day for 14 days, 3 today",
                      "no alert", al, al == []))
    # C: a new kind of scam
    for d in range(1, 15):
        sb.report(sb.number(), d * D + sb.within(20), a_new)
    for _ in range(3):
        sb.report(sb.number(), sb.within(10), a_new, typ="job-offer")
    al = sb.engine.alerts(a_new, now)[1]["alerts"]
    out.append(_check("A3", "A new kind of scam in the area", "area: 14 days of one scam type, then 3 job-offer reports today",
                      "NEW_TYPE", al, any(a["type"] == "NEW_TYPE" for a in al)))
    # D: map window
    for days_old in (8, 6, 1):
        sb.report(sb.number(), days_old * D, a_map)
    cl = [c for c in sb.engine.map(a_map, 7, 0, now)[1]["clusters"] if c["pincode"] == a_map]
    out.append(_check("A4", "The map shows the last 7 days", "area: reports 8, 6 and 1 days old; GET /map?days=7",
                      "count 2", cl, len(cl) == 1 and cl[0]["count"] == 2))
    return out


# ============================================================================ row 4: privacy
def _privacy(sb):
    n = sb.number()
    note = "%s they called from %s and asked for my OTP" % (CANARY["note_word"], CANARY["note_phone"])
    for i in range(3):
        sb.report(n, (i + 1) * D, sb.pins[0], rid=CANARY["reporter"] + str(i), net=CANARY["network"] if i == 0 else None,
                  note=note if i == 0 else None)
    stored = sb.rows[-3]
    blob = json.dumps(sb.rows)
    leaks = [v for v in CANARY.values() if v in blob]
    shown = dict(stored)
    if isinstance(shown.get("shingles"), str) and len(shown["shingles"]) > 24:
        shown["shingles"] = shown["shingles"][:24] + "..."
    out = [_check("P1", "What the server stores about a reporter", "report with reporter ID %s, network %s and a note containing %s and a phone number"
                  % (CANARY["reporter"] + "0", CANARY["network"], CANARY["note_word"]),
                  "none of those values stored (only keyed hashes)", {"stored_row": shown, "leaked": leaks}, not leaks)]
    _, r = sb.look(n)
    text = json.dumps(r)
    bad = [k for k in ("rid", "org", "reporter", "ip", "note", "shingles") if '"%s"' % k in text]
    bad += [v for v in CANARY.values() if v in text]
    out.append(_check("P2", "What anyone can see in a lookup", "GET /lookup on that number (3 people, so evidence is shown)",
                      "no reporter, network or note; evidence is time, channel, type, area",
                      {"evidence": r.get("evidence"), "leaked": bad}, not bad))
    return out


# ============================================================================ bonus
def _bonus(registry, config, rng, now):
    out = []
    sb = Sandbox(registry, config, rng, now)
    items = registry.verified_items()
    pick = []
    for t in ("phone", "sender_id", "url", "upi"):
        pick += [x for x in items if x[0] == t][:1]
    got = {}
    for t, c, label in pick:
        r = sb.look(c, t)[1]
        got[t] = "%s (%s)" % (r["verdict"], r.get("label", ""))
    out.append(_check("B1", "Verified list: real businesses and helplines are marked safe",
                      "GET /lookup for one verified phone, SMS sender, website and UPI ID",
                      VERIFIED_BUSINESS, got, all(v.startswith(VERIFIED_BUSINESS) for v in got.values())))
    pin = rng.choice(sb.pins[:10])
    n = sb.number()
    for _ in range(5):
        sb.report(n, rng.uniform(1, 5) * D, pin)
    before = sb.look(n)[1]["verdict"]
    st, ch = sb.engine.handle_challenge({"identifier_type": "phone", "identifier_value": n,
                                         "claimant_name": "Demo Shop (made up)",
                                         "contact_email": "owner@shop.example",
                                         "proof_note": "GST certificate"}, now)
    r = sb.look(n)[1]
    on_map = any(c["pincode"] == pin for c in sb.engine.map(pin, 7, 0, now)[1]["clusters"])
    out.append(_check("B2", "Dispute: an owner can contest a listing", "5 people report a number; the owner files POST /challenges",
                      "KNOWN_SCAM before; after: SUSPICIOUS, masked, challenged, off the map",
                      {"before": before, "challenge": ch, "after": _brief(r), "challenged": r["challenged"], "on_map": on_map},
                      before == KNOWN_SCAM and st == 201 and r["verdict"] == SUSPICIOUS and r["challenged"]
                      and "X" in r["display_value"] and not on_map))
    # fake reports never alert: a quiet area, then every trick with a scam type new to the area
    sb2 = Sandbox(registry, config, rng, now)
    quiet = rng.choice(sb2.pins[:10])
    for d in range(1, 15):
        for _ in range(2):
            sb2.report(sb2.number(), d * D + sb2.within(20), quiet)
    typ = "job-offer"
    n1, n2, n3, n4, n5, n6 = (sb2.number() for _ in range(6))
    for _ in range(40):
        sb2.report(n1, sb2.within(2), quiet, typ=typ)                      # 40 friends, own words
    w = sb2.net()
    for _ in range(22):
        sb2.report(n2, sb2.within(2), quiet, net=w, typ=typ)               # one Wi-Fi
    p = sb2.rid()
    for _ in range(6):
        sb2.report(n3, sb2.within(2), quiet, rid=p, typ=typ)               # one person x6
    for _ in range(11):
        sb2.report(n4, sb2.within(1), quiet, typ=typ)                      # 1 + 10 friends
    t = sb2.words()
    for _ in range(40):
        sb2.report(n5, sb2.within(2), quiet, note=t, typ=typ)              # pasted text
    for _ in range(40):
        sb2.report(n6, sb2.within(2), quiet, note="", typ=typ)             # empty notes
    al = sb2.engine.alerts(quiet, now)[1]["alerts"]
    out.append(_check("B3", "Fake reports never raise an alert",
                      "quiet area (2 a day); then 40 friends, 22 accounts on one Wi-Fi, one person x6, 1 + 10 friends, "
                      "40 pasted texts and 40 empty notes, all with a scam type new to the area",
                      "no alert", al, al == []))
    return out


# ============================================================================ entry point
def run(registry, config, seed=None, now=None) -> dict:
    seed = int(seed) if seed not in (None, "") else random.randrange(10 ** 6)
    now = now or datetime.now(IST)
    t0 = time.perf_counter()
    rng = random.Random(seed)
    sb = Sandbox(registry, config, rng, now)
    fakes = _fake_reports(sb)
    waves, w1 = _real_waves(sb)
    sections = [
        {"row": 1, "title": "Stops fake reports", "checks": fakes + waves},
        {"row": 2, "title": "Checking a number", "checks": _lookup(sb, w1)},
        {"row": 3, "title": "Map and alerts", "checks": _map_alerts(registry, config, rng, now)},
        {"row": 4, "title": "Privacy", "checks": _privacy(sb)},
        {"row": "bonus", "title": "Bonus: verified list, disputes, no alerts from fakes",
         "checks": _bonus(registry, config, rng, now)},
    ]
    passed = sum(c["ok"] for s in sections for c in s["checks"])
    total = sum(len(s["checks"]) for s in sections)
    return {"seed": seed, "config": config.hash(), "ran_ms": round((time.perf_counter() - t0) * 1000),
            "live_data_touched": False, "passed": passed, "total": total, "sections": sections,
            "note": "Fresh in-memory engine per run, same code and config as this server. Synthetic data only."}
