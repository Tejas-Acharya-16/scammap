"""Train the AI campaign watchdog on a randomised attack simulator. Standard library only.

    python tools/train_watchdog.py              # train, evaluate, write app/data/watchdog_model.json
    python tools/train_watchdog.py --check      # evaluate the shipped model only

Training data: synthetic worlds in which a randomised attacker plants campaigns and randomised
groups of real victims report real scams. Both sides draw their size from the same range (3 to 50
reports), so size alone says nothing. Each attacker independently decides whether to pay for each
disguise: many networks, many accounts, aged accounts, patience (spreading over days), unique words,
different areas. The model has to learn which combinations give a campaign away.

Evaluation: held-out simulator worlds (other seeds), then the 40 hand-written scenarios in
tests/engine/scenarios.py, which the model never trains on. Synthetic data only: numbers in
+91 90000 xxxxx, made-up reporters and networks. "Accuracy" here means in our simulator.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.engine import TrustConfig, normalise                           # noqa: E402
from app.engine.watchdog import FEATURES, MODEL_PATH, Watchdog, features  # noqa: E402
from tests.engine import scenarios as sc                                # noqa: E402
from tests.engine.scenarios import (AREAS, NOW, TYPES, D, H, free_note, new_number,  # noqa: E402
                                    new_prefix, new_rid, paraphrase, templ_note, words)

EXAMPLE = "caller said my parcel has drugs and asked me to pay to avoid arrest"
MIN = H / 60


def loguniform(rng, lo, hi):
    return math.exp(rng.uniform(math.log(lo), math.log(hi)))


def fresh(world):
    rng = world.rng
    n = new_number(rng)
    while n in world.used:
        n = new_number(rng)
    return n


def real_wave(world, rng):
    """Independent victims of one real scam number."""
    target, typ = fresh(world), rng.choice(TYPES)
    n = int(round(loguniform(rng, 3, 50)))
    hist = rng.uniform(0.1, 0.7) if rng.random() < 0.5 else 0.0          # some have reported before
    carrier = [new_prefix(rng) for _ in range(rng.randint(2, 6))]         # shared mobile networks
    share = rng.uniform(0.1, 0.5) if rng.random() < 0.5 else 0.0
    dur = loguniform(rng, 1, 14 * 24) * H                                  # a wave of 1 hour to 2 weeks
    end = NOW - rng.uniform(0, 2) * D
    if rng.random() < 0.5:
        local = rng.sample(AREAS, rng.randint(1, 3))                       # a local scam
        area = lambda: rng.choice(local)
    else:
        area = lambda: rng.choice(AREAS)                                   # a scam dialling anyone
    # Lazy test tools are real too: one example sentence or empty notes for every report (rows J1-J6).
    style = rng.choices(["own", "mixed", "empty", "example", "templ", "short"], [30, 22, 15, 15, 10, 8])[0]
    for _ in range(n):
        if rng.random() < hist:
            rid, prefix = rng.choice(world.pool)
        else:
            rid, prefix = new_rid(rng), new_prefix(rng)
        if rng.random() < share:
            prefix = rng.choice(carrier)
        when = end - dur * rng.random() ** 1.5
        filed = min(when + loguniform(rng, 2, 48 * 60) * MIN, NOW)       # minutes to two days later
        s = rng.choice(["own", "empty", "templ", "short"]) if style == "mixed" else style
        note = {"own": free_note, "templ": templ_note, "short": lambda r: words(r, 2, 5),
                "empty": lambda r: "", "example": lambda r: EXAMPLE}[s](rng)
        world.report(target, when, area(), typ, note, rid, prefix, reported=filed)
    return target


def campaign(world, rng):
    """One attacker planting reports. Each disguise is a separate choice with its own cost."""
    target, typ = fresh(world), rng.choice(TYPES)
    n = int(round(loguniform(rng, 3, 50)))
    if rng.random() < 0.65:                                                # enough accounts for each report
        accounts = [new_rid(rng) for _ in range(n)]
    else:                                                                  # a few accounts, reused
        accounts = [new_rid(rng) for _ in range(rng.randint(1, max(1, n // 3)))]
    if rng.random() < 0.15:                                                # bought or borrowed aged accounts
        aged = rng.uniform(0.2, 0.8)
        accounts = [rng.choice(world.pool)[0] if rng.random() < aged else a for a in accounts]
    if rng.random() < 0.45:                                                # proxies: a network per report
        net = lambda i: new_prefix(rng)
    else:
        nets = [new_prefix(rng) for _ in range(rng.randint(1, max(1, n // 4)))]
        net = lambda i: nets[i % len(nets)]
    patient = rng.random() < 0.3                                           # spread over days
    backdate = not patient and rng.random() < 0.25                         # claim old calls, file now
    if patient:
        dur, end = loguniform(rng, 24, 14 * 24) * H, NOW - rng.uniform(0, 2) * D
    else:
        dur, end = loguniform(rng, 0.2, 6) * H, NOW - rng.uniform(0, 1) * D
    home = rng.choice(AREAS)
    where = rng.choices(["one", "each", "random"], [50, 25, 25])[0]
    order = rng.sample(AREAS, len(AREAS))
    area = {"one": lambda i: home, "each": lambda i: order[i % len(order)],
            "random": lambda i: rng.choice(AREAS)}[where]
    style = rng.choices(["same", "paraphrase", "canned", "own", "empty", "example"], [20, 15, 20, 25, 15, 5])[0]
    same, canned = free_note(rng), [words(rng, 2, 12) for _ in range(rng.randint(3, 10))]
    for i in range(n):
        when = end - dur * rng.random()
        if patient:
            filed = min(when + loguniform(rng, 2, 48 * 60) * MIN, NOW)
        else:
            filed = min(when + rng.uniform(1, 30) * MIN, NOW)
        if backdate:
            when = filed - rng.uniform(0.5, 7) * D
        note = {"same": lambda: same, "paraphrase": lambda: paraphrase(rng), "canned": lambda: rng.choice(canned),
                "own": lambda: free_note(rng), "empty": lambda: "", "example": lambda: EXAMPLE}[style]()
        world.report(target, when, area(i), typ, note, accounts[i % len(accounts)], net(i), reported=filed)
    return target


def sample(engine, number):
    ikey = "phone:" + normalise("phone", number)
    reports = engine._reports[ikey]
    voices = engine._voices(ikey)
    return features(reports, voices, [engine._proven(v, ikey) for v in voices])


def simulator(seeds, per_world=60):
    """(features, labels, verdicts): 1 = planted campaign, 0 = real wave; the rules' verdict for each."""
    X, y, v = [], [], []
    for s in seeds:
        world = sc.World(random.Random(77_000 + s), TrustConfig())
        world.background()
        rng = world.rng
        planted = [(campaign(world, rng), 1) if rng.random() < 0.5 else (real_wave(world, rng), 0)
                   for _ in range(per_world)]
        for number, label in planted:
            X.append(sample(world.engine, number)); y.append(label)
            v.append(world.engine.lookup("phone", number, NOW)[1]["verdict"])
    return X, y, v


def catalogue(seeds):
    """The hand-written scenarios (never used for training)."""
    rows = []
    for s in seeds:
        world = sc.World(random.Random(9000 + s), TrustConfig())
        world.background()
        for name, *_ in sc.LOOKUP_ROWS:
            number = sc.scenario(world, name)
            ikey = "phone:" + normalise("phone", number)
            if ikey in world.engine._reports:
                rows.append((name, sample(world.engine, number)))
    return rows


def solve(A, b):
    n = len(b)
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c]))
        M[c], M[p] = M[p], M[c]
        if abs(M[c][c]) < 1e-12:
            continue
        for r in range(n):
            if r != c:
                f = M[r][c] / M[c][c]
                for k in range(c, n + 1):
                    M[r][k] -= f * M[c][k]
    return [M[i][n] / M[i][i] if abs(M[i][i]) > 1e-12 else 0.0 for i in range(n)]


def _irls(Z, y, sw, active, l2, iters):
    k = len(active)
    w = [0.0] * k
    for _ in range(iters):
        g = [0.0] * k
        Hm = [[0.0] * k for _ in range(k)]
        for z, t, c in zip(Z, y, sw):
            zz = [z[a] for a in active]
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, sum(wi * zi for wi, zi in zip(w, zz))))))
            q = c * p * (1 - p)
            for i in range(k):
                g[i] += c * (p - t) * zz[i]
                zi = q * zz[i]
                row = Hm[i]
                for j in range(i, k):
                    row[j] += zi * zz[j]
        for i in range(k):
            for j in range(i):
                Hm[i][j] = Hm[j][i]
        for i in range(1, k):                    # no penalty on the bias (index 0)
            g[i] += l2 * w[i]
            Hm[i][i] += l2
        step = solve(Hm, g)
        w = [wi - si for wi, si in zip(w, step)]
        if max(abs(si) for si in step) < 1e-7:
            break
    return w


def fit(X, y, sw, l2=2.0, iters=30):
    """Logistic regression with weights constrained to zero or more: Newton's method (IRLS) with an
    L2 penalty on standardised features; any feature whose weight comes out negative is dropped and
    the rest refitted, until all weights are zero or positive."""
    d = len(X[0])
    mean = [sum(x[j] for x in X) / len(X) for j in range(d)]
    std = [math.sqrt(sum((x[j] - mean[j]) ** 2 for x in X) / len(X)) or 1.0 for j in range(d)]
    Z = [[1.0] + [(x[j] - mean[j]) / std[j] for j in range(d)] for x in X]
    active = list(range(d + 1))
    while True:
        w = _irls(Z, y, sw, active, l2, iters)
        worst = min(range(1, len(active)), key=lambda i: w[i], default=None)
        if worst is None or w[worst] >= 0:
            break
        del active[worst]
    full = [0.0] * (d + 1)
    for a, wi in zip(active, w):
        full[a] = wi
    return {"features": list(FEATURES), "mean": mean, "std": std, "bias": full[0], "weights": full[1:]}


def auc(scores, y):
    pos = [s for s, t in zip(scores, y) if t == 1]
    neg = [s for s, t in zip(scores, y) if t == 0]
    wins = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg)
    return wins / max(1, len(pos) * len(neg))


def metrics(wd, X, y, verdicts=None):
    s = [wd.score(x)[0] for x in X]
    tp = sum(1 for a, t in zip(s, y) if a >= 0.5 and t == 1)
    fp = sum(1 for a, t in zip(s, y) if a >= 0.5 and t == 0)
    fn = sum(1 for a, t in zip(s, y) if a < 0.5 and t == 1)
    tn = sum(1 for a, t in zip(s, y) if a < 0.5 and t == 0)
    out = {"n": len(y), "accuracy": round((tp + tn) / len(y), 3), "precision": round(tp / max(1, tp + fp), 3),
           "recall": round(tp / max(1, tp + fn), 3), "false_alarm_rate": round(fp / max(1, fp + tn), 3),
           "auc": round(auc(s, y), 3)}
    if verdicts is not None:
        # The gap the watchdog exists for: planted campaigns that the rules confirmed anyway.
        beat = [a for a, t, v in zip(s, y, verdicts) if t == 1 and v == "KNOWN_SCAM"]
        real = [a for a, t, v in zip(s, y, verdicts) if t == 0 and v == "KNOWN_SCAM"]
        fakes = sum(y)
        out["campaigns_that_beat_the_rules"] = f"{len(beat)} of {fakes}"
        out["of_those_flagged"] = f"{sum(1 for a in beat if a >= 0.5)} of {len(beat)}"
        out["confirmed_real_waves_flagged"] = f"{sum(1 for a in real if a >= 0.5)} of {len(real)}"
    return out


def catalogue_table(wd, rows):
    per = {}
    for name, x in rows:
        per.setdefault(name, []).append(wd.score(x)[0])
    out = []
    for name, desc, *_ in sc.LOOKUP_ROWS:
        v = per.get(name, [])
        if v:
            out.append((name, desc, sum(v) / len(v), sum(1 for a in v if a >= 0.5) / len(v)))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="evaluate the shipped model, do not train")
    ap.add_argument("--worlds", type=int, default=120)
    a = ap.parse_args(argv)
    if a.check:
        model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    else:
        X, y, v = simulator(range(a.worlds))
        # The confirmed cases count three times: a campaign that beat the rules is what the watchdog
        # is for, and a confirmed real wave is where a false alarm would do the most harm.
        model = fit(X, y, [3.0 if verdict == "KNOWN_SCAM" else 1.0 for verdict in v])
        model["version"] = "watchdog-v1"
        model["training"] = (f"{len(y)} synthetic identifiers from {a.worlds} worlds of our randomised attack "
                             f"simulator ({sum(y)} planted campaigns, {len(y) - sum(y)} real waves)")
        model["train"] = metrics(Watchdog(model), X, y, v)
    wd = Watchdog(model)
    Xh, yh, vh = simulator(range(1000, 1030))
    held = metrics(wd, Xh, yh, vh)
    table = catalogue_table(wd, catalogue(range(10)))
    fakes = [r for r in table if r[0][0] in "FK"]
    reals = [r for r in table if r[0][0] in "RJ" and r[0] != "R15"]
    model["held_out"] = held
    model["catalogue"] = {
        "seeds": 10,
        "fake_rows_flagged": f"{sum(1 for r in fakes if r[3] >= 0.5)} of {len(fakes)}",
        "real_rows_flagged": f"{sum(1 for r in reals if r[3] >= 0.5)} of {len(reals)}",
        "rows": {r[0]: round(r[2], 2) for r in table},
    }
    if not a.check:
        MODEL_PATH.write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8")
    print("train   ", json.dumps(model.get("train")))
    print("held-out", json.dumps(held))
    print("catalogue (never trained on): fake rows flagged", model["catalogue"]["fake_rows_flagged"],
          "| real rows flagged", model["catalogue"]["real_rows_flagged"], "(R15 holds a ring: shown, not counted)")
    for name, desc, mean, rate in table:
        print(f"  {mean:5.2f}  flagged {rate:4.0%}  {name:<4} {desc}")
    for f, w in sorted(zip(FEATURES, model["weights"]), key=lambda t: -abs(t[1])):
        print(f"  weight {w:+.2f}  {f}")


if __name__ == "__main__":
    main()
