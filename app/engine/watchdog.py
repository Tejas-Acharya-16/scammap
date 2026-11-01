"""AI campaign watchdog: a small logistic-regression model that scores how coordinated the reports
on one identifier look (a planted campaign) against an independent wave of real victims.

Advisory only. It never sets, raises or lowers a verdict: the deterministic trust rules decide, and
the watchdog flags patterns for a human to review, including ones the rules do not catch (friends
who each pick a different area). Trained offline by tools/train_watchdog.py on our own randomised
attack simulator; the weights are in app/data/watchdog_model.json and printed in the README.

Inference is one dot product over 15 aggregate features of the stored reports, with weights that
can only be zero or positive (each feature points towards "coordinated"). It never sees a
reporter's identity, a network, a note's words or a location finer than the area, and it never
looks at how many reports there are: only at how they relate to each other.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

# Every feature points the same way: a higher value looks more coordinated. The model's weights are
# constrained to be zero or positive, so no signal can ever count in the "wrong" direction (copied
# text can never make reports look more independent).
FEATURES = (
    "linked_share",     # reports linked to another by the same reporter, network or copied text
    "new_share",        # voices with no track record
    "shared_net_share", # reports from a network another report already used
    "burst1_share",     # most reports inside any 1-hour window, as a share
    "burst6_share",     # most reports inside any 6-hour window, as a share
    "area_top_share",   # share from the busiest area
    "area_spread",      # distinct areas per report
    "empty_share",      # reports with no words
    "dup_text_share",   # reports whose exact text another reporter also sent
    "short_span",       # minus log(1 + hours from the first to the last report)
    "backdated",        # filed inside one hour, but describing calls spread wider than that
    "dup_x_burst",      # copied text, and within 6 hours
    "empty_x_burst",    # no words, and within 6 hours
    "spread_x_burst",   # a different area each, and within 1 hour
    "new_x_burst",      # no track record, and within 1 hour
)
BASE = 11               # the first 11 are single signals; the last 4 are combinations

# Plain words for each feature: (above usual: looks coordinated, below usual: looks independent).
SIGNALS = {
    "linked_share": ("the same people or networks reporting again and again", "a separate person behind every report"),
    "new_share": ("reporters with no track record", "reporters with a track record"),
    "shared_net_share": ("many reports from the same few networks", "a different network for every report"),
    "burst1_share": ("most reports within one hour", "reports spread across the day"),
    "burst6_share": ("most reports within six hours", "reports spread across days"),
    "area_top_share": ("most reports from one area", "reports from many areas"),
    "area_spread": ("a different area for every report", "reports clustered in a few areas"),
    "empty_share": ("reports with no words of their own", "reports in people's own words"),
    "dup_text_share": ("the same text sent by several reporters", "different words in every report"),
    "short_span": ("all reports within a short time", "reports spread over a long time"),
    "backdated": ("filed together, but describing calls days apart", "filed around when the calls happened"),
    "dup_x_burst": ("the same text, all within a few hours", "no copied text in a rush"),
    "empty_x_burst": ("empty reports, all within a few hours", "no rush of empty reports"),
    "spread_x_burst": ("a different area each, all within one hour", "no area-hopping rush"),
    "new_x_burst": ("brand-new reporters, all within one hour", "no rush of brand-new reporters"),
}

MODEL_PATH = Path(__file__).resolve().parents[1] / "data" / "watchdog_model.json"
MIN_REPORTS = 3


def _max_in_window(times, window) -> int:
    best, lo = 0, 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def features(reports, voices, proven) -> list:
    """The 15 features for one identifier, from its stored reports, its raw voices (before the
    burst rule merges anything) and each voice's track record."""
    n = len(reports)
    if n == 0:
        return [0.0] * len(FEATURES)
    times = sorted(r.t for r in reports)
    filed = sorted(min(r.reported_at or r.t, r.received_at) for r in reports)
    stamped = len({r.reported_at for r in reports if r.reported_at is not None})
    pins = Counter(r.pincode for r in reports)
    writers = defaultdict(set)
    for r in reports:
        if r.note_hash:
            writers[r.note_hash].add(r.rid)
    dup = sum(1 for r in reports if r.note_hash and len(writers[r.note_hash]) >= 2) / n
    span_h = (times[-1] - times[0]).total_seconds() / 3600.0
    b1 = _max_in_window(times, timedelta(hours=1)) / n
    b6 = _max_in_window(times, timedelta(hours=6)) / n
    # Filed together but describing older calls. Only when the filing times look human: a single
    # stamp, no stamps, or every stamp within 5 minutes is how bulk tools write data, not a ring.
    human = stamped > 2 and filed[-1] - filed[0] >= timedelta(minutes=5)
    f1 = _max_in_window(filed, timedelta(hours=1)) / n if human else b1
    new = (1.0 - sum(1 for p in proven if p) / len(voices)) if voices else 1.0
    empty = sum(1 for r in reports if r.ntok == 0) / n
    spread = len(pins) / n
    return [
        1.0 - len(voices) / n,
        new,
        1.0 - len({r.org for r in reports}) / n,
        b1,
        b6,
        pins.most_common(1)[0][1] / n,
        spread,
        empty,
        dup,
        -math.log1p(max(0.0, span_h)),
        max(0.0, f1 - b1),
        dup * b6,
        empty * b6,
        spread * b1,
        new * b1,
    ]


class Watchdog:
    def __init__(self, model: dict):
        if tuple(model["features"]) != FEATURES:
            raise ValueError("model was trained on other features")
        self.mean, self.std = model["mean"], model["std"]
        self.w, self.b = model["weights"], model["bias"]
        self.version = model.get("version", "watchdog")

    @classmethod
    def load(cls, path=MODEL_PATH):
        """The shipped model, or None. No model means no watchdog; the verdicts never depend on it."""
        try:
            return cls(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def score(self, x) -> tuple:
        """(probability the reports are coordinated, up to 3 reasons). The reasons explain the result:
        the strongest signals pushing it up when it is 0.5 or more, else the strongest pulling it down."""
        z = [(xi - m) / s if s else 0.0 for xi, m, s in zip(x, self.mean, self.std)]
        contrib = [wi * zi for wi, zi in zip(self.w, z)]
        logit = self.b + sum(contrib)
        p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, logit))))
        if p >= 0.5:
            top = sorted(((c, i) for i, c in enumerate(contrib) if c > 0.25), reverse=True)[:3]
            reasons = [(FEATURES[i] + "+", SIGNALS[FEATURES[i]][0]) for _, i in top]
        else:
            top = sorted((c, i) for i, c in enumerate(contrib[:BASE]) if c < -0.25)[:3]
            reasons = [(FEATURES[i] + "-", SIGNALS[FEATURES[i]][1]) for _, i in top]
        return p, reasons

    def assess(self, reports, voices, proven) -> dict:
        p, reasons = self.score(features(reports, voices, proven))
        level = "high" if p >= 0.8 else "medium" if p >= 0.5 else "low"
        return {"coordinated": round(p, 2), "level": level,
                "signals": [text for _, text in reasons], "signal_codes": [code for code, _ in reasons],
                "model": self.version, "advisory": True}
