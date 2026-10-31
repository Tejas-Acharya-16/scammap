"""Community Scam Map engine: the in-memory model and the request handlers.

BUILD_SPEC sections 3 (API), 5 (time and areas), 6 (trust), 7 (verdicts), 8 (map and alerts),
10 (privacy) and 12 (disputes). No I/O: storing a row is a callback the server supplies.
Every method takes `now` from the server's injected clock; nothing reads the system clock.
Thread-safe: one lock guards all state (the server runs one worker).
"""
from __future__ import annotations

import hashlib
import secrets
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Optional

from . import trust
from .config import TrustConfig
from .fingerprint import derive_key, identity_hash, network_prefix, note_fingerprint
from .normalise import InvalidIdentifier, mask, normalise, normalise_type
from .registry import Registry
from .timeutil import day_floor_ist, ensure_aware, iso_ist, parse_time

KNOWN_SCAM = "KNOWN_SCAM"
SUSPICIOUS = "SUSPICIOUS"
NO_REPORTS = "NO_REPORTS"
VERIFIED_BUSINESS = "VERIFIED_BUSINESS"

Persist = Optional[Callable[[dict], None]]


def case_id_for(identifier_type: str, canon: str) -> str:
    return "case_" + hashlib.sha256(f"{identifier_type}:{canon}".encode()).hexdigest()[:10]


# ============================================================================ records
@dataclass(frozen=True)
class Report:
    """One accepted report, as stored. No raw reporter data, no note text, no location
    finer than the registry area."""
    report_id: str
    identifier_type: str
    identifier: str
    occurred_at: datetime
    reported_at: Optional[datetime]
    received_at: datetime
    rid: str                 # keyed hash of reporter_id
    org: str                 # keyed hash of the network prefix
    channel: str
    scam_type: str           # shown to people ('other' for unknown types)
    scam_type_key: str       # used for NEW_TYPE (an unknown type keeps its own name)
    pincode: str
    note_hash: Optional[str]
    shingles: frozenset
    ntok: int
    has_screenshot: bool
    amount_lost_inr: int
    t: datetime = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        # Windows use occurred_at against the server clock (brief, rule 1). A time slightly in
        # the future (clock skew, within tolerance) counts as the moment the report arrived.
        object.__setattr__(self, "t", min(self.occurred_at, self.received_at))

    @property
    def ikey(self) -> str:
        return f"{self.identifier_type}:{self.identifier}"

    def to_row(self) -> dict:
        return {
            "report_id": self.report_id,
            "identifier_type": self.identifier_type,
            "identifier": self.identifier,
            "occurred_at": self.occurred_at.isoformat(),
            "reported_at": self.reported_at.isoformat() if self.reported_at else None,
            "received_at": self.received_at.isoformat(),
            "rid": self.rid,
            "org": self.org,
            "channel": self.channel,
            "scam_type": self.scam_type,
            "scam_type_key": self.scam_type_key,
            "pincode": self.pincode,
            "note_hash": self.note_hash,
            "shingles": " ".join(format(x, "08x") for x in sorted(self.shingles)),
            "ntok": self.ntok,
            "has_screenshot": self.has_screenshot,
            "amount_lost_inr": self.amount_lost_inr,
        }

    @classmethod
    def from_row(cls, row: dict) -> "Report":
        def when(value):
            dt = parse_time(value)
            if dt is None:
                raise ValueError("bad time in a stored report row")
            return dt

        return cls(
            report_id=str(row["report_id"]),
            identifier_type=row["identifier_type"],
            identifier=row["identifier"],
            occurred_at=when(row["occurred_at"]),
            reported_at=when(row["reported_at"]) if row.get("reported_at") else None,
            received_at=when(row["received_at"]),
            rid=row["rid"],
            org=row["org"],
            channel=row["channel"],
            scam_type=row["scam_type"],
            scam_type_key=row.get("scam_type_key") or row["scam_type"],
            pincode=str(row["pincode"]),
            note_hash=row.get("note_hash") or None,
            shingles=frozenset(int(x, 16) for x in (row.get("shingles") or "").split()),
            ntok=int(row.get("ntok") or 0),
            has_screenshot=bool(row.get("has_screenshot")),
            amount_lost_inr=int(row.get("amount_lost_inr") or 0),
        )


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    identifier_type: str
    identifier: str
    claimant_name: str
    contact_email: str
    proof_note: str
    created_at: datetime

    @property
    def ikey(self) -> str:
        return f"{self.identifier_type}:{self.identifier}"

    def to_row(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "identifier_type": self.identifier_type,
            "identifier": self.identifier,
            "claimant_name": self.claimant_name,
            "contact_email": self.contact_email,
            "proof_note": self.proof_note,
            "created_at": self.created_at.isoformat(),
            "status": "under_review",
        }


@dataclass(frozen=True)
class Prepared:
    report: Optional[Report] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class SubmitResult:
    report_id: str
    case_id: str
    merged: bool
    duplicate: bool


@dataclass(frozen=True)
class _Counted:
    t: datetime
    scam_type: str
    key: str
    personal: bool


_BAD = object()   # a malformed query value


# ============================================================================ engine
class Engine:
    def __init__(self, registry: Registry, salt: str, config: Optional[TrustConfig] = None):
        if not isinstance(salt, str) or len(salt) < 8:
            raise ValueError("TRUST_SALT must be set (at least 8 characters)")
        self.registry = registry
        self.config = config or TrustConfig()
        self._config_hash = self.config.hash()
        self._key = derive_key(salt)
        self._lock = threading.RLock()
        self._clear()

    def _clear(self) -> None:
        self._reports = defaultdict(list)     # ikey -> [Report]
        self._ids = {}                        # report_id -> {(ikey, rid)}; a retry counts once
        self._rid_index = defaultdict(dict)   # rid -> {ikey: earliest time}
        self._challenged = set()              # ikeys under dispute
        self._voices_cache = {}               # ikey -> [Voice]
        self._core_cache = {}                 # ikey -> burst core over all voices (track records)
        self._counted_cache = None            # pincode -> [_Counted]
        self._generation = 0                  # bumps on every change
        self._live_cache = None               # (days, computed_at, reply): the live summary, kept 10 s

    # ------------------------------------------------------------------ lifecycle
    def reset(self) -> None:
        """POST /admin/reset: forget every report and challenge (the server deletes the rows)."""
        with self._lock:
            self._clear()

    def load(self, report_rows: Iterable[dict] = (), challenge_rows: Iterable[dict] = ()) -> int:
        """Rebuild memory from stored rows at start-up. Returns the number of reports loaded."""
        with self._lock:
            self._clear()
            n = 0
            for row in report_rows:
                self._apply(Report.from_row(row))
                n += 1
            for row in challenge_rows:
                itype = normalise_type(row.get("identifier_type"))
                if itype:
                    self._challenged.add(f"{itype}:{row['identifier']}")
            return n

    def stats(self) -> dict:
        """Aggregate counts for STATE.md and debugging. Contains nothing about anyone."""
        with self._lock:
            return {"reports": sum(len(v) for v in self._reports.values()),
                    "identifiers": len(self._reports),
                    "challenges": len(self._challenged),
                    "config": self._config_hash}

    # ------------------------------------------------------------------ POST /reports
    def handle_report(self, body, now, client_ip=None, persist: Persist = None) -> tuple:
        prepared = self.prepare(body, now, client_ip)
        if prepared.error:
            return 400, {"error": prepared.error}
        res = self.submit(prepared.report, persist)
        return 201, {"report_id": res.report_id, "case_id": res.case_id, "merged": res.merged}

    def prepare(self, body, now, client_ip=None) -> Prepared:
        """Validate and anonymise one report. Raw identity and note text are dropped here."""
        cfg = self.config
        now = ensure_aware(now)
        if not isinstance(body, dict):
            return Prepared(error="invalid_body")
        itype = normalise_type(body.get("identifier_type"))
        if itype is None:
            return Prepared(error="invalid_identifier")
        try:
            canon = normalise(itype, body.get("identifier_value"))
        except InvalidIdentifier:
            return Prepared(error="invalid_identifier")
        pincode = _pincode(body.get("pincode"))
        if pincode is None or pincode not in self.registry.areas:
            return Prepared(error="invalid_pincode")
        occurred = parse_time(body.get("occurred_at"))
        if (occurred is None
                or occurred > now + timedelta(minutes=cfg.future_tolerance_minutes)
                or occurred < now - timedelta(days=cfg.max_age_days)):
            return Prepared(error="invalid_time")
        reported = None
        if body.get("reported_at") not in (None, ""):
            reported = parse_time(body.get("reported_at"))
            if reported is None:
                return Prepared(error="invalid_time")
        raw_id = body.get("report_id")
        report_id = (str(raw_id).strip()[:100] if raw_id not in (None, "") else "") or "rep_" + secrets.token_hex(6)

        # Identity comes from the report (brief, rule 2) and is hashed immediately.
        prefix = network_prefix(body.get("ip_prefix")) or network_prefix(client_ip) or "unknown"
        reporter = body.get("reporter_id")
        reporter = str(reporter).strip()[:200] if reporter not in (None, "") else ""
        rid = identity_hash(self._key, "rid", reporter or "net:" + prefix)
        org = identity_hash(self._key, "org", prefix)

        scam_type, type_key = self.registry.scam_type(body.get("scam_type"))
        fp = note_fingerprint(body.get("note"), self._key, cfg.note_max_chars)
        return Prepared(report=Report(
            report_id=report_id, identifier_type=itype, identifier=canon,
            occurred_at=occurred, reported_at=reported, received_at=now,
            rid=rid, org=org, channel=self.registry.channel(body.get("channel")),
            scam_type=scam_type, scam_type_key=type_key, pincode=pincode,
            note_hash=fp.note_hash, shingles=fp.shingles, ntok=fp.ntok,
            has_screenshot=_flag(body.get("has_screenshot")),
            amount_lost_inr=_amount(body.get("amount_lost_inr")),
        ))

    def submit(self, report: Report, persist: Persist = None) -> SubmitResult:
        """Store (via `persist`) then apply. A retry with the same report_id, identifier and
        reporter is answered with the same case and counted once."""
        with self._lock:
            ikey = report.ikey
            cid = case_id_for(report.identifier_type, report.identifier)
            if (ikey, report.rid) in self._ids.get(report.report_id, ()):
                return SubmitResult(report.report_id, cid, True, True)
            merged = bool(self._reports.get(ikey))
            if persist is not None:
                persist(report.to_row())     # memory changes only if storing succeeded
            self._apply(report)
            return SubmitResult(report.report_id, cid, merged, False)

    def _apply(self, r: Report) -> None:
        ikey = r.ikey
        self._reports[ikey].append(r)
        self._ids.setdefault(r.report_id, set()).add((ikey, r.rid))
        seen = self._rid_index[r.rid]
        if ikey not in seen or r.t < seen[ikey]:
            seen[ikey] = r.t
        self._voices_cache.pop(ikey, None)
        self._core_cache.pop(ikey, None)
        self._counted_cache = None
        self._generation += 1

    # ------------------------------------------------------------------ POST /challenges
    def handle_challenge(self, body, now, persist: Persist = None) -> tuple:
        if not isinstance(body, dict):
            return 400, {"error": "invalid_body"}
        itype = normalise_type(body.get("identifier_type"))
        if itype is None:
            return 400, {"error": "invalid_identifier"}
        try:
            canon = normalise(itype, body.get("identifier_value"))
        except InvalidIdentifier:
            return 400, {"error": "invalid_identifier"}
        ch = Challenge(
            challenge_id="ch_" + secrets.token_hex(6),
            identifier_type=itype,
            identifier=canon,
            claimant_name=_text(body.get("claimant_name"), 100),
            contact_email=_text(body.get("contact_email"), 200),
            proof_note=_text(body.get("proof_note"), 1000),
            created_at=ensure_aware(now),
        )
        with self._lock:
            if persist is not None:
                persist(ch.to_row())
            self._challenged.add(ch.ikey)
            self._counted_cache = None
            self._generation += 1
        return 201, {"challenge_id": ch.challenge_id, "status": "under_review"}

    # ------------------------------------------------------------------ GET /lookup
    def lookup(self, identifier_type, value, now) -> tuple:
        now = ensure_aware(now)
        itype = normalise_type(identifier_type)
        if itype is None:
            return 400, {"error": "invalid_identifier"}
        try:
            canon = normalise(itype, value)
        except InvalidIdentifier:
            return 400, {"error": "invalid_identifier"}
        cfg = self.config
        with self._lock:
            ikey = f"{itype}:{canon}"
            reports = self._reports.get(ikey, [])
            label = self.registry.verified_label(itype, canon)
            challenged = ikey in self._challenged
            voices, proven, burst = self._final(ikey)
            n, points_q = trust.score(voices, proven, cfg)
            if label is not None:
                verdict = VERIFIED_BUSINESS
            elif not reports:
                verdict = NO_REPORTS
            elif n >= cfg.min_voices and points_q >= cfg.min_points_q and not challenged:
                verdict = KNOWN_SCAM
            else:
                verdict = SUSPICIOUS
            hold = False
            if burst and verdict == SUSPICIOUS and not challenged:
                # Say so only when the burst rule changed the answer.
                raw = self._voices(ikey)
                rn, rq = trust.score(raw, [self._proven(v, ikey) for v in raw], cfg)
                hold = rn >= cfg.min_voices and rq >= cfg.min_points_q
            confirmed = n >= cfg.min_voices          # "3 different people" after the trust rules
            show_full = label is not None or (confirmed and not challenged)
            body = {
                "verdict": verdict,
                "report_count": len(reports),
                "distinct_reporters": n,
                "first_seen": None,
                "last_seen": None,
                "scam_type": None,
                "display_value": canon if show_full else mask(itype, canon),
                "evidence": [],
                "challenged": challenged,
                "type": itype,
                "trust": {"voices": n, "points": points_q / 4, "needed": cfg.min_points_q / 4,
                          "burst_voices": burst,
                          "hold": "burst_from_new_accounts_in_one_area" if hold else None,
                          "config": self._config_hash},
            }
            if label is not None:
                body["label"] = label
            if reports:
                first = min(r.occurred_at for r in reports)
                last = max(r.occurred_at for r in reports)
                if not confirmed:                     # a precise time plus an area can point to a person
                    first, last = day_floor_ist(first), day_floor_ist(last)
                body["first_seen"], body["last_seen"] = iso_ist(first), iso_ist(last)
                body["scam_type"] = _top_type([(v.first.scam_type, v.first.t) for v in voices])
                if confirmed and label is None:
                    latest = sorted(voices, key=lambda v: v.first.t, reverse=True)[: cfg.evidence_max]
                    body["evidence"] = [{"occurred_at": iso_ist(v.first.occurred_at),
                                         "channel": v.first.channel,
                                         "scam_type": v.first.scam_type,
                                         "pincode": v.first.pincode} for v in latest]
            return 200, body

    # ------------------------------------------------------------------ GET /map
    def map(self, pincode=None, days=None, radius_km=None, now=None) -> tuple:
        now = ensure_aware(now)
        pin = _query_pincode(pincode)
        if pin is _BAD:
            return 400, {"error": "invalid_pincode"}
        days_n = _num(days, 7, 1, 60, int)
        radius = _num(radius_km, 2.0, 0.0, 100.0, float)
        with self._lock:
            counted = self._counted_by_area()
            if pin is None:
                areas = [self.registry.areas[p] for p in counted if p in self.registry.areas]
            elif pin not in self.registry.areas:
                return 200, {"clusters": []}
            else:
                areas = self.registry.within(pin, radius)
            start = now - timedelta(days=days_n)
            clusters = []
            for a in areas:
                cv = [c for c in counted.get(a.pincode, ()) if start < c.t <= now]
                if not cv:
                    continue
                count = len(cv)
                clusters.append({
                    "pincode": a.pincode, "locality": a.area, "city": a.city, "count": count,
                    "top_scam_type": _top_type([(c.scam_type, c.t) for c in cv]),
                    "severity": "CRIT" if count >= 10 else "HIGH" if count >= 5 else "MED",
                    "lat": a.lat, "lng": a.lng,
                })
            clusters.sort(key=lambda c: (-c["count"], c["pincode"]))
            return 200, {"clusters": clusters}

    # ------------------------------------------------------------------ GET /alerts
    def alerts(self, pincode=None, now=None) -> tuple:
        now = ensure_aware(now)
        pin = _query_pincode(pincode)
        if pin is _BAD:
            return 400, {"error": "invalid_pincode"}
        cfg = self.config
        day = timedelta(hours=24)
        with self._lock:
            counted = self._counted_by_area()
            if pin is None:
                pins = sorted(p for p in counted if p in self.registry.areas)
            elif pin not in self.registry.areas:
                return 200, {"alerts": []}
            else:
                pins = [pin]
            out = []
            for p in pins:
                cv = counted.get(p, ())
                recent = [c for c in cv if now - day < c.t <= now]
                base_n = sum(1 for c in cv if now - 8 * day < c.t <= now - day)
                # SPIKE: last 24 h at least `spike_min` and at least double the daily average
                # of the 7 days before.
                if len(recent) >= cfg.spike_min and len(recent) * 7 >= cfg.spike_factor * base_n:
                    out.append({"type": "SPIKE", "pincode": p, "window": "24h",
                                "count": len(recent), "baseline_per_day": round(base_n / 7, 2)})
                # NEW_TYPE: a scam type in the last 24 h not seen in this area in the 30 days before.
                lookback = now - day - timedelta(days=cfg.new_type_lookback_days)
                seen = {c.key for c in cv if lookback < c.t <= now - day}
                fresh = defaultdict(list)
                for c in recent:
                    if c.key not in seen:
                        fresh[c.key].append(c)
                for key in sorted(fresh):
                    group = fresh[key]
                    if (len(group) >= cfg.new_type_min_voices
                            or (cfg.new_type_personal_alone and any(c.personal for c in group))):
                        out.append({"type": "NEW_TYPE", "pincode": p, "scam_type": key,
                                    "window": "24h", "count": len(group)})
            return 200, {"alerts": out}

    # ------------------------------------------------------------------ GET /live/summary
    def live_summary(self, now=None, days=None) -> tuple:
        """The live scam map: areas, top scam types, most reported numbers and alerts in one reply.
        An extra route for our own page, not part of the brief's API. Built only from counted
        (clean) voices, at area level, so it carries nothing about any reporter. Cached for 10 s."""
        now = ensure_aware(now)
        days_n = _num(days, 7, 1, 30, int)
        cfg = self.config
        with self._lock:
            key = days_n
            cached = self._live_cache   # one rebuild per 10 s at most, however many pages poll it
            if cached and cached[0] == key and 0 <= (now - cached[1]).total_seconds() < 10:
                return 200, cached[2]
            start, day_ago = now - timedelta(days=days_n), now - timedelta(hours=24)
            areas, all_types, type_areas, total, last_24h = [], Counter(), defaultdict(set), 0, 0
            for pin, cv in self._counted_by_area().items():
                area = self.registry.areas.get(pin)
                if area is None:
                    continue
                window = [c for c in cv if start < c.t <= now]
                if not window:
                    continue
                types = Counter(c.scam_type for c in window)
                recent = sum(1 for c in window if c.t > day_ago)
                count = len(window)
                total += count
                last_24h += recent
                for t, k in types.items():
                    all_types[t] += k
                    type_areas[t].add(pin)
                areas.append({
                    "pincode": pin, "locality": area.area, "city": area.city, "lat": area.lat, "lng": area.lng,
                    "count": count, "last_24h": recent,
                    "severity": "CRIT" if count >= 10 else "HIGH" if count >= 5 else "MED",
                    "top_types": [{"scam_type": t, "count": k} for t, k in sorted(types.items(), key=lambda x: (-x[1], x[0]))[:3]],
                })
            areas.sort(key=lambda a: (-a["count"], a["pincode"]))
            top_types = [{"scam_type": t, "count": k, "areas": len(type_areas[t])}
                         for t, k in sorted(all_types.items(), key=lambda x: (-x[1], x[0]))[:6]]
            # Most reported numbers: only ones that are KNOWN_SCAM now (3+ independent voices), so the
            # full value may be shown; never verified or disputed ones.
            known = []
            for ikey, reports in self._reports.items():
                if len(reports) < cfg.min_voices or self._excluded(ikey):
                    continue
                if not any(start < r.t <= now for r in reports):
                    continue
                voices, proven, _ = self._final(ikey)
                n, points_q = trust.score(voices, proven, cfg)
                if n < cfg.min_voices or points_q < cfg.min_points_q:
                    continue
                itype, canon = ikey.split(":", 1)
                last = max(r.occurred_at for r in reports)
                known.append((n, last, {
                    "type": itype, "display_value": canon, "voices": n,
                    "scam_type": _top_type([(v.first.scam_type, v.first.t) for v in voices]),
                    "last_seen": iso_ist(day_floor_ist(last)),
                }))
            known.sort(key=lambda x: (-x[0], -x[1].timestamp()))
            reply = {
                "updated_at": iso_ist(now), "window_days": days_n,
                "total": total, "last_24h": last_24h, "areas_active": len(areas), "known_numbers": len(known),
                "top_types": top_types, "areas": areas,
                "top_numbers": [k[2] for k in known[:5]],
                "alerts": self.alerts(None, now)[1]["alerts"],
            }
            self._live_cache = (key, now, reply)
            return 200, reply

    # ------------------------------------------------------------------ internals
    def _voices(self, ikey: str) -> list:
        v = self._voices_cache.get(ikey)
        if v is None:
            v = trust.build_voices(self._reports.get(ikey, []), self.config)
            self._voices_cache[ikey] = v
        return v

    def _core_all(self, ikey: str) -> list:
        """Burst core over ALL voices (no track-record check), cached. Used only to count an
        identifier's independent voices for track records, so it never depends on other identifiers."""
        c = self._core_cache.get(ikey)
        if c is None:
            c = trust.burst_core(self._voices(ikey), self.config)
            self._core_cache[ikey] = c
        return c

    def _independent(self, ikey: str) -> int:
        """Voices on an identifier, a burst counted once. A ring cannot confirm a number by bursting
        it and then use that number as a track record."""
        core = self._core_all(ikey)
        return len(self._voices(ikey)) - (len(core) - 1 if core else 0)

    def _final(self, ikey: str, need_proven: bool = True) -> tuple:
        """(voices, proven, burst size) after rule 5: brand-new voices (no track record) that form a
        burst in one area merge into one linked voice. No burst over all voices means none over a subset."""
        voices = self._voices(ikey)
        if not self._core_all(ikey):
            proven = [self._proven(v, ikey) for v in voices] if need_proven else None
            return voices, proven, 0
        proven = [self._proven(v, ikey) for v in voices]
        core = trust.burst_core(voices, self.config, eligible=[not p for p in proven])
        if not core:
            return voices, proven, 0
        merged, merged_proven = trust.merge_burst(voices, proven, core)
        return merged, merged_proven, len(core)

    def _excluded(self, ikey: str) -> bool:
        """Verified or disputed identifiers never confirm a track record and never move the map."""
        if ikey in self._challenged:
            return True
        itype, canon = ikey.split(":", 1)
        return self.registry.verified_label(itype, canon) is not None

    def _proven(self, voice, ikey: str) -> bool:
        """Track record: a reporter in this voice earlier reported a different identifier that
        at least `proven_other_voices` other voices confirmed (and that is not verified or disputed)."""
        cfg = self.config
        for rid in voice.rids:
            for other, t_other in self._rid_index.get(rid, {}).items():
                if other == ikey:
                    continue
                if cfg.proven_requires_earlier and t_other >= voice.first.t:
                    continue
                if self._excluded(other):
                    continue
                if self._independent(other) - 1 >= cfg.proven_other_voices:
                    return True
        return False

    def _counted_by_area(self) -> dict:
        if self._counted_cache is None:
            by_area = defaultdict(list)
            for ikey, reports in self._reports.items():
                if not reports or self._excluded(ikey):
                    continue
                voices, _, _ = self._final(ikey, need_proven=False)
                for v in trust.counted_voices(voices, self.config):
                    f = v.first
                    by_area[f.pincode].append(_Counted(f.t, f.scam_type, f.scam_type_key, v.personal))
            self._counted_cache = by_area
        return self._counted_cache


# ============================================================================ helpers
def _top_type(pairs):
    """Most common type; a tie goes to the type reported most recently."""
    if not pairs:
        return None
    count = Counter(t for t, _ in pairs)
    latest = {}
    for t, when in pairs:
        if t not in latest or when > latest[t]:
            latest[t] = when
    return max(count, key=lambda t: (count[t], latest[t]))


def _pincode(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        v = str(v)
    if not isinstance(v, str):
        return None
    s = v.strip()
    return s if len(s) == 6 and s.isascii() and s.isdigit() else None


def _query_pincode(v):
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    p = _pincode(v)
    return p if p is not None else _BAD


def _num(v, default, lo, hi, cast):
    if v is None or v == "":
        return default
    try:
        x = cast(float(v))
    except (TypeError, ValueError, OverflowError):
        return default
    if x != x:
        return default
    return max(lo, min(hi, x))


def _flag(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return False


def _amount(v) -> int:
    if isinstance(v, bool):
        return 0
    try:
        x = float(v)
    except (TypeError, ValueError, OverflowError):
        return 0
    if x != x or x < 0:
        return 0
    return int(min(x, 1e10))


def _text(v, limit: int) -> str:
    return v.strip()[:limit] if isinstance(v, str) else ""
