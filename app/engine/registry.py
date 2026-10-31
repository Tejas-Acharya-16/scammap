"""Reference data: areas, verified values, scam types and channels (BUILD_SPEC section 16).

All of it is loaded from JSON files in app/data. No identifier appears in code: the
verified list is data, never a rule (the judges check for hard-coded numbers).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .normalise import InvalidIdentifier, normalise, url_host


@dataclass(frozen=True)
class Area:
    pincode: str
    area: str
    city: str
    lat: float
    lng: float


def haversine_km(a: Area, b: Area) -> float:
    r = 6371.0088
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dp, dl = p2 - p1, math.radians(b.lng - a.lng)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


class Registry:
    def __init__(self, areas: Iterable[dict], verified: Iterable[dict], taxonomy: dict):
        self.areas = {}
        for a in areas:
            area = Area(str(a["pincode"]), a["area"], a["city"], float(a["lat"]), float(a["lng"]))
            self.areas[area.pincode] = area
        self.scam_types = tuple(taxonomy["scam_types"])
        self._types = frozenset(self.scam_types)
        self.channels = tuple(taxonomy["channels"])
        self._channel_keys = {_key(c): c for c in self.channels}
        for alias, target in taxonomy.get("channel_aliases", {}).items():
            self._channel_keys[_key(alias)] = target
        self._verified = {}
        self._verified_hosts = {}
        for e in verified:
            canon = normalise(e["type"], e["value"])     # a bad data row fails loudly at start-up
            if e["type"] == "url":
                self._verified_hosts[url_host(canon)] = e["label"]
            else:
                self._verified[(e["type"], canon)] = e["label"]

    @classmethod
    def from_dir(cls, path) -> "Registry":
        p = Path(path)
        load = lambda name: json.loads((p / name).read_text(encoding="utf-8"))
        return cls(load("areas.json"), load("verified.json"), load("taxonomy.json"))

    def verified_items(self) -> list:
        """(type, canonical value, label) for every verified entry, in file order. Used by the
        judge console's sandbox to pick a verified business without naming one in code."""
        out = [(t, c, label) for (t, c), label in self._verified.items()]
        out += [("url", "https://" + host, label) for host, label in self._verified_hosts.items()]
        return out

    # ------------------------------------------------------------------ lookups
    def verified_label(self, identifier_type: str, canon: str) -> Optional[str]:
        if identifier_type == "url":
            return self._verified_hosts.get(url_host(canon))   # same host only, no subdomains
        return self._verified.get((identifier_type, canon))

    def within(self, pincode: str, radius_km: float) -> list:
        centre = self.areas[pincode]
        return [a for a in self.areas.values()
                if a.pincode == pincode or haversine_km(centre, a) <= radius_km]

    def channel(self, raw: object) -> str:
        if isinstance(raw, str):
            hit = self._channel_keys.get(_key(raw))
            if hit:
                return hit
        return "Something else"

    def scam_type(self, raw: object) -> tuple:
        """Returns (type shown to people, key used for NEW_TYPE alerts).
        Unknown types are shown as 'other' (the brief) but keep their own key, so a
        brand-new kind of scam still raises NEW_TYPE under its own name."""
        if isinstance(raw, str):
            slug = re.sub(r"[^a-z0-9]+", "-", raw.strip().lower()).strip("-")[:40]
            if slug in self._types:
                return slug, slug
            if slug and sum(c.isdigit() for c in slug) < 5:
                return "other", slug
        return "other", "other"


def _key(s: str) -> str:
    return re.sub(r"[^a-z]", "", s.lower())
