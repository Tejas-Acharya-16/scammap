"""Trust rule parameters (BUILD_SPEC section 6.3).

One frozen object holds every dial. Its short hash is returned in every lookup
(`trust.config`) and printed in the attack table, so a result can always be traced
to the rules that produced it. Points are integers in quarter-points (4 = 1.0).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Optional


@dataclass(frozen=True)
class TrustConfig:
    # --- Verdict -------------------------------------------------------------
    min_voices: int = 3               # voices needed for KNOWN_SCAM; also the unmask threshold (brief)
    min_points_q: int = 6             # points needed for KNOWN_SCAM: 6 quarter-points = 1.5
    weight_new_q: int = 2             # a voice from a reporter with no confirmed history: 0.5
    weight_proven_q: int = 4          # a voice from a reporter whose earlier report was confirmed: 1.0
    personal_min_tokens: int = 3      # "own words": at least this many words, written by one reporter
    linked_voices_generic: bool = True  # a voice that links 2+ reporter IDs is never "own words"
    generic_cap_q: int = 4            # empty, short or shared-text voices add at most 1.0 in total
    linked_cap_q: Optional[int] = 0   # a coordinated (linked) group is one voice and adds no weight

    # --- Linking reports into voices (one voice = one person) -----------------
    org_link_hours: Optional[float] = 24.0  # same network within this time = same person; None = any time
    note_link_min_reporters: int = 3  # a text shared by this many reporters is copy-paste (2 can be chance)
    note_campaign_clusters: int = 2   # this many copy-paste texts on one number: any shared text links
    neardup_jaccard: float = 0.7      # copy-paste with light edits
    neardup_min_tokens: int = 6
    neardup_max_reports: int = 400    # near-duplicate check runs on the latest N long notes per identifier

    # --- Track record ----------------------------------------------------------
    proven_other_voices: int = 2      # the earlier identifier must have this many OTHER voices
    proven_requires_earlier: bool = True  # the confirming report must come before this one

    # --- Coordinated burst (v1.2, rule 5). Raised at checkpoint 1: one person asks 10 friends, each on
    # their own phone and in their own words, to report a number. The count of people alone never
    # decides: brand-new voices (no track record) whose first reports come from ONE area within a few
    # hours, and that make up most of the voices on the number, count as ONE linked voice. So the number
    # stays SUSPICIOUS and masked, and never moves the map or alerts, until independent people (other
    # areas, other days, or with a track record) report it. None turns the rule off.
    ring_min_voices: Optional[int] = 8      # smallest burst treated as coordinated
    ring_window_hours: float = 6.0          # by occurred time (the only clock a bulk upload keeps)
    ring_area_share: float = 0.8            # the burst must be at least this share of all voices

    # --- Map and alerts (section 8) ---------------------------------------------
    exclude_linked_from_counts: bool = True  # voices that link 2+ reporter IDs never move map or alerts
    copy_paste_mutes_counts: bool = True     # a number hit by pasted text never moves map or alerts
    spam_reports: int = 3             # one reporter filing this many reports on one identifier is spamming
    counted_generic_per_number: int = 1
    spike_min: int = 5
    spike_factor: float = 2.0
    new_type_min_voices: int = 2      # NEW_TYPE needs this many counted voices ...
    new_type_personal_alone: bool = True  # ... or a single counted voice in the reporter's own words
    new_type_lookback_days: int = 30

    # --- Input limits (section 5) --------------------------------------------------
    future_tolerance_minutes: int = 60
    max_age_days: int = 400
    note_max_chars: int = 500
    evidence_max: int = 5

    def as_dict(self) -> dict:
        return asdict(self)

    def hash(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:8]

    def with_(self, **changes) -> "TrustConfig":
        return replace(self, **changes)


# The v1 rules from BUILD_SPEC v2.1, kept only so the attack table can compare old and new.
V1_CONFIG = TrustConfig(
    personal_min_tokens=5,
    linked_voices_generic=False,
    org_link_hours=None,
    note_link_min_reporters=2,
    note_campaign_clusters=0,
    linked_cap_q=None,
    copy_paste_mutes_counts=False,
    ring_min_voices=None,
    proven_requires_earlier=False,
    exclude_linked_from_counts=False,
    spam_reports=10**9,
    new_type_personal_alone=False,
    future_tolerance_minutes=10,
)
