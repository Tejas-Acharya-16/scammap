"""Trust rules v1.1 (BUILD_SPEC section 6): pure functions over the reports of ONE identifier.

1. Link reports that come from one person, or from one coordinated group:
   same reporter ID (any time); same network within `org_link_hours`; identical note text;
   near-identical long notes. Each linked group is one VOICE.
2. A voice is "own words" (personal) when ONE reporter wrote a note of at least
   `personal_min_tokens` words. A voice that links 2+ reporter IDs is never personal:
   shared text and shared networks are what coordinated fakes look like.
3. Weight: 0.5 for a new reporter, 1.0 when the reporter earlier reported a different,
   confirmed number. Generic voices (empty, short or shared text) count half, and all of
   them together add at most 1.0.
4. KNOWN_SCAM needs at least 3 voices and at least 1.5 points.
Map and alerts count only clean voices: one reporter, not spamming, and either own words
or the earliest generic voice of that identifier.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Voice:
    reports: tuple      # the linked reports
    rids: frozenset     # reporter hashes inside this voice
    linked: bool        # the rules linked 2+ reporter IDs together
    spam: bool          # one reporter filed `spam_reports`+ reports on this identifier
    personal: bool      # own words from one reporter
    first: object       # earliest report: sets the voice's date, area and scam type
    copy_paste: bool = False  # this identifier has pasted text shared by several reporters


def build_voices(reports, cfg) -> list:
    n = len(reports)
    if n == 0:
        return []
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        a, b = find(i), find(j)
        if a != b:
            parent[b] = a

    # 1: one reporter is one person, at any time.
    first_seen = {}
    for i, r in enumerate(reports):
        j = first_seen.setdefault(r.rid, i)
        if j != i:
            union(j, i)

    # 2: same network within a short time is one person (the brief's own wording).
    by_org = defaultdict(list)
    for i, r in enumerate(reports):
        by_org[r.org].append(i)
    window = None if cfg.org_link_hours is None else timedelta(hours=cfg.org_link_hours)
    for idx in by_org.values():
        if len(idx) < 2:
            continue
        if window is None:
            for i in idx[1:]:
                union(idx[0], i)
            continue
        for attr in ("t", "reported_at"):        # close in time by either clock links them
            seq = sorted((getattr(reports[i], attr), i) for i in idx
                         if getattr(reports[i], attr) is not None)
            for (ta, ia), (tb, ib) in zip(seq, seq[1:]):
                if tb - ta <= window:
                    union(ia, ib)

    # 3: copy-paste. Identical notes, or near-identical long notes, form a text cluster. A text
    # cluster written by `note_link_min_reporters`+ different reporters is one coordinated voice.
    # Two people sharing a text can be chance (a test tool may draw notes from a short list).
    tparent = list(range(n))

    def tfind(i):
        while tparent[i] != i:
            tparent[i] = tparent[tparent[i]]
            i = tparent[i]
        return i

    def tunion(i, j):
        a, b = tfind(i), tfind(j)
        if a != b:
            tparent[b] = a

    by_hash = {}
    for i, r in enumerate(reports):
        if r.note_hash:
            j = by_hash.setdefault(r.note_hash, i)
            if j != i:
                tunion(j, i)
    long_idx = [i for i, r in enumerate(reports) if r.ntok >= cfg.neardup_min_tokens and r.shingles]
    if len(long_idx) > cfg.neardup_max_reports:
        long_idx = sorted(long_idx, key=lambda i: reports[i].t)[-cfg.neardup_max_reports:]
    for a in range(len(long_idx)):
        i = long_idx[a]
        sa = reports[i].shingles
        for b in range(a + 1, len(long_idx)):
            j = long_idx[b]
            if tfind(i) == tfind(j):
                continue
            sb = reports[j].shingles
            inter = len(sa & sb)
            if inter and inter >= cfg.neardup_jaccard * (len(sa) + len(sb) - inter):
                tunion(i, j)
    clusters = defaultdict(list)
    for i, r in enumerate(reports):
        if r.note_hash:
            clusters[tfind(i)].append(i)
    writers = {root: len({reports[i].rid for i in members}) for root, members in clusters.items()}
    need = cfg.note_link_min_reporters
    # A campaign: several texts each pasted by many people on this one number. Then every
    # shared text, even one shared by only two people, is treated as copy-paste.
    if cfg.note_campaign_clusters and sum(w >= need for w in writers.values()) >= cfg.note_campaign_clusters:
        need = 2
    copy_paste = False
    for root, members in clusters.items():
        if writers[root] >= need:
            copy_paste = True
            for i in members[1:]:
                union(members[0], i)

    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(reports[i])
    voices = []
    for members in groups.values():
        per_rid = Counter(r.rid for r in members)
        linked = len(per_rid) >= 2
        own_words = max(r.ntok for r in members) >= cfg.personal_min_tokens
        voices.append(Voice(
            reports=tuple(members),
            rids=frozenset(per_rid),
            linked=linked,
            spam=max(per_rid.values()) >= cfg.spam_reports,
            personal=own_words and not (linked and cfg.linked_voices_generic),
            first=min(members, key=lambda r: (r.t, r.report_id)),
            copy_paste=copy_paste,
        ))
    voices.sort(key=lambda v: (v.first.t, v.first.report_id))
    return voices


def score(voices, proven, cfg) -> tuple:
    """(number of voices, points in quarter-points)."""
    personal_q = generic_q = linked_q = 0
    for v, is_proven in zip(voices, proven):
        w = cfg.weight_proven_q if is_proven else cfg.weight_new_q
        if v.personal:
            personal_q += w
        elif v.linked:
            linked_q += w // 2
        else:
            generic_q += w // 2
    if cfg.linked_cap_q is not None:
        linked_q = min(linked_q, cfg.linked_cap_q)
    return len(voices), personal_q + min(generic_q + linked_q, cfg.generic_cap_q)


def counted_voices(voices, cfg) -> list:
    """Voices that move the map and alerts (section 8). `voices` is sorted by time.
    A number hit by pasted text never moves the map or alerts at all."""
    if cfg.copy_paste_mutes_counts and any(v.copy_paste for v in voices):
        return []
    eligible = [v for v in voices
                if not v.spam and not (v.linked and cfg.exclude_linked_from_counts)]
    personal = [v for v in eligible if v.personal]
    generic = [v for v in eligible if not v.personal][: cfg.counted_generic_per_number]
    return personal + generic
