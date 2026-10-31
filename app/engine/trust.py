"""Trust rules v1.1 (BUILD_SPEC section 6): pure functions over the reports of ONE identifier.

1. Link reports that come from one person, or from one coordinated group:
   same reporter ID (any time); same network within `org_link_hours`; identical note text;
   near-identical long notes. Each linked group is one VOICE.
2. A voice is "own words" (personal) when ONE reporter wrote a note of at least
   `personal_min_tokens` words. A voice that links 2+ reporter IDs is never personal:
   shared text and shared networks are what coordinated fakes look like.
3. Weight: 0.5 for a new reporter, 1.0 when the reporter earlier reported a different,
   confirmed number. v1.3: an unlinked voice weighs the same with or without a note, so empty
   notes or one example sentence never block an honest report. Shared text links writers only
   when the copies arrive within `note_link_window_hours` of each other.
4. KNOWN_SCAM needs at least 3 voices and at least 1.5 points.
5. (v1.2) A coordinated burst, many brand-new voices from ONE area within a few hours that make up
   most of the voices on the number, counts as ONE linked voice. One signal alone (the number of
   people) never decides; time, area and track record must agree.
   v1.3: a burst of brand-new voices with no words of their own also merges when it is spread over
   areas.
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
    burst: int = 0            # v1.2: this voice is a coordinated burst of this many voices


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
    note_window = None if cfg.note_link_window_hours is None else timedelta(hours=cfg.note_link_window_hours)

    def campaign(members, need):
        """Members of one text cluster that sit in a time window holding `need`+ different writers.
        v1.3: copies spread over days are what a test tool's example note looks like, not a campaign."""
        if note_window is None:
            return members if len({reports[i].rid for i in members}) >= need else []
        seq = sorted(members, key=lambda i: (reports[i].t, reports[i].report_id))
        marked, held, lo = set(), Counter(), 0
        for hi, i in enumerate(seq):
            held[reports[i].rid] += 1
            while reports[i].t - reports[seq[lo]].t > note_window:
                gone = reports[seq[lo]].rid
                held[gone] -= 1
                if not held[gone]:
                    del held[gone]
                lo += 1
            if len(held) >= need:
                marked.update(seq[lo:hi + 1])
        return sorted(marked)

    need = cfg.note_link_min_reporters
    linked_text = {root: campaign(members, need) for root, members in clusters.items()}
    # A campaign: several texts each pasted by many people on this one number. Then every
    # shared text, even one shared by only two people, is treated as copy-paste.
    if cfg.note_campaign_clusters and sum(bool(m) for m in linked_text.values()) >= cfg.note_campaign_clusters:
        linked_text = {root: campaign(members, 2) for root, members in clusters.items()}
    copy_paste = False
    for marked in linked_text.values():
        if marked:
            copy_paste = True
            for i in marked[1:]:
                union(marked[0], i)

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
        if v.personal or (cfg.generic_full_weight and not v.linked):
            personal_q += w
        elif v.linked:
            linked_q += w // 2
        else:
            generic_q += w // 2
    if cfg.linked_cap_q is not None:
        linked_q = min(linked_q, cfg.linked_cap_q)
    return len(voices), personal_q + min(generic_q + linked_q, cfg.generic_cap_q)


def burst_core(voices, cfg, eligible=None) -> list:
    """A coordinated burst (v1.2): the largest group of voices whose first reports come from ONE area
    within `ring_window_hours` of each other. Returned (as indices) only when the group has at least
    `ring_min_voices` voices AND makes up at least `ring_area_share` of all voices on the identifier,
    so a big real wave that also hits other areas or other days is left alone. `eligible` (a list of
    bools) limits who can be in the group: the engine passes "no track record"."""
    if cfg.ring_min_voices is None or len(voices) < cfg.ring_min_voices:
        return []
    window = timedelta(hours=cfg.ring_window_hours)
    by_area = defaultdict(list)
    for i, v in enumerate(voices):
        if eligible is None or eligible[i]:
            by_area[v.first.pincode].append((v.first.t, v.first.report_id, i))
    best = []
    for pin in sorted(by_area):
        seq = sorted(by_area[pin])
        lo = 0
        for hi in range(len(seq)):
            while seq[hi][0] - seq[lo][0] > window:
                lo += 1
            if hi - lo + 1 > len(best):
                best = [i for _, _, i in seq[lo:hi + 1]]
    if cfg.ring_generic_any_area:
        # v1.3: brand-new voices with no words of their own, arriving together, from any area.
        seq = sorted((v.first.t, v.first.report_id, i) for i, v in enumerate(voices)
                     if (eligible is None or eligible[i]) and not v.personal)
        lo = 0
        for hi in range(len(seq)):
            while seq[hi][0] - seq[lo][0] > window:
                lo += 1
            if hi - lo + 1 > len(best):
                best = [i for _, _, i in seq[lo:hi + 1]]
    if len(best) < cfg.ring_min_voices or len(best) < cfg.ring_area_share * len(voices):
        return []
    return sorted(best)


def merge_burst(voices, proven, core) -> tuple:
    """The burst counts as ONE coordinated voice, like a linked group: it adds no weight and never
    moves the map or alerts. Voices outside the burst (other areas, other days, track record) still
    count on their own. Returns (voices, proven), sorted by time."""
    if not core:
        return voices, proven
    members = [voices[i] for i in core]
    merged = Voice(
        reports=tuple(r for v in members for r in v.reports),
        rids=frozenset().union(*(v.rids for v in members)),
        linked=True, spam=False, personal=False,
        first=min((v.first for v in members), key=lambda r: (r.t, r.report_id)),
        copy_paste=any(v.copy_paste for v in members),
        burst=len(members),
    )
    inside = set(core)
    pairs = [(v, p) for i, (v, p) in enumerate(zip(voices, proven)) if i not in inside]
    pairs.append((merged, False))
    pairs.sort(key=lambda vp: (vp[0].first.t, vp[0].first.report_id))
    return [v for v, _ in pairs], [p for _, p in pairs]


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
