# BUILD_SPEC v2.2: Community Scam Map (Team Smashers)

v2.2, Sat 31 Oct 2026, 13:24 IST. Changes from v2.1: the core engine exists and is tested (`app/engine`, `app/data`, `tests/engine`; brief E1 in section 15); trust rules v1.1 (section 6) close three attack holes and one real-wave miss, re-measured on the real code (6.4); map and alerts count only clean voices (8); input rules loosened where a strict rule could reject the judges' good data (3, 4.1, 5, 12). Changes in v2.1: section 15 adds T3 (the Antigravity agent) and gives it /tests/api, /tests/attack and /tests/privacy; section 14 adds the T3 timeline; the lookup `trust` object gains `config` (sections 3 and 7). Put at docs/BUILD_SPEC.md. Read docs/PROBLEM_CARD.md first.
Top source: the organisers' brief "Community Scam Map: Student Brief" (29 Oct), called "the brief" below. Where this file disagrees with the brief, the brief wins. Tell Tejas.
Labels: OFFICIAL = from the brief. SIMULATED = from my throwaway prototype, using generators I wrote; not the judges' tool, not team code. JUDGMENT = my call. UNVERIFIED = not checked.
v1 of this file is void (the /v1 API, WARNED states, token login, 3-hour Poisson alerts, evidence panel as the core).
Binds only when AGENTS.md says PHASE: BUILD. Agents: load sections 0 to 3, then the section for your task, then your brief in section 15.

## 0. What the judges score (OFFICIAL) and our answer
100 points plus up to 7 bonus. Rows 1 to 4 are scored by a test tool run against our live public server. Rows 5 to 7 are scored by a judge watching.
| # | Row | Pts | What is checked | Our answer | Owner | Done when |
|---|---|---|---|---|---|---|
| 1 | Stops fake reports | 20 | 40 friends vs a real bakery, 22 accounts on one Wi-Fi, one person x6, junk like "12345". None may make a number KNOWN_SCAM. Zero if one person reporting many times can. | Trust rules, section 6 | Tejas | `make attack` shows all four tricks held and real waves flip |
| 2 | Lookup right | 15 | Real scams KNOWN_SCAM, unreported NO_REPORTS, `+91 98765 43210` and `09876543210` identical, each answer under 0.5 s | Normaliser (4), verdicts (7), in-memory model | Tejas | formats equal, p95 under 0.3 s from the venue network |
| 3 | Map and alerts | 10 | Sudden jump alerts, normal area does not, new scam type alerts, month-old reports off the map | Section 8 | Tejas | AT-3.x green |
| 4 | Privacy | 15 | Under 3 reporters hidden, map never shows a person's location, judge reads the result screen. "Reported by 7 people near you" good; "This person is a fraud" loses up to 5. A reporter identifiable: disqualified. | Sections 7, 10, 11 | both | `make privacy` green, wording test green |
| 5 | Server and licence | 15 | Live 4-step licence demo on an https address, no restart. Works but needs a restart: about half. Laptop only: zero. | Sections 1 and 9 | Tejas | three clean rehearsals |
| 6 | Easy to report | 15 | Judge times a report on a phone, then tries Hindi and icons only. Under 60 s and usable in Hindi or icons: full. Over 2 min or a login first: zero. | Section 11 | Bhumika | hand-timed median under 45 s |
| 7 | Demo and code | 10 | Judge runs it from the README, reads our trust and licence explanation, hears the pitch | README, video, pitch | Bhumika | a stranger runs it from the README |
Bonus (7): 3 if verified businesses and helplines show VERIFIED_BUSINESS (4.4); 2 for disputes (12); 2 if fake reports never set off an alert (8). Tie-break: more bonus, then faster report time.
Hidden data: judges load a new secret report set. A rule written for one number fails, and they check for it. The verified list is data, not a rule.
Automatic disqualification: a reporter can be identified; exact locations stored; personal data scraped; code written before the event.

## 1. Stack and deploy (approved when Tejas says "go")
- Server: Python 3.12, FastAPI, Uvicorn with ONE worker, SQLAlchemy 2 Core with plain SQL, psycopg 3 for Postgres, sqlite for local runs and tests, PyNaCl (licence signatures), Pydantic 2, pytest, httpx.
- One process, one origin. The built mobile website is served by the same app (`app/static`). Build it with `make web` and commit the output, so the host never needs Node (JUDGMENT: fewer build minutes and fewer failures on a free host).
- Web: React, Vite, TypeScript. Leaflet for the map, optional (a list is the fallback).
- Host (decided 12:14, facts from Render's docs page): Render web service (Docker) plus Render free Postgres, same region, Singapore if offered (UNVERIFIED). Health check path `/health`. Free service sleeps after 15 minutes without traffic, cold start about a minute, disk wiped on every restart and redeploy, no persistent disk. Free Postgres: 1 GB, expires 30 days after creation. So all state lives in Postgres, never in a file. A free uptime monitor pings `/health` every 5 minutes (UptimeRobot is the one I know; UNVERIFIED). Fallback host: Railway trial. Fly.io has no free tier.
- Gotchas: Render gives the port in `$PORT`. Postgres URLs may start with `postgres://`; rewrite to `postgresql+psycopg://`. Run uvicorn with `--no-access-log`. FastAPI answers bad bodies with 422 by default; the brief wants 400, so override the validation handler.
- Env vars (never in Git): `DATABASE_URL` (default `sqlite:///./dev.db`), `TRUST_SALT` (stable; changing it splits every reporter's history), `ALLOW_RESET` (default 1), `PORT`. The licence PUBLIC key is a constant in code (the brief says built in). The PRIVATE key never leaves Tejas's laptop and never goes in a prompt.
- Make targets: `make dev`, `make web`, `make test`, `make attack [URL=...]` (local by default), `make smoke URL=...` (black-box tests against any server), `make perf URL=...`, `make privacy`, `make docker`.
- `docker compose up --build` runs app plus Postgres on localhost:8000 for judges reading the README.
- Warm-up before any judging slot: `curl $URL/health`, `make smoke URL=$URL`, and check `GET /license` shows valid.
- Speed: the engine answers a lookup in about 0.15 ms (p95, in-process, 5,000 reports: `python -m tests.engine.bench`). Live p95 is network time plus the host's CPU share. If `make perf` from the venue shows p95 over 300 ms, consider Render's paid Starter instance (cost and decision for Tejas; the free tier's CPU share is UNVERIFIED).

## 2. Architecture and trust boundaries
```
phone browser --https--> FastAPI (1 worker)
                          middleware: size limit -> licence gate -> router
                          engine (pure functions, no I/O): normalise, trust, alerts, masking, areas, verified
                          Model (in memory): rebuilt at start from the reports table; updated under a lock on every write
                          Postgres (prod) / sqlite (dev): reports, challenges, kv (licence, latest clock seen)
```
- Event-log style: every accepted report is inserted, then applied to the in-memory model. Lookups never touch the database. Restart rebuilds the model from the table (a few thousand rows load in under a second).
- Clock and time are injected (`Clock.now()`); tests use a fake clock. No header or parameter may override the clock in production.
- Untrusted: every request field, every reported URL (we never fetch one), every note.
- No outbound network calls in the request path. No LLM in the request path. AI tools help us write code; the trust rules are ours and deterministic.

## 3. API contract (OFFICIAL; frozen; extra reply fields are allowed)
JSON in and out. Times are ISO 8601; we reply in +05:30. Errors: `{"error": "<code>"}`; the message never echoes the input. No login on any of these. Unknown route 404, wrong method 405, both JSON.
| Route | Reply |
|---|---|
| GET /health | 200 `{"ok": true}` |
| POST /reports | 201 `{"report_id","case_id","merged"}`; 400 `{"error"}`; 429 allowed, not used in v1 |
| GET /lookup?type=&value= | 200 object below; 400 for an impossible value or unknown type |
| GET /map?pincode=&days=7&radius_km=2 | 200 `{"clusters":[...]}` |
| GET /alerts?pincode= | 200 `{"alerts":[...]}` |
| POST /admin/reset | 200 `{"ok": true}`; deletes every report and challenge, keeps the licence and the clock guard |
| POST /challenges | 201 `{"challenge_id","status":"under_review"}`; 400 |
| GET /license | 200 (section 9) |
| POST /license | 200 (section 9); 400 `{"error":"INVALID_LICENSE"}` |
When the licence is not valid, every route except GET /health, GET /license, POST /license (and the static app files) returns 403 `{"error":"LICENSE_EXPIRED"}`. Spelling: error code and path use S (`LICENSE_EXPIRED`, `/license`); the screen text uses C ("Licence expired. Contact your provider.").

POST /reports body (OFFICIAL): report_id, occurred_at, reported_at, reporter_id, ip_prefix, channel, scam_type, identifier_type (phone, upi, url, sender_id), identifier_value, pincode, locality, city, note, has_screenshot, amount_lost_inr.
- Required for a 201: valid identifier (per type), pincode in the area registry (16), occurred_at. Everything else is optional and never causes a 400 by itself: unknown `scam_type` becomes `other`; unknown `channel` becomes `Something else`; missing `reporter_id` or `ip_prefix` fall back to a hash of the request's /24 (our own app sends `reporter_id` only); `locality` and `city` are ignored (we use the registry names).
- 400 codes: `invalid_body`, `invalid_identifier`, `invalid_pincode`, `invalid_time`.
- A retry (same `report_id`, same identifier, same reporter) is 201 with the same case and counted once. A reused `report_id` from a different reporter is stored as a new report (a test tool may reuse IDs across batches).
- `merged` is true when the identifier already had a report. `case_id` = `case_` + first 10 hex of SHA-256 of `type:normalised`.
- The reply never says whether a report was discounted. Accepted and discounted reports look the same to the sender.

GET /lookup reply: `verdict` (KNOWN_SCAM, SUSPICIOUS, NO_REPORTS or VERIFIED_BUSINESS), `report_count`, `distinct_reporters`, `first_seen`, `last_seen`, `scam_type`, `display_value`, `evidence` (list of `{occurred_at, channel, scam_type, pincode}`), `challenged`. Extras we add: `type`, `label` (verified only), `trust` `{voices, points, needed, config}`.
GET /map cluster: `{pincode, locality, city, count, top_scam_type, severity (CRIT, HIGH, MED), lat, lng}`. GET /alerts items: SPIKE `{type, pincode, window:"24h", count, baseline_per_day}`; NEW_TYPE `{type, pincode, scam_type, window:"24h"}`; none: `{"alerts": []}`.

## 4. Normaliser, validation, masking, verified list
Always first: map every Unicode decimal digit to ASCII, strip zero-width and non-breaking spaces, trim. The `type` given by the caller decides the validator. The app's UI auto-detects the type for the user.
### 4.1 Rules (OFFICIAL formats; the validity limits are JUDGMENT)
- phone: digits only after stripping `+`, spaces, dashes, brackets. Strip `0091`, `91` (when 12 digits), `091` (13 digits) or a leading `0` (11 digits). Then:
  - 10 digits starting 6 to 9 (mobile, and landlines such as 80 and 79): `+91` plus the digits.
  - 10 digits starting 1 to 5: a landline with its area code (Jaipur 141, Lucknow 522 and Kochi 484 are in the area list): `+91` plus the digits. v2 accepted only a short list of codes, which could have rejected the judges' landlines.
  - toll-free: starts 1800 or 1860, 8 to 11 digits: keep as digits, no `+91`.
  - short helpline: allow-list 100, 101, 102, 108, 112, 181, 1091, 1098, 1909, 1930, 14422, 155260. Every other 3 to 6 digit value is invalid (this rejects `12345`).
  - reject all-same-digit values, `1234567890`, `0123456789`, and anything starting with 0 after the country code. `+91 0 98765 43210` works. International (`+` or `00`): `+` then 8 to 15 digits, first digit 1 to 9, not +91, is kept as `+digits`.
- upi: remove all whitespace, lower case. Local part `[a-z0-9._-]{2,64}`, handle letters and digits only, 2 to 32. No dot in the handle (that is an email). This is our validator, not NPCI's (UNVERIFIED). A pasted UPI QR link (`upi://pay?pa=...`) uses its `pa` value.
- url: de-fang `hxxp` and `[.]`. Add `https://` if no scheme; only http and https allowed. Lower case everything. Drop scheme to `https://`, `www.`, default ports, userinfo, query, fragment, trailing slash, trailing dot on host. Host needs a dot. Reject localhost, private, loopback and link-local IPs, empty host, over 2048 chars. Public IP hosts are allowed. Limitation: case-sensitive short-link paths lose case.
- sender_id: upper case, remove spaces, drop a 2-letter prefix plus dash (`VM-`, `AD-`). The rest must be exactly 6 characters of A to Z and 0 to 9 with at least 3 letters. Also accepted: a 1-letter suffix (`VM-HDFCBK-S`, the newer header format; JUDGMENT) and the prefix typed without the dash (`VMHDFCBK`).
### 4.2 Test vectors (all must pass; add more)
| Input | Result |
|---|---|
| phone `+91 98765 43210`, `09876543210`, `98765-43210`, `919876543210`, `(+91) 98765-43210`, `९८७६५४३२१०` | `+919876543210` |
| phone `+91 80 4100 2233` | `+918041002233` |
| phone `1930`, `1909` | same digits |
| phone `1800 1600`, `1800-1600` | `18001600` |
| phone `1860 419 5555` | `18604195555` |
| phone `12345`, `test`, `0000000000`, `+91 00000 00000`, `9999999999`, `1234567890`, `` | 400 |
| upi `Ravi12@OKAXIS`, ` ravi12 @ okaxis ` | `ravi12@okaxis` |
| upi `ravi12`, `ravi12@`, `@okaxis`, `x@evil.com` | 400 |
| url `http://www.sbi-kyc.in/pay?utm=sms` | `https://sbi-kyc.in/pay` |
| url `HTTPS://SBI-KYC.IN/Pay/`, `sbi-kyc.in/pay#top`, `hxxps://sbi-kyc[.]in/pay`, `https://sbi-kyc.in:443/pay` | `https://sbi-kyc.in/pay` |
| url `http://localhost/x`, `http://192.168.60.13/x`, `javascript:alert(1)`, `not a link`, `http://` | 400 |
| sender `VM-HDFCBK`, `AD-HDFCBK`, `HDFCBK`, `hdfcbk` | `HDFCBK` |
| sender `test`, `12345`, `123456` | 400 |
Property tests: idempotence (normalising a normalised value changes nothing); the normaliser never raises on arbitrary Unicode.
### 4.3 Masking (display_value)
Shown in full only when distinct_reporters is at least 3 and the value is not under dispute, or when VERIFIED_BUSINESS. Otherwise:
| Type | Normalised | Masked |
|---|---|---|
| phone (10 digits) | `+919876543210` | `98XXXXX210` |
| upi | `ravi12@okaxis` | `r***@okaxis` |
| url | `https://sbi-kyc.in/pay` | `sbi***.in/...` (first 3 characters of the host, `***`, the last dot and label of the host, `/...`) |
| sender_id | `HDFCBK` | `HD****` |
| other phone shapes | | first 2 and last 3 digits kept when 7 or more digits, else only the first digit |
NO_REPORTS is masked too (zero reporters). Full value only after 3 voices.
### 4.4 Verified list (3 bonus points): data in section 16
A lookup on a verified value is VERIFIED_BUSINESS whatever reports exist. Phones compare after normalising. URLs match on host (so `https://cybercrime.gov.in/anything` is verified; `cybercrime.gov.in.evil.example` is not). Reports against verified values are stored but excluded from map and alerts. `label` carries the owner name from the table.

## 5. Time and area rules
- `occurred_at` and `reported_at` must parse as ISO 8601 with an offset (`Z` allowed; a naive time is read as IST). Reject `occurred_at` more than 60 minutes in the future or more than 400 days old (JUDGMENT: 60 minutes, so a judge's laptop clock that runs fast cannot get every report rejected; `2030` is still junk). A bad `reported_at` is also `invalid_time`.
- All windows use each report's `occurred_at` against the server clock (OFFICIAL rule 1), capped at the moment it arrived, so a few minutes of clock skew never puts a report in the future. Never use receive time otherwise: the test tool loads a month of reports in one go.
- `pincode` must be one of the 25 registry areas (section 16), or an area we add ourselves with a checked map point. Anything else is `invalid_pincode`. A well-formed unknown pincode on /map or /alerts returns 200 with an empty list; a malformed one returns 400.
- Distance for `radius_km` is haversine between registry points. The query area is always in range. With no `pincode` on /map, return every area with reports.
- The map point is always the registry point. No client coordinates are accepted, stored or returned.

## 6. Trust rules v1.2 (the wedge; rows 1 and 2; 35 points). Built and tested: `app/engine/trust.py` (v1.2 = v1.1 plus rule 7, config `76f35c12`)
### 6.1 In plain English (this is also the README text)
1. Junk is turned away at the door: a number, UPI ID, link or sender that cannot exist, an area we do not know, or an impossible time.
2. One person is one voice. Reports on one number are linked into one voice when they share a reporter ID (at any time), or a network within 24 hours (the brief: "many reports from the same internet connection within a short time count as one person").
3. Copy-paste is one voice. The same text, or a lightly edited copy of a long text, pasted by 3 or more different reporters on one number links them. If a number carries 2 or more such pasted texts, any text shared by even two people links them too (a campaign working from a list of texts).
4. Track record. A voice counts 1.0 when its reporter earlier reported a different number that at least two other voices confirmed (and that is not verified or disputed). Otherwise 0.5.
5. Own words. A voice from one reporter with a note of 3 or more words counts in full. An empty or very short note counts half, and all of those together add at most 1.0. A linked group (rule 2 or 3) is one voice and adds no weight at all.
6. A number is a KNOWN_SCAM when at least 3 voices report it and they add up to at least 1.5 points. Fewer is SUSPICIOUS. Nothing reported is NO_REPORTS. A verified number is VERIFIED_BUSINESS whatever is reported, and a disputed number is never KNOWN_SCAM.
7. (v1.2, raised by the mentor at checkpoint 1: "one person asks 10 friends to report") A coordinated burst is one voice. When 8 or more voices with no track record come from ONE area within 6 hours (by occurred time) and make up at least 80% of all voices on the number, they merge into one linked voice: no weight, never on the map or in alerts. The number stays SUSPICIOUS and masked, and the app says why, until independent people (other areas, other days, or with a track record) report it. The count of people alone never decides.

### 6.2 Algorithm (identity = keyed hashes of `reporter_id` and `ip_prefix`; see 10)
```python
def voices(reports):                     # all reports of ONE identifier
    union reports with equal rid                                     # one person, any time
    union reports with equal org less than 24 h apart                # by occurred time or by reported_at
    text clusters: equal note_hash, plus pairs with ntok >= 6 and jaccard(shingles) >= 0.7
    need = 2 if at least 2 text clusters have 3+ distinct rids else 3
    union every text cluster written by `need` or more distinct rids
    voice.linked   = 2+ distinct rids in the voice
    voice.personal = not linked and max(ntok) >= 3
    voice.spam     = one rid filed 3+ reports on this identifier      # used by section 8

def proven(voice, X):                    # track record
    any rid in the voice reported Y != X EARLIER, Y not verified or disputed,
    and independent(Y) - 1 >= 2          # independent = voices with any burst on Y counted once

def burst(X):                            # rule 7 (v1.2)
    eligible = voices of X that are not proven
    core = largest group of eligible voices with one first-report pincode within 6 h (occurred time)
    if len(core) >= 8 and len(core) >= 0.8 * len(voices(X)): merge core into ONE linked voice

def points(X):                           # integers in quarter-points: 4 = 1.0
    w = 4 if proven else 2
    personal voice: +w;  unlinked generic voice: +w // 2 (all such capped at 4);  linked voice: +0
# KNOWN_SCAM iff len(voices) >= 3 and points >= 6 (1.5), not verified, not challenged
```
Note fingerprint (the note text is never stored): Unicode NFKC, lower case, keep letters and combining marks only (Hindi matras survive, digits are dropped), split on spaces, `ntok` = word count. `note_hash` = keyed hash of the joined words. Shingles = keyed 32-bit hashes of each word and each adjacent pair. Notes are cut at 500 characters first. The near-duplicate check runs on the latest 400 long notes of an identifier.

### 6.3 Parameters (one `TrustConfig` in `app/engine/config.py`; hash `eacc847a`, returned in every lookup as `trust.config`)
| Name | Value | Meaning |
|---|---|---|
| min_voices | 3 | voices needed for KNOWN_SCAM; also the unmasking threshold (OFFICIAL) |
| min_points_q | 6 | 1.5 points needed |
| weight_new_q / weight_proven_q | 2 / 4 | 0.5 / 1.0 per voice |
| personal_min_tokens | 3 | words for "own words" (v1: 5) |
| generic_cap_q | 4 | empty or short notes add at most 1.0 |
| linked_cap_q | 0 | a linked group adds no weight (v1: counted like any voice) |
| org_link_hours | 24 | same network within this time is one person (v1: any time) |
| note_link_min_reporters / note_campaign_clusters | 3 / 2 | pasted text links at 3 writers, or at 2 when a number carries 2+ pasted texts (v1: 2 always) |
| neardup_jaccard / neardup_min_tokens | 0.7 / 6 | copy-paste with light edits |
| proven_other_voices / proven_requires_earlier | 2 / yes | track record must come first and be confirmed by 2 others |
| spam_reports | 3 | one reporter, 3+ reports on one number: never moves map or alerts |
| counted_generic_per_number | 1 | section 8 |
| new_type_min_voices / new_type_personal_alone | 2 / yes | section 8 |
| future_tolerance_minutes / max_age_days | 60 / 400 | section 5 |
| ring_min_voices / ring_window_hours / ring_area_share | 8 / 6 / 0.8 | rule 7: burst size, window (occurred time only: a bulk upload resets the other clocks), share of all voices |

### 6.4 Results: in-process attack table on the real engine (`python -m tests.engine.scenarios --seeds 60 --compare`)
60 seeds per row; each seed has 300 background reporters and 40 background numbers. The generators are our guesses about the judges' data, not the judges' tool, and the run is in-process, not over HTTP (T3's `make attack` is the black-box version).
| Scenario | v1.1 KNOWN_SCAM | v1 | Want |
|---|---|---|---|
| 8 reporters with history, spread over 13 days | 100% | 100% | high |
| 8 brand-new reporters, spread | 100% | 100% | high |
| 6 brand-new, all within 2 hours | 100% | 100% | high |
| 3 brand-new, own words | 100% | 100% | high |
| 8 new, templated notes | 98% | 100% | high |
| 8 new, half with empty notes | 100% | 100% | high |
| 10 reporters on only 15 shared networks | 100% | 100% | high |
| 8 new, short notes of 3 to 4 words | 100% | 0% | high |
| 8 new, 4 of them on 2 shared networks, days apart | 100% | 100% | high |
| 7 new, notes picked from a list of 10 sample texts | 98% | 100% | high |
| 4 new, notes picked from a list of 10 sample texts | 98% | 98% | high |
| 8 new, all empty notes | 0% | 0% | known limit |
| 2 new, own words | 0% (SUSPICIOUS) | 0% | low |
| 40 friends, same note, 40 networks | 0% | 0% | 0 |
| 40 friends, empty notes | 0% | 0% | 0 |
| 22 accounts, one network, varied notes | 0% | 0% | 0 |
| 22 accounts, one network, empty notes | 0% | 0% | 0 |
| 22 accounts, one network, times spread over 5 days, reported in one burst | 0% | 0% | 0 |
| one person x6, same network | 0% | 0% | 0 |
| one person x6, rotating networks | 0% | 0% | 0 |
| 20 accounts on 2 networks, same note | 0% | 0% | 0 |
| 40 friends, 5 canned short phrases | 0% | 0% | 0 |
| 40 friends, 5 canned long phrases | 0% | 100% | 0 |
| 40 friends, notes picked from a list of 10 texts | 0% | 100% | 0 |
| 3 attackers x 10 accounts, 3 networks, varied notes | 0% | 100% | 0 |
| 40 friends report the verified bakery | 0% (VERIFIED_BUSINESS) | 0% | 0 |
| 40 friends, own varied notes, 40 networks, one area | 0% (v1.2; v1.1: 100%) | 100% | 0 |
| 40 friends, lightly reworded (up to 3 word swaps) | 0% (v1.2; v1.1: 100%) | 100% | 0 |
| 1 person + 10 friends, own words, one area, 1 hour (v1.2) | 0% | 100% | 0 |
| 12 new within 3 hours, across 6 areas (v1.2) | 100% | 100% | high |
| 20 friends in one hour + 3 real people elsewhere (v1.2) | 100% | 100% | high |
| 1 person + 10 friends, each picks another area (v1.2) | 100% | 100% | known limit |

v1.2 table: `tests/engine/ATTACK_TABLE.txt` (60 seeds, all rows PASS except the two known limits). Same table over HTTP on the mock server (`tests.blackbox.attack`): 0 failures, 0 rejected.

Alerts (15 seeds each, v1.2): planted jump (14 in the 7 days before, 10 today) SPIKE 100%; normal area (2 a day, 3 today) no alert 100%; no history and 5 today SPIKE 100%; new type with 3 people NEW_TYPE 100%; new type with 1 person in own words NEW_TYPE 100% (v1: 0%); type seen 10 days ago no NEW_TYPE 100%; 10 empty notes on one number no alert, on 10 numbers SPIKE, both 100%. Every trick above, placed in a quiet area with a scam type new to it, raised no alert in 100% of seeds, now including 40 friends in their own varied words and 1 person + 10 friends. Map: 30- and 8-day-old reports off the 7-day map, 6-day-old on it, registry point used.
These are not results from the judges' tool and not real-world accuracy. Quote them as "in our tests".

### 6.5 Known limits (say these out loud in the README; judges ask)
- Many new accounts on different networks, each writing different words in their own voice, arriving together look exactly like a real wave. Rule 7 (v1.2) now holds such a burst when it comes from one area within 6 hours. Still open: a ring of 3 to 7, a ring whose members each pick a different area, or a ring spread over more than 6 hours. A real local wave of 8+ brand-new people in one area within 6 hours also waits (SUSPICIOUS, not KNOWN_SCAM) until independent reports arrive; the map and alerts do not count that burst either. Remedy for a wrongly listed business: the dispute route.
- Lightly reworded copies (3 word swaps in an 18-word text) are not caught. Lowering the near-duplicate threshold would merge real victims who describe one campaign in similar words.
- Real waves where every reporter left the note empty stay SUSPICIOUS: empty notes add at most 1.0.
- A ring can build a track record by first reporting numbers that other ring members also report (a burst no longer earns one: it counts as one voice there too, but a small ring of 3 to 7 can).
- People behind one network prefix within 24 hours (a campus, carrier NAT, a family) count as one voice and add no weight.
- Dials, only after one of OUR fair scenarios fails, and with the table re-run: (a) `min_points_q` 8 (2.0); (b) `neardup_jaccard` 0.6; (c) `note_link_min_reporters` 2 (costs real waves whose notes come from a short list: "4 new, notes from a list of 10" drops to 45%); (d) `new_type_personal_alone` false (if single reports cause noisy NEW_TYPE alerts in a rehearsal). Do not pre-apply any of them.

## 7. Verdicts and the lookup reply
Order: 1) invalid value gives 400. 2) verified gives VERIFIED_BUSINESS. 3) no reports gives NO_REPORTS. 4) else KNOWN_SCAM or SUSPICIOUS by 6.2. 5) a number under dispute is at most SUSPICIOUS.
- `report_count` = all accepted reports for the value. `distinct_reporters` = voices (6.2). Six reports by one person: 6 and 1.
- `first_seen`, `last_seen` = earliest and latest `occurred_at`. With fewer than 3 voices, round both down to 00:00 IST of that day (JUDGMENT: a precise time plus an area can identify a reporter). NO_REPORTS: null.
- `scam_type` = most common among voices (tie: latest). `other` stays `other`. NO_REPORTS: null.
- `evidence` = the 5 latest voice representatives (earliest report of each voice), only with 3 or more voices, else `[]`. Never a reporter ID, IP, note or exact location. A verified value shows no evidence.
- `display_value` per 4.3. `challenged` per section 12.
- `trust` = `{voices, points, needed: 1.5, config}`. `config` is the first 8 hex characters of the SHA-256 of the `TrustConfig` as JSON with sorted keys (6.3), so `make attack` can print which rules produced a table. Aggregate only.
- A value nobody reported is 200 NO_REPORTS, never 404.
- Speed: answer from memory, no database call. Target p95 under 50 ms on the server and under 300 ms from a phone on the venue network (UNVERIFIED until measured).

## 8. Map and alerts (OFFICIAL definitions; the severity scale and the counting rule are ours). Built and tested: `app/engine/engine.py`
- Counted voice: take every identifier that is not verified, not under dispute, and carries no text pasted by several reporters (6.2, rule 3). From its voices, count those that come from ONE reporter (not linked), whose reporter did not file 3+ reports on it, and that are in own words; plus at most one generic voice per number (the earliest). A counted voice's date, area and scam type are those of its earliest report. So none of the four tricks moves the map or the alerts (bonus: 2 points).
- Map: for the query area and every registry area within `radius_km` (default 2, haversine between registry points), count counted voices with time in the last `days` (default 7, clamp 1 to 60). A malformed `days` or `radius_km` falls back to the default. Skip zeros. Sort by count, highest first. Severity: 10 or more CRIT, 5 or more HIGH, else MED. `top_scam_type` = most common (tie: latest). No `pincode`: every area with counted voices.
- SPIKE for a pincode: count in the last 24 h is at least 5 and at least double `baseline_per_day`, where the baseline is the counted voices between now minus 8 days and now minus 24 hours, divided by 7 (reported with 2 decimals; the comparison uses the exact value).
- NEW_TYPE for a pincode: a scam type with counted voices in the last 24 h and none in that area in the 30 days before that window. It fires on one counted voice in the reporter's own words, or on 2 or more counted voices (JUDGMENT: one empty-note report of a new type is not enough). An unknown scam type is shown as `other` in lookups (the brief) but keeps its own name for NEW_TYPE (lower case, letters, digits and dashes, at most 40 characters), so a brand-new kind of scam alerts under its own name. Extra field: `count`.
- Alerts never fire per report; the same SPIKE or NEW_TYPE shows in the list while it holds. No `pincode` on /alerts: every area. Malformed pincode: 400 `invalid_pincode`. Well-formed but unknown: 200 with an empty list.

## 9. Licence (15 points; build it once, test it with a fake clock, rehearse it three times live)
### 9.1 Format and signing
- File: `{"licensee":"Demo Bank","expires_at":"2026-11-15T10:05:00+05:30","signature":"<base64>"}`. Extra keys are ignored (they are not signed).
- Signature: Ed25519 (PyNaCl). Signed message = `licensee` + newline + `expires_at`, exactly as written in the file, UTF-8. The public key is a constant in `app/license.py`. A different string means a different signature, so never reformat the timestamp.
- `tools/gen_keys.py` writes the private key to a path outside the repo (default `~/smashers_keys/license.key`) and prints the public key to paste into code. `tools/make_license.py --licensee NAME --minutes 5` (or `--until ISO`) prints a signed file. Keep a copy of the private key in a password manager, not Git, not chat. `.gitignore` has `*.key`; `make check` fails if any tracked file name contains `key` or `private`.
- Ship `licenses/long.json` (valid to 31 Jan 2027) in the repo. It is public data. It is also the default installed on an empty database. Also keep `licenses/expired.json` (validly signed, already expired) for quick tests.
### 9.2 State and gate
| State | When | Gate | GET /license `status` |
|---|---|---|---|
| valid | now before `expires_at`, clock not rolled back | everything works | `valid` |
| expired | now at or after `expires_at` | 403 `{"error":"LICENSE_EXPIRED"}` except /health, /license, static files | `expired` |
| none | nothing installed | same as expired | `none` |
| rollback | now earlier than the latest time we saw by more than 2 minutes | same as expired | `clock_rollback` |
- The gate runs on EVERY request (cheap compare against the in-memory licence). Not only at startup.
- Latest time seen: written to `kv` at most every 30 s. Never lowered. On rollback keep refusing until the clock passes the saved time; uploading a licence does not clear it. Escape hatch for a real clock fault: Tejas edits the saved value in the database by hand. Never expose a way to clear it over HTTP.
- GET /license reply: `{"licensee","expires_at","status","valid","seconds_remaining"}`.
- POST /license: verify the signature, then store the file in `kv` and swap the in-memory copy. No restart. A valid signature with a past date is accepted and shows `expired`. Bad JSON, bad date or bad signature: 400 `INVALID_LICENSE`. Data is never deleted on expiry.
- All licence state is in Postgres (Render's disk is wiped on restart).
- `/admin/reset` also needs a valid licence (it is not exempt). Before any judge or test-tool run, check `GET /license` says valid.
### 9.3 The app side
- The static app always loads. It calls GET /license on start and every 10 s while the page is open. Any 403 `LICENSE_EXPIRED` from the API shows the full-screen "Licence expired. Contact your provider." (Hindi below it). While shown, keep polling; when status is valid, hide the screen and refetch. No reload needed. Target: back within 15 s of the upload.
### 9.4 Live runbook (put in README and in docs/LICENSE_DEMO.md)
1. `curl $URL/health`; `curl $URL/license` shows licensee and expiry; open the app and show a lookup that works and a report that is already there.
2. `python tools/make_license.py --licensee "Demo Bank" --minutes 5 > lic5.json` then `curl -X POST $URL/license -H 'content-type: application/json' --data @lic5.json`.
3. Talk through the trust rules for 5 minutes. Then a lookup in the app: expired screen. `curl $URL/lookup?type=phone\&value=1930` shows 403 `LICENSE_EXPIRED`.
4. `curl -X POST $URL/license ... --data @licenses/long.json`. The app recovers by itself; the earlier report is still there.
Rehearse three times: once at 15:00, once before sleep, once at 09:30. Time each. Any step that needs a restart is a bug.
### 9.5 Tests (fake clock)
valid works; at `expires_at` minus 1 s works, at plus 1 s returns 403 on /lookup, /map, /alerts, /reports, /admin/reset, /challenges but 200 on /health and /license; POST valid file restores with no restart and old reports intact; tampered date fails with 400; tampered licensee fails; rollback of the clock gives `clock_rollback`; a restart (new app on the same database) keeps the installed licence; a 403 body is exactly `{"error":"LICENSE_EXPIRED"}`.

## 10. Privacy and logging (any breach disqualifies)
Stored per report: `report_id`, identifier type and normalised value, `occurred_at`, `reported_at`, `rid` and `org` (below), channel, scam type, pincode, `note_hash`, note shingle hashes, `ntok`, `has_screenshot`, `amount_lost_inr`, server receive time.
- `rid` = HMAC-SHA256(TRUST_SALT, `reporter_id`) cut to 16 bytes. `org` = same over `ip_prefix` (or the request's /24 when absent). The raw values are used in memory for that request and never stored, logged or returned.
- Never stored, logged or returned: reporter name, phone, email, exact location or coordinates, raw IP, user agent, raw reporter_id, raw ip_prefix, the note text, screenshots. GPS is never requested. We do not collect or look up anything on social media or people-search sites.
- Exception, and a judgment call Tejas can veto: `challenges` keeps `claimant_name` and `contact_email` (a business, not a reporter, who gave them to be contacted). Never returned, never logged.
- Logs: one line per request with time, method, path WITHOUT the query string, status, duration, request id. No bodies, no IPs in our own logs. The host's platform logs may show IPs; say so in the README.
- Tests (`make privacy`): insert reports using canary values (reporter `r_CANARY1`, prefix `10.9.8.7`, a note containing `CANARYNOTE` and a phone-like string), dump every table, assert none appear; capture log output for a lookup with a canary value in the query and assert it is absent; assert no response contains `rid`, `org` or the note; assert no column named name, phone, email, ip, lat or lng exists outside `challenges`.

## 11. The app: a mobile website, no login (rows 4 and 6; 30 points)
Mobile first at 360 to 414 px, no horizontal scroll. Light surfaces and one green accent (pack Part 6.9 tokens in AGENTS.md). A pseudonymous `reporter_id` is a random UUID kept in the phone's local storage, with a "Reset my anonymous ID" link. The form is the first screen. No sign-in, no cookies banner, no name or phone field anywhere.
### 11.1 Report: one screen, tap budget
| Step | Control | Taps |
|---|---|---|
| 1 | How did they reach you: 6 big icon tiles (Phone call, SMS or WhatsApp, QR code, Fake website, UPI request, Something else) | 1 |
| 2 | The number, UPI ID, link or SMS sender: one box with Paste. Detected type shown as a chip; user can change it | 1 paste |
| 3 | Kind of scam: 12 icon tiles plus "Not sure" | 1 |
| 4 | When: Just now (default), Today, Yesterday, Earlier | 0 or 1 |
| 5 | Where: area, remembered after the first use; one picker of the 25 areas grouped by city | 0 or 1 |
| 6 | Optional note, max 280 characters. No other fields | 0 |
| 7 | Post. Then show the lookup result for that value and "Thanks, your report is anonymous" | 1 |
- Budget: at most 7 interactions, median under 45 s on a phone. Scripted browser test (Playwright) measures it; Bhumika hand-times 5 runs in English, Hindi and icons-only.
- Every tile has an icon AND a short label. A reader who cannot read the language can finish with the icons. Suggested icons (Lucide; check each name exists): phone-call, message-square, qr-code, globe, indian-rupee, ellipsis for channels; shield-alert, link, qr-code, users, package, briefcase, gift, smartphone, zap, headphones, key-round, video for the 12 scam types.
- Language switch EN / हिन्दी on every screen, remembered. Strings live in one file (`web/src/i18n`). Starter Hindi (have a Hindi speaker check every line): धोखाधड़ी की रिपोर्ट करें (Report a scam), नंबर जाँचें (Check a number), नक्शा (Map), अलर्ट (Alerts), फ़ोन कॉल, SMS या WhatsApp, QR कोड, नकली वेबसाइट, UPI अनुरोध, कुछ और (channels), अभी (Just now), आज, कल, पहले, भेजें (Post), आपके पास {n} लोगों ने रिपोर्ट किया (Reported by {n} people near you), संदिग्ध (Suspicious), कोई रिपोर्ट नहीं (No reports), सत्यापित व्यवसाय (Verified business), लाइसेंस समाप्त हो गया है। अपने प्रदाता से संपर्क करें। (Licence expired. Contact your provider.)
### 11.2 Check and the result card
- One box, paste, Check. Result card shows: verdict chip with icon and colour, the sentence, the display value (masked or full by 4.3), last reported (day only), scam type with one line of advice, "Report this too" (prefilled), "Is this your number? Dispute" (section 12).
- Sentences: KNOWN_SCAM "Known scam. Reported by {n} people" (add "near you" only when the user's home area is within 5 km of an evidence area); SUSPICIOUS "Suspicious. Reported by {n} {person|people}. Not enough to confirm."; NO_REPORTS "No reports yet. That does not mean it is safe."; VERIFIED_BUSINESS "Verified business: {label}".
- Wording rule (row 4): say "reported", never "scammer", "fraud", "fraudster", "criminal", "thief" or "is a scam" about a number or person. A test greps the strings file and README for the banned words.
- Advice, one line per scam type, Bhumika to finalise and translate. Keep it generic and safe: never share OTP or PIN; scanning a QR code only sends money, never receives it; no officer arrests anyone over a video call, hang up; do not click links in SMS, open the bank's own app; report at 1930 or cybercrime.gov.in (both public, both in the verified list).
### 11.3 Map, alerts, expired screen
- Map tab: area bubbles for the last 7 days from GET /map (Leaflet with OpenStreetMap tiles, attribution shown; fall back to a plain list if tiles fail). Tapping an area shows count, top scam type, severity.
- Alerts: for the home area, plain sentences ("Scam reports in your area doubled today", "New kind of scam in your area: job offer"). A badge on the tab.
- Expired screen: section 9.3. Test it with `licenses/expired.json`.
- States: loading skeleton, timeout at 5 s with retry, offline message.

## 12. Disputes (2 bonus points)
POST /challenges validates the identifier only (400 `invalid_identifier`). `claimant_name`, `contact_email` and `proof_note` are optional, trimmed to 100, 200 and 1000 characters, and never cause a 400 (a judge's challenge must not fail on a field check). It stores the challenge and replies 201 `{"challenge_id","status":"under_review"}`. A lookup of that value then shows `challenged: true`, the verdict is at most SUSPICIOUS, the value stays masked, and the value is excluded from map and alerts while the dispute is open. A verified value stays VERIFIED_BUSINESS with `challenged: true`. Resolving a dispute is FUTURE; say so. The app has a short form behind "Is this your number? Dispute".

## 13. Tests (write first; every row of section 0 has one)
Black-box tests run against any base URL (`make smoke URL=...`), so the same suite checks local, Docker and the live server. Unit tests run the engine with a fake clock. Engine tests (E1, already passing): `python -m pytest tests/engine -q` gives 205 passed and 2 expected failures (the known limits in 6.5); `python -m tests.engine.scenarios` prints the in-process attack table in about 20 seconds.
| ID | Given, when, then | Row |
|---|---|---|
| AT-1.1 | 40 friends (new IDs, 40 networks, same note, one hour) report the Fresh Bakes phone: lookup is VERIFIED_BUSINESS. Same on an unlisted number: not KNOWN_SCAM | 1 |
| AT-1.2 | 22 accounts, one network, varied notes, one number: `distinct_reporters` 1, not KNOWN_SCAM | 1 |
| AT-1.3 | One reporter, six reports in an hour (also with rotating networks): `distinct_reporters` 1, `report_count` 6, not KNOWN_SCAM | 1 |
| AT-1.4 | Junk (`12345`, `test`, empty, `+91 00000 00000`, pincode `000000`, time `yesterday`, time in 2030): 400 and nothing stored | 1 |
| AT-1.5 | Real waves from 6.4 (history, new, burst, exactly 3, templated, half empty): KNOWN_SCAM. Two voices: SUSPICIOUS | 1, 2 |
| AT-1.6 | The "NOT stopped" rows of 6.4 are in the suite as expected-fail (xfail with reason), so the table shows them honestly | 7 |
| AT-1.7 | A source scan finds no rule keyed on a specific identifier except the verified data file | 1 |
| AT-2.1 | Every format variant in 4.2 gives the same verdict and `case_id` | 2 |
| AT-2.2 | NO_REPORTS is 200, with masked `display_value` and null dates | 2 |
| AT-2.3 | 200 lookups against the live server: p50, p95, max printed; p95 under 500 ms (target 300) | 2 |
| AT-2.4 | All verified values in section 16 give VERIFIED_BUSINESS with full `display_value` | bonus |
| AT-2.5 | Dispute (12): POST /challenges gives 201 `under_review`; the next lookup shows `challenged: true`, a verdict of at most SUSPICIOUS and a masked value; a verified value stays VERIFIED_BUSINESS; bad input gives 400 | bonus |
| AT-3.1 | Spike: 14 voices in the 7 days before, 10 today: SPIKE with count 10 and baseline 2.0 | 3 |
| AT-3.2 | Normal area with 3 today: no alert. Zero history and 5 today: SPIKE | 3 |
| AT-3.3 | New type with 3 voices today: NEW_TYPE. A scam type seen 10 days ago: no NEW_TYPE | 3 |
| AT-3.4 | Month-old and 8-day-old reports are not on the 7-day map; 6-day-old are; one cluster per area; coordinates equal the registry | 3 |
| AT-3.5 | Every attack in AT-1.x raises zero alerts | bonus |
| AT-4.1 | `make privacy` (section 10) | 4 |
| AT-4.2 | Fewer than 3 voices: `display_value` masked in all four shapes, `evidence` empty | 4 |
| AT-4.3 | Banned-word grep on UI strings and README | 4 |
| AT-5.x | The licence tests in 9.5, plus three timed live rehearsals logged in STATE.md | 5 |
| AT-6.1 | Playwright: report in at most 7 interactions and under 45 s, in English, Hindi and with only icons used | 6 |
| AT-7.1 | A clean clone follows the README (`docker compose up --build`) and passes `make smoke URL=http://localhost:8000` | 7 |
`make attack` prints one table (scenario, voices, verdict, pass or fail, config hash) for all of the above. Never change an expected result to make a run pass. Publish the misses.

## 14. Plan and submission
| Time | Tejas (server) | Bhumika (web, docs) |
|---|---|---|
| now to 13:00 | Repo, Dockerfile, `/health` on Render with Postgres. Send the URL | Shell, tokens, routes, i18n file, mock API from section 3 |
| 13:00 to 14:30 | Stage 2: copy in `app/engine`, `app/data`, `tests/engine`; tables; wire the seven routes as `app/engine/README.md` shows; deploy (T3 writes the black-box tests) | Report screen (section 11.1), result card on mock data |
| 14:30 to 16:00 | Licence (section 9) end to end, expired-screen hook, rehearsal 1 | Check screen on the live API, expired screen, Hindi strings |
| 16:00 to 19:00 | Checkpoint 1: show the live URL, report and lookup in 3 formats, the licence demo. Then T3's `make attack` on the live URL; the trust rules are already in the engine | Same checkpoint. Map tab, alerts list, README skeleton |
| 19:00 to 22:00 | Check map, alerts, challenges and reset on live; perf run from the venue network; licence hardening | Dispute form, polish, e2e timing test, claims audit |
| 22:00 to 00:00 | Fix what T3's privacy and attack runs report, publish the attack table with its misses, rehearsal 2 | README final draft, video storyboard |
| 00:00 to 06:00 | Staggered sleep (pack Part 6.8). Whoever is awake only fixes and rehearses | |
| 06:00 to 09:00 | Hardening, `make smoke` on live, warm-up routine | Hindi review, record the video (3 minutes max), hand-time reports |
| 09:00 | Feature freeze | |
| 09:00 to 11:00 | Bug fixes only, rehearsal 3, confirm licence valid and uptime monitor green | Final README, links, submission form |
| 11:00 to 11:30 | Submit in the first 10 minutes | |

T3 (Antigravity on Tejas's laptop, section 15): 13:00 to 14:30 writes the tests and scenario generators first (red until the server exists); about 14:30 first run against T1's local server, then `tests/FINDINGS.md` to Tejas; 16:00 to 19:00 attack table against trust v1, then map and alert scenarios; 19:00 to 22:00 privacy canaries and `make perf`; from 22:00 reruns everything after each merge, and on the live URL before each rehearsal. If its quota locks, a second Claude Code session takes the same worktree, using `tests/README.md`.

Submit (OFFICIAL list): Git repository; public server address working during judging; the app as a mobile website link (an APK only if time allows; JUDGMENT: skip); README with how to run, how the trust rules work, how the licence works; demo video up to 3 minutes; two licence files ready (long file in the repo, 5-minute file minted on the spot with the tool, plus a spare). Ask whether the repository must be public or shared with the judges.
Video (3:00): 0:00 the digital-arrest story in one line; 0:10 a Hindi report with a stopwatch; 0:40 one number typed three ways, same result, masked then unmasked; 1:10 `make attack` against the live URL; 1:50 map and alert; 2:15 the licence cycle (cut the wait); 2:50 close with the limits.
Questions for the hackathon channel (ask now): (1) does the repository need to be public or shared with judges, (2) do judges reach our server over the open internet at the venue, (3) is a mobile website enough, or must there be an APK, (4) does the test tool call GET /license.

## 15. Agent briefs (paste with the section numbers named)
**T1. Tejas, main agent, server.** Own only: /app (not /app/static), /tools, /deploy, /tests/unit, Makefile. /tests/api, /tests/attack and /tests/privacy belong to T3; you wire them into the Makefile as its brief says. The ASGI app is `app.main:app`. Order: wire `app/engine` exactly as its README shows and do not rewrite it (tables, the seven routes, persist callbacks, start-up `load`, reset); middleware for size limit, JSON 404 and 405, 400 instead of 422, and the logging rules (3, 10); licence module, gate, endpoints, tools and tests (9, 9.5); then fix what `tests/FINDINGS.md` reports. An engine bug goes to Tejas with the failing case, not into a rewrite. Done = tests green, deployed, `make smoke URL=<live>` green, report in the Prompt 0 format. API paths and fields in section 3 are frozen. If something must change, stop and ask.
**B1. Bhumika, her Claude, web and docs.** Own only: /web, /docs (not PROBLEM_CARD.md or BUILD_SPEC.md), /tests/e2e. Build against mock JSON from section 3 until the live API answers. Order: shell, i18n, tokens; Report (11.1); Check and result card (11.2); expired screen and polling (11.3, 9.3); Map and Alerts; Dispute; Hindi review; README, DISCLOSURE.md, DECISIONS.md, STATE.md, LICENSE_DEMO.md; video. Never edit /app. Output of `make web` goes to /app/static; ask Tejas before committing there.
**T2. Optional, only after rows 1 to 6 are green:** an "Attack this number" screen that runs the four tricks against a sandbox copy of the engine, not the live data (reset wipes the live data).
**T3. Antigravity agent on Tejas's laptop: black-box tests and the attack table.** Own only: /tests/api, /tests/attack, /tests/privacy, in its own git worktree (`../scammap-tests`, branch `tests-agent`). Never edit /app, /web, /docs, Makefile, AGENTS.md or this file. Work from sections 3 to 8, 10, 12, 13 and 16 as if you had never seen the server; open /app only to debug a failure after a first run, and then report it instead of fixing it. Give this agent the repo and docs/BUILD_SPEC.md only: never the organisers' PDFs or anything from the file server (AGENTS.md rule 5).
- Interface with T1 (frozen): the app is `app.main:app`; the base URL is `BASE_URL` (default `http://localhost:8000`). T1 wires `make smoke URL=x` to `BASE_URL=x python -m pytest tests/api -q`; `make attack [URL=x]` to `python tests/attack/run.py --base-url x`; `make perf URL=x` to `python tests/api/perf.py --base-url x`; `make privacy` to `python -m pytest tests/privacy -q`.
- Order, tests first (red until T1 deploys): (1) `tests/api`: 404 and 405 as JSON, error bodies that never echo input, AT-1.4, AT-2.1, AT-2.2, AT-2.4, AT-2.5, AT-4.2, the same `report_id` twice, and `perf.py` (AT-2.3). (2) `tests/attack`: seeded generators for every row of 6.4 and for AT-3.x; `run.py` prints one table: scenario, seeds, KNOWN_SCAM rate, want, PASS, FAIL or KNOWN LIMIT, and `trust.config`. (3) `tests/privacy`: the canaries of section 10 over HTTP (no response, error body or lookup holds the canary reporter, prefix or note text, or `rid` or `org`); when run locally, also start the server as a subprocess on a temporary sqlite file (rebase on main to get /app), dump every table, capture its log output, and assert the canaries are absent.
- Scenario rules: synthetic data only (AGENTS.md rule 22): numbers `+91 90000 xxxxx`, made-up UPI names, `.example` links, reporters `r_<seed>_<n>`, networks in `10.x.y`, notes from a fixed word list. Each seed uses its own reporters and numbers, so lookup scenarios share one `POST /admin/reset` at the start of a run; map and alert scenarios reset before every run. Take "now" from the `Date` header of `GET /health`, not the laptop clock. One keep-alive client, at most 8 requests in flight, retry a 429 after a pause. Defaults: 20 seeds, 100 background reporters, 15 background numbers; `--full` is the 6.4 setting (60, 300, 40).
- Pass rule: Want high = at least 90% of seeds KNOWN_SCAM. Want 0 = no seed. Want low = no seed KNOWN_SCAM and every seed SUSPICIOUS. The "NOT stopped" rows and the all-empty-notes row are KNOWN LIMIT (xfail with a reason, section 6.5): the table prints the measured rate and does not fail the run; if one is now stopped, print NOW STOPPED and tell Tejas. Never change a Want to make a run pass.
- Findings: every failing test gets an entry in `tests/FINDINGS.md`: test ID, spec section, request, expected, actual (status and body), and your view: server bug, spec gap or test bug. Do not guess on a spec gap; list it under "Questions for Tejas". Keep `tests/README.md` current (how to run each suite, what is done, what is red) so another agent can take over if the quota locks.
- Safety: only `BASE_URL`. `run.py` refuses any host except localhost unless `--base-url` is given, prints the host before it sends anything, and never targets 192.168.60.13 or any host we do not own. No LLM calls, no scraping, no real data.
- Git: small commits on `tests-agent`, rebase on main before asking Tejas to merge, never push to main. Done = suites run with the output shown, FINDINGS updated, report in the Prompt 0 format.
- First prompt (paste into Antigravity; paste it again if a conversation restarts): "You are T3 on Team Smashers' build of the Community Scam Map server: black-box tests and the attack table. Read, in this order: AGENTS.md, then docs/BUILD_SPEC.md sections 0 to 8, 10, 12, 13 and 16, then the T3 brief in section 15. Work only in tests/api, tests/attack and tests/privacy in this worktree. Tests first. Do not open /app until a test has failed against a running server. Send requests only to http://localhost:8000 unless I give you another URL. Before writing code, show me your plan in at most 10 lines: the files you will create and the first five tests."

**E1. Claude (chat), via Tejas: the engine.** Delivered with v2.2: `app/engine` (normaliser, masking, fingerprints, trust rules, verdicts, map, alerts, challenges, reset, rebuild), `app/data` (areas, verified values, scam types, channels) and `tests/engine` (189 tests, the attack table, a benchmark). Pure Python, standard library only. It owns those three folders; changes go through Tejas, each with a test and a fresh attack table (`python -m tests.engine.scenarios --seeds 60`).

## 16. Data tables (needed to build; derived from the brief's appendices; the only organiser content that may be copied into the repo as data files)
### Areas (`app/data/areas.json`): pincode, area, city, latitude, longitude
| Pincode | Area | City | Lat | Lng |
|---|---|---|---|---|
| 560102 | HSR Layout | Bengaluru | 12.9116 | 77.6473 |
| 560038 | Indiranagar | Bengaluru | 12.9784 | 77.6408 |
| 560034 | Koramangala | Bengaluru | 12.9352 | 77.6245 |
| 560066 | Whitefield | Bengaluru | 12.9698 | 77.7500 |
| 560076 | BTM Layout | Bengaluru | 12.9166 | 77.6101 |
| 560011 | Jayanagar | Bengaluru | 12.9299 | 77.5826 |
| 560037 | Marathahalli | Bengaluru | 12.9591 | 77.6974 |
| 560103 | Bellandur | Bengaluru | 12.9260 | 77.6762 |
| 560100 | Electronic City | Bengaluru | 12.8452 | 77.6602 |
| 560078 | JP Nagar | Bengaluru | 12.9077 | 77.5851 |
| 560003 | Malleshwaram | Bengaluru | 13.0035 | 77.5709 |
| 560010 | Rajajinagar | Bengaluru | 12.9915 | 77.5520 |
| 560024 | Hebbal | Bengaluru | 13.0358 | 77.5970 |
| 560064 | Yelahanka | Bengaluru | 13.1007 | 77.5963 |
| 560070 | Banashankari | Bengaluru | 12.9250 | 77.5468 |
| 400050 | Bandra West | Mumbai | 19.0596 | 72.8295 |
| 110016 | Hauz Khas | Delhi | 28.5494 | 77.2001 |
| 500081 | Madhapur | Hyderabad | 17.4486 | 78.3908 |
| 600020 | Adyar | Chennai | 13.0012 | 80.2565 |
| 411014 | Viman Nagar | Pune | 18.5679 | 73.9143 |
| 700091 | Salt Lake Sector V | Kolkata | 22.5790 | 88.4290 |
| 380015 | Satellite | Ahmedabad | 23.0260 | 72.5085 |
| 302017 | Malviya Nagar | Jaipur | 26.8570 | 75.8080 |
| 226010 | Gomti Nagar | Lucknow | 26.8540 | 80.9990 |
| 682030 | Kakkanad | Kochi | 10.0159 | 76.3419 |
### Verified (`app/data/verified.json`): type, value, owner label
| Type | Value | Label |
|---|---|---|
| phone | 1930 | National Cybercrime Helpline |
| phone | 1909 | TRAI Do Not Disturb |
| phone | 1800 1600 | HDFC Bank customer care |
| phone | 1800 2600 | HDFC Bank customer care |
| phone | 1800 1080 | ICICI Bank customer care |
| phone | 1800 1234 | State Bank of India customer care |
| phone | 1800 2100 | State Bank of India customer care |
| phone | 1860 419 5555 | Axis Bank customer care |
| phone | 1860 266 2666 | Kotak Mahindra Bank customer care |
| sender_id | HDFCBK | HDFC Bank SMS sender |
| sender_id | ICICIB | ICICI Bank SMS sender |
| sender_id | SBIINB | State Bank of India SMS sender |
| sender_id | AXISBK | Axis Bank SMS sender |
| sender_id | KOTAKB | Kotak Mahindra Bank SMS sender |
| url | https://cybercrime.gov.in | National Cyber Crime Reporting Portal |
| url | https://sancharsaathi.gov.in | Sanchar Saathi |
| phone | +91 80 4100 2233 | Fresh Bakes, Indiranagar (made up) |
| phone | +91 80 2553 0190 | Koramangala Pharmacy (made up) |
| upi | freshbakes@okaxis | Fresh Bakes, Indiranagar (made up) |
Normalise the values with 4.1 when loading. `1800 1600` is a toll-free number, not a mobile.
### Scam types and channels
Types: digital-arrest, fake-kyc-link, upi-refund-qr, investment-group, courier-customs, job-offer, lottery-prize, loan-app-harassment, electricity-disconnection, fake-customer-care, otp-call, sextortion. Any other value is accepted and stored as `other`.
Channels: Phone call, SMS or WhatsApp, QR code, Fake website, UPI request, Something else.
Delivered as `app/data/areas.json`, `app/data/verified.json` and `app/data/taxonomy.json` (with channel aliases such as `sms` and `whatsapp`).

## 17. Claims audit and disclosure starters
| Claim | Evidence | Status |
|---|---|---|
| Stops the four named tricks | in-process attack table on the engine, 60 seeds (6.4) | CHECKED in-process with our generators |
| Stops the four named tricks on the live server | `make attack` on the live URL | UNVERIFIED |
| Lookup p95 under 0.5 s | engine 0.15 ms in-process (`tests.engine.bench`); live `make perf` from the venue | in-process CHECKED; live UNVERIFIED |
| Report takes under 60 s | Playwright timing plus hand timing | UNVERIFIED |
| No reporter data stored | engine canary tests (`tests/engine/test_privacy.py`) pass; `make privacy` on the server (tables, logs) | engine CHECKED; server UNVERIFIED |
| Licence works with no restart | three logged rehearsals | UNVERIFIED |
| Hosted on a public https address | the URL, `GET /health` | UNVERIFIED |
Wording: "in our tests" and "against the tricks we modelled"; never "secure", "accurate" or "real-time" without evidence.
DISCLOSURE.md starter (add version and licence at first use): FastAPI, Uvicorn, Pydantic, SQLAlchemy, psycopg, PyNaCl, pytest, httpx, Playwright, React, Vite, TypeScript, Leaflet, OpenStreetMap tiles, Lucide icons, Inter and JetBrains Mono, Render, UptimeRobot, Claude Code, Claude and Antigravity as build tools. No LLM at runtime.

## 18. Decisions for Tejas (my default in brackets)
1. Host: Render plus Postgres [yes, now].
2. Round `first_seen` and `last_seen` to the day, and hide `evidence`, below 3 voices [yes].
3. Keep claimant name and email in `challenges` [yes; drop them if you prefer, the dispute still works].
4. No APK, mobile website only [yes].
5. Do not pre-apply any trust dial in 6.5 [agree].
6. Post the four questions in section 14 to the channel [yes].
7. Trust rules v1.1 as in section 6: linked groups add no weight; pasted text links at 3 writers, or 2 in a campaign; network link within 24 h; own words from 3 words [yes].
8. NEW_TYPE fires on one own-words report of a new type [yes; turn `new_type_personal_alone` off if rehearsals show noise].
9. 60-minute tolerance for `occurred_at` in the future [yes].
10. Challenges never return 400 for the optional fields [yes].
