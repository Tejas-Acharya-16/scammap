# Community Scam Map for India

Report and verify scams in seconds, anonymously.

**Live:** <https://scammap-yp1k.onrender.com>
**Judge console:** <https://scammap-yp1k.onrender.com/judge>

---

## Run locally

**Requirements:** Python 3.12+, pip

```bash
pip install -r requirements.txt
```

Set the trust salt (any stable string; changing it splits reporter histories):

```bash
export TRUST_SALT=my-local-salt
```

Start the server (uses SQLite by default):

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Or with Docker (app + Postgres):

```bash
docker compose up --build
# Server at http://localhost:8000
```

---

## API

JSON in and out. Times are ISO 8601 with `+05:30`. Errors: `{"error": "<code>"}`. No login on any route.

| Route | Method | Success | Errors |
|---|---|---|---|
| `/health` | GET | `200 {"ok": true}` | — |
| `/reports` | POST | `201 {"report_id", "case_id", "merged"}` | `400 {"error": "…"}` |
| `/lookup?type=&value=` | GET | `200` (verdict object) | `400` for impossible values |
| `/map?pincode=&days=7&radius_km=2` | GET | `200 {"clusters": [...]}` | `400` for malformed pincode |
| `/alerts?pincode=` | GET | `200 {"alerts": [...]}` | `400` for malformed pincode |
| `/admin/reset` | POST | `200 {"ok": true}` | — |
| `/challenges` | POST | `201 {"challenge_id", "status": "under_review"}` | `400` |
| `/license` | GET | `200` (licence status) | — |
| `/license` | POST | `200` (installed licence) | `400 {"error": "INVALID_LICENSE"}` |

When the licence is not valid, every route except `/health`, `/license` and static files returns `403 {"error": "LICENSE_EXPIRED"}`.

Unknown routes return `404 {"error": "not_found"}`. Wrong method returns `405 {"error": "method_not_allowed"}`. Error messages never echo user input.

---

## How the trust rules work

The system counts independent **voices**, not raw reports. A number is marked KNOWN_SCAM only when at least 3 voices report it and they add up to at least 1.5 points. Fewer voices means SUSPICIOUS. No reports means NO_REPORTS.

1. **Junk is turned away at the door.** A number, UPI ID, link or sender that cannot exist, an area we do not cover, or an impossible time is rejected before anything is stored.

2. **One person is one voice.** Reports on one number are linked into one voice when they share a reporter identity (at any time), or a network within 24 hours. Many reports from the same connection within a short time count as one person.

3. **Copy-paste is one voice.** The same text, or a lightly edited copy of a long text, posted by 3 or more different reporters on one number links those reports. If a number carries 2 or more such pasted texts, pairs sharing even two people are also linked (a campaign working from a list of texts).

4. **Track record.** A voice counts 1.0 points when its reporter earlier reported a different number that at least two other voices confirmed (and that number is not verified or disputed). Otherwise 0.5.

5. **Own words.** A voice from one reporter with a note of 3 or more words counts in full. An empty or very short note counts half, and all such short-note voices together add at most 1.0. A linked group (rule 2 or 3) is one voice and adds no weight at all.

6. **Threshold.** A number is KNOWN_SCAM when at least 3 voices report it and they add up to at least 1.5 points. A verified number is always VERIFIED_BUSINESS, whatever is reported. A disputed number is never KNOWN_SCAM.

7. **Map and alerts count only clean voices.** None of the four tricks (friends, same network, one person, copy-paste) can move the map or trigger alerts.

---

## Known limits

We say these out loud. In our tests:

- **Many new accounts on different networks, each writing different words in their own voice, arriving together** look exactly like a real wave. The verified list protects listed businesses from this; for unlisted numbers, this is the main hole.
- **Lightly reworded copies** (3 word swaps in an 18-word text) are not caught. Lowering the threshold would merge real reporters who describe one campaign in similar words.
- **Real waves where every reporter left the note empty** stay SUSPICIOUS. Empty notes add at most 1.0 point total.
- **A ring can build a track record** by first reporting numbers that other ring members also report.
- **People behind one network prefix within 24 hours** (a campus, carrier NAT, a family) count as one voice and add no weight.

---

## How the licence works

The server runs under a signed licence. An Ed25519 public key is built into the server code. The private key never leaves the operator's machine and is never in this repository.

- A licence file contains a licensee name, an expiry time, and a signature.
- `POST /license` verifies the signature, stores the licence in the database, and swaps the in-memory copy. No restart needed.
- `GET /license` shows the current licensee, expiry, status (`valid`, `expired`, `none`, `clock_rollback`) and seconds remaining.
- When the licence is expired (or missing, or the clock has rolled back by more than 2 minutes), every route except `/health` and `/license` returns `403 {"error": "LICENSE_EXPIRED"}`.
- Data is never deleted on expiry. Uploading a valid licence restores full service instantly.
- The web app polls `/license` every 10 seconds. When the licence expires, it shows "Licence expired. Contact your provider." When a valid licence is uploaded, the app recovers by itself.

**Live demo steps:**

```bash
# 1. Check health and licence
curl $URL/health
curl $URL/license

# 2. Install a 5-minute licence
python tools/make_license.py --licensee "Demo Bank" --minutes 5 > lic5.json
curl -X POST $URL/license -H 'content-type: application/json' --data @lic5.json

# 3. Wait for expiry → lookups return 403
curl "$URL/lookup?type=phone&value=1930"

# 4. Restore with the long licence → service recovers, no restart
curl -X POST $URL/license -H 'content-type: application/json' --data @licenses/long.json
```

---

## Privacy

### What is stored per report

Report ID, identifier type and normalised value, `occurred_at`, `reported_at`, hashed reporter identity (`rid`), hashed network prefix (`org`), channel, scam type, pincode, note hash, note shingle hashes, word count, `has_screenshot`, `amount_lost_inr`, server receive time.

Reporter identity and network prefix are HMAC-SHA256 hashed with a secret salt before storage. Only the hashes are kept.

### What is never stored, logged or returned

Reporter name, phone number, email, exact location or coordinates, raw IP address, user agent, raw reporter identity, raw network prefix, the note text, screenshots. GPS is never requested. We do not collect or look up anything on social media or people-search sites.

### Display rules

A value is shown in full only after 3 different voices report it and it is not under dispute. Below that threshold, values are masked (e.g. `98XXXXX210`).

### Logging

One line per request: time, method, path (without the query string), status, duration, request ID. No bodies, no IPs in our own logs. The hosting platform may log IPs at the infrastructure level.

---

## Proof

All results below are from our own synthetic data and generators. They are not from the judges' tool and do not represent results on unknown data. We quote them as "in our tests".

### Test commands

```bash
# Engine unit tests (189 passed, 4 expected failures for known limits)
python -m pytest tests/engine -q

# In-process attack table (60 seeds, ~20 seconds)
python -m tests.engine.scenarios --seeds 60 --compare
```

### Attack table (in our tests, config `eacc847a`)

**Real waves — should be detected:**

| Scenario | Seeds | Result |
|---|---|---|
| 8 reporters with history, spread over 13 days | 60 | 100% detected |
| 8 brand-new reporters, spread | 60 | 100% detected |
| 6 brand-new, all within 2 hours | 60 | 100% detected |
| 3 brand-new, own words | 60 | 100% detected |
| 8 new, templated notes | 60 | 98% detected |
| 8 new, half with empty notes | 60 | 100% detected |
| 10 reporters on only 15 shared networks | 60 | 100% detected |
| 8 new, short notes of 3 to 4 words | 60 | 100% detected |
| 8 new, 4 on 2 shared networks, days apart | 60 | 100% detected |
| 7 new, notes from a list of 10 texts | 60 | 98% detected |
| 4 new, notes from a list of 10 texts | 60 | 98% detected |

**Tricks — should be stopped:**

| Scenario | Seeds | Result |
|---|---|---|
| 40 friends, same note, 40 networks | 60 | 0% — stopped |
| 40 friends, empty notes | 60 | 0% — stopped |
| 22 accounts, one network, varied notes | 60 | 0% — stopped |
| 22 accounts, one network, empty notes | 60 | 0% — stopped |
| 22 accounts, one network, spread over 5 days | 60 | 0% — stopped |
| One person ×6, same network | 60 | 0% — stopped |
| One person ×6, rotating networks | 60 | 0% — stopped |
| 20 accounts on 2 networks, same note | 60 | 0% — stopped |
| 40 friends, 5 canned short phrases | 60 | 0% — stopped |
| 40 friends, 5 canned long phrases | 60 | 0% — stopped |
| 40 friends, notes from a list of 10 texts | 60 | 0% — stopped |
| 3 attackers × 10 accounts, 3 networks | 60 | 0% — stopped |
| 40 friends report a verified business | 60 | 0% — VERIFIED_BUSINESS held |

**Known limits (not stopped, in our tests):**

| Scenario | Seeds | Result |
|---|---|---|
| 40 friends, own varied notes, 40 networks | 60 | 100% — not stopped |
| 40 friends, lightly reworded (3 word swaps) | 60 | 100% — not stopped |
| 8 new, all empty notes | 60 | 0% detected (stays SUSPICIOUS) |

**Alerts (in our tests, 15 seeds each):**

| Scenario | Expected | Result |
|---|---|---|
| 14 voices in 7 days, 10 today | SPIKE | 100% |
| Normal area, 3 today | No alert | 100% |
| No history, 5 today | SPIKE | 100% |
| New type, 3 people | NEW_TYPE | 100% |
| New type, 1 person in own words | NEW_TYPE | 100% |
| Type seen 10 days ago | No NEW_TYPE | 100% |
| Every trick above in a quiet area | No alert | 100% |

---

## Team

**Team Smashers** — CyberForge 2026 final round, Mitigata × HackCulture, Bengaluru

- **Tejas Prakash** — tech lead, server, trust rules, licence, integration
- **Bhumika** — product, UX, web app, documentation, demo, QA

All code in this repository was written during the event. Third-party libraries and tools are listed in [DISCLOSURE.md](DISCLOSURE.md).
