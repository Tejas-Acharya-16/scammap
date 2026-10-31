# Community Scam Map for India

Report and verify scams in seconds, anonymously.

**Live:** <https://scammap-yp1k.onrender.com> (opens on Report; <https://scammap-yp1k.onrender.com/#check> opens Check)
**Judge console:** <https://scammap-yp1k.onrender.com/judge>
Judge console: /judge runs every scoring check on a sandbox copy of the engine.

---

## Run locally

**Requirements:** Python 3.12+ (or Docker). Install into a virtual environment: a plain `pip install` is refused by the system Python on recent Ubuntu, Debian and Homebrew (`externally-managed-environment`).

macOS / Linux (on Debian or Ubuntu, `sudo apt install python3-venv` first if `venv` is missing):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export TRUST_SALT=my-local-salt   # any stable string; changing it splits reporter histories
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:TRUST_SALT = "my-local-salt"
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

The server uses SQLite by default. On a fresh database it installs the licence in `licenses/long.json` by itself, so it answers at once. Check it from a second terminal:

```bash
curl http://127.0.0.1:8000/health                                     # {"ok":true}
curl "http://127.0.0.1:8000/lookup?type=phone&value=%2B919876543210"  # 200, verdict NO_REPORTS
```

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod "http://127.0.0.1:8000/lookup?type=phone&value=%2B919876543210"
```

Or with Docker (app + Postgres):

```bash
docker compose up --build
# Server at http://localhost:8080 (docker-compose.yml maps port 8080 to the app)
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

**Licence demo, no private key needed.** Run it from the repository folder. Set `URL` to `http://127.0.0.1:8000` locally, `http://localhost:8080` with Docker, or the live address. `licenses/expired.json` is a correctly signed licence whose date has passed; `licenses/long.json` runs to 31 Jan 2027.

```bash
URL=http://127.0.0.1:8000

# 1. The licence is valid. Add one synthetic report so step 3 can show the data survives.
curl $URL/license                                  # "status":"valid"
curl -X POST $URL/reports -H 'content-type: application/json' -d '{"report_id":"demo-licence-1","occurred_at":"2026-10-31T12:00:00+05:30","reporter_id":"r_demo_licence","channel":"Phone call","scam_type":"otp-call","identifier_type":"phone","identifier_value":"+91 90000 00042","pincode":"560102","note":"demo report to show the data survives the licence check"}'
curl "$URL/lookup?type=phone&value=9000000042"     # "report_count":1

# 2. Install the expired licence. Every API route answers 403 {"error":"LICENSE_EXPIRED"},
#    and the app (open $URL in a browser) shows "Licence expired. Contact your provider." at its next check (every 10 s).
curl -X POST $URL/license -H 'content-type: application/json' --data @licenses/expired.json   # "status":"expired"
for r in "lookup?type=phone&value=9000000042" "map?pincode=560102" "alerts?pincode=560102"; do
  curl -s -o /dev/null -w "GET /$r -> %{http_code}\n" "$URL/$r"; done
for r in reports challenges demo/run; do
  curl -s -o /dev/null -w "POST /$r -> %{http_code}\n" -X POST "$URL/$r" -H 'content-type: application/json' -d '{}'; done
curl $URL/health                                   # still 200: /health and /license stay open

# 3. Install the long licence. The API is back at once, with no restart and the same data;
#    the app clears the expired screen at its next check, within 15 s.
curl -X POST $URL/license -H 'content-type: application/json' --data @licenses/long.json      # "status":"valid"
curl "$URL/lookup?type=phone&value=9000000042"     # 200, "report_count":1 as in step 1

# 4. Change one digit (expiry 2027 -> 2028) and upload the copy: the signature check fails.
sed 's/2027-01-31/2028-01-31/' licenses/long.json > tampered.json
curl -X POST $URL/license -H 'content-type: application/json' --data @tampered.json          # 400 {"error":"INVALID_LICENSE"}
curl $URL/license                                  # unchanged: still the long licence, "status":"valid"
```

`POST /admin/reset` is behind the licence too. It is left out above because with a valid licence it deletes every report.

The same steps in Windows PowerShell. An error status shows up in the `catch`, which prints the code:

```powershell
$URL = "http://127.0.0.1:8000"
# 1
Invoke-RestMethod "$URL/license"
Invoke-RestMethod -Method Post -Uri "$URL/reports" -ContentType "application/json" -Body '{"report_id":"demo-licence-1","occurred_at":"2026-10-31T12:00:00+05:30","reporter_id":"r_demo_licence","channel":"Phone call","scam_type":"otp-call","identifier_type":"phone","identifier_value":"+91 90000 00042","pincode":"560102","note":"demo report to show the data survives the licence check"}'
Invoke-RestMethod "$URL/lookup?type=phone&value=9000000042"
# 2
Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile licenses\expired.json
foreach ($r in "lookup?type=phone&value=9000000042", "map?pincode=560102", "alerts?pincode=560102") {
  try { Invoke-RestMethod "$URL/$r" | Out-Null; "GET /$r -> 200" } catch { "GET /$r -> $([int]$_.Exception.Response.StatusCode)" } }
foreach ($r in "reports", "challenges", "demo/run") {
  try { Invoke-RestMethod -Method Post -Uri "$URL/$r" -ContentType "application/json" -Body '{}' | Out-Null; "POST /$r -> 200" } catch { "POST /$r -> $([int]$_.Exception.Response.StatusCode)" } }
Invoke-RestMethod "$URL/health"
# 3
Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile licenses\long.json
Invoke-RestMethod "$URL/lookup?type=phone&value=9000000042"
# 4
(Get-Content licenses\long.json -Raw).Replace("2027-01-31", "2028-01-31") | Set-Content -Encoding ascii tampered.json
try { Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile tampered.json } catch { [int]$_.Exception.Response.StatusCode }
Invoke-RestMethod "$URL/license"
```

**Operator only** (needs the private key, which is never in this repository): mint a short licence for a live countdown.

```bash
python tools/make_license.py --licensee "Demo Bank" --minutes 5 > lic5.json
curl -X POST $URL/license -H 'content-type: application/json' --data @lic5.json
```

---

## Privacy

Security notes (what we protect, how, what is open by design, known limits): see [SECURITY.md](SECURITY.md).

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

**Live run:** the attack scenarios sent over HTTP to the live server (31 Oct 2026, 21:48 IST, 2 seeds, 1,677 reports, 0 failures, 2 known limits): [tests/attack/LIVE_ATTACK_TABLE.txt](tests/attack/LIVE_ATTACK_TABLE.txt).

### Test commands

```bash
# Engine unit tests (205 passed, 2 known limits)
python -m pytest tests/engine -q

# In-process attack table (60 seeds, ~20 seconds)
python -m tests.engine.scenarios --seeds 60 --compare
```

### Attack table (in our tests, config `76f35c12`)

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
| 12 new within 3 hours, across 6 areas | 60 | 100% detected |
| 20 friends in one hour + 3 real people elsewhere | 60 | 100% detected |

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
| 1 person + 10 friends, own words, one area, 1 hour | 60 | 0% — stopped |
| 40 friends, own varied notes, 40 networks, one area | 60 | 0% — stopped |
| 40 friends, lightly reworded (up to 3 word swaps) | 60 | 0% — stopped |

**Known limits (not stopped, in our tests):**

| Scenario | Seeds | Result |
|---|---|---|
| 1 person + 10 friends, each picks another area | 60 | 100% — not stopped |
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
| 10 empty notes, one number | No alert | 100% |
| 10 empty notes, 10 numbers | SPIKE | 100% |
| Trick: 1 person + 10 friends, one area, 1 hour | No alert | 100% |
| Trick: 40 friends, own varied notes, one area | No alert | 100% |
| Trick: 40 friends, lightly reworded | No alert | 100% |
| Every trick above in a quiet area | No alert | 100% |

---

## Team

**Team Smashers** — CyberForge 2026 final round, Mitigata × HackCulture, Bengaluru

- **Tejas Prakash** — tech lead, server, trust rules, licence, integration
- **Bhumika** — product, UX, web app, documentation, demo, QA

All code in this repository was written during the event. Third-party libraries and tools are listed in [DISCLOSURE.md](DISCLOSURE.md).
