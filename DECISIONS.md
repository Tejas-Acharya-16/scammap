# Decisions

Decisions that took more than 10 minutes. Newest last.

## 1. How to tell real reports from fake ones (trust rules v1.1)
- Question: count people, or weigh them?
- Options: count distinct reporters; machine learning; deterministic rules that link reports into "voices".
- Chosen: deterministic voices. Reports sharing a reporter ID, a network within 24 hours, or pasted text form one voice; a voice weighs 0.5, or 1.0 with a confirmed track record; KNOWN_SCAM needs 3 voices and 1.5 points. Why: explainable, testable, no training data, and the judges check for rules tied to specific numbers, which this avoids.
- Would change our mind: a fair real-wave scenario in our table failing.
- Cost if wrong: a fake campaign marks a number, or a real wave stays SUSPICIOUS.
- Status: done; 60-seed attack table in `tests/engine/ATTACK_TABLE.txt`.

## 2. One person asks 10 friends (rule 7, v1.2)
- Question: raised at checkpoint 1. How do we stop a ring of new accounts, each on its own phone, in their own words?
- Options: lower weights for everyone; hold every burst; merge only a burst that several signals agree on.
- Chosen: 8 or more voices with no track record, from one area, within 6 hours, making up 80% or more of the voices, count as one linked voice. Why: no single signal decides; real waves across areas or days still confirm.
- Would change our mind: a real local wave of 8+ new people in one area in our tests or the judges' feedback.
- Cost if wrong: such a real wave waits as SUSPICIOUS until independent people report it.
- Status: done; `tests/engine/test_burst.py`.

## 3. Licence design
- Question: how to make a licence that cannot be forged and needs no restart?
- Chosen: Ed25519 signature over licensee and expiry, public key in code, state in the database, upload over `POST /license`, a gate on every request. A correctly signed expired file (`licenses/expired.json`) lets a judge run the demo without our private key.
- Cost if wrong: 15 points.
- Status: 4 steps passed on live, 31 Oct 18:46.

## 4. No rate limit on reports
- Question: should the server throttle many reports from one machine?
- Chosen: no. The judges' tool loads its secret data from one machine; a 429 there would lose data and points. Abuse is handled by the trust rules, not by speed limits.
- Would change our mind: the organisers say their tool retries a 429.
- Status: bulk test, 2,000 reports, 0 x 429.

## 5. Hosting
- Question: free Render instance or paid?
- Chosen so far: free, with a keep-awake monitor; switch to the cheapest paid instance for the judging window.
- Why: the free instance sleeps after 15 minutes idle and slowed lookups to about 2 s during a bulk upload in our capped test.
- Status: open, decision for Tejas before judging.

## 6. The judge console (`/judge`)
- Question: how do we let a judge check every row quickly without touching the live data?
- Chosen: a page that runs 26 checks on a fresh in-memory copy of the engine with the same code and config, plus read-only live checks.
- Status: done; 26/26 on live.

## 7. Notes must never block an honest report (engine v1.3)
- Question: found at 02:40 on 1 Nov. A test tool may give its real reports empty notes or one example sentence copied from the brief's sample. Do our note rules still find real scams?
- Finding: no. Engine v1.2 marked 0% of such real waves KNOWN_SCAM, even 3 different people with empty notes (in our tests).
- Options: keep v1.2 (strong on fakes, blind to lazy data); ignore notes entirely (loses multi-area fake bursts); notes count only when the copies or empty notes arrive together.
- Chosen: the third. An unlinked voice weighs the same with or without a note; shared text links only within 6 hours; a burst of 8+ new empty-note voices merges from any area. Why: every fake trick in our table stays stopped, and every lazy real wave flips except 8+ identical notes within 2 hours.
- Would change our mind: the organisers' sample data showing real reports always carry distinct notes.
- Cost if wrong: a slow multi-day ring with empty notes could mark a number.
- Status: done; 60-seed table in `tests/engine/ATTACK_TABLE.txt`, config `d7a23b4c`.
