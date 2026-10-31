# Problem Card: Community Scam Map for India

Team Smashers: Tejas Prakash (tech lead, integrator, security core), Bhumika (product, UX, demo, QA).
CyberForge 2026 final. Draft v2, Sat 31 Oct 2026, written about 12:25 IST (an earlier copy said 13:20 by mistake). Put this file at docs/PROBLEM_CARD.md. v1 (11:50) is void: it was written before the organisers' brief arrived.
Labels: OFFICIAL = the organisers' written brief. CHECKED = read on the date given. SIMULATED = my throwaway prototype, not the judges' tool. JUDGMENT = reasoning, not data; test it. UNVERIFIED = nobody has checked. RELAYED = said by someone, not in writing.

## 1. The statement
- Title (OFFICIAL): "Community Scam Map for India: Report and verify scams in seconds, anonymously". Numbering differs between documents. Always say the title, never the number.
- Sources: the brief "Community Scam Map: Student Brief" (14 pages, dated 29 Oct 2026), taken from the organisers' file server at 11:57; and the organisers' problem-statement PDF, marked "Confidential to Mitigata". Keep both out of the repo and out of the README, deck and video. Paraphrase only. The data tables in BUILD_SPEC section 16 (areas, verified numbers, scam types) may be used as data files.
- Bonus points: the brief gives our statement its own bonus, up to 7 (section 5). The relayed "10 bonus points for flagship statements" is not in the brief and the sheet does not tag ours (UNVERIFIED). Plan on 100 plus 7.

## 2. What the brief asks (OFFICIAL, paraphrased)
Build a mobile website or Android app plus a server where people warn each other about scam phone numbers, UPI IDs, links and SMS senders, and check one before trusting it.
1. Report a scam: under 60 seconds; saves the area (for example "HSR Layout"), never the exact address.
2. Look it up: answers in under half a second with exactly one of KNOWN_SCAM, SUSPICIOUS, NO_REPORTS, VERIFIED_BUSINESS. Every way of typing one number must give one answer.
3. Scam map: last 7 days only, grouped by area.
4. Alerts: only when something is unusual, never per report.
5. Dispute (bonus): "that is our real number" marks it under review.
6. Beat fake reports: report-bombing (40 friends), fake accounts (22 on one Wi-Fi), spamming (one person x6), junk ("12345", "test"), without missing real scam waves.
7. Ship it: run on a real cloud server with a public https address. A signed licence file (licensee, expiry, signature) is checked on every request. Expired: every route except /health and /license answers 403 `LICENSE_EXPIRED`, the app shows "Licence expired. Contact your provider.", no data is deleted. A new file posted to /license restores service with no restart.
8. Privacy rules (breaking any disqualifies): anonymous reporters, numbers hidden until 3 different people reported them, "reported" not "scammer", no personal-data digging, no personal data in logs.
9. Judging day: the organisers' tool calls seven fixed addresses plus /license on our live server and loads a new, secret set of reports full of the tricks. Rules written for one number fail, and they check for it.
Pitch hook (CHECKED 31 Oct, headlines only): the Home Ministry told the Rajya Sabha on 12 Mar 2025 that 83,668 WhatsApp accounts and 3,962 Skype IDs had been blocked over "digital arrest" scams. The brief's own story (Ravi's father, three hours on a video call, Rs 2 lakh) is the better opening.

## 3. User, pain, buyer
- User (OFFICIAL framing): someone who just got a call, SMS, WhatsApp, QR code or UPI request from a stranger and needs a quick answer.
- Pain: the next victim cannot see that someone already reported the same number. Crowd systems get gamed (a rival shop reports a bakery), so people stop trusting them.
- Buyer (OFFICIAL framing): a bank that wants to run the app on its own server and stop it when the licence ends. That is why the licence is scored. We claim no integration with any Mitigata product.

## 4. What people do today
- CHECKED (headline only): the Department of Telecommunications runs Chakshu on the Sanchar Saathi portal for reporting suspected fraud calls and messages.
- OFFICIAL: the brief names 1930 (National Cybercrime Helpline) and cybercrime.gov.in as usable in the app; both are on the verified list.
- UNVERIFIED: caller-ID apps with spam labels. Check before any pitch line says what they lack.
- Gap we target (JUDGMENT): an instant check of a number, UPI ID, link or sender, with a plain reason, where reporting is anonymous and hard to game. Never say "nothing like it exists".

## 5. How we are scored (OFFICIAL) and what it means
100 points plus up to 7 bonus. Rows 1 to 4 by the organisers' test tool on our live server; rows 5 to 7 by a judge watching.
| # | Row | Pts | Zero when | Our plan |
|---|---|---|---|---|
| 1 | Stops fake reports | 20 | one person reporting many times can make a number KNOWN_SCAM | trust rules, BUILD_SPEC 6 |
| 2 | Lookup right | 15 | most answers wrong | normaliser, in-memory model |
| 3 | Map and alerts | 10 | neither works | BUILD_SPEC 8 |
| 4 | Privacy | 15 | a reporter can be identified (disqualified) | hashed IDs, no note text, wording tests |
| 5 | Server and licence | 15 | laptop only, or nothing stops it | Render plus Postgres, licence gate, 3 rehearsals |
| 6 | Easy to report | 15 | over 2 minutes, or a login first | one-screen form, Hindi, icons |
| 7 | Demo and code | 10 | cannot be run | README, video, pitch |
Bonus: 3 verified businesses and helplines shown as VERIFIED_BUSINESS; 2 dispute; 2 fake reports never set off an alert. Tie-break: more bonus, then faster report time.
Reading (JUDGMENT): rows 1 and 2 (35 points) are where our wedge pays. The other 65 points are execution: privacy, deploy plus licence, report speed in Hindi or icons, README. A team with a clever engine and a licence demo that needs a restart loses the same points as a team with no engine. Hold both.

## 6. The field on our statement (from your 11:17 sheet screenshots; UNVERIFIED, partial)
- My count of the first 41 visible rows on page 1: Community Scam Map 14, Fast Multi-Tenant 14, Config-Driven 12, Kill Chain 1. The viewer says "1 of 3". If pages hold about 60 rows the field is about 180 teams, not thousands. Recount on the full sheet.
- Reading (JUDGMENT): about a third of early teams picked ours. Most will count reports and ship a map. Four rows are scored by machine against the same hidden data, so a team that stops the tricks, keeps every format equal and passes the licence demo ranks above one with a nicer map.

## 7. Three candidate wedges (uniqueness test, pack Part 7.2; one point per check, pass needs 3)
Checks: P proof or artifact. M measurable on adversarial scenarios with criteria fixed first. B a judge can break it live and see a trace. I fits an Indian or Mitigata workflow. D deterministic and boring to run.
| Wedge | P | M | B | I | D | Score |
|---|---|---|---|---|---|---|
| A. Attack-tested trust engine: anonymous reports, trust rules tried against the four named tricks, results published with the misses | 1 | 1 | 1 | 1 | 1 | 5 |
| C. Early-warning map: alerts that fire only when unusual | 0 | 1 | 1 | 1 | 1 | 4 |
| B. Indic-first intake: Hindi strings, icons, Indian digits | 0 | 0 | 1 | 1 | 0 | 2 |
| D. Provenance lookup with outside signals | 1 | 0 | 0 | 1 | 0 | 2 |
My own scoring (JUDGMENT). The brief confirms A (rows 1 and 2, 35 points, machine-checked) and C (row 3 plus a bonus). B is now partly a requirement (row 6: Hindi or icons), so we build its deterministic part. D is cut: the brief forbids digging up personal data and we have no outside data.

## 8. Decision: build A, with C and the deterministic part of B inside it, plus the required parts
**Wedge in one sentence: anonymous scam reports whose trust rules are tested against the organisers' own named tricks, in public, with the misses listed.**
What we ship:
1. Report and look up (rows 2, 6). One-screen report in English, Hindi or icons only; phone, UPI, link and SMS sender in any typing reduce to one value; verified list.
2. Trust rules (row 1). One person is one voice (same reporter, network or text). Track record and own words add weight. KNOWN_SCAM needs 3 voices and 1.5 points.
3. Map and alerts (row 3). Last 7 days by area; SPIKE and NEW_TYPE exactly as defined in the brief; fakes the rules collapsed move nothing.
4. Privacy by construction (row 4). Hashed reporter and network, no note text stored, values masked until 3 voices, "reported" wording.
5. Server and licence (row 5). Render plus Postgres, Ed25519-signed licence, gate on every request, live renewal.
6. Bonus: dispute, verified list, zero alerts from fakes.
Three minutes in front of a judge or on video: a Hindi report with a stopwatch; one number typed three ways; `make attack` against the live URL showing the tricks held and a real wave flipping; the map and an alert; the licence cycle; the limits we know about.
Why this should win (JUDGMENT): the tool is automated and the data is secret, so honest rules beat tuned ones. Most rivals will count reports. We can show a table with our misses in it.
Fallback: if by 19:00 the attack table shows no gain over "3 distinct reporters on different networks", ship that simple rule with the verified list and spend the time on the licence demo and the report flow (30 points). Keep the table as honesty evidence.
What would change our mind: an organiser reply that real waves come from new accounts with empty notes (lower min_points, accept more risk on bombing); a sample of the test data; a different bar than the brief states.

## 9. Anonymity, stated honestly
- The brief's rules: keep reporters anonymous, save the area only, hide values until 3 different people reported them, say "reported", do not dig up personal data, keep personal data out of logs. We add: the note text is never stored (only a fingerprint), and no exact time is shown for values with fewer than 3 voices.
- The test tool sends a pretend identity in each report (`reporter_id`, `ip_prefix`). We hash both with a server secret on arrival and keep only the hashes. That is pseudonymous: one device's reports link to each other. Our app uses a random ID on the phone with a reset link; no name, phone, email or GPS is ever asked.
- Exception: a business that files a dispute gives a name and email so it can be contacted. Stored only for that, never shown or logged. Tejas can veto.
- The host's own platform logs may show IP addresses. We say so in the README.
- FUTURE, not built: unlinkable tokens (Privacy Pass, RFC 9578; CHECKED 31 Oct).

## 10. What we will NOT build
- Accounts, login, OTP, KYC. A login before the form scores zero on row 6.
- Any scraping or lookup of people on social media or people-search sites (disqualifying).
- Integrations with real telco, UPI, NPCI, I4C or portal systems; real scam data.
- An LLM in the request path, or any rule that lets a model set a verdict. The brief allows AI help; our trust rules must be our own and explainable.
- A native app (a mobile website; an APK only if time remains), a WhatsApp bot, caller-ID, call blocking.
- Blockchain, microservices, queues, Kubernetes.
- Cut order if time runs short: attack-arena screen, map tiles (use a list), scenarios beyond the brief's four plus the real waves, APK, polish. Never cut: deploy, licence demo, report flow in Hindi or icons, privacy tests, trust rules and the attack table, README, DISCLOSURE, the video.

## 11. Real, synthetic, mocked
- Real: server on a public https address, Postgres, normaliser, trust rules, licence signing and gate, map, alerts, UI.
- Synthetic: every test report we make (reserved fake numbers, `.example` links, made-up UPI names). The judges load their own secret set. The made-up shops in the brief are test data, not real businesses.
- Mocked: nothing in the request path. Alert delivery is in-app only.
- Claim boundary: our tables show robustness against the tricks we modelled, not real-world accuracy.

## 12. Constraints
- Rules (OFFICIAL): original work created for this hackathon, and the brief says code written before the event disqualifies; disclose third-party tools, APIs, datasets and open source; exactly 2 members; AI tools allowed; security testing only on authorised systems. Any language or framework is fine if the API rules are followed. No Mitigata code is needed. No practice data or test tool is provided.
- Clock (indicative): build 11:00 Sat to 11:00 Sun; checkpoint 1 at 16:00 to 19:00; checkpoint 2 at 09:00 to 11:00 (bug fixes only); freeze 09:00; submission 11:00 to 11:30.
- 192.168.60.13 is the organisers' file server (README: "Mitigata edge file share. Public-facing artifact mirror. Internal services are NOT exposed here."). It holds one brief per statement and large log files for another statement. We downloaded only our brief and the README. We touch nothing else: no logs, no uploads, no renames, no deletes, no logins, no scanning.
- Host facts (CHECKED 31 Oct 12:14, vendor docs pages): Render free web service sleeps after 15 minutes idle, cold start about a minute, disk wiped on restart, no persistent disk; free Postgres 1 GB, expires 30 days after creation. Fly.io has no free tier. Railway trial is $5 once, up to 30 days, restricted network if GitHub cannot be verified.

## 13. Success metrics (targets are JUDGMENT; they mirror the scoring rows; evidence files in brackets)
- The four named tricks never make a number KNOWN_SCAM, and junk gets 400, on the live URL (`make attack` table, with config hash).
- Real waves flip to KNOWN_SCAM in the 7 scenarios we call fair (same table). Misses are listed, not hidden.
- Every typing variant in the test vectors gives one answer (`make test`).
- Lookup p95 under 300 ms from a phone on the venue network; the brief's bar is under 500 ms (`make perf`, UNVERIFIED until run).
- Report time: hand-timed median under 45 s in English, Hindi and icons-only; the brief's bar is under 60 s (STATE.md log).
- Licence cycle: 3 of 3 rehearsals with no restart, app back within 15 s of the upload; the brief's bar is within a minute.
- Privacy: `make privacy` green; zero banned words in UI strings and README.
- Bonus: all 19 verified values return VERIFIED_BUSINESS; dispute works; zero alerts from blocked attacks.

## 14. Open questions, ranked
1. Has the build clock started? If yes, Tejas sets PHASE: BUILD in AGENTS.md. The brief being on the file server suggests it has.
2. For the hackathon channel: does the repo need to be public or shared with judges; do judges reach our server over the open internet; is a mobile website enough; does the test tool call GET /license.
3. Host details nobody has checked (UNVERIFIED): whether Render needs a card for a free instance, which regions it offers, whether UptimeRobot's free plan pings every 5 minutes.
4. Who is the registered team leader; what Bhumika's tools and logins are.
5. Total rows on the sheet.
6. How judges see the demo (their phone on our URL, our video, or both).

## 15. Top risks
1. The licence demo fails live or needs a restart (15 points). Fix: all licence state in Postgres, gate on every request, GET /license polled by the app, three rehearsals.
2. Free host sleeps or loses its disk. Fix: state in Postgres, uptime monitor, warm-up before each judging slot.
3. The trust rules miss a real wave or pass a fake in a form we did not model. BUILD_SPEC 6.5 lists the known holes. Fix: attack table, dials in 6.5, no pre-tuning on hunches.
4. The report flow is slow or not usable in Hindi (15 points). Fix: scripted and hand timing, Hindi review by a speaker.
5. A privacy slip (disqualifying): note text, IP in logs, precise times, personal data in an error message. Fix: hashed IDs, tests in `make privacy`.
6. Scope creep into an arena or dashboard. Fix: the cut order in section 10.
7. Quota, clock, sleep. Keep a 20% reserve, check hourly, merge every 2 hours.

## 16. Sources (opened or seen 31 Oct 2026)
- The brief: "Community Scam Map: Student Brief", organisers' file server, downloaded 11:57 (file name only; do not link or commit).
- Render, Deploy for Free: https://render.com/docs/free
- Railway, Pricing Plans: https://docs.railway.com/pricing/plans and Free Trial: https://docs.railway.com/pricing/free-trial
- Fly.io, Pricing: https://docs.fly.io/about/pricing
- ETV Bharat: https://www.etvbharat.com/en/!bharat/government-india-skype-ids-whatsapp-accounts-digital-arrest-centre-enn25031204310
- Free Press Journal: https://www.freepressjournal.in/india/3962-skype-ids-83668-whatsapp-accounts-used-for-digital-arrest-blocked-so-far-ministry-of-home-affairs-to-rajya-sabha
- Chakshu explainer (Factly): https://factly.in/explainer-government-launches-chakshu-to-report-sms-call-or-whatsapp-messages-attempting-to-commit-fraud
- RFC 9578, Privacy Pass Issuance Protocols: https://datatracker.ietf.org/doc/rfc9578/
