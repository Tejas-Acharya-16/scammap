"""Phone check: Check, Report and My area on a 390x844 phone, in English and Hindi.

Nothing may stick out sideways or overlap, the Hindi screens must be in Hindi, a language switch
repaints what is already on screen, and dates show the India day on a phone set to any time zone.
Fixtures are in conftest.py. Synthetic data only: +91 90000 3xxxx and a made-up .example link.
"""
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

IST = timezone(timedelta(hours=5, minutes=30))
KNOWN = "+91 90000 30001"
LONG_URL = "https://accountverificationupdateportalforcustomers.example/kycrenewcustomerdetailsconfirmation"
LATIN = re.compile("[A-Za-z]")
DEVANAGARI = re.compile("[ऀ-ॿ]")
NOTES = ["caller said a parcel in my name had illegal items and kept me on video",
         "man in uniform on a video call said I was under digital arrest",
         "they said my number was linked to a case and asked me to stay on call",
         "a fake officer asked me to move money to clear my name",
         "the call came from someone who said he was police and wanted money"]

LAYOUT_JS = r"""() => {
  const W = document.documentElement.clientWidth, out = [];
  if (document.documentElement.scrollWidth > W) out.push('page is ' + document.documentElement.scrollWidth + 'px wide');
  const vis = e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !e.closest('#expired'); };
  const tag = e => (e.id ? '#' + e.id : e.tagName.toLowerCase() + '.' + e.className) + ' "' + (e.innerText || '').trim().slice(0, 30) + '"';
  const els = [...document.querySelectorAll('header *, nav *, main *')].filter(vis);
  for (const e of els) { const r = e.getBoundingClientRect(); if (r.right > W + 0.5 || r.left < -0.5) out.push('sticks out: ' + tag(e)); }
  const ctl = els.filter(e => e.matches('button,input,select,textarea,.chip,.tile,.verdict,.sev'));
  for (let i = 0; i < ctl.length; i++) for (let j = i + 1; j < ctl.length; j++) {
    const a = ctl[i], b = ctl[j];
    if (a.contains(b) || b.contains(a) || a.closest('.postbar') || b.closest('.postbar')) continue;
    const p = a.getBoundingClientRect(), q = b.getBoundingClientRect();
    if (Math.min(p.right, q.right) - Math.max(p.left, q.left) > 1 && Math.min(p.bottom, q.bottom) - Math.max(p.top, q.top) > 1)
      out.push('overlap: ' + tag(a) + ' / ' + tag(b));
  }
  for (const row of document.querySelectorAll('#clusters .cluster')) {
    const n = row.querySelector('b').getBoundingClientRect(), s = row.querySelector('.sev').getBoundingClientRect();
    if (Math.abs((n.top + n.bottom) / 2 - (s.top + s.bottom) / 2) > 4) out.push('count and badge on two lines: ' + row.innerText.replace(/\n/g, ' '));
  }
  return out;
}"""


@pytest.fixture(scope="session")
def seeded(base_url):
    """5 own-words voices on one number and 3 on one long link, all in Koramangala (560034)."""
    now = datetime.now(IST)
    with __import__("httpx").Client(base_url=base_url, trust_env=False, timeout=5) as c:
        def report(i, itype, value, scam_type, minutes):
            body = {"report_id": "e2e_" + uuid.uuid4().hex[:10],
                    "occurred_at": (now - timedelta(minutes=minutes)).isoformat(),
                    "reported_at": now.isoformat(), "reporter_id": f"r_e2e_{itype}_{i}",
                    "ip_prefix": f"10.{70 + i}.{i * 11}", "channel": "Phone call", "scam_type": scam_type,
                    "identifier_type": itype, "identifier_value": value, "pincode": "560034",
                    "note": NOTES[i], "has_screenshot": False, "amount_lost_inr": 0}
            assert c.post("/reports", json=body).status_code == 201

        for i in range(5):
            report(i, "phone", KNOWN, "digital-arrest", 20 + 15 * i)
        for i in range(3):
            report(i, "url", LONG_URL, "fake-kyc-link", 30 + i)
        assert c.get("/lookup", params={"type": "phone", "value": KNOWN}).json()["verdict"] == "KNOWN_SCAM"
        assert c.get("/lookup", params={"type": "url", "value": LONG_URL}).json()["display_value"] == LONG_URL


def _check(page, value):
    page.locator('nav button[data-tab="check"]').tap()
    page.fill("#q", value)
    page.tap("#go")
    page.locator("#result .verdict").wait_for()


def _post(page, value):
    page.locator('nav button[data-tab="report"]').tap()
    page.fill("#rv", value)
    page.tap("#post")
    page.locator("#rdone .verdict").wait_for()


def _area(page, pin="560034"):
    page.locator('nav button[data-tab="area"]').tap()
    page.select_option("#aarea", pin)
    page.locator("#clusters .cluster", has_text="Koramangala").wait_for()


@pytest.mark.parametrize("lang", ["en", "hi"])
def test_screens_fit_a_390px_phone(seeded, base_url, new_page, lang):
    page = new_page(lang)
    page.goto(base_url + "/")
    problems = []

    def look(screen):
        problems.extend(f"{screen}: {p}" for p in page.evaluate(LAYOUT_JS))

    _check(page, KNOWN)
    look("check, known scam")
    page.tap("#disp")
    look("check, dispute form")
    _check(page, LONG_URL)
    look("check, long link shown in full")
    page.locator('nav button[data-tab="report"]').tap()
    look("report form")
    _post(page, {"en": "+91 90000 31001", "hi": "+91 90000 32001"}[lang])
    look("report result")
    _area(page)
    look("my area")
    assert not problems, "\n".join(problems)


def test_hindi_screens_are_in_hindi(seeded, base_url, new_page):
    page = new_page("hi")
    page.goto(base_url + "/")
    _check(page, KNOWN)
    advice = page.inner_text("#result .advice")
    assert DEVANAGARI.search(advice) and not LATIN.search(advice), advice
    _post(page, "+91 90000 33001")
    sentence = page.inner_text("#rcard b")
    assert sentence.startswith("1 व्यक्ति ने"), sentence  # one person, not "1 लोगों"
    _area(page)
    badges = page.locator("#clusters .sev").all_inner_texts()
    assert badges and all(DEVANAGARI.search(b) and not LATIN.search(b) for b in badges), badges


def test_switching_language_repaints_what_is_on_screen(seeded, base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/")
    _check(page, KNOWN)
    page.tap("#l-hi")
    assert page.inner_text("#result .verdict") == "ज्ञात स्कैम"
    assert page.inner_text("#too") == "इसे भी रिपोर्ट करें"
    _post(page, "+91 90000 34001")
    page.tap("#l-en")
    assert page.inner_text("#rdone .verdict") == "Suspicious"
    assert page.inner_text("#again") == "Report another"
    _area(page)
    page.tap("#l-hi")
    page.wait_for_function(
        "() => /[\\u0900-\\u097F]/.test(document.querySelector('#clusters .sev').innerText)", timeout=5000)


def test_last_reported_day_is_the_india_day_on_any_phone(base_url, api, new_page):
    value = "+91 90000 35001"
    page = new_page("en", timezone_id="UTC")
    page.goto(base_url + "/")
    _post(page, value)
    last_seen = api.get("/lookup", params={"type": "phone", "value": value}).json()["last_seen"]
    india_day = datetime.fromisoformat(last_seen).astimezone(IST).day
    shown = re.search(r"Last reported: (\d+) ", page.inner_text("#rdone"))
    assert shown and int(shown.group(1)) == india_day, (last_seen, page.inner_text("#rdone"))
