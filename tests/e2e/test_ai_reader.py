"""The AI reading in the app (app/static/ai/reader.js), on a 390x844 phone.

- the browser gives the same answers as Python (tools/ai/train_reader.py) on the same model file
- classifying makes no network request (every request is routed and recorded)
- it pre-selects the kind of scam only at 0.7 or more, and the person can change it
- it is shown apart from the verdict, which stays the server's
Fixtures (throwaway server, Chromium, phone pages) are in conftest.py. Synthetic data only.
"""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tests.e2e.test_phone_screens as screens

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ai"))
import train_reader as tr  # noqa: E402

MODEL = json.loads((ROOT / "app" / "static" / "ai" / "reader_model.json").read_text(encoding="utf-8"))
HELDOUT = [json.loads(x) for x in (ROOT / "tests" / "unit" / "data" / "ai_heldout.jsonl").read_text(encoding="utf-8").splitlines()]
TRAINING = [json.loads(x) for x in (ROOT / "tools" / "ai" / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
IST = timezone(timedelta(hours=5, minutes=30))
KYC = "Your KYC has expired, update now at kyc-check.example or your account will be blocked today"
UNSURE = "The officer said the parcel had a problem and I should pay a fee to the bank"
PASTE = """t => { const dt = new DataTransfer(); dt.setData("text/plain", t);
  document.getElementById("q").dispatchEvent(new ClipboardEvent("paste", {clipboardData: dt, bubbles: true, cancelable: true})); }"""


def open_app(new_page, base_url, path="/", lang="en"):
    page = new_page(lang)
    page.goto(base_url + path)
    assert page.evaluate("() => ScamMapReader.load()") is True       # the model file, fetched once at load
    return page


def test_browser_matches_python_on_held_out_and_training_messages(base_url, new_page):
    page = open_app(new_page, base_url)
    texts = [r["text"] for r in HELDOUT] + [r["text"] for r in TRAINING[::3]]
    got = page.evaluate("ts => ts.map(t => ScamMapReader.classify(t))", texts)
    for text, g in zip(texts, got):
        want = tr.classify(MODEL, text)
        assert g["type"] == want["type"] and abs(g["confidence"] - want["confidence"]) < 1e-3, text
        assert g["top_words"] == want["top_words"], text
    for row, g in zip(HELDOUT, got):
        assert g["type"] == row["type"], row                         # the 10 held-out messages, in the browser
    assert page.evaluate("() => ScamMapReader.classify('+91 90000 55501')") is None


def test_classifying_makes_no_network_request(base_url, new_page):
    page = new_page("en")
    log = []
    page.route("**/*", lambda route: (log.append((route.request.method, route.request.url,
                                                   route.request.post_data or "")), route.continue_()))
    page.goto(base_url + "/")
    assert page.evaluate("() => ScamMapReader.load()") is True
    page.wait_for_load_state("networkidle")
    loaded = len(log)
    assert any(u.endswith("/static/ai/reader_model.json") for _, u, _ in log[:loaded])
    page.fill("#rv", KYC)                                            # Report form: read as it is typed
    page.wait_for_selector("#air:not(.hidden)")
    page.fill("#note", "they also told me to share the OTP that came on my phone")
    page.evaluate("t => ScamMapReader.classify(t)", "Sir aapka bijli bill pending hai, aaj raat light kat jayegi")
    page.wait_for_timeout(700)
    later = [x for x in log[loaded:] if not x[1].endswith("/license")]   # the licence poll is not the reader
    assert later == [], later
    words = ("kyc", "blocked", "otp", "bijli")
    assert not [x for x in log if any(w in (x[1] + x[2]).lower() for w in words)], log


def test_report_preselects_the_kind_only_at_0_7_or_more(base_url, new_page):
    page = open_app(new_page, base_url)
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "other"
    unsure = page.evaluate("t => ScamMapReader.classify(t)", UNSURE)
    assert unsure["type"] != "not_scam" and unsure["confidence"] < 0.7, unsure
    page.fill("#rv", UNSURE)
    page.wait_for_selector("#air:not(.hidden)")
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "other"     # not sure enough
    assert page.locator("#air .ai-pre").count() == 0
    page.fill("#rv", KYC)
    page.wait_for_selector("#air .ai-pre")
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "fake-kyc-link"
    text = page.inner_text("#air")
    assert "AI reading of this message" in text and "AI suggestion, can be wrong" in text
    assert page.locator("#air .ai-words .mono").count() == 3 and "% sure" in text
    page.tap('#kinds [data-kind="otp-call"]')                         # the person changes it ...
    page.fill("#note", "the link said my account will be blocked and to update KYC")
    page.wait_for_timeout(500)
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "otp-call"   # ... and it stays changed


def test_check_shows_the_ai_reading_apart_from_the_verdict(base_url, api, new_page):
    number = "+91 90000 64001"
    when = datetime.now(IST).isoformat()
    assert api.post("/reports", json={
        "report_id": "ai-e2e-1", "occurred_at": when, "reported_at": when, "reporter_id": "ai-e2e-r1",
        "ip_prefix": "77.88.1.0/24", "channel": "SMS or WhatsApp", "scam_type": "other",
        "identifier_type": "phone", "identifier_value": number, "pincode": "560102", "note": "",
        "has_screenshot": False, "amount_lost_inr": 0}).status_code == 201
    page = open_app(new_page, base_url, "/#check")
    page.fill("#q", number)
    page.evaluate(PASTE, KYC + " Call " + number + " now.")              # the message the number came from
    page.tap("#go")
    page.wait_for_selector("#result .verdict")
    page.wait_for_selector("#aiq:not(.hidden)")
    assert page.inner_text("#result .verdict") == "Suspicious"           # the server's verdict, unchanged
    assert api.get("/lookup", params={"type": "phone", "value": number}).json()["verdict"] == "SUSPICIOUS"
    assert "Fake KYC link" in page.inner_text("#aiq")
    assert page.locator("#result .ai, #result .ai-type").count() == 0    # not inside the verdict card
    assert set(page.locator("#aiq .flag").evaluate_all("els => els.map(e => e.dataset.flag)")) >= {"urgency", "link"}
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems


def test_ai_reading_in_hindi_fits_the_phone(base_url, new_page):
    row = next(r for r in HELDOUT if r["type"] == "electricity-disconnection")
    page = open_app(new_page, base_url, "/", lang="hi")
    page.fill("#rv", row["text"])
    page.wait_for_selector("#air .ai-pre")
    text = page.inner_text("#air")
    assert "AI का सुझाव, गलत हो सकता है" in text and "बिजली कटौती SMS" in text, text
    assert re.search("[ऀ-ॿ]", page.inner_text("#air .ai-pre"))
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "electricity-disconnection"
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems
