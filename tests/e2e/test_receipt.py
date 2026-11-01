"""Signed Scam Receipt on a 390x844 phone.

Three independent reports -> Check -> "Signed receipt" opens /receipt#r=... in a new tab: GENUINE, 3 people,
the number matches. "Try to fake it" -> TAMPERED. One changed character in the link -> TAMPERED. Nothing the
pages send to our server carries the receipt or the number. With the licence expired the page still checks.
cdnjs is not reachable from CI, so tweetnacl is served from tests/e2e/assets (same file, so the pinned integrity
hash still has to match) and qrcodejs is replaced by a stub that records what it was asked to draw.
"""
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
NACL_URL = "https://cdnjs.cloudflare.com/ajax/libs/tweetnacl/1.0.3/nacl-fast.min.js"
QR_URL = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
ASSET = Path(__file__).parent / "assets" / "tweetnacl-1.0.3-nacl-fast.min.js"
QR_STUB = ("window.QRCode=function(el,o){el.setAttribute('data-qr',o.text)};"
           "window.QRCode.CorrectLevel={L:1,M:0,Q:3,H:2};")
JSON_CT = {"content-type": "application/json"}
IST = timezone(timedelta(hours=5, minutes=30))
NOTES = ["Caller said my KYC would lapse today and sent a link to update it",
         "Got an SMS that my bank account is blocked unless I verify on a website",
         "A man claiming to be from the bank asked me to open a link and enter my card"]


def seed(base_url, number, tag):
    """Three independent reports: own reporter, own network, own words."""
    now = datetime.now(IST)
    with httpx.Client(base_url=base_url, trust_env=False, timeout=5) as c:
        for i in range(3):
            when = (now - timedelta(minutes=10 * (i + 1))).isoformat()
            body = {"report_id": f"rcpt-{tag}-{i}", "occurred_at": when, "reported_at": when,
                    "reporter_id": f"r_rcpt_{tag}_{i}", "ip_prefix": f"10.{90 + i}.{7 * i}",
                    "channel": "Phone call", "scam_type": "fake-kyc-link", "identifier_type": "phone",
                    "identifier_value": number, "pincode": "560102", "note": NOTES[i],
                    "has_screenshot": False, "amount_lost_inr": 0}
            assert c.post("/reports", json=body).status_code == 201
        assert c.get("/lookup", params={"type": "phone", "value": number}).json()["verdict"] == "KNOWN_SCAM"


def phone(new_page):
    page = new_page("en")
    ctx = page.context
    ctx.route(NACL_URL, lambda r: r.fulfill(status=200, body=ASSET.read_bytes(), headers={
        "content-type": "application/javascript; charset=utf-8", "access-control-allow-origin": "*"}))
    ctx.route(QR_URL, lambda r: r.fulfill(status=200, body=QR_STUB,
                                          headers={"content-type": "application/javascript"}))
    return page


def test_receipt_from_check_genuine_then_tampered(base_url, api, new_page):
    number, digits = "+91 90000 71234", "9000071234"
    seed(base_url, number, "a")
    page = phone(new_page)
    ctx = page.context
    page.goto(base_url + "/#check")
    page.fill("#q", number)
    page.tap("#go")
    link = page.locator("#result a.rcpt")
    link.wait_for()
    assert link.inner_text() == "Signed receipt" and link.get_attribute("target") == "_blank"
    assert link.get_attribute("href").startswith("/receipt#r=")

    sent = []  # every request either tab makes from here on
    ctx.on("request", lambda r: sent.append((r.url, r.post_data or "")))
    with ctx.expect_page() as opened:
        link.tap()
    rc = opened.value
    rc.locator("#big.ok").wait_for(timeout=10_000)
    assert rc.inner_text("#big") == "GENUINE"
    assert rc.inner_text("#people") == "3 independent people"
    assert rc.inner_text("#count") == "3"
    assert rc.inner_text("#num") == "matches: +91" + digits
    assert rc.inner_text("#kid") == api.get("/attestation/key").json()["key_id"]
    assert rc.inner_text("#pill") == "Known scam"
    assert rc.inner_text("#issued").endswith(" IST")
    assert rc.locator("#qr").get_attribute("data-qr") == rc.url  # the QR holds the full page URL
    assert "Show this to your bank" in rc.inner_text(".qrw")
    assert "It does not prove the number is a scam." in rc.inner_text(".honest")

    fake = rc.locator("#fake")
    assert fake.inner_text() == "Try to fake it: change 3 people to 30"
    fake.tap()
    rc.locator("#big.bad").wait_for()
    assert rc.inner_text("#big") == "TAMPERED"
    assert rc.inner_text("#people") == "30 independent people"

    payload = urlsplit(rc.url).fragment[2:]
    i = len(payload) // 2
    edited = payload[:i] + ("A" if payload[i] != "A" else "B") + payload[i + 1:]
    rc2 = ctx.new_page()
    rc2.goto(base_url + "/receipt#r=" + edited)
    rc2.locator("#big.bad").wait_for(timeout=10_000)
    assert rc2.inner_text("#big") == "TAMPERED"

    ours = [(u, b) for u, b in sent if u.startswith(base_url)]
    assert any(urlsplit(u).path == "/receipt" for u, _ in ours)
    for url, body in ours:
        blob = url + body
        assert "#" not in url and "r=" not in urlsplit(url).query, url
        assert digits not in blob and payload[:24] not in blob and "value_sha256" not in blob, url


def test_receipt_still_checks_while_the_licence_is_expired(base_url, api, new_page):
    number = "+91 90000 71235"
    seed(base_url, number, "b")
    reply = api.get("/lookup", params={"type": "phone", "value": number}).json()
    blob = json.dumps({"a": reply["attestation"], "v": reply["display_value"]}).encode()
    url = base_url + "/receipt#r=" + base64.urlsafe_b64encode(blob).decode().rstrip("=")
    try:
        r = api.post("/license", content=(ROOT / "licenses" / "expired.json").read_bytes(), headers=JSON_CT)
        assert r.json()["status"] == "expired"
        assert api.get("/attestation/key").status_code == 403
        page = phone(new_page)
        page.goto(url)
        page.locator("#big.ok").wait_for(timeout=10_000)
        assert page.inner_text("#big") == "GENUINE"
        assert page.inner_text("#people") == "3 independent people"
    finally:
        api.post("/license", content=(ROOT / "licenses" / "long.json").read_bytes(), headers=JSON_CT)
