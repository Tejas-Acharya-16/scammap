"""The live scam map (/live) on a 390x844 phone and a laptop. Synthetic data only: +91 90000 47xxx (other e2e files use other ranges)."""
import uuid
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
NOTES = ["caller said a parcel in my name had illegal items", "man on a video call said I was under arrest",
         "they asked me to move money to clear my name", "fake officer wanted a fine paid by UPI",
         "said my number was linked to a case"]


def seed(api):
    now = datetime.now(IST)
    run = uuid.uuid4().hex[:6]
    for i, pin in enumerate(["560102", "560034", "560038"]):   # 3 independent people: KNOWN_SCAM
        r = api.post("/reports", json={"identifier_type": "phone", "identifier_value": "+91 90000 47111",
                     "pincode": pin, "occurred_at": (now - timedelta(days=i + 1)).isoformat(),
                     "reporter_id": f"r_live_{run}_{i}", "ip_prefix": f"10.41.{i}", "channel": "Phone call",
                     "scam_type": "digital-arrest", "note": NOTES[i]})
        assert r.status_code == 201
    for i in range(4):                                          # other numbers in other areas
        r = api.post("/reports", json={"identifier_type": "phone", "identifier_value": f"+91 90000 4720{i}",
                     "pincode": ["560066", "560102", "400050", "110016"][i], "occurred_at": (now - timedelta(hours=i + 2)).isoformat(),
                     "reporter_id": f"r_live_{run}_b{i}", "ip_prefix": f"10.42.{i}", "channel": "SMS or WhatsApp",
                     "scam_type": "fake-kyc-link", "note": NOTES[i + 1] if i < 4 else NOTES[0]})
        assert r.status_code == 201


def test_live_map_shows_areas_top_scams_and_known_numbers(base_url, api, new_page):
    seed(api)
    for size in (None, {"width": 1280, "height": 800}):
        page = new_page() if size is None else new_page(viewport=size, is_mobile=False, has_touch=False)
        page.goto(base_url + "/live")
        page.wait_for_function("() => /\\d/.test(document.querySelector('#s-total b').textContent)", timeout=15000)
        assert page.locator("#top .bar").count() >= 2
        assert "+919000047111" in page.locator("#nums").inner_text()
        assert page.locator(".leaflet-container, #fallback").first.is_visible()
        wide = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert wide <= 0, f"page is {wide}px too wide"
        assert "scammer" not in page.content().lower()


def test_live_map_in_hindi(base_url, api, new_page):
    seed(api)
    page = new_page("hi")
    page.goto(base_url + "/live")
    page.wait_for_function("() => /\\d/.test(document.querySelector('#s-total b').textContent)", timeout=15000)
    assert "लाइव" in page.locator("h1").inner_text()
