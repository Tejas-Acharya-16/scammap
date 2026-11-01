"""The AI watchdog line on the Check card, on a 390x844 phone, in English and Hindi.
Synthetic data only: +91 90000 46xxx (other e2e files use other ranges)."""
import uuid
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
RING = "+91 90000 46101"
REAL = "+91 90000 46102"
WORDS = ["kala", "mito", "rasu", "neva", "pado", "jobe", "hazi", "fuge", "yano", "chimu", "lavi", "tora"]


def note(i):
    return " ".join(WORDS[(i + k) % len(WORDS)] + str(i) for k in range(9))


SEEDED = []


def seed(api):
    """Once per test session: a second seeding would add a copy of every report and change the pattern."""
    if SEEDED:
        return
    SEEDED.append(True)
    now, run = datetime.now(IST), uuid.uuid4().hex[:6]
    for i in range(12):                     # a ring: 12 accounts on one Wi-Fi, one area, within an hour
        r = api.post("/reports", json={"identifier_type": "phone", "identifier_value": RING, "pincode": "560102",
                     "occurred_at": (now - timedelta(minutes=5 + 4 * i)).isoformat(),
                     "reporter_id": f"r_ai_{run}_{i}", "ip_prefix": "10.46.1", "channel": "Phone call",
                     "scam_type": "digital-arrest", "note": note(i)})
        assert r.status_code == 201
    for i, pin in enumerate(["560102", "560034", "560038", "560066"]):   # 4 people, own networks, over days
        r = api.post("/reports", json={"identifier_type": "phone", "identifier_value": REAL, "pincode": pin,
                     "occurred_at": (now - timedelta(days=1 + 2 * i, hours=i)).isoformat(),
                     "reporter_id": f"r_ai_{run}_r{i}", "ip_prefix": f"10.46.{10 + i}", "channel": "Phone call",
                     "scam_type": "fake-kyc-link", "note": note(20 + i)})
        assert r.status_code == 201


def check(page, value):
    page.locator('nav button[data-tab="check"]').tap()
    page.fill("#q", value)
    page.tap("#go")
    page.locator("#result .verdict").wait_for()


def test_check_card_shows_the_ai_opinion_and_its_reasons(base_url, api, new_page):
    seed(api)
    assert api.get("/lookup", params={"type": "phone", "value": RING}).json()["ai_watchdog"]["level"] == "high"
    page = new_page()
    page.goto(base_url + "/#check")
    check(page, RING)
    ai = page.locator("#result .wd")
    assert ai.get_attribute("data-wd") == "high"
    text = ai.inner_text()
    assert "AI watchdog: these reports look coordinated" in text and "not the AI" in text
    assert ai.locator("li").count() >= 1
    assert "SUSPICIOUS" in page.locator("#result .verdict").get_attribute("class")
    check(page, REAL)
    assert page.locator("#result .wd").get_attribute("data-wd") == "low"
    assert "independent reports" in page.locator("#result .wd").inner_text()
    wide = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert wide <= 0, f"page is {wide}px too wide"
    assert "scammer" not in page.content().lower() and "fraud" not in page.content().lower()


def test_ai_opinion_in_hindi(base_url, api, new_page):
    seed(api)
    page = new_page("hi")
    page.goto(base_url + "/#check")
    check(page, RING)
    text = page.locator("#result .wd").inner_text()
    assert "AI निगरानी" in text
    assert "वही लोग या नेटवर्क बार-बार रिपोर्ट कर रहे हैं" in text      # the top reason, translated
