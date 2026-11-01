"""Family-share link on eligible Check results; uses synthetic reports only."""
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, parse_qs, urlsplit

import pytest


IST = timezone(timedelta(hours=5, minutes=30))
FAMILY_EN = "Ask family before you pay"
FAMILY_HI = "पैसे देने से पहले परिवार से पूछें"
NOTES = [
    "A surprise call demanded that I transfer money today and keep this private",
    "An unknown parcel text rushed me to pay a customs fee on a web page",
    "The caller claimed police would arrest me and said not to tell my family",
]


def report(api, value: str, index: int) -> None:
    now = datetime.now(IST) - timedelta(minutes=index + 2)
    response = api.post("/reports", json={
        "report_id": f"family-button-{value[-5:]}-{index}",
        "occurred_at": now.isoformat(),
        "reported_at": now.isoformat(),
        "reporter_id": f"r_family_button_{value[-5:]}_{index}",
        "ip_prefix": f"10.91.{index}.0/24",
        "channel": "SMS or WhatsApp",
        "scam_type": "digital-arrest",
        "identifier_type": "phone",
        "identifier_value": value,
        "pincode": "560102",
        "note": NOTES[index % len(NOTES)],
        "has_screenshot": False,
        "amount_lost_inr": 0,
    })
    assert response.status_code == 201, response.text


def check(page, base_url: str, value: str) -> None:
    page.goto(base_url + "/")
    page.locator('nav button[data-tab="check"]').click()
    page.locator("#check").wait_for(state="visible")
    page.locator("#q").fill(value)
    page.locator("#go").click()
    page.locator("#result .verdict").wait_for(timeout=10_000)


def family_link(page, label: str):
    return page.get_by_role("link", name=label, exact=True)


def test_known_scam_family_link_has_masked_display_text_and_click_is_local_request_free(
    base_url, api, new_page
):
    value = "+91 90000 45001"
    for index in range(3):
        report(api, value, index)
    result = api.get("/lookup", params={"type": "phone", "value": value}).json()
    assert result["verdict"] == "KNOWN_SCAM"

    page = new_page("en")
    page.context.route("https://wa.me/**", lambda route: route.fulfill(
        status=200, content_type="text/html", body="WhatsApp handoff intercepted by test."
    ))
    check(page, base_url, value)
    link = family_link(page, FAMILY_EN)
    assert link.count() == 1
    href = link.get_attribute("href")
    assert href.startswith("https://wa.me/?text=")

    message = parse_qs(urlsplit(href).query)["text"][0]
    display_value = page.locator("#result .mono").inner_text()
    sentence = page.locator("#result #cbody > div > b").first.inner_text()
    assert display_value == result["display_value"]
    assert display_value in message
    assert sentence in message and sentence == "Reported by 3 people."
    assert "before I pay anything" in message
    assert "Check any number here: " + base_url + "/#check" in message
    assert href == "https://wa.me/?text=" + quote(message, safe="~()*!.'-")
    assert link.get_attribute("target") == "_blank"
    assert link.get_attribute("rel") == "noopener noreferrer"

    local_requests, clicking = [], [False]
    page.on("request", lambda request: local_requests.append(request.url)
            if clicking[0] and request.url.startswith(base_url) else None)
    clicking[0] = True
    with page.context.expect_page() as popup_info:
        link.click()
    popup = popup_info.value
    clicking[0] = False
    assert popup.url.startswith("https://wa.me/?text=")
    assert local_requests == []
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_suspicious_family_link_uses_masked_display_value(base_url, api, new_page):
    value = "+91 90000 45002"
    report(api, value, 0)
    result = api.get("/lookup", params={"type": "phone", "value": value}).json()
    assert result["verdict"] == "SUSPICIOUS"
    assert result["display_value"] != value

    page = new_page("en")
    check(page, base_url, value)
    message = parse_qs(urlsplit(family_link(page, FAMILY_EN).get_attribute("href")).query)["text"][0]
    assert result["display_value"] in message
    assert value not in message
    assert "before I pay anything" in message


@pytest.mark.parametrize(
    ("value", "expected_verdict"),
    [("+91 90000 45003", "NO_REPORTS"), ("+91 80 4100 2233", "VERIFIED_BUSINESS")],
)
def test_family_link_is_absent_for_no_reports_and_verified_business(
    base_url, api, new_page, value, expected_verdict
):
    page = new_page("en")
    check(page, base_url, value)
    assert page.locator("#result .verdict").get_attribute("class").split()[-1] == \
        "v-" + expected_verdict
    assert family_link(page, FAMILY_EN).count() == 0


def test_hindi_family_link_label_and_message_and_phone_width(base_url, api, new_page):
    value = "+91 90000 45004"
    report(api, value, 0)
    result = api.get("/lookup", params={"type": "phone", "value": value}).json()
    assert result["verdict"] == "SUSPICIOUS"

    page = new_page("hi")
    check(page, base_url, value)
    link = family_link(page, FAMILY_HI)
    assert link.count() == 1
    message = parse_qs(urlsplit(link.get_attribute("href")).query)["text"][0]
    assert "मुझे " + result["display_value"] + " से कॉल या मैसेज आया है।" in message
    assert "ScamMap के अनुसार:" in message
    assert "मुझे कॉल करें।" in message
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
