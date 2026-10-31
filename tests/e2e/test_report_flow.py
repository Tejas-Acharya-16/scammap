"""AT-6.1 (BUILD_SPEC 11.1 and 13): one report on a 390x844 phone takes 6 interactions or fewer.

One interaction = one tap, one paste into a box, one scroll, or one step of a native picker
(open it, choose an item: 2). Every control must be on screen when it is used: the helper fails
the test instead of letting Playwright scroll for us, and a scroll has to be done (and counted)
on purpose. Fixtures (throwaway server, Chromium, phone pages) are in conftest.py.
Synthetic numbers only.
"""
from datetime import datetime, timezone

import pytest

BUDGET = 6
# Every field the app sends (BUILD_SPEC 3). The faster flow must keep all of them.
API_FIELDS = {"report_id", "occurred_at", "reported_at", "reporter_id", "channel", "scam_type",
              "identifier_type", "identifier_value", "pincode", "note", "has_screenshot",
              "amount_lost_inr"}
SMS = "SMS or WhatsApp"
KYC = '#kinds [data-kind="fake-kyc-link"]'
POST_LABEL = {"en": "Post report", "hi": "भेजें"}
JUST_NOW = {"en": "Just now", "hi": "अभी"}


class Phone:
    """Drives the page like a person and writes down every interaction."""

    def __init__(self, page):
        self.page, self.steps = page, []

    def on_screen(self, selector) -> bool:
        """Fully inside the screen and not covered by anything (such as the sticky Post bar)."""
        return self.page.locator(selector).evaluate("""e => {
            const r = e.getBoundingClientRect();
            if (r.top < 0 || r.bottom > innerHeight + 0.5) return false;
            const hit = document.elementFromPoint((r.left + r.right) / 2, (r.top + r.bottom) / 2);
            return !!hit && (e === hit || e.contains(hit));
        }""")

    def _reachable(self, selector):
        assert self.on_screen(selector), \
            f"{selector} is off screen or covered: a person would have to scroll"

    def scroll_to(self, selector, what):
        if not self.on_screen(selector):  # a person scrolls it into clear view, not to the very edge
            self.page.locator(selector).evaluate("e => e.scrollIntoView({block: 'center'})")
            self.steps.append("scroll to " + what)

    def tap(self, selector, what):
        self._reachable(selector)
        self.page.locator(selector).tap()
        self.steps.append("tap " + what)

    def paste(self, selector, text):
        self._reachable(selector)
        self.page.locator(selector).fill(text)
        self.steps.append("paste")

    def pick(self, selector, value, what):
        self._reachable(selector)
        self.page.locator(selector).select_option(value)
        self.steps += ["open " + what, "choose " + what]


def _focused(page) -> str:
    return page.evaluate("document.activeElement ? document.activeElement.id : ''")


def _wait_for_result(page):
    page.locator("#rdone .verdict").wait_for(timeout=10_000)
    assert page.locator("#again").is_visible()


def _record_posts(page) -> list:
    sent = []
    page.on("request", lambda r: sent.append(r.post_data_json)
            if r.method == "POST" and r.url.endswith("/reports") else None)
    return sent


@pytest.mark.parametrize("lang", ["en", "hi"])
def test_one_report_takes_six_interactions_or_fewer(base_url, api, new_page, lang):
    first = {"en": 11001, "hi": 12001}[lang]
    n1, n2, n3 = ("+91 90000 %05d" % (first + i) for i in range(3))
    page = new_page(lang)
    sent = _record_posts(page)
    page.goto(base_url + "/")

    # 1. First report in a fresh browser: the app opens on Report with the number box focused.
    #    SMS, fake KYC link, home area left as it is, just now.
    phone = Phone(page)
    assert page.is_visible("#rform") and _focused(page) == "rv"
    assert page.locator("#post").inner_text() == POST_LABEL[lang]
    phone.paste("#rv", n1)
    phone.tap(f'#channels [data-ch="{SMS}"]', SMS)
    phone.tap(KYC, "kind: fake KYC link")
    assert page.locator("#when .chip.on").inner_text() == JUST_NOW[lang]
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    body = sent[-1]
    assert API_FIELDS <= set(body), API_FIELDS - set(body)
    assert (body["channel"], body["scam_type"], body["identifier_type"], body["pincode"]) == \
        (SMS, "fake-kyc-link", "phone", "560102")
    occurred = datetime.fromisoformat(body["occurred_at"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - occurred).total_seconds()) < 120  # "Just now"
    assert api.get("/lookup", params={"type": "phone", "value": n1}).json()["report_count"] == 1

    # 2. "Report another": fresh box with focus, channel and "Just now" kept; this time a new area.
    phone = Phone(page)
    phone.tap("#again", "Report another")
    assert _focused(page) == "rv" and page.input_value("#rv") == ""
    assert page.locator("#channels .tile.on").get_attribute("data-ch") == SMS
    assert page.locator("#when .chip.on").inner_text() == JUST_NOW[lang]
    phone.paste("#rv", n2)
    phone.scroll_to("#parea", "area")
    phone.pick("#parea", "560034", "area")
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    assert (sent[-1]["identifier_value"], sent[-1]["channel"], sent[-1]["pincode"]) == \
        (n2, SMS, "560034")

    # 3. Next visit (reload): opens on Report again; the last channel and area are remembered.
    page.reload()
    phone = Phone(page)
    assert page.is_visible("#rform") and _focused(page) == "rv"
    assert page.locator("#channels .tile.on").get_attribute("data-ch") == SMS
    assert page.input_value("#parea") == "560034"
    phone.paste("#rv", n3)
    phone.tap(KYC, "kind: fake KYC link")
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    assert (sent[-1]["channel"], sent[-1]["pincode"], sent[-1]["scam_type"]) == \
        (SMS, "560034", "fake-kyc-link")


def test_kind_of_scam_is_icon_tiles_and_not_sure_is_the_default(base_url, new_page):
    page = new_page("en")
    sent = _record_posts(page)
    page.goto(base_url + "/")
    tiles = page.locator("#kinds .tile")
    assert tiles.count() == 13  # 12 scam types plus "Not sure" (BUILD_SPEC 11.1)
    for i in range(13):
        icon = tiles.nth(i).locator("i").inner_text().strip()
        label = tiles.nth(i).inner_text().replace(icon, "").strip()
        assert icon and label, f"tile {i} needs an icon and a label"
    assert page.locator("#kinds .tile.on").get_attribute("data-kind") == "other"
    assert page.locator("#kinds .tile.on").get_attribute("aria-pressed") == "true"
    page.fill("#rv", "+91 90000 13001")
    page.tap("#post")
    _wait_for_result(page)
    assert sent[-1]["scam_type"] == "other"  # nothing chosen = "Not sure", never a made-up type


def test_app_opens_on_report_and_hash_check_opens_check(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/")
    assert page.is_visible("#report") and not page.is_visible("#check")
    assert page.locator("nav button.on").get_attribute("data-tab") == "report"

    page = new_page("en")
    page.goto(base_url + "/#check")
    assert page.is_visible("#check") and not page.is_visible("#report")
    assert page.locator("nav button.on").get_attribute("data-tab") == "check"
    page.goto(base_url + "/#area")  # same page, new hash
    page.locator("#area").wait_for()
    assert page.locator("nav button.on").get_attribute("data-tab") == "area"
