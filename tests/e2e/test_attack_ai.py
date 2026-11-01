"""Attack our AI on /arena, on a 390x844 phone, and the browser's hardened reader against Python's.
Synthetic data only. Nothing typed into the box may leave the page."""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ai"))
import robustness as rb  # noqa: E402
import train_reader as tr  # noqa: E402

MODEL = json.loads((ROOT / "app" / "static" / "ai" / "reader_model.json").read_text(encoding="utf-8"))
ROWS = [json.loads(line) for line in (ROOT / "tools" / "ai" / "messages.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()]
HELDOUT = [json.loads(line)["text"] for line in (ROOT / "tests" / "unit" / "data" / "ai_heldout.jsonl")
           .read_text(encoding="utf-8").splitlines() if line.strip()]


def open_arena(new_page, base_url, lang="en"):
    page = new_page(lang)
    page.goto(base_url + "/arena")
    page.wait_for_function("() => window.ScamMapReader && ScamMapReader.ready()", timeout=10000)
    return page


def test_browser_hardening_matches_python_on_every_trick(base_url, new_page):
    page = open_arena(new_page, base_url)
    rng = random.Random(5)
    friendly = [r["text"] for r in ROWS if r["type"] == "not_scam"][:30]
    texts = [attack(rng, t, friendly) for t in HELDOUT for _, _, attack in rb.ATTACKS]
    got = page.evaluate("ts => ts.map(t => ScamMapReader.classify(t))", texts)
    for text, g in zip(texts, got):
        want = tr.classify(MODEL, text)
        if want is None:
            assert g is None, text
            continue
        assert g["type"] == want["type"] and abs(g["confidence"] - want["confidence"]) < 1e-3, text
        assert g["top_words"] == want["top_words"], text
        assert set(want["tricks"]) <= set(g["flags"]), text


def test_attack_our_ai_on_a_phone(base_url, new_page):
    page = open_arena(new_page, base_url)
    page.wait_for_selector("#score table")
    assert page.locator("#score tbody tr").count() == 8
    assert "caught" in page.locator("#atkHard .read").get_attribute("class")
    page.locator('#tricks button[data-k="lookalike"]').click()
    assert "fooled" in page.locator("#atkRaw .read").get_attribute("class")
    assert "caught" in page.locator("#atkHard .read").get_attribute("class")
    assert page.locator('#atkHard .chips [data-flag="lookalike"]').count() == 1
    assert "fooled" in page.locator("#atkVerdict").inner_text()
    page.locator('#tricks button[data-k="reset"]').click()
    page.locator('#tricks button[data-k="padding"]').click()
    assert page.locator("#atkRaw .read").inner_text() == "Not a scam"
    assert page.locator('#atkHard .chips [data-flag="padding"]').count() == 1
    wide = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert wide <= 0, f"page is {wide}px too wide"
    page.locator("#l-hi").click()
    assert "हमारे AI पर हमला करें" in page.locator("#aiatk h2").inner_text()


def test_attack_our_ai_sends_nothing(base_url, new_page):
    page = new_page("en")
    log = []
    page.route("**/*", lambda route: (log.append((route.request.url, route.request.post_data or "")), route.continue_()))
    page.goto(base_url + "/arena")
    page.wait_for_function("() => window.ScamMapReader && ScamMapReader.ready()", timeout=10000)
    page.wait_for_load_state("networkidle")
    loaded = len(log)
    page.fill("#atkText", "Your SIM will be blocked today, share the OTP now with the officer")
    for k in ("lookalike", "leet", "note", "padding"):
        page.locator(f'#tricks button[data-k="{k}"]').click()
    page.wait_for_timeout(500)
    later = [x for x in log[loaded:] if "/license" not in x[0]]
    assert later == [], later
    assert not [x for x in log if "otp" in (x[0] + x[1]).lower() or "officer" in (x[0] + x[1]).lower()], log
