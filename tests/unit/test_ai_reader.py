"""The on-device message reader: its data, its model file and the guarantees around it.

The model runs in the browser (app/static/ai/reader.js). These tests check the committed files with the same
classifier in Python (tools/ai/train_reader.py); tests/e2e/test_ai_reader.py checks the browser gives the same answers.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ai"))
import train_reader as tr  # noqa: E402

import app.main as main  # noqa: E402

DATA = ROOT / "tools" / "ai" / "messages.jsonl"
MODEL = ROOT / "app" / "static" / "ai" / "reader_model.json"
READER_JS = ROOT / "app" / "static" / "ai" / "reader.js"
HELDOUT = ROOT / "tests" / "unit" / "data" / "ai_heldout.jsonl"
TAXONOMY = json.loads((ROOT / "app" / "data" / "taxonomy.json").read_text(encoding="utf-8"))


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def model():
    return json.loads(MODEL.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ the model file
def test_model_loads_and_covers_the_12_types_plus_not_scam(model):
    types = [t if isinstance(t, str) else t["id"] for t in TAXONOMY["scam_types"]]
    assert len(types) == 12
    assert sorted(model["classes"]) == sorted(types + ["not_scam"])
    assert model["version"] == "reader-v1"
    assert set(model["log_priors"]) == set(model["classes"]) == set(model["log_likelihoods"])
    assert len(model["vocabulary"]) > 1000 and model["temperature"] > 0
    cv = model["cross_validation"]
    assert cv["folds"] == 5 and 0 < cv["accuracy"] <= 1 and 0 < cv["macro_f1"] <= 1
    assert len(cv["confusion"]["matrix"]) == 13
    assert MODEL.stat().st_size < 300_000                     # small enough for a phone


def test_ten_held_out_messages_get_the_right_type(model):
    held = rows(HELDOUT)
    assert len(held) == 10
    for row in held:
        got = tr.classify(model, row["text"])
        assert got and got["type"] == row["type"], (row, got)
        assert len(got["top_words"]) == 3


def test_held_out_messages_are_not_in_the_training_data():
    train = {r["text"] for r in rows(DATA)}
    assert not train & {r["text"] for r in rows(HELDOUT)}


def test_committed_model_is_exactly_what_the_committed_data_trains(tmp_path, model):
    assert model["trained_on"]["data_sha256"] == __import__("hashlib").sha256(DATA.read_bytes()).hexdigest()
    out = tmp_path / "model.json"
    assert tr.main(["--data", str(DATA), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == model


def test_too_little_text_gives_no_reading(model):
    for text in ("+91 90000 55501", "9000055501", "", "₹ 500"):
        assert tr.classify(model, text) is None, text
    assert tr.classify(model, "kyc-update.example")["type"] == "fake-kyc-link"   # a link made of words is read


def test_tokenizer_keeps_devanagari_and_drops_digits():
    assert tr.tokenize("OTP 482913 बताइए, URGENT!!") == ["otp", "बताइए", "urgent"]
    assert tr.tokenize("ज़रूरी") == tr.tokenize("ज़रूरी")          # nukta: precomposed or not, one token
    assert tr.tokenize("क्‍ष") == ["क्ष"]                              # zero-width joiner removed
    assert tr.tokenize("₹२,४५० का रिफंड") == ["का", "रिफंड"]         # Devanagari digits removed too


# ------------------------------------------------------------------ the data
def test_dataset_size_languages_and_variety():
    data = rows(DATA)
    per = Counter(r["type"] for r in data)
    assert set(per) == set(json.loads(MODEL.read_text(encoding="utf-8"))["classes"])
    assert min(per.values()) >= 40, per
    for cls in per:
        langs = Counter(r["lang"] for r in data if r["type"] == cls)
        assert set(langs) == {"en", "hinglish", "hi"} and min(langs.values()) >= 10, (cls, langs)
        texts = [r["text"] for r in data if r["type"] == cls]
        assert len(set(texts)) == len(texts)
        firsts = Counter(" ".join(t.split()[:3]).lower() for t in texts)   # not one template
        assert firsts.most_common(1)[0][1] <= 3, (cls, firsts.most_common(3))
    hi = [r["text"] for r in data if r["lang"] == "hi"]
    assert all(re.search("[ऀ-ॿ]", t) for t in hi)


def test_dataset_uses_synthetic_identifiers_only():
    text = DATA.read_text(encoding="utf-8")
    for m in re.finditer(r"(?:\+91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b", text):
        assert re.sub(r"\D", "", m.group())[-10:].startswith("90000"), m.group()
    for host in re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?:/|\b)", text):
        assert host.endswith(".example") or "@" in host or host.split(".")[-1] not in {
            "com", "in", "net", "org", "co", "io", "xyz", "info", "app"}, host
    for upi in re.findall(r"[a-z0-9._-]+@([a-z]+)", text):
        assert upi in {"upifake", "paydemo"}, upi


# ------------------------------------------------------------------ never sends the text, never sets a verdict
def test_reader_js_makes_one_request_and_it_is_the_model_file():
    js = READER_JS.read_text(encoding="utf-8")
    assert len(re.findall(r"\bfetch\(", js)) == 1
    assert 'fetch(MODEL_URL' in js and 'MODEL_URL = "/static/ai/reader_model.json"' in js
    for banned in ("XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "import(", "new Image",
                   "localStorage", "postMessage", "navigator."):
        assert banned not in js, banned


def test_app_ai_code_never_posts_or_touches_the_verdict():
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    start = html.index("// ------------------------------------------------------------------ AI reading")
    block = html[start:html.index("\n", html.index("ScamMapReader.load()", start))]
    ai = "\n".join(line for line in block.splitlines() if not line.lstrip().startswith("//"))   # code, not comments
    for banned in ("fetch(", "api(", "XMLHttpRequest", "sendBeacon", "lastCheck", "cbody", '$("result")', "verdict"):
        assert banned not in ai, banned


# ------------------------------------------------------------------ served like the theme
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def test_files_are_served_with_the_right_types_even_when_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    js = client.get("/static/ai/reader.js")
    js_model = client.get("/static/ai/reader_model.json")
    assert js.status_code == 200 and js.headers["content-type"].startswith("application/javascript")
    assert js_model.status_code == 200 and js_model.headers["content-type"].startswith("application/json")
    assert js_model.json()["version"] == "reader-v1"
    assert js.headers["x-content-type-options"] == "nosniff"
