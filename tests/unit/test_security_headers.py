"""Security headers on every response (HTTP, JSON, HTML, errors), and a JSON 500."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {
    "content-security-policy": ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=31536000",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c


def check(r):
    for k, v in EXPECTED.items():
        assert r.headers.get(k) == v, (k, r.status_code, r.request.method, r.request.url.path)


def install(client, name):
    lic = json.loads((ROOT / "licenses" / f"{name}.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200


def test_pages_and_api_answers_carry_every_header(client):
    for path in ("/", "/judge", "/health", "/license", "/map?pincode=560102", "/alerts?pincode=560102",
                 "/lookup?type=phone&value=1930"):
        r = client.get(path)
        assert r.status_code == 200, path
        check(r)


def test_error_answers_carry_every_header(client):
    check(client.get("/lookup?type=phone&value=12345"))           # 400
    check(client.get("/map?pincode=abc"))                         # 400
    check(client.get("/no/such/route"))                           # 404
    check(client.post("/health"))                                 # 405
    check(client.post("/reports", content=b"{" + b" " * 70000))   # 413
    check(client.post("/reports", content=b"not json"))           # 400
    check(client.post("/license", json={"x": 1}))                 # 400 INVALID_LICENSE


def test_licence_expired_answers_carry_every_header(client):
    install(client, "expired")
    try:
        r = client.get("/lookup?type=phone&value=1930")
        assert r.status_code == 403 and r.json() == {"error": "LICENSE_EXPIRED"}
        check(r)
        check(client.get("/"))
        check(client.get("/health"))
    finally:
        install(client, "long")


def test_unhandled_error_is_json_500_with_every_header_and_no_detail(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail 9876543210")
    monkeypatch.setattr(main.ENGINE, "lookup", boom)
    r = client.get("/lookup?type=phone&value=1930")
    assert r.status_code == 500
    assert r.json() == {"error": "server_error"}
    assert "9876543210" not in r.text
    check(r)


def test_html_pages_are_not_sniffable_or_frameable(client):
    r = client.get("/")
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
