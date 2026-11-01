"""GET /receipt, the Signed Scam Receipt page: served like /judge (also while the licence is expired),
carries this server's public key, and leaves the Content-Security-Policy exactly as it was."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
RECEIPT = ROOT / "app" / "static" / "receipt.html"
JUDGE = ROOT / "app" / "static" / "judge.html"
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def install_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    assert client.get("/license").json()["status"] == "expired"


def test_receipt_page_is_served_with_this_servers_public_key(client):
    r = client.get("/receipt")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    key = client.get("/attestation/key").json()
    assert key["public_key"] in r.text and key["key_id"] in r.text
    assert "__RECEIPT_KEY__" not in r.text
    assert '<link rel="stylesheet" href="/static/theme.css">' in r.text


def test_receipt_page_loads_while_the_licence_is_expired(client):
    key = client.get("/attestation/key").json()
    install_expired(client)
    assert client.get("/attestation/key").status_code == 403  # the API route stays behind the licence
    r = client.get("/receipt")
    assert r.status_code == 200 and key["public_key"] in r.text
    r = client.post("/receipt")  # only GET pages are exempt from the licence gate
    assert r.status_code == 403 and r.json() == {"error": "LICENSE_EXPIRED"}


def test_csp_unchanged(client):
    assert main.CSP == CSP
    for path in ("/receipt", "/judge", "/"):
        assert client.get(path).headers["content-security-policy"] == CSP, path


def test_receipt_uses_the_judge_consoles_pinned_libraries_and_wording():
    judge, html = JUDGE.read_text(encoding="utf-8"), RECEIPT.read_text(encoding="utf-8")
    for lib in ("tweetnacl/1.0.3/nacl-fast.min.js", "qrcodejs/1.0.0/qrcode.min.js"):
        tag = next(line.strip() for line in judge.splitlines() if lib in line and "<script" in line)
        assert tag in html, lib
    assert "Proves what ScamMap said and when. It does not prove the number is a scam." in html
    for word in ("scammer", "fraud"):
        assert word not in html.lower(), word
