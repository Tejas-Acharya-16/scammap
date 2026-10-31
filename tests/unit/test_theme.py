"""GET /static/theme.css: the one stylesheet both pages use (/ and /judge).

It sits under /static, so it loads while the licence is expired: the expired screen keeps its look.
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "app" / "static"
THEME = STATIC / "theme.css"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def test_theme_is_served_as_css(client):
    r = client.get("/static/theme.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.content == THEME.read_bytes()


def test_theme_loads_while_the_licence_is_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    assert client.get("/lookup", params={"type": "phone", "value": "1930"}).status_code == 403
    assert client.get("/static/theme.css").status_code == 200


@pytest.mark.parametrize("page", ["index.html", "judge.html"])
def test_both_pages_use_the_one_theme(page):
    html = (STATIC / page).read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="/static/theme.css">' in html
    # no third-party fonts, images or stylesheets: the CSP allows this origin only
    for banned in ("fonts.googleapis", "fonts.gstatic", "<img", "url(http"):
        assert banned not in html, (page, banned)
    assert "url(http" not in THEME.read_text(encoding="utf-8")


def test_only_files_we_name_are_served_from_static(client):
    assert client.get("/static/index.html").status_code == 404
    assert client.get("/static/../app/main.py").status_code != 200
