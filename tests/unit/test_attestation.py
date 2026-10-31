"""Signed answers: every GET /lookup answer carries an Ed25519 attestation, and GET /attestation/key
gives the public key. Synthetic numbers only (+91 90000 6xxxx).
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey, VerifyKey

import app.main as main
from app.attestation import FIELDS, Signer, canonical_json, key_id_for, verify
from app.engine.normalise import normalise

ROOT = Path(__file__).resolve().parents[2]
IST = timezone(timedelta(hours=5, minutes=30))
NUMBER = "+91 90000 61001"
ATTESTATION_KEYS = set(FIELDS) | {"sig"}
NOTES = ["Caller said my KYC would lapse today and sent a link to update it",
         "Got an SMS that my bank account is blocked unless I verify on a website",
         "A man claiming to be from the bank asked me to open a link and enter my card"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def post_reports(client, value=NUMBER, n=3):
    now = datetime.now(IST)
    for i in range(n):
        when = (now - timedelta(minutes=20 * (i + 1))).isoformat()
        r = client.post("/reports", json={
            "report_id": f"att-{abs(hash(value)) % 10**6}-{i}", "occurred_at": when, "reported_at": when,
            "reporter_id": f"att-reporter-{i}", "ip_prefix": f"{30 + 40 * i}.{50 + i}.{i}.0/24",
            "channel": "Phone call", "scam_type": "fake-kyc-link", "identifier_type": "phone",
            "identifier_value": value, "pincode": "560102", "note": NOTES[i % 3],
            "has_screenshot": False, "amount_lost_inr": 0})
        assert r.status_code == 201, r.text


def public_key(client) -> bytes:
    return base64.b64decode(client.get("/attestation/key").json()["public_key"])


def answer(client, value=NUMBER, itype="phone"):
    r = client.get("/lookup", params={"type": itype, "value": value})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ the key
def test_key_route_gives_alg_key_id_and_public_key(client):
    r = client.get("/attestation/key")
    js = r.json()
    assert r.status_code == 200 and set(js) == {"alg", "key_id", "public_key"} and js["alg"] == "Ed25519"
    pub = base64.b64decode(js["public_key"], validate=True)
    assert len(pub) == 32
    assert js["key_id"] == hashlib.sha256(pub).hexdigest()[:8]


def test_key_is_derived_from_trust_salt_as_specified():
    seed = hmac.new(b"some-salt-value", b"scammap-attestation-v1", hashlib.sha256).digest()
    assert Signer("some-salt-value").public_key == bytes(SigningKey(seed).verify_key)
    assert Signer("some-salt-value").key_id == Signer("some-salt-value").key_id
    assert Signer("some-salt-value").key_id != Signer("another-salt-value").key_id


def test_the_seed_is_never_shown(client):
    s = Signer("some-salt-value")
    seed_hex = hmac.new(b"some-salt-value", b"scammap-attestation-v1", hashlib.sha256).hexdigest()
    assert seed_hex not in repr(s) and "some-salt-value" not in repr(s)
    for path in ("/attestation/key", "/lookup?type=phone&value=1930"):
        body = client.get(path).text
        assert main.TRUST_SALT not in body
        assert hmac.new(main.TRUST_SALT.encode(), b"scammap-attestation-v1", hashlib.sha256).hexdigest() not in body


def test_key_route_is_behind_the_licence_gate(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    r = client.get("/attestation/key")
    assert r.status_code == 403 and r.json() == {"error": "LICENSE_EXPIRED"}


# ------------------------------------------------------------------ the signed answer
def test_signing_round_trip_on_every_kind_of_answer(client):
    post_reports(client)
    pub = public_key(client)
    for value in (NUMBER, "09000061001", "+91 90000 61002", "1930"):   # known, same number typed differently, unreported, verified
        js = answer(client, value)
        a = js["attestation"]
        assert set(a) == ATTESTATION_KEYS, a
        assert verify(a, pub), a
        assert (a["v"], a["type"], a["verdict"], a["voices"], a["report_count"], a["config"]) == \
            (1, js["type"], js["verdict"], js["distinct_reporters"], js["report_count"], js["trust"]["config"])
        assert a["value_sha256"] == hashlib.sha256(normalise("phone", value).encode()).hexdigest()
        issued = datetime.fromisoformat(a["issued_at"])
        assert a["issued_at"].endswith("+05:30") and abs((datetime.now(IST) - issued).total_seconds()) < 60
    assert answer(client, NUMBER)["attestation"]["value_sha256"] == answer(client, "09000061001")["attestation"]["value_sha256"]


def test_signature_is_over_the_canonical_json_of_every_other_field(client):
    a = answer(client)["attestation"]
    sig = base64.b64decode(a.pop("sig"))
    msg = json.dumps(a, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert msg == canonical_json(a)
    VerifyKey(public_key(client)).verify(msg, sig)         # raises if not


def test_existing_fields_are_unchanged(client):
    post_reports(client)
    js = answer(client)
    _, plain = main.ENGINE.lookup("phone", NUMBER, main.clock.now())
    assert {k: v for k, v in js.items() if k != "attestation"} == plain


@pytest.mark.parametrize("field,new", [
    ("verdict", "NO_REPORTS"), ("verdict", "SUSPICIOUS"), ("voices", 99), ("report_count", 0),
    ("value_sha256", "0" * 64), ("issued_at", "2026-01-01T00:00:00+05:30"), ("config", "00000000"),
    ("type", "upi"), ("v", 2)])
def test_a_tampered_answer_fails(client, field, new):
    post_reports(client)                                    # 3 own-words voices: Known scam
    a = answer(client)["attestation"]
    assert a["verdict"] == "KNOWN_SCAM" and a[field] != new
    a[field] = new
    assert not verify(a, public_key(client))


def test_added_removed_or_broken_parts_fail(client):
    a = answer(client)["attestation"]
    pub = public_key(client)
    assert verify(dict(a), pub)
    assert not verify({**a, "note": "extra field"}, pub)
    assert not verify({k: v for k, v in a.items() if k != "config"}, pub)
    assert not verify({**a, "sig": "not base64!"}, pub)
    assert not verify({**a, "sig": base64.b64encode(b"\0" * 64).decode()}, pub)
    assert not verify(a, Signer("a-different-salt").public_key)           # another server's key
    assert not verify("not a dict", pub)


def test_errors_carry_no_attestation(client):
    r = client.get("/lookup", params={"type": "phone", "value": "12345"})
    assert r.status_code == 400 and r.json() == {"error": "invalid_identifier"}


# ------------------------------------------------------------------ restarts
def _start(tmp_path, salt):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    env = dict(os.environ, DATABASE_URL="sqlite:///" + (tmp_path / "restart.db").as_posix(), TRUST_SALT=salt)
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                             "--port", str(port), "--no-access-log"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    with httpx.Client(trust_env=False, timeout=2) as c:
        for _ in range(150):
            try:
                if c.get(url + "/health").status_code == 200:
                    return proc, url
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    proc.kill()
    pytest.fail("server did not start")


def _key_after_start(tmp_path, salt):
    proc, url = _start(tmp_path, salt)
    try:
        return httpx.get(url + "/attestation/key", timeout=5, trust_env=False).json()
    finally:
        proc.terminate()
        proc.wait(10)


def test_key_id_is_stable_across_restarts(tmp_path):
    first = _key_after_start(tmp_path, "restart-test-salt-1")
    second = _key_after_start(tmp_path, "restart-test-salt-1")
    other = _key_after_start(tmp_path, "restart-test-salt-2")
    assert first == second
    assert other["key_id"] != first["key_id"]
    assert first["key_id"] == key_id_for(base64.b64decode(first["public_key"]))


# ------------------------------------------------------------------ speed
def test_signing_leaves_lookup_p95_unchanged(capsys):
    """In-process bench: the same lookups with and without the signing step, interleaved."""
    import random

    from app.engine import TrustConfig
    from tests.engine.scenarios import AREAS, NOW, TYPES, D, World, free_note, new_number, new_prefix, new_rid

    rng = random.Random(7)
    world = World(rng, TrustConfig())
    numbers = [new_number(rng) for _ in range(400)]
    for i in range(2400):
        world.engine.handle_report({
            "report_id": f"bench_{i}", "occurred_at": (NOW - rng.uniform(0, 30) * D).isoformat(),
            "reporter_id": new_rid(rng), "ip_prefix": new_prefix(rng), "channel": "Phone call",
            "scam_type": rng.choice(TYPES), "identifier_type": "phone", "identifier_value": rng.choice(numbers),
            "pincode": rng.choice(AREAS), "note": free_note(rng)}, NOW, persist=lambda row: None)
    e, signer = world.engine, Signer("bench-salt-0001")

    def plain(v):
        return e.lookup("phone", v, NOW)

    def signed(v):
        status, reply = e.lookup("phone", v, NOW)
        reply["attestation"] = signer.attest(itype=reply["type"], canonical_value=normalise("phone", v),
                                             verdict=reply["verdict"], voices=reply["distinct_reporters"],
                                             report_count=reply["report_count"], config=reply["trust"]["config"],
                                             now=NOW)
        return status, reply

    a, b, sign_only = [], [], []
    for _ in range(1500):
        v = rng.choice(numbers)
        plain(v)                                                # warm-up: both timed calls see the same caches
        pair = [(plain, a), (signed, b)]
        rng.shuffle(pair)
        for fn, out in pair:
            t = time.perf_counter()
            fn(v)
            out.append((time.perf_counter() - t) * 1000)
        _, reply = plain(v)
        t = time.perf_counter()
        signer.attest(itype="phone", canonical_value=normalise("phone", v), verdict=reply["verdict"],
                      voices=reply["distinct_reporters"], report_count=reply["report_count"],
                      config=reply["trust"]["config"], now=NOW)
        sign_only.append((time.perf_counter() - t) * 1000)
    p95 = lambda xs: sorted(xs)[int(0.95 * len(xs))]
    with capsys.disabled():
        print(f"\nlookup p95 {p95(a):.3f} ms; with signing {p95(b):.3f} ms; "
              f"signing step alone p95 {p95(sign_only):.3f} ms")
    assert p95(sign_only) < 0.5, p95(sign_only)
    assert p95(b) - p95(a) < 0.5, (p95(a), p95(b))
