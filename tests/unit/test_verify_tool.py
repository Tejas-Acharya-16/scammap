"""tools/verify_attestation.py: a lookup answer plus a public key in, VALID or INVALID out."""
import base64
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.attestation import Signer
from app.engine.normalise import normalise

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "verify_attestation.py"
IST = timezone(timedelta(hours=5, minutes=30))
SIGNER = Signer("verify-tool-test-salt")


def lookup_answer(value="+91 90000 62001", verdict="KNOWN_SCAM"):
    att = SIGNER.attest(itype="phone", canonical_value=normalise("phone", value), verdict=verdict, voices=3,
                        report_count=3, config="d7a23b4c", now=datetime.now(IST))
    return {"verdict": verdict, "distinct_reporters": 3, "report_count": 3, "display_value": "90XXXXX001",
            "type": "phone", "attestation": att}


def run(tmp_path, answer, key, *extra):
    f = tmp_path / "answer.json"
    f.write_text(json.dumps(answer), encoding="utf-8")
    r = subprocess.run([sys.executable, str(TOOL), str(f), key, *extra], capture_output=True, text=True, cwd=tmp_path)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


@pytest.fixture
def key_file(tmp_path):
    p = tmp_path / "key.json"
    p.write_text(json.dumps(SIGNER.key_info()), encoding="utf-8")
    return str(p)


def test_valid_answer_with_key_file(tmp_path, key_file):
    code, out, err = run(tmp_path, lookup_answer(), key_file)
    assert (code, out) == (0, "VALID"), err
    assert SIGNER.key_id in err and "KNOWN_SCAM" in err


def test_valid_with_the_base64_key_and_the_attestation_alone(tmp_path):
    key = base64.b64encode(SIGNER.public_key).decode()
    assert run(tmp_path, lookup_answer()["attestation"], key)[:2] == (0, "VALID")


def test_tampered_answer_is_invalid(tmp_path, key_file):
    answer = lookup_answer()
    answer["attestation"]["verdict"] = "NO_REPORTS"
    code, out, err = run(tmp_path, answer, key_file)
    assert (code, out) == (1, "INVALID") and "signature" in err


def test_another_servers_key_is_invalid(tmp_path):
    other = base64.b64encode(Signer("some-other-server-salt").public_key).decode()
    assert run(tmp_path, lookup_answer(), other)[:2] == (1, "INVALID")


def test_value_check(tmp_path, key_file):
    answer = lookup_answer("+91 90000 62001")
    assert run(tmp_path, answer, key_file, "--value", "09000062001")[:2] == (0, "VALID")       # same number, other format
    code, out, err = run(tmp_path, answer, key_file, "--value", "+91 90000 62002")
    assert (code, out) == (1, "INVALID") and "different value" in err


def test_unreadable_input_is_exit_2(tmp_path, key_file):
    f = tmp_path / "bad.json"
    f.write_text("{not json", encoding="utf-8")
    r = subprocess.run([sys.executable, str(TOOL), str(f), key_file], capture_output=True, text=True)
    assert r.returncode == 2 and r.stdout == ""
    assert run(tmp_path, lookup_answer(), "not-base64!")[0] == 2
