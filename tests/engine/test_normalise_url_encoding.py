"""URL paths are percent-encoded outside the RFC 3986 path set (stored XSS, layer a).

The path of a normalised URL reaches display_value in full once 3 voices report it,
so nothing that can open or close an HTML tag or attribute may survive in it.
"""
import random

import pytest

from app.engine.normalise import InvalidIdentifier, normalise

XSS = "evil.example/<svg/onload=alert(1)>"


def url(v):
    return normalise("url", v)


def test_the_confirmed_xss_vector_is_encoded():
    assert url(XSS) == "https://evil.example/%3Csvg/onload=alert(1)%3E"


@pytest.mark.parametrize("ch,enc", [
    ("<", "%3C"), (">", "%3E"), ('"', "%22"), ("'", "%27"), ("`", "%60"), ("{", "%7B"),
    ("}", "%7D"), ("|", "%7C"), ("\\", "%5C"), ("^", "%5E"), ("[", "%5B"), ("]", "%5D"),
])
def test_each_unsafe_character_is_encoded(ch, enc):
    out = url(f"evil.example/a{ch}b")
    assert out == f"https://evil.example/a{enc}b"
    assert ch not in out


def test_a_space_inside_a_path_cannot_survive():
    # whitespace is stripped from the whole value before parsing (existing rule), so it can
    # never reach the path; the check is that no raw space is ever in the output
    assert " " not in url("evil.example/a b")


def test_non_ascii_path_is_utf8_percent_encoded():
    assert url("evil.example/नमस्ते") == "https://evil.example/%E0%A4%A8%E0%A4%AE%E0%A4%B8%E0%A5%8D%E0%A4%A4%E0%A5%87"


def test_raw_and_percent_typed_forms_give_one_answer():
    assert url("evil.example/<a>") == url("evil.example/%3Ca%3E") == url("evil.example/%3ca%3e")


def test_a_lone_percent_is_encoded_and_a_valid_triplet_is_kept_once():
    assert url("evil.example/100%") == "https://evil.example/100%25"
    assert url("evil.example/a%2Fb") == "https://evil.example/a%2Fb"
    assert url("evil.example/%zz") == "https://evil.example/%25zz"


@pytest.mark.parametrize("v", [XSS, "evil.example/100%", "evil.example/a%2fb", "evil.example/नमस्ते",
                               "evil.example/'\"`", "sbi-kyc.in/Pay/"])
def test_idempotent(v):
    once = url(v)
    assert url(once) == once


@pytest.mark.parametrize("raw,want", [
    ("http://www.sbi-kyc.in/pay?utm=sms", "https://sbi-kyc.in/pay"),
    ("HTTPS://SBI-KYC.IN/Pay/", "https://sbi-kyc.in/pay"),
    ("sbi-kyc.in/pay#top", "https://sbi-kyc.in/pay"),
    ("hxxps://sbi-kyc[.]in/pay", "https://sbi-kyc.in/pay"),
    ("https://sbi-kyc.in:443/pay", "https://sbi-kyc.in/pay"),
    ("https://sbi-kyc.in:8080/pay", "https://sbi-kyc.in:8080/pay"),
    ("evil.example/a-b_c.d~e/f:g@h!$&()*+,;=", "https://evil.example/a-b_c.d~e/f:g@h!$&()*+,;="),
    ("evil.example/", "https://evil.example"),
])
def test_existing_canonical_forms_are_unchanged(raw, want):
    assert url(raw) == want


def test_output_never_holds_an_html_significant_character():
    rng = random.Random(7)
    alphabet = list("<>\"'`{}|\\^[]%&=/ ;:()abcXYZ019.-_~") + ["\ud800", "‮", "\x00", "é", "ह", "＜", "＞"]
    for _ in range(4000):
        v = "evil.example/" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 25)))
        try:
            out = url(v)
        except InvalidIdentifier:
            continue
        assert not any(c in out for c in "<>\"'`{}|\\^ "), (v, out)
        assert all(0x20 < ord(c) < 0x7F for c in out.split("://", 1)[1].split("/", 1)[-1]), (v, out)
