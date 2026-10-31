"""BUILD_SPEC 4.2 test vectors plus edge cases (AT-2.1, AT-1.4 for identifiers)."""
import random

import pytest

from app.engine import InvalidIdentifier, mask, normalise

SAME_PHONE = ["+91 98765 43210", "09876543210", "98765-43210", "919876543210",
              "(+91) 98765-43210", "९८७६५४३२१०",
              "0091 98765 43210", "+91 0 98765 43210", "+91-98765-43210", "​+91 98765 43210 "]


@pytest.mark.parametrize("raw", SAME_PHONE)
def test_phone_formats_are_one_number(raw):
    assert normalise("phone", raw) == "+919876543210"


@pytest.mark.parametrize("raw,canon", [
    ("+91 80 4100 2233", "+918041002233"),       # Bengaluru landline (verified made-up shop)
    ("080 4100 2233", "+918041002233"),
    ("0141 234 5678", "+911412345678"),          # Jaipur landline: area code starts with 1
    ("1930", "1930"), ("1909", "1909"), ("112", "112"),
    ("1800 1600", "18001600"), ("1800-1600", "18001600"), ("+91 1800 1600", "18001600"),
    ("1860 419 5555", "18604195555"),
    ("+1 415 555 0100", "+14155550100"),
])
def test_phone_shapes(raw, canon):
    assert normalise("phone", raw) == canon


@pytest.mark.parametrize("raw", ["12345", "test", "", "   ", "0000000000", "+91 00000 00000", "9999999999",
                                 "1234567890", "98765 4321", "98765+43210", "+91 98765 43210 ext 2",
                                 "+0 12345678", "abc9876543210", None, 9876543210])
def test_phone_junk_rejected(raw):
    with pytest.raises(InvalidIdentifier):
        normalise("phone", raw)


@pytest.mark.parametrize("raw", ["Ravi12@OKAXIS", " ravi12 @ okaxis ", "ravi12@okaxis",
                                 "upi://pay?pa=ravi12@okaxis&pn=Ravi&am=10"])
def test_upi(raw):
    assert normalise("upi", raw) == "ravi12@okaxis"


@pytest.mark.parametrize("raw", ["ravi12", "ravi12@", "@okaxis", "x@evil.com", "r@b", "test", ""])
def test_upi_junk(raw):
    with pytest.raises(InvalidIdentifier):
        normalise("upi", raw)


@pytest.mark.parametrize("raw", ["http://www.sbi-kyc.in/pay?utm=sms", "HTTPS://SBI-KYC.IN/Pay/",
                                 "sbi-kyc.in/pay#top", "hxxps://sbi-kyc[.]in/pay", "https://sbi-kyc.in:443/pay",
                                 "  https://www.sbi-kyc.in/pay/  ", "https://user:pw@sbi-kyc.in/pay",
                                 "https://sbi-kyc.in./pay", "//sbi-kyc.in/pay"])
def test_url_forms(raw):
    assert normalise("url", raw) == "https://sbi-kyc.in/pay"


def test_url_root_and_port():
    assert normalise("url", "https://cybercrime.gov.in/") == "https://cybercrime.gov.in"
    assert normalise("url", "http://evil.example:8080/x") == "https://evil.example:8080/x"


@pytest.mark.parametrize("raw", ["http://localhost/x", "http://192.168.60.13/x", "http://127.0.0.1",
                                 "http://10.0.0.1/a", "javascript:alert(1)", "not a link", "http://",
                                 "mailto:a@b.com", "ftp://files.example/x", "https://[::1]/", "https://1.2.3/x",
                                 "https://exa mple", "data:text/html,hi"])
def test_url_junk(raw):
    with pytest.raises(InvalidIdentifier):
        normalise("url", raw)


@pytest.mark.parametrize("raw", ["VM-HDFCBK", "AD-HDFCBK", "HDFCBK", "hdfcbk", "VM-HDFCBK-S", "vm hdfcbk", "VMHDFCBK"])
def test_sender(raw):
    assert normalise("sender_id", raw) == "HDFCBK"


@pytest.mark.parametrize("raw", ["test", "12345", "123456", "HDFC", "VM-HD-FC", "HDFCBANK1"])
def test_sender_junk(raw):
    with pytest.raises(InvalidIdentifier):
        normalise("sender_id", raw)


def test_unknown_type():
    with pytest.raises(InvalidIdentifier):
        normalise("email", "a@b.com")


def test_masks_match_the_brief():
    assert mask("phone", "+919876543210") == "98XXXXX210"
    assert mask("upi", "ravi12@okaxis") == "r***@okaxis"
    assert mask("url", "https://sbi-kyc.in/pay") == "sbi***.in/..."
    assert mask("sender_id", "HDFCBK") == "HD****"


@pytest.mark.parametrize("itype,raw", [("phone", "+91 98765 43210"), ("phone", "1800 1600"), ("upi", "Ravi12@OKAXIS"),
                                       ("url", "http://www.sbi-kyc.in/pay?x=1"), ("sender_id", "VM-HDFCBK")])
def test_idempotent(itype, raw):
    once = normalise(itype, raw)
    assert normalise(itype, once) == once


def test_never_raises_anything_else_on_random_unicode():
    rng = random.Random(42)
    alphabet = [chr(c) for c in list(range(32, 127)) + list(range(0x900, 0x97f)) + [0x200b, 0xa0, 0xff10, 0x1d7ce]]
    for _ in range(3000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        for itype in ("phone", "upi", "url", "sender_id"):
            try:
                out = normalise(itype, s)
            except InvalidIdentifier:
                continue
            assert normalise(itype, out) == out
