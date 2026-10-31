"""Identifier normaliser and masking (BUILD_SPEC section 4).

Pure functions, no I/O. For any input, `normalise` either returns the standard form or
raises InvalidIdentifier; it raises nothing else.

Standard forms (from the brief's API rules):
    phone      +91 and 10 digits; short helplines and 1800/1860 toll-free numbers as digits
    upi        lower case, no spaces
    url        https://, no www., nothing after ?, no / at the end
    sender_id  the 6-character code without the 2-letter prefix the phone adds
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Optional
from urllib.parse import parse_qs, urlsplit

IDENTIFIER_TYPES = ("phone", "upi", "url", "sender_id")

_TYPE_ALIASES = {
    "phone": "phone", "mobile": "phone",
    "upi": "upi", "vpa": "upi", "upi_id": "upi",
    "url": "url", "link": "url",
    "sender_id": "sender_id", "sender": "sender_id", "senderid": "sender_id", "sms_sender": "sender_id",
}


class InvalidIdentifier(ValueError):
    """The value cannot be a valid identifier of this type."""


def normalise_type(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return _TYPE_ALIASES.get(value.strip().lower().replace("-", "_").replace(" ", "_"))


def normalise(identifier_type: object, value: object) -> str:
    t = normalise_type(identifier_type)
    if t is None:
        raise InvalidIdentifier("type")
    return _NORMALISERS[t](value)


# --------------------------------------------------------------------------- shared
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_MAX_INPUT = 2048


def _clean(raw: object) -> str:
    """NFKC, drop zero-width characters, map every Unicode decimal digit to ASCII, trim."""
    if not isinstance(raw, str) or len(raw) > _MAX_INPUT:
        raise InvalidIdentifier("value")
    s = unicodedata.normalize("NFKC", raw).translate(_INVISIBLE)
    out = []
    for ch in s:
        d = unicodedata.decimal(ch, None)
        if d is not None:
            out.append(str(d))
        elif ch.isspace():
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out).strip()


# --------------------------------------------------------------------------- phone
_HELPLINES = frozenset({"100", "101", "102", "108", "112", "181", "1091", "1098",
                        "1909", "1930", "14422", "155260"})
_PHONE_SEPARATORS = re.compile(r"[\s\-().\/]")


def _ascending_run(d: str) -> bool:
    """Keyboard junk such as a run of digits counting up by one (wrapping 9 to 0).
    A descending run stays valid: the brief's own example number counts down."""
    return all((int(b) - int(a)) % 10 == 1 for a, b in zip(d, d[1:]))


def _phone(raw: object) -> str:
    t = _PHONE_SEPARATORS.sub("", _clean(raw))
    plus = t.startswith("+")
    d = t[1:] if plus else t
    if not d.isdigit():                      # letters, '*', '#', a second '+', or empty
        raise InvalidIdentifier("phone")
    if not plus and d.startswith("00"):      # 0091..., 001...: international dialling prefix
        d, plus = d[2:], True
    if plus:
        if d.startswith("91"):
            d = d[2:]
            if len(d) == 11 and d.startswith("0"):   # +91 0 98765 43210
                d = d[1:]
        elif 8 <= len(d) <= 15 and d[0] != "0":
            return "+" + d                   # another country: kept as dialled
        else:
            raise InvalidIdentifier("phone")
    elif len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 13 and d.startswith(("091", "910")):
        d = d[3:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]

    if d.startswith(("1800", "1860")) and 8 <= len(d) <= 11:
        return d                             # toll-free: digits, no +91
    if len(d) == 10:
        if d[0] == "0" or len(set(d)) == 1 or _ascending_run(d):
            raise InvalidIdentifier("phone")
        return "+91" + d                     # mobile (6-9) or landline with its STD code
    if d in _HELPLINES:
        return d                             # short helplines such as 1930
    raise InvalidIdentifier("phone")


# --------------------------------------------------------------------------- upi
_UPI_RE = re.compile(r"[a-z0-9._-]{2,64}@[a-z0-9]{2,32}")


def _upi(raw: object) -> str:
    s = _clean(raw)
    if s.lower().startswith("upi://"):       # a pasted UPI QR link: take the payee address
        s = (parse_qs(urlsplit(s).query).get("pa") or [""])[0]
    s = "".join(s.split()).lower()
    if not _UPI_RE.fullmatch(s) or not any(c.isalpha() for c in s.partition("@")[2]):
        raise InvalidIdentifier("upi")
    return s


# --------------------------------------------------------------------------- url
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+\-]*):", re.I)
_BAD_SCHEMES = frozenset({"javascript", "data", "mailto", "file", "ftp", "tel", "sms", "intent",
                          "vbscript", "blob", "about", "chrome", "upi", "content"})
_LABEL_RE = re.compile(r"^[a-z0-9¡-￿](?:[a-z0-9¡-￿\-]{0,61}[a-z0-9¡-￿])?$")
# Unicode categories that cannot be part of a host name a person reads: control, format (direction marks and
# overrides), surrogate, private use, unassigned, line and paragraph separators, spaces. Letters, digits and
# combining marks of every script stay valid.
_HOST_REFUSED = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})
_DEFANG_RE = re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.I)


def _url(raw: object) -> str:
    s = _DEFANG_RE.sub(".", _clean(raw))
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = "".join(s.split())
    if not s or len(s) > 2048:
        raise InvalidIdentifier("url")
    m = _SCHEME_RE.match(s)
    if m and s[m.end():m.end() + 2] == "//":
        if m.group(1).lower() not in ("http", "https"):
            raise InvalidIdentifier("url")
    elif m and m.group(1).lower() in _BAD_SCHEMES:
        raise InvalidIdentifier("url")
    else:
        s = "https://" + s.lstrip("/")
    try:
        parts = urlsplit(s)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise InvalidIdentifier("url") from None
    if not host:
        raise InvalidIdentifier("url")
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:                 # private, loopback, link-local, reserved
            raise InvalidIdentifier("url")
        host_out = host if ip.version == 4 else f"[{host}]"
    else:
        if any(unicodedata.category(ch) in _HOST_REFUSED for ch in host):
            raise InvalidIdentifier("url")   # direction overrides, separators, private use, lone surrogates
        labels = host.split(".")
        if (host == "localhost" or host.endswith(".localhost") or len(labels) < 2
                or labels[-1].isdigit() or not all(_LABEL_RE.match(x) for x in labels)):
            raise InvalidIdentifier("url")
        host_out = host
    path = _encode_path(parts.path.lower().rstrip("/"))
    netloc = host_out if port in (None, 80, 443) else f"{host_out}:{port}"
    return f"https://{netloc}{path}"


# RFC 3986 path characters (unreserved, sub-delims, ":" "@" "/") minus the apostrophe, which is a
# sub-delim but also closes an HTML attribute. Everything else is percent-encoded as UTF-8 so that
# nothing in a stored link can open or close an HTML tag or attribute (stored XSS, layer a).
_PATH_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&()*+,;=:@/")
_HEX = frozenset("0123456789abcdefABCDEF")


def _encode_path(path: str) -> str:
    out = []
    i, n = 0, len(path)
    while i < n:
        ch = path[i]
        if ch == "%" and i + 2 < n and path[i + 1] in _HEX and path[i + 2] in _HEX:
            out.append("%" + path[i + 1:i + 3].upper())   # a valid triplet stays, in one case
            i += 3
            continue
        if ch in _PATH_SAFE:
            out.append(ch)
        else:                                              # "%" alone, markup, non-ASCII, controls
            out.extend("%%%02X" % b for b in ch.encode("utf-8", "replace"))
        i += 1
    return "".join(out)


def url_host(canon: str) -> str:
    """Host of a normalised URL, without port."""
    netloc = canon.split("://", 1)[-1].split("/", 1)[0]
    if netloc.startswith("["):
        return netloc[1:netloc.index("]")]
    return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc


# --------------------------------------------------------------------------- sender_id
_SENDER6 = re.compile(r"[A-Z0-9]{6}")


def _ok_sender(p: str) -> bool:
    return bool(_SENDER6.fullmatch(p)) and sum(c.isalpha() for c in p) >= 3


def _sender(raw: object) -> str:
    s = "".join(_clean(raw).upper().split())
    parts = [p for p in s.split("-") if p]
    if len(parts) >= 2 and len(parts[0]) == 2 and parts[0].isalpha():
        parts = parts[1:]                    # VM-ABCDEF, AD-ABCDEF: the 2-letter prefix the phone adds
    if len(parts) == 2 and len(parts[1]) == 1 and parts[1].isalpha():
        parts = parts[:1]                    # ABCDEF-S: the newer 1-letter category suffix
    if len(parts) != 1:
        raise InvalidIdentifier("sender_id")
    p = parts[0]
    if len(p) == 8 and p[:2].isalpha() and _ok_sender(p[2:]):
        p = p[2:]                            # VMABCDEF typed without the dash
    if not _ok_sender(p):
        raise InvalidIdentifier("sender_id")
    return p


_NORMALISERS = {"phone": _phone, "upi": _upi, "url": _url, "sender_id": _sender}


# --------------------------------------------------------------------------- masking
def mask(identifier_type: str, canon: str) -> str:
    """Shapes from the brief: first 2 and last 3 digits of a phone, first letter of a UPI ID,
    first 3 letters and the last label of a link's host, first 2 letters of a sender."""
    if identifier_type == "phone":
        if canon.startswith("+91") and len(canon) == 13:
            d = canon[3:]
            return d[:2] + "X" * 5 + d[-3:]
        d = canon.lstrip("+")
        if len(d) >= 7:
            return d[:2] + "X" * (len(d) - 5) + d[-3:]
        return d[:1] + "X" * (len(d) - 1)
    if identifier_type == "upi":
        local, _, handle = canon.partition("@")
        return local[:1] + "***@" + handle
    if identifier_type == "url":
        host = url_host(canon)
        dot = host.rfind(".")
        return host.split(".")[0][:3] + "***" + (host[dot:] if dot > 0 else "") + "/..."
    if identifier_type == "sender_id":
        return canon[:2] + "*" * (len(canon) - 2)
    raise InvalidIdentifier("type")
