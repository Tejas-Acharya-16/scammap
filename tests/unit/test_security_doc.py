"""SECURITY.md exists, the README links it, and both keep to the wording rule (row 4: say "reported")."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BANNED = re.compile(r"\b(scammer|scammers|fraud|fraudster|fraudsters|criminal|thief)\b", re.I)


def test_security_md_is_linked_from_the_readme():
    assert (ROOT / "SECURITY.md").is_file()
    assert "(SECURITY.md)" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_security_md_and_readme_use_no_banned_words():
    for name in ("SECURITY.md", "README.md"):
        hits = BANNED.findall((ROOT / name).read_text(encoding="utf-8"))
        assert hits == [], (name, hits)


def test_security_md_covers_what_it_must():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for heading in ("What we protect", "How we protect it", "Open by design", "Known limits"):
        assert heading in text
    assert "/admin/reset" in text and "UNVERIFIED" in text
    assert len(text.splitlines()) <= 90          # one page
