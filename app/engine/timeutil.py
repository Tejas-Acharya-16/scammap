"""Time parsing and formatting (BUILD_SPEC section 5). Replies use IST (+05:30)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

IST = timezone(timedelta(hours=5, minutes=30))


def parse_time(value: object) -> Optional[datetime]:
    """ISO 8601 with an offset ('Z' allowed). A time without an offset is read as IST.
    Returns None for anything that is not a time (for example 'yesterday')."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=IST)
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > 40:
        return None
    if s[-1] in "Zz":
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=IST)


def ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=IST)


def iso_ist(dt: datetime) -> str:
    """'2026-10-27T18:21:04+05:30'"""
    return dt.astimezone(IST).isoformat(timespec="seconds")


def day_floor_ist(dt: datetime) -> datetime:
    d = dt.astimezone(IST)
    return d.replace(hour=0, minute=0, second=0, microsecond=0)
