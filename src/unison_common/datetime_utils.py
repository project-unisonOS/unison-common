"""
Timezone-aware datetime helpers used across services.

These helpers keep all timestamps aligned to UTC with explicit tzinfo objects
so we can avoid deprecated naive-UTC APIs and consistently
produce ISO 8601 strings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def now_utc() -> datetime:
    """Return the current UTC time with timezone awareness."""
    return datetime.now(timezone.utc)


def isoformat_utc(value: Optional[datetime] = None) -> str:
    """
    Convert a datetime to an ISO 8601 string with UTC timezone.

    Args:
        value: The datetime to format. When omitted, `now_utc()` is used.
    """
    dt = value or now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


__all__ = ["now_utc", "isoformat_utc"]
