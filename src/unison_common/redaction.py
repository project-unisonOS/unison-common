from __future__ import annotations

import re
from typing import Any, Mapping


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_BEARER_RE = re.compile(r"bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

_SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "api_key",
    "apikey",
    "api-key",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "set-cookie",
    "cookie",
    "x-api-key",
}


def redact_text(value: str) -> str:
    """
    Best-effort redaction for tokens/emails embedded in strings.
    """
    if not isinstance(value, str):
        return value  # type: ignore[return-value]
    if _BEARER_RE.search(value) or _JWT_RE.search(value):
        return "[REDACTED]"
    if _EMAIL_RE.search(value):
        return _EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    return value


def redact_obj(obj: Any) -> Any:
    """
    Recursively redact sensitive keys and token/email-like values.

    Intended for logs, trace artifacts, and event payloads before persistence.
    """
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            key_lower = str(k).lower()
            if key_lower in _SENSITIVE_KEYS:
                out[str(k)] = "[REDACTED]"
            else:
                out[str(k)] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def redact_headers(headers: Mapping[str, str] | None) -> dict[str, str] | None:
    if headers is None:
        return None
    clean: dict[str, str] = {}
    for k, v in headers.items():
        if str(k).lower() in _SENSITIVE_KEYS:
            clean[str(k)] = "[REDACTED]"
        else:
            clean[str(k)] = redact_text(str(v))
    return clean
