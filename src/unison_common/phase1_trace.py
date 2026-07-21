from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


_LOCK = threading.Lock()


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_text(text: str) -> str:
    digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class Phase1NdjsonTrace:
    """
    Phase 1 MVP NDJSON trace writer.

    Emits one JSON object per line, intended to conform to:
    `schemas/phase1/orchestrator_event.v1.schema.json`.
    """

    path: Path

    @classmethod
    def from_env(cls) -> "Phase1NdjsonTrace":
        raw = os.getenv("UNISON_PHASE1_TRACE_PATH", "var/traces/unison-phase1.ndjson")
        return cls(path=Path(raw).expanduser().resolve())

    def emit(
        self,
        *,
        trace_id: str,
        source: str,
        type: str,
        level: str = "info",
        payload: Optional[Dict[str, Any]] = None,
        redactions: Optional[Iterable[str]] = None,
        span_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        event_id: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> None:
        record: Dict[str, Any] = {
            "event_id": event_id or uuid.uuid4().hex,
            "ts": ts or _iso_utc_now(),
            "trace_id": trace_id,
            "span_id": span_id or uuid.uuid4().hex[:8],
            "source": source,
            "type": type,
            "level": level,
            "payload": dict(payload or {}),
        }
        if parent_span_id:
            record["parent_span_id"] = parent_span_id
        if redactions:
            record["redactions"] = list(redactions)
        else:
            record["redactions"] = []

        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))

        # Single-process safety: keep writes atomic-ish for multi-threaded emitters.
        with _LOCK:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


__all__ = ["Phase1NdjsonTrace", "sha256_text"]

