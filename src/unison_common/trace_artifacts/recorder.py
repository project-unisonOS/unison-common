from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, Optional


class TraceSpanStatus(str, Enum):
    OK = "ok"
    ERROR = "error"


def _now_unix_ms() -> int:
    return int(time.time() * 1000)


def _now_monotonic_ns() -> int:
    return time.perf_counter_ns()


@dataclass
class _Span:
    span_id: str
    name: str
    parent_span_id: Optional[str]
    start_monotonic_ns: int
    attrs: Dict[str, Any] = field(default_factory=dict)
    end_monotonic_ns: Optional[int] = None
    status: TraceSpanStatus = TraceSpanStatus.OK

    def end(self, *, status: TraceSpanStatus = TraceSpanStatus.OK, attrs: Optional[Dict[str, Any]] = None) -> None:
        if self.end_monotonic_ns is None:
            self.end_monotonic_ns = _now_monotonic_ns()
        self.status = status
        if attrs:
            self.attrs.update(attrs)

    def to_dict(self, trace_id: str) -> Dict[str, Any]:
        end_ns = self.end_monotonic_ns
        duration_ms = None
        if end_ns is not None:
            duration_ms = (end_ns - self.start_monotonic_ns) / 1_000_000.0
        return {
            "schema_version": "trace-span.v1",
            "trace_id": trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "start_monotonic_ns": self.start_monotonic_ns,
            "end_monotonic_ns": end_ns,
            "duration_ms": duration_ms,
            "status": self.status.value,
            "attrs": dict(self.attrs),
        }


@dataclass
class _Event:
    name: str
    ts_monotonic_ns: int
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, trace_id: str) -> Dict[str, Any]:
        return {
            "schema_version": "trace-event.v1",
            "trace_id": trace_id,
            "name": self.name,
            "ts_monotonic_ns": self.ts_monotonic_ns,
            "attrs": dict(self.attrs),
        }


class TraceRecorder:
    """
    Records a file-friendly trace artifact (JSON) for a single interaction.

    This is intentionally independent from OpenTelemetry exporters so it works
    in local/dev environments without collectors.
    """

    def __init__(self, *, trace_id: Optional[str] = None, service: str = "unison", attrs: Optional[Dict[str, Any]] = None):
        self.trace_id = trace_id or uuid.uuid4().hex
        self.service = service
        self.created_unix_ms = _now_unix_ms()
        self.created_monotonic_ns = _now_monotonic_ns()
        self._spans: list[_Span] = []
        self._events: list[_Event] = []
        self._span_stack: list[_Span] = []
        self.attrs: Dict[str, Any] = dict(attrs or {})

    def emit_event(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> None:
        self._events.append(_Event(name=name, ts_monotonic_ns=_now_monotonic_ns(), attrs=dict(attrs or {})))

    def start_span(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> _Span:
        parent = self._span_stack[-1] if self._span_stack else None
        span = _Span(
            span_id=uuid.uuid4().hex[:16],
            name=name,
            parent_span_id=parent.span_id if parent else None,
            start_monotonic_ns=_now_monotonic_ns(),
            attrs=dict(attrs or {}),
        )
        self._spans.append(span)
        self._span_stack.append(span)
        return span

    def end_span(self, span: _Span, *, status: TraceSpanStatus = TraceSpanStatus.OK, attrs: Optional[Dict[str, Any]] = None) -> None:
        span.end(status=status, attrs=attrs)
        if self._span_stack and self._span_stack[-1] is span:
            self._span_stack.pop()
        else:
            try:
                self._span_stack.remove(span)
            except ValueError:
                pass

    @contextmanager
    def span(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> Iterator[_Span]:
        span = self.start_span(name, attrs=attrs)
        try:
            yield span
            self.end_span(span, status=TraceSpanStatus.OK)
        except Exception as exc:
            self.end_span(span, status=TraceSpanStatus.ERROR, attrs={"error": str(exc)})
            raise

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "trace-artifact.v1",
            "trace_id": self.trace_id,
            "service": self.service,
            "created_unix_ms": self.created_unix_ms,
            "created_monotonic_ns": self.created_monotonic_ns,
            "attrs": dict(self.attrs),
            "spans": [s.to_dict(self.trace_id) for s in self._spans],
            "events": [e.to_dict(self.trace_id) for e in self._events],
        }

    def write_json(self, path: str | Path) -> Path:
        from unison_common.redaction import redact_obj

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        payload = self.to_dict()
        if os.getenv("UNISON_REDACT_TRACE_ARTIFACTS", "true").lower() in {"1", "true", "yes", "on"}:
            payload = redact_obj(payload)
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        tmp.replace(target)
        return target

    def write_default(self, *, directory: Optional[str | Path] = None) -> Path:
        base = Path(directory or os.getenv("UNISON_TRACE_DIR", "traces"))
        return self.write_json(base / f"{self.trace_id}.json")
