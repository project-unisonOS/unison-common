from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class TraceSpan(BaseModel):
    schema_version: Literal["trace-span.v1"] = "trace-span.v1"
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    name: str
    start_monotonic_ns: int
    end_monotonic_ns: Optional[int] = None
    status: Literal["ok", "error"] = "ok"
    attrs: Dict[str, Any] = Field(default_factory=dict)


class TraceEvent(BaseModel):
    schema_version: Literal["trace-event.v1"] = "trace-event.v1"
    trace_id: str
    name: str
    ts_monotonic_ns: int
    attrs: Dict[str, Any] = Field(default_factory=dict)

