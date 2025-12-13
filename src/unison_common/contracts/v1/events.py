from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class InputEventEnvelope(BaseModel):
    schema_version: Literal["input-event.v1"] = "input-event.v1"
    event_id: str = Field(..., description="Unique event identifier (UUID recommended).")
    trace_id: str = Field(..., description="Trace id used for end-to-end correlation.")
    ts_unix_ms: int = Field(..., description="Unix time in milliseconds when received/created.")

    source: str = Field(..., description="Source module (e.g., 'renderer', 'io-speech', 'cli').")
    modality: Literal["text", "speech", "vision", "sign", "braille", "bci", "system"] = Field(...)
    payload: Dict[str, Any] = Field(default_factory=dict, description="Modality payload.")

    person_id: Optional[str] = Field(default=None)
    session_id: Optional[str] = Field(default=None)
    auth: Dict[str, Any] = Field(
        default_factory=dict, description="Auth context (jwt subject, roles, scopes, baton)."
    )


class RendererEventEnvelope(BaseModel):
    schema_version: Literal["renderer-event.v1"] = "renderer-event.v1"
    event_id: str
    trace_id: str
    ts_unix_ms: int
    type: str = Field(..., description="Renderer event type (e.g., 'rom.render').")
    payload: Dict[str, Any] = Field(default_factory=dict)


class EventGraphAppend(BaseModel):
    schema_version: Literal["event-graph-append.v1"] = "event-graph-append.v1"
    trace_id: str
    session_id: Optional[str] = None
    person_id: Optional[str] = None
    events: list[Dict[str, Any]] = Field(default_factory=list, description="Append-only event nodes.")

