from __future__ import annotations

from typing import Any, Dict, Literal, Optional, Union, List

from pydantic import BaseModel, Field


class EventGraphEvent(BaseModel):
    schema_version: Literal["event-graph-event.v1"] = "event-graph-event.v1"
    event_id: str = Field(..., description="Unique event identifier (UUID recommended).")
    trace_id: str
    ts_unix_ms: int = Field(..., description="Unix time in milliseconds when recorded.")
    ts_monotonic_ns: Optional[int] = Field(default=None, description="Optional monotonic timestamp for ordering.")

    event_type: str = Field(..., description="Event type (e.g., 'input_received', 'policy_decision').")
    actor: Optional[str] = Field(default=None, description="Actor identity (service/user) if known.")
    person_id: Optional[str] = Field(default=None)
    session_id: Optional[str] = Field(default=None)

    causation_id: Optional[str] = Field(default=None, description="Upstream event that caused this event.")
    parent_event_id: Optional[str] = Field(default=None, description="Parent event for hierarchical grouping.")

    attrs: Dict[str, Any] = Field(default_factory=dict, description="Small structured metadata.")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Event payload (keep small or use refs).")
    tags: List[str] = Field(default_factory=list)


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
    events: list[Union[EventGraphEvent, Dict[str, Any]]] = Field(
        default_factory=list, description="Append-only event nodes."
    )


class EventGraphQuery(BaseModel):
    schema_version: Literal["event-graph-query.v1"] = "event-graph-query.v1"
    trace_id: Optional[str] = None
    session_id: Optional[str] = None
    person_id: Optional[str] = None
    limit: int = 500
