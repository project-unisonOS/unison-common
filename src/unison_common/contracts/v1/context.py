from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class ContextSnapshot(BaseModel):
    schema_version: Literal["context-snapshot.v1"] = "context-snapshot.v1"
    person_id: Optional[str] = Field(default=None)
    profile: Optional[Dict[str, Any]] = Field(default=None)
    dashboard: Optional[Dict[str, Any]] = Field(default=None)
    fetched_at_unix_ms: int = Field(..., description="Unix time (ms) when snapshot was fetched.")


class ContextWriteBehindBatch(BaseModel):
    schema_version: Literal["context-write-behind.v1"] = "context-write-behind.v1"
    batch_id: str = Field(..., description="Unique batch identifier (UUID recommended).")
    person_id: Optional[str] = Field(default=None, description="Principal whose context is being updated.")
    session_id: Optional[str] = Field(default=None)
    updates: list[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of context updates; each item is a structured patch instruction.",
    )
    queued_at_unix_ms: int = Field(..., description="Unix time (ms) when queued.")
