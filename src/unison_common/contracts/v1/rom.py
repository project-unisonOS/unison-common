from __future__ import annotations

from typing import Any, Dict, Literal, Optional, Union

from pydantic import BaseModel, Field


class RomText(BaseModel):
    type: Literal["text"] = "text"
    text: str


class RomCard(BaseModel):
    type: Literal["card"] = "card"
    title: str
    body: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


RomBlock = Union[RomText, RomCard]


class ResponseObjectModel(BaseModel):
    schema_version: Literal["rom.v1"] = "rom.v1"
    trace_id: str
    session_id: Optional[str] = None
    person_id: Optional[str] = None
    blocks: list[RomBlock] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict, description="Renderer hints, provenance, safety notes.")

