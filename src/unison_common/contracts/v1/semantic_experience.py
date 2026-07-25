from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SemanticNodeKind(str, Enum):
    OUTCOME = "outcome"
    ENTITY = "entity"
    VALUE = "value"
    GROUP = "group"
    SEQUENCE = "sequence"
    COMPARISON = "comparison"
    TREND = "trend"
    SPATIAL = "spatial"
    NOTICE = "notice"


class SemanticProvenance(StrictContract):
    source_id: str = Field(min_length=1)
    source_type: str = Field(min_length=1)
    observed_at: datetime | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class SemanticRelationship(StrictContract):
    predicate: str = Field(min_length=1)
    target_node_id: str = Field(min_length=1)


class SemanticNode(StrictContract):
    node_id: str = Field(min_length=1)
    kind: SemanticNodeKind
    label: str = Field(min_length=1)
    value: Any = None
    summary: str | None = None
    detail: str | None = None
    relationships: list[SemanticRelationship] = Field(default_factory=list)
    provenance: list[SemanticProvenance] = Field(default_factory=list)
    required: bool = False
    exact: bool = False
    uncertainty: str | None = None


class SemanticAction(StrictContract):
    action_id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    target: dict[str, Any] = Field(default_factory=dict)
    consequence: str = Field(min_length=1)
    risk: Literal["low", "medium", "high", "critical"] = "low"
    reversible: bool = False
    confirmation_required: bool = False
    recipient: str | None = None
    cancellation: str | None = None
    recovery: str | None = None
    provenance: list[SemanticProvenance] = Field(default_factory=list)


class SemanticExperience(StrictContract):
    schema_version: Literal["sem.v1"] = "sem.v1"
    experience_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    session_id: str | None = None
    person_id: str | None = None
    purpose: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    nodes: list[SemanticNode] = Field(default_factory=list)
    actions: list[SemanticAction] = Field(default_factory=list)
    privacy: dict[str, Any] = Field(default_factory=dict)
    attention: Literal["ambient", "normal", "important", "urgent"] = "normal"
    recovery: str | None = None

    @model_validator(mode="after")
    def validate_bindings(self) -> "SemanticExperience":
        node_ids = [node.node_id for node in self.nodes]
        action_ids = [action.action_id for action in self.actions]
        if len(node_ids) != len(set(node_ids)) or len(action_ids) != len(set(action_ids)):
            raise ValueError("semantic node and action identifiers must be unique")
        known = set(node_ids)
        dangling = [
            rel.target_node_id
            for node in self.nodes
            for rel in node.relationships
            if rel.target_node_id not in known
        ]
        if dangling:
            raise ValueError(f"semantic relationships reference unknown nodes: {sorted(set(dangling))}")
        return self


class SemanticExpression(StrictContract):
    schema_version: Literal["semantic-expression.v1"] = "semantic-expression.v1"
    experience_id: str
    modality: Literal["conversation", "visual", "braille", "sign", "haptic", "switch-aac"]
    summary: str
    segments: list[dict[str, Any]] = Field(default_factory=list)
    action_ids: list[str] = Field(default_factory=list)
    required_node_ids: list[str] = Field(default_factory=list)
    action_risk: dict[str, Literal["low", "medium", "high", "critical"]] = Field(default_factory=dict)
    provenance_source_ids: list[str] = Field(default_factory=list)
    fallback: str | None = None
