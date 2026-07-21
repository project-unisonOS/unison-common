"""Canonical Phase 2 governed-context contracts.

These models describe data classification and authority.  They deliberately do
not grant access: callers must still prove membership in the governing space.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SpaceKind(str, Enum):
    PRIVATE = "private"
    SHARED = "shared"
    SYSTEM = "system"
    EPHEMERAL = "ephemeral"


class MemberRole(str, Enum):
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class MemoryKind(str, Enum):
    ASSERTED_FACT = "asserted_fact"
    IMPORTED_DATA = "imported_data"
    INFERRED_HYPOTHESIS = "inferred_hypothesis"
    USER_CORRECTION = "user_correction"
    SUMMARY = "summary"
    DERIVED_INDEX = "derived_index"
    CALENDAR_EVENT = "calendar_event"
    GROCERY_ITEM = "grocery_item"


class DeletionState(str, Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    EXPIRED = "expired"


class CommitmentState(str, Enum):
    OPEN = "open"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class GovernedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContextSpace(GovernedModel):
    version: str = "2.0"
    space_id: str
    kind: SpaceKind
    owner_person_id: str
    household_id: str | None = None
    assistant_instance_id: str | None = None
    name: str
    purpose: str
    key_handle: str
    key_version: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    deleted_at: datetime | None = None

    @model_validator(mode="after")
    def validate_private_owner(self) -> "ContextSpace":
        if self.kind is SpaceKind.PRIVATE and not self.assistant_instance_id:
            raise ValueError("private spaces require an assistant instance")
        if self.kind is SpaceKind.SHARED and not self.household_id:
            raise ValueError("shared spaces require a household identifier")
        return self


class SpaceMembership(GovernedModel):
    version: str = "2.0"
    membership_id: str
    space_id: str
    person_id: str
    role: MemberRole
    invited_by: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    removed_at: datetime | None = None


class Relationship(GovernedModel):
    version: str = "2.0"
    relationship_id: str
    owner_person_id: str
    subject_id: str
    label: str
    context_tags: tuple[str, ...] = ()
    provenance: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    deleted_at: datetime | None = None


class MemoryGovernance(GovernedModel):
    sensitivity: str = "private"
    purposes: tuple[str, ...] = ()
    audiences: tuple[str, ...] = ()
    allow_inference: bool = False
    allow_action: bool = False
    allow_disclosure: bool = False
    allow_backup: bool = False
    allow_sync: bool = False
    retention_until: datetime | None = None


class MemoryRecord(GovernedModel):
    version: str = "2.0"
    record_id: str
    owner_person_id: str
    space_id: str
    kind: MemoryKind
    content: dict[str, Any]
    provenance: str
    source_record_id: str | None = None
    relationship_ids: tuple[str, ...] = ()
    governance: MemoryGovernance = Field(default_factory=MemoryGovernance)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    revision: int = Field(default=1, ge=1)
    deletion_state: DeletionState = DeletionState.ACTIVE
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def inferred_records_need_uncertainty(self) -> "MemoryRecord":
        if self.kind is MemoryKind.INFERRED_HYPOTHESIS and self.confidence >= 1.0:
            raise ValueError("inferred hypotheses must express uncertainty")
        return self


class PersonalCharter(GovernedModel):
    version: str = "2.0"
    charter_id: str
    person_id: str
    principles: tuple[str, ...]
    prohibited_objectives: tuple[str, ...] = (
        "third_party_engagement",
        "sponsored_placement",
        "sale_of_personal_context",
    )
    origin: str
    revision: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("principles")
    @classmethod
    def principles_are_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item.strip() for item in value):
            raise ValueError("a charter requires non-blank principles")
        return value


class Goal(GovernedModel):
    version: str = "2.0"
    goal_id: str
    person_id: str
    space_id: str
    title: str
    origin: str
    status: str = "active"
    revision: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Commitment(GovernedModel):
    version: str = "2.0"
    commitment_id: str
    person_id: str
    space_id: str
    title: str
    origin: str
    due_at: datetime | None = None
    state: CommitmentState = CommitmentState.OPEN
    revision: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class SemanticPrivacyState(GovernedModel):
    active_space_ids: tuple[str, ...]
    space_kinds: tuple[SpaceKind, ...]
    purpose: str
    audience: tuple[str, ...] = ()
    contains_inferences: bool = False
    disclosure_allowed: bool = False
    ambiguous_context: bool = False
