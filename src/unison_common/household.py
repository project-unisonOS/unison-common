"""Canonical contracts for the bounded Phase 4 two-adult household proof."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HouseholdModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HouseholdArtifactKind(str, Enum):
    CALENDAR_EVENT = "calendar_event"
    GROCERY_ITEM = "grocery_item"


class CoordinationAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"


class CoordinationStatus(str, Enum):
    COMPLETED = "completed"
    DENIED = "denied"
    NO_CHANGE = "no_change"


class CalendarEventDetails(HouseholdModel):
    title: str = Field(min_length=1, max_length=160)
    starts_at: datetime
    ends_at: datetime
    location: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def ends_after_start(self) -> "CalendarEventDetails":
        if self.ends_at <= self.starts_at:
            raise ValueError("calendar event must end after it starts")
        return self


class GroceryItemDetails(HouseholdModel):
    item: str = Field(min_length=1, max_length=120)
    quantity: str | None = Field(default=None, max_length=40)
    state: str = Field(default="needed", pattern="^(needed|purchased|removed)$")


class HouseholdCoordinationRequest(HouseholdModel):
    version: str = "4.0"
    household_id: str
    space_id: str
    action: CoordinationAction
    purpose: str = Field(min_length=1, max_length=160)
    artifact_id: str | None = None
    artifact_kind: HouseholdArtifactKind | None = None
    calendar: CalendarEventDetails | None = None
    grocery: GroceryItemDetails | None = None

    @model_validator(mode="after")
    def validate_action_shape(self) -> "HouseholdCoordinationRequest":
        payloads = int(self.calendar is not None) + int(self.grocery is not None)
        if self.action is CoordinationAction.CREATE:
            if self.artifact_id is not None or self.artifact_kind is None or payloads != 1:
                raise ValueError("create requires one typed payload and no artifact_id")
        elif self.action is CoordinationAction.UPDATE:
            if not self.artifact_id or self.artifact_kind is None or payloads != 1:
                raise ValueError("update requires an artifact_id and one typed payload")
        elif self.action is CoordinationAction.DELETE:
            if not self.artifact_id or payloads:
                raise ValueError("delete requires only an artifact_id")
        elif self.action is CoordinationAction.LIST:
            if self.artifact_id is not None or payloads:
                raise ValueError("list does not accept an artifact payload")
        if self.calendar is not None and self.artifact_kind is not HouseholdArtifactKind.CALENDAR_EVENT:
            raise ValueError("calendar payload requires calendar_event kind")
        if self.grocery is not None and self.artifact_kind is not HouseholdArtifactKind.GROCERY_ITEM:
            raise ValueError("grocery payload requires grocery_item kind")
        return self


class SharedFact(HouseholdModel):
    name: str
    value: Any
    classification: str = "household-shared"


class HouseholdArtifact(HouseholdModel):
    version: str = "4.0"
    artifact_id: str
    household_id: str
    space_id: str
    kind: HouseholdArtifactKind
    created_by_person_id: str
    content: dict[str, Any]
    revision: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class HouseholdCoordinationOutcome(HouseholdModel):
    version: str = "4.0"
    status: CoordinationStatus
    action: CoordinationAction
    space_id: str
    artifact: HouseholdArtifact | None = None
    artifacts: tuple[HouseholdArtifact, ...] = ()
    shared_facts: tuple[SharedFact, ...] = ()
    explanation: str
    private_sources_read: int = Field(default=0, ge=0)


class HouseholdMembershipSummary(HouseholdModel):
    person_id: str
    assistant_instance_id: str
    membership_role: str
    status: str
    display_name: str


class AssistantResourceQuota(HouseholdModel):
    assistant_instance_id: str
    max_concurrent_tasks: int = Field(default=1, ge=1, le=64)
    max_queued_tasks: int = Field(default=16, ge=1, le=4096)
    cpu_units: int = Field(default=1, ge=1, le=128)
    memory_mb: int = Field(default=512, ge=64, le=1048576)


class SharePreview(HouseholdModel):
    source_record_id: str
    source_remains_private: bool = True
    target_space_id: str
    target_audience: tuple[str, ...]
    fields_to_share: tuple[str, ...]
    purpose: str
    confirmation_required: bool = True

