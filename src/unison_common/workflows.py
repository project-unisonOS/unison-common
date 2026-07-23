"""Canonical contracts for bounded, governed Phase 7 assistant workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WorkflowKind(str, Enum):
    CALENDAR_COORDINATION = "calendar_coordination"
    EMAIL_TRIAGE_DRAFT = "email_triage_draft"
    REMINDER_COMMITMENT_REVIEW = "reminder_commitment_review"
    HOUSEHOLD_COORDINATION = "household_coordination"
    CONTACT_RECALL = "contact_recall"
    DOCUMENT_WEB_RESEARCH = "document_web_research"
    TRAVEL_PLANNING = "travel_planning"


class WorkflowState(str, Enum):
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    CANCELLED = "cancelled"
    RECOVERABLE = "recoverable"
    COMPENSATED = "compensated"
    COMPLETED = "completed"
    FAILED = "failed"


class StepState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    COMPENSATED = "compensated"


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    capability: str
    action: str
    provider: str
    state: StepState = StepState.PENDING
    requires_approval: bool = False
    external_call: bool = False
    reversible: bool = True
    recipient_ids: tuple[str, ...] = ()
    disclosed_fields: tuple[str, ...] = ()
    attempt: int = Field(default=0, ge=0)


class TaskPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "7.0"
    plan_id: str = Field(default_factory=lambda: str(uuid4()))
    person_id: str
    assistant_id: str
    kind: WorkflowKind
    purpose: str
    context_space_ids: tuple[str, ...]
    charter_constraints: tuple[str, ...] = ()
    commitment_ids: tuple[str, ...] = ()
    steps: tuple[WorkflowStep, ...]
    state: WorkflowState = WorkflowState.PLANNED
    idempotency_key: str
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_plan(self) -> "TaskPlan":
        if not self.context_space_ids:
            raise ValueError("at least one governed context space is required")
        if not self.steps:
            raise ValueError("at least one workflow step is required")
        if any(step.external_call and not step.disclosed_fields for step in self.steps):
            raise ValueError("external calls must declare minimized disclosed fields")
        return self


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    plan_id: str
    step_id: str
    person_id: str
    exact_action: str
    exact_recipients: tuple[str, ...] = ()
    approved: bool
    created_at: datetime = Field(default_factory=utc_now)


class FailureRecovery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    failure_code: str
    failed_step_id: str
    safe_to_retry: bool
    retry_count: int = Field(default=0, ge=0)
    compensation_actions: tuple[str, ...] = ()
    user_message: str


class OutcomeMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    administrative_tasks_completed: int = Field(default=0, ge=0)
    commitments_completed: int = Field(default=0, ge=0)
    interruptions_avoided: int = Field(default=0, ge=0)
    corrections: int = Field(default=0, ge=0)
    recoveries: int = Field(default=0, ge=0)
    external_calls: int = Field(default=0, ge=0)
    minimized_fields_disclosed: int = Field(default=0, ge=0)
    estimated_minutes_returned: int = Field(default=0, ge=0)
    user_confirmed_minutes_returned: int | None = Field(default=None, ge=0)
    boundary_incidents: int = Field(default=0, ge=0)


class OutcomeEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "7.0"
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    plan_id: str
    person_id: str
    kind: WorkflowKind
    state: WorkflowState
    completed_step_ids: tuple[str, ...] = ()
    provider_receipts: tuple[str, ...] = ()
    recovery: FailureRecovery | None = None
    metrics: OutcomeMetrics
    audit_events: tuple[str, ...]
    completed_at: datetime = Field(default_factory=utc_now)


class WorkflowRecord(BaseModel):
    """Portable record/replay envelope containing no provider credential."""

    model_config = ConfigDict(extra="forbid")

    version: str = "7.0"
    fixture_id: str
    provider_kind: str
    request: dict[str, Any]
    response: dict[str, Any]
    contains_personal_data: bool = False

    @model_validator(mode="after")
    def reject_personal_data(self) -> "WorkflowRecord":
        if self.contains_personal_data:
            raise ValueError("record/replay fixtures must not contain personal data")
        return self


PROHIBITED_RANKING_SIGNALS = frozenset(
    {
        "advertising",
        "engagement",
        "attention_capture",
        "sponsored",
        "provider_lock_in",
        "third_party_data_acquisition",
    }
)


def validate_ranking_signals(signals: dict[str, float]) -> None:
    prohibited = PROHIBITED_RANKING_SIGNALS.intersection(signals)
    if prohibited:
        raise ValueError(f"prohibited ranking signals: {', '.join(sorted(prohibited))}")
