"""Contracts for shared household incidents and natural resolution attempts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SensorObservation(StrictContract):
    schema_version: Literal["sensor-observation.v1"] = "sensor-observation.v1"
    observation_id: str = Field(min_length=1)
    sensor_id: str = Field(min_length=1)
    source_sequence: int = Field(ge=0)
    observed_at: datetime
    received_at: datetime
    state: str = Field(min_length=1)
    value: Any
    unit: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    fresh_until: datetime
    integrity_state: Literal["verified", "unverified", "failed", "fixture"]
    device_health: Literal["healthy", "degraded", "offline", "unknown"]

    @model_validator(mode="after")
    def validate_timing(self) -> "SensorObservation":
        if self.received_at < self.observed_at:
            raise ValueError("sensor receipt cannot predate observation")
        if self.fresh_until < self.received_at:
            raise ValueError("sensor observation cannot be stale when received")
        return self


class EvidenceState(str, Enum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    STALE = "stale"
    CONFLICTING = "conflicting"
    MISSING = "missing"
    INVALID = "invalid"


class EvidenceRecord(StrictContract):
    schema_version: Literal["evidence-state.v1"] = "evidence-state.v1"
    evidence_id: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    state: EvidenceState
    source_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    conflicts: list[str] = Field(default_factory=list)
    uncertainty: str | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> "EvidenceRecord":
        if self.state == EvidenceState.MISSING:
            if self.source_ids:
                raise ValueError("missing evidence cannot cite an observed source")
        elif not self.source_ids:
            raise ValueError("observed evidence requires at least one source")
        if self.state == EvidenceState.CONFLICTING and not self.conflicts:
            raise ValueError("conflicting evidence requires conflict references")
        if self.state != EvidenceState.CONFIRMED and not self.uncertainty:
            raise ValueError("non-confirmed evidence requires an uncertainty explanation")
        return self


class HouseholdEquipment(StrictContract):
    schema_version: Literal["household-equipment.v1"] = "household-equipment.v1"
    equipment_id: str = Field(min_length=1)
    household_space_id: str = Field(pattern=r"^shared:")
    kind: str = Field(min_length=1)
    label: str = Field(min_length=1)
    location_id: str = Field(min_length=1)
    component_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(min_length=1)
    procedure_ids: list[str] = Field(default_factory=list)


class KnowledgeProcedure(StrictContract):
    procedure_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    steps: list[str] = Field(min_length=1)


class OfflineKnowledgePack(StrictContract):
    schema_version: Literal["offline-knowledge-pack.v1"] = "offline-knowledge-pack.v1"
    pack_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    region: str = Field(min_length=1)
    language: str = Field(min_length=1)
    authority: str = Field(min_length=1)
    source_ids: list[str] = Field(min_length=1)
    effective_at: datetime
    review_by: datetime
    hazards: list[str] = Field(min_length=1)
    stop_rules: list[str] = Field(min_length=1)
    procedures: list[KnowledgeProcedure] = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature_key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "OfflineKnowledgePack":
        if self.review_by <= self.effective_at:
            raise ValueError("knowledge pack review date must follow its effective date")
        procedure_ids = [item.procedure_id for item in self.procedures]
        if len(procedure_ids) != len(set(procedure_ids)):
            raise ValueError("knowledge pack procedure identifiers must be unique")
        return self


class IncidentState(str, Enum):
    OBSERVED = "observed"
    ASSESSING = "assessing"
    ACTION_NEEDED = "action-needed"
    ISOLATING = "isolating"
    MONITORING = "monitoring"
    RECOVERED = "recovered"
    ESCALATED = "escalated"
    CLOSED = "closed"


LEGAL_INCIDENT_TRANSITIONS: dict[IncidentState, frozenset[IncidentState]] = {
    IncidentState.OBSERVED: frozenset({IncidentState.ASSESSING, IncidentState.CLOSED, IncidentState.ESCALATED}),
    IncidentState.ASSESSING: frozenset({IncidentState.ACTION_NEEDED, IncidentState.MONITORING, IncidentState.ESCALATED, IncidentState.CLOSED}),
    IncidentState.ACTION_NEEDED: frozenset({IncidentState.ISOLATING, IncidentState.ESCALATED}),
    IncidentState.ISOLATING: frozenset({IncidentState.MONITORING, IncidentState.ESCALATED}),
    IncidentState.MONITORING: frozenset({IncidentState.RECOVERED, IncidentState.ESCALATED, IncidentState.CLOSED}),
    IncidentState.RECOVERED: frozenset({IncidentState.CLOSED, IncidentState.ESCALATED}),
    IncidentState.ESCALATED: frozenset({IncidentState.MONITORING, IncidentState.CLOSED}),
    IncidentState.CLOSED: frozenset(),
}


class IncidentTimelineEvent(StrictContract):
    event_id: str = Field(min_length=1)
    state: IncidentState
    occurred_at: datetime
    actor_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    source_ids: list[str] = Field(default_factory=list)
    deterministic_rule: str | None = None


class IncidentAssignment(StrictContract):
    schema_version: Literal["incident-assignment.v1"] = "incident-assignment.v1"
    assignment_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    workflow_step_id: str = Field(min_length=1)
    assignee_person_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    state: Literal["proposed", "acknowledged", "completed", "cancelled"] = "proposed"
    created_at: datetime
    acknowledged_at: datetime | None = None
    completed_at: datetime | None = None
    source_ids: list[str] = Field(min_length=1)
    physical_actuation: Literal[False] = False

    @model_validator(mode="after")
    def validate_assignment_state(self) -> "IncidentAssignment":
        if self.state in {"acknowledged", "completed"} and self.acknowledged_at is None:
            raise ValueError("acknowledged assignments require an acknowledgement time")
        if self.state == "completed" and self.completed_at is None:
            raise ValueError("completed assignments require a completion time")
        if self.acknowledged_at and self.acknowledged_at < self.created_at:
            raise ValueError("assignment acknowledgement cannot predate creation")
        if self.completed_at and (self.acknowledged_at is None or self.completed_at < self.acknowledged_at):
            raise ValueError("assignment completion cannot predate acknowledgement")
        return self


class HouseholdIncident(StrictContract):
    schema_version: Literal["household-incident.v1"] = "household-incident.v1"
    incident_id: str = Field(min_length=1)
    space_id: str = Field(pattern=r"^shared:")
    kind: str = Field(min_length=1)
    state: IncidentState
    severity: Literal["notice", "prompt", "urgent", "emergency"]
    source_ids: list[str] = Field(min_length=1)
    facts: list[EvidenceRecord] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    assignments: list[IncidentAssignment] = Field(default_factory=list)
    timeline: list[IncidentTimelineEvent] = Field(min_length=1)
    retention_class: Literal["ephemeral", "incident", "person-controlled"] = "incident"
    physical_actuation_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_timeline(self) -> "HouseholdIncident":
        states = [event.state for event in self.timeline]
        if states[0] != IncidentState.OBSERVED:
            raise ValueError("incident timeline must begin with observed")
        for previous, current in zip(states, states[1:]):
            if current not in LEGAL_INCIDENT_TRANSITIONS[previous]:
                raise ValueError(f"illegal incident transition: {previous.value} -> {current.value}")
        if states[-1] != self.state:
            raise ValueError("incident state must match the final timeline event")
        event_ids = [event.event_id for event in self.timeline]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("incident timeline event identifiers must be unique")
        if any(self.timeline[index].occurred_at > self.timeline[index + 1].occurred_at for index in range(len(self.timeline) - 1)):
            raise ValueError("incident timeline must be chronological")
        if self.state in {IncidentState.RECOVERED, IncidentState.CLOSED} and not self.timeline[-1].source_ids:
            raise ValueError("recovery and closure require source evidence")
        if self.state == IncidentState.ESCALATED and not self.timeline[-1].deterministic_rule:
            raise ValueError("escalation requires a deterministic rule")
        return self


class ResolutionBudget(StrictContract):
    max_seconds: int = Field(gt=0)
    max_model_calls: int = Field(ge=0)
    max_external_calls: int = Field(ge=0)
    max_cost: float = Field(ge=0)
    max_disclosed_fields: int = Field(ge=0)


class StructuralFingerprint(StrictContract):
    contract_types: list[str] = Field(default_factory=list)
    tool_kinds: list[str] = Field(default_factory=list)
    route_kinds: list[str] = Field(default_factory=list)
    error_classes: list[str] = Field(default_factory=list)
    modality_transitions: list[str] = Field(default_factory=list)
    risk_class: Literal["low", "medium", "high", "critical"]
    outcome_shape: str = Field(min_length=1)
    contains_person_content: Literal[False] = False


class ResolutionAttempt(StrictContract):
    schema_version: Literal["resolution-attempt.v1"] = "resolution-attempt.v1"
    attempt_id: str = Field(min_length=1)
    outcome_id: str = Field(min_length=1)
    person_id: str = Field(min_length=1)
    assistant_instance_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    risk: Literal["low", "medium", "high", "critical"]
    authorized_space_ids: list[str] = Field(default_factory=list)
    authorized_domain_handles: list[str] = Field(default_factory=list)
    routes_considered: list[str] = Field(min_length=1)
    rejection_reasons: dict[str, str] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    state: Literal["planning", "running", "partial", "blocked", "completed", "cancelled"]
    partial_artifact_ids: list[str] = Field(default_factory=list)
    recovery: str | None = None
    budget: ResolutionBudget
    structural_fingerprint: StructuralFingerprint

    @model_validator(mode="after")
    def validate_resolution_state(self) -> "ResolutionAttempt":
        if self.state == "partial" and not self.partial_artifact_ids:
            raise ValueError("partial resolution requires a useful artifact")
        if self.state in {"partial", "blocked"} and not self.recovery:
            raise ValueError("partial or blocked resolution requires a continuation or handoff")
        if self.budget.max_external_calls == 0 and self.budget.max_disclosed_fields != 0:
            raise ValueError("a local-only attempt cannot budget external disclosure")
        return self
