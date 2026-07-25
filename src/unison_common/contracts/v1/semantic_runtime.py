from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Modality = Literal["conversation", "visual", "braille", "sign", "haptic", "switch-aac"]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModalityCapability(StrictContract):
    modality: Modality
    input_available: bool = False
    output_available: bool = False
    healthy: bool = True
    latency_ms: int = Field(default=0, ge=0)
    resource_cost: int = Field(default=1, ge=0, le=10)


class ExpressionContext(StrictContract):
    shared_room: bool = False
    bystanders: bool = False
    quiet_mode: bool = False
    offline: bool = False
    sensitive_content: bool = False
    allow_spoken_sensitive: bool = False
    allow_displayed_sensitive: bool = False


class ExpressionPlanRequest(StrictContract):
    schema_version: Literal["expression-plan-request.v1"] = "expression-plan-request.v1"
    person_id: str
    session_id: str
    requested_input: Modality | None = None
    requested_outputs: list[Modality] = Field(default_factory=list)
    preferred_inputs: list[Modality] = Field(default_factory=list)
    preferred_outputs: list[Modality] = Field(default_factory=list)
    unavailable_modalities: list[Modality] = Field(default_factory=list)
    capabilities: list[ModalityCapability]
    environment: ExpressionContext = Field(default_factory=ExpressionContext)
    risk: Literal["low", "medium", "high", "critical"] = "low"


class ExpressionPlan(StrictContract):
    schema_version: Literal["expression-plan.v1"] = "expression-plan.v1"
    plan_id: str
    person_id: str
    session_id: str
    input_modality: Modality
    output_modalities: list[Modality] = Field(min_length=1)
    fallbacks: list[Modality] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)
    deterministic_constraints: list[str] = Field(default_factory=list)
    recorded_inputs_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class PendingConfirmation(StrictContract):
    confirmation_id: str
    action_id: str
    person_id: str
    issued_for_modality: Modality
    nonce: str
    consumed: bool = False


class InteractionSession(StrictContract):
    schema_version: Literal["interaction-session.v1"] = "interaction-session.v1"
    session_id: str
    person_id: str
    semantic_focus: str | None = None
    dialogue_references: dict[str, str] = Field(default_factory=dict)
    pending_action_ids: list[str] = Field(default_factory=list)
    confirmations: list[PendingConfirmation] = Field(default_factory=list)
    progress: dict[str, Any] = Field(default_factory=dict)
    recovery: str | None = None
    active_modalities: list[Modality] = Field(default_factory=list)
    revision: int = Field(default=1, ge=1)


class EquivalenceFinding(StrictContract):
    severity: Literal["error", "warning"]
    code: str
    detail: str


class EquivalenceReport(StrictContract):
    schema_version: Literal["semantic-equivalence-report.v1"] = "semantic-equivalence-report.v1"
    experience_id: str
    left_modality: Modality
    right_modality: Modality
    equivalent: bool
    findings: list[EquivalenceFinding] = Field(default_factory=list)


class SemanticObservation(StrictContract):
    schema_version: Literal["semantic-observation.v1"] = "semantic-observation.v1"
    observation_id: str
    source_type: Literal["api", "document", "accessibility-tree", "computer-use", "vision"]
    source_id: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    state_version: str
    trust: Literal["trusted", "untrusted"] = "untrusted"
    confidence: float = Field(ge=0.0, le=1.0)
    content: dict[str, Any]
    ambiguities: list[str] = Field(default_factory=list)
    injection_signals: list[str] = Field(default_factory=list)


class AuthenticatedTarget(StrictContract):
    capability: str
    target_id: str
    person_id: str
    state_version: str
    authority_token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: datetime

    @model_validator(mode="after")
    def require_future_expiry(self) -> "AuthenticatedTarget":
        if self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("authenticated target is expired")
        return self
