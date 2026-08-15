"""Contracts for open-world resolution and governed deterministic evolution."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from .governed_context import utc_now

RouteKind = Literal["known-deterministic", "deterministic-composition", "retrieval-adaptation",
                    "bounded-local-inference", "governed-external", "clarification",
                    "simulation", "partial-outcome", "safe-handoff"]

class ResolutionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

class ResolutionBudget(ResolutionContract):
    time_seconds: int = Field(ge=1, le=86400)
    model_calls: int = Field(ge=0, le=1000)
    tool_calls: int = Field(ge=0, le=10000)
    external_disclosures: int = Field(default=0, ge=0, le=100)
    energy_wh: float | None = Field(default=None, ge=0)
    cost_limit: float | None = Field(default=None, ge=0)

class ResolutionRoute(ResolutionContract):
    route_id: str
    kind: RouteKind
    state: Literal["considered", "selected", "running", "succeeded", "failed", "blocked", "cancelled"]
    deterministic_rejection_reason: str | None = None
    tool_ids: tuple[str, ...] = ()
    skill_ids: tuple[str, ...] = ()
    algorithm_ids: tuple[str, ...] = ()
    model_ids: tuple[str, ...] = ()
    source_handles: tuple[str, ...] = ()
    provider_ids: tuple[str, ...] = ()

class ResolutionAttempt(ResolutionContract):
    schema_version: Literal["resolution-attempt.v1"] = "resolution-attempt.v1"
    attempt_id: str
    owner_person_id: str
    assistant_instance_id: str
    purpose: str
    risk: Literal["low", "medium", "high", "critical"]
    requested_result_class: str
    authorized_space_ids: tuple[str, ...]
    authorized_domain_ids: tuple[str, ...]
    budget: ResolutionBudget
    routes: tuple[ResolutionRoute, ...]
    state: Literal["active", "waiting", "partial", "complete", "blocked", "cancelled"] = "active"
    assumptions: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()
    partial_artifact_handles: tuple[str, ...] = ()
    recovery_state: dict[str, Any] = Field(default_factory=dict)
    structural_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def authority_is_explicit(self) -> "ResolutionAttempt":
        if not self.purpose.strip() or not self.routes:
            raise ValueError("resolution attempts require purpose and at least one route")
        return self

class ResolutionReceipt(ResolutionContract):
    schema_version: Literal["resolution-receipt.v1"] = "resolution-receipt.v1"
    receipt_id: str
    attempt_id: str
    outcome: Literal["complete", "partial", "blocked", "cancelled"]
    selected_route_ids: tuple[str, ...]
    action_receipt_ids: tuple[str, ...] = ()
    usefulness: Literal["unknown", "useful", "not-useful"] = "unknown"
    correction_recorded: bool = False
    completed_at: datetime = Field(default_factory=utc_now)

class DeterminizationCandidate(ResolutionContract):
    schema_version: Literal["determinization-candidate.v1"] = "determinization-candidate.v1"
    candidate_id: str
    scope: Literal["person-local", "household", "contribution"]
    candidate_kind: Literal["algorithm", "query", "rule", "workflow", "tool-wrapper", "skill", "adapter", "cache", "fixture", "knowledge-pack"]
    structural_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_attempt_ids: tuple[str, ...]
    invariant_steps: tuple[str, ...]
    parameter_schema: dict[str, Any]
    authority_requirements: tuple[str, ...]
    privacy_requirements: tuple[str, ...]
    modality_requirements: tuple[str, ...]
    failure_modes: tuple[str, ...]
    expected_benefit: str
    state: Literal["observed", "proposed", "specified", "tested", "reviewed", "signed", "canary", "promoted", "rejected", "revoked"] = "proposed"
    executable: bool = False
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def candidates_never_self_authorize(self) -> "DeterminizationCandidate":
        if self.executable and self.state not in {"signed", "canary", "promoted"}:
            raise ValueError("candidate cannot execute before signed review")
        if self.state == "promoted" and not self.executable:
            raise ValueError("promoted candidate must be explicitly executable")
        return self

class CandidateTransition(ResolutionContract):
    candidate_id: str
    from_state: str
    to_state: str
    reviewer_ids: tuple[str, ...] = ()
    package_digest: str | None = None
    reason: str
    transitioned_at: datetime = Field(default_factory=utc_now)

class ResolutionPilotSignal(ResolutionContract):
    """Content-free outcome signal for an explicitly opted-in pilot attempt."""
    schema_version: Literal["resolution-pilot-signal.v1"] = "resolution-pilot-signal.v1"
    signal_id: str
    attempt_id: str
    participant_id: str
    opted_in: bool
    usefulness: Literal["useful", "partly-useful", "not-useful"]
    outcome: Literal["complete", "partial", "blocked", "cancelled"]
    elapsed_seconds: int = Field(ge=0, le=86400)
    interaction_turns: int = Field(ge=1, le=1000)
    clarification_count: int = Field(ge=0, le=100)
    correction_count: int = Field(ge=0, le=100)
    generic_refusal: bool = False
    candidate_suggested: bool = False
    candidate_relevant: bool | None = None
    trust_rating: int | None = Field(default=None, ge=1, le=5)
    privacy_understood: bool | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def require_opt_in_and_consistent_candidate_rating(self) -> "ResolutionPilotSignal":
        if not self.opted_in:
            raise ValueError("pilot signals require explicit opt-in")
        if not self.candidate_suggested and self.candidate_relevant is not None:
            raise ValueError("candidate relevance requires a candidate suggestion")
        return self

class ModalityAdapterManifest(ResolutionContract):
    """Common integration point for independently developed native modalities."""
    schema_version: Literal["modality-adapter.v1"] = "modality-adapter.v1"
    adapter_id: str
    modality: str
    input_supported: bool
    output_supported: bool
    sem_versions: tuple[str, ...]
    expression_versions: tuple[str, ...]
    capability_ids: tuple[str, ...]
    required_permissions: tuple[str, ...] = ()
    device_classes: tuple[str, ...] = ()
    fallback_modalities: tuple[str, ...] = ()
    package_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    signer_id: str

    @model_validator(mode="after")
    def require_direction_and_contract(self) -> "ModalityAdapterManifest":
        if not self.input_supported and not self.output_supported:
            raise ValueError("adapter must provide input or output")
        if not self.sem_versions or not self.expression_versions:
            raise ValueError("adapter must declare semantic and expression contracts")
        return self
