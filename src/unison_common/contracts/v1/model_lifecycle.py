from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GoldenSemanticJourney(StrictContract):
    schema_version: Literal["golden-semantic-journey.v1"] = "golden-semantic-journey.v1"
    journey_id: str
    synthetic: bool = True
    approved_data_reference: str | None = None
    required_fact_ids: list[str]
    required_node_ids: list[str]
    action_ids: list[str]
    provenance_source_ids: list[str]
    recovery_required: bool = True
    permitted_disclosure_fields: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def comparison_data_is_authorized(self) -> "GoldenSemanticJourney":
        if not self.synthetic and not self.approved_data_reference:
            raise ValueError("non-synthetic comparison data requires an approval reference")
        return self


class ModelEvaluationResult(StrictContract):
    schema_version: Literal["model-evaluation-result.v1"] = "model-evaluation-result.v1"
    model_ref: str
    journey_id: str
    passed: bool
    required_fact_diff: list[str] = Field(default_factory=list)
    semantic_diff: list[str] = Field(default_factory=list)
    modality_equivalent: bool
    disclosure_fields: list[str] = Field(default_factory=list)
    latency_ms: int = Field(ge=0)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelHealthSignal(StrictContract):
    schema_version: Literal["model-health-signal.v1"] = "model-health-signal.v1"
    model_ref: str
    sample_count: int = Field(ge=1)
    contract_success_rate: float = Field(ge=0, le=1)
    semantic_success_rate: float = Field(ge=0, le=1)
    fallback_rate: float = Field(ge=0, le=1)
    error_rate: float = Field(ge=0, le=1)
    p95_latency_ms: int = Field(ge=0)
    contains_person_content: Literal[False] = False


class ModelDeployment(StrictContract):
    schema_version: Literal["model-deployment.v1"] = "model-deployment.v1"
    task: str
    active_model_ref: str
    prior_model_ref: str | None = None
    stage: Literal["shadow", "canary", "active", "rolled-back"]
    canary_fraction: float = Field(default=0, ge=0, le=1)
    rollback_window_open: bool = True
    generation: int = Field(default=1, ge=1)
    audit: list[dict[str, Any]] = Field(default_factory=list)


class ModelHardwareQualification(StrictContract):
    schema_version: Literal["model-hardware-qualification.v1"] = "model-hardware-qualification.v1"
    model_ref: str
    runtime_ref: str
    hardware_profile: str
    evidence_kind: Literal["synthetic", "developer-host", "physical-device"]
    processor: str
    architecture: str
    accelerator: str | None = None
    ram_mb: int = Field(ge=1)
    storage_mb: int = Field(ge=1)
    latency_ms: dict[str, int]
    energy_wh: float | None = Field(default=None, ge=0)
    peak_temperature_c: float | None = None
    concurrent_workloads: int = Field(ge=1)
    offline_passed: bool
    update_passed: bool
    rollback_passed: bool
    semantic_quality_passed: bool
    safe_fallback_passed: bool
    limitations: list[str] = Field(default_factory=list)
    supported: bool = False

    @model_validator(mode="after")
    def support_requires_complete_physical_evidence(self) -> "ModelHardwareQualification":
        gates = (
            self.evidence_kind == "physical-device", self.energy_wh is not None,
            self.peak_temperature_c is not None, self.offline_passed,
            self.update_passed, self.rollback_passed, self.semantic_quality_passed,
            self.safe_fallback_passed,
        )
        if self.supported and not all(gates):
            raise ValueError("supported qualification requires complete passing physical-device evidence")
        return self


class ModelCompatibilityMatrix(StrictContract):
    schema_version: Literal["model-compatibility-matrix.v1"] = "model-compatibility-matrix.v1"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    records: list[ModelHardwareQualification]
    supported_model_refs: list[str]
    truthful_notice: str

    @model_validator(mode="after")
    def supported_list_matches_evidence(self) -> "ModelCompatibilityMatrix":
        supported = sorted({record.model_ref for record in self.records if record.supported})
        if sorted(self.supported_model_refs) != supported:
            raise ValueError("supported model list must derive only from supported qualification records")
        return self
