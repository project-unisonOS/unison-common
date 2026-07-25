from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .semantic_experience import SemanticAction, SemanticNode, SemanticProvenance


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelTask(str, Enum):
    INTERPRETATION = "interpretation"
    EXTRACTION = "extraction"
    VISION = "vision"
    SEMANTIC_CONSTRUCTION = "semantic-construction"
    SYNTHESIS = "synthesis"
    CONVERSATION = "conversation"


class ModelTaskRequirement(StrictContract):
    task: ModelTask
    modality: str = "text"
    language: str = "en"
    min_context_tokens: int = Field(default=1, ge=1)
    structured_output: bool = True
    max_latency_ms: int = Field(default=5000, ge=1)
    max_cost: float = Field(default=0, ge=0)
    risk: Literal["low", "medium", "high", "critical"] = "low"
    local_only: bool = True
    deterministic_fallback_required: bool = False
    required_fact_ids: list[str] = Field(default_factory=list)


class ModelHardwareRequirement(StrictContract):
    architectures: list[str] = Field(default_factory=list)
    min_ram_mb: int = Field(default=0, ge=0)
    min_vram_mb: int = Field(default=0, ge=0)
    accelerator: str | None = None
    storage_mb: int = Field(default=0, ge=0)


class ModelManifest(StrictContract):
    schema_version: Literal["model-manifest.v1"] = "model-manifest.v1"
    model_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    artifact_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    source: str = Field(min_length=1)
    provenance: list[str] = Field(min_length=1)
    runtime: str = Field(min_length=1)
    runtime_version: str = Field(min_length=1)
    tasks: list[ModelTask] = Field(min_length=1)
    modalities: list[str] = Field(min_length=1)
    languages: list[str] = Field(min_length=1)
    context_tokens: int = Field(ge=1)
    structured_output: bool
    hardware: ModelHardwareRequirement
    execution_location: Literal["device", "remote"]
    provider: str
    license: str = Field(min_length=1)
    license_approved: bool
    privacy: dict[str, Any]
    measured_quality: dict[str, float]
    measured_latency_ms: dict[str, int]
    approved_risk: list[Literal["low", "medium", "high", "critical"]]
    known_limits: list[str] = Field(default_factory=list)
    rollback_compatible_with: list[str] = Field(default_factory=list)
    supported: bool = False
    estimated_cost: float = Field(default=0, ge=0)


class SignedModelManifest(StrictContract):
    schema_version: Literal["signed-model-manifest.v1"] = "signed-model-manifest.v1"
    manifest: ModelManifest
    key_id: str
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


class ModelRouteDecision(StrictContract):
    schema_version: Literal["model-route-decision.v1"] = "model-route-decision.v1"
    operation_id: str
    task: ModelTask
    selected_model_id: str | None = None
    selected_version: str | None = None
    minimized_disclosure_fields: list[str] = Field(default_factory=list)
    fallback: str
    eligible: list[str] = Field(default_factory=list)
    rejected: dict[str, list[str]] = Field(default_factory=dict)
    ranking: list[dict[str, Any]] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)


class ModelSemanticProposal(StrictContract):
    schema_version: Literal["model-semantic-proposal.v1"] = "model-semantic-proposal.v1"
    operation_id: str
    model_id: str
    model_version: str
    source_state_versions: dict[str, str]
    nodes: list[SemanticNode] = Field(default_factory=list)
    actions: list[SemanticAction] = Field(default_factory=list)
    fact_claims: dict[str, Any] = Field(default_factory=dict)
    recipients: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    recovery: str | None = None
    provenance: list[SemanticProvenance] = Field(min_length=1)
    untrusted: Literal[True] = True

    @model_validator(mode="after")
    def require_provenance_for_content(self) -> "ModelSemanticProposal":
        if any(not node.provenance for node in self.nodes):
            raise ValueError("every proposed node requires provenance")
        return self
