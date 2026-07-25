"""Canonical contracts for private life operations intake and connections."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProvenanceRegion(BaseModel):
    page: int | None = Field(default=None, ge=1)
    bounding_box: tuple[float, float, float, float] | None = None
    character_range: tuple[int, int] | None = None
    label: str | None = None


class SourceObject(BaseModel):
    schema_version: Literal["source-object.v1"] = "source-object.v1"
    source_id: str
    person_id: str
    space_id: str
    import_session_id: str
    media_type: str
    filename: str
    checksum_sha256: str
    size_bytes: int = Field(ge=0)
    state: Literal["quarantined", "admitted", "rejected", "deleted"] = "quarantined"
    visibility: Literal["private", "shared"] = "private"
    version: int = Field(default=1, ge=1)
    prior_version_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class ImportSession(BaseModel):
    schema_version: Literal["import-session.v1"] = "import-session.v1"
    session_id: str
    person_id: str
    space_id: str
    channel: Literal["file", "camera", "folder", "share", "provider"]
    state: Literal["receiving", "quarantined", "preview", "admitted", "rejected", "rolled_back"] = "receiving"
    source_ids: list[str] = Field(default_factory=list)
    checkpoint: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ExtractedField(BaseModel):
    schema_version: Literal["extracted-field.v1"] = "extracted-field.v1"
    field_id: str
    source_id: str
    name: str
    value: Any
    region: ProvenanceRegion
    confidence: float = Field(ge=0, le=1)
    corrected_value: Any | None = None
    correction_actor: Literal["person", "assistant"] | None = None


class DerivedRecord(BaseModel):
    schema_version: Literal["derived-record.v1"] = "derived-record.v1"
    record_id: str
    person_id: str
    space_id: str
    kind: str
    value: Any
    source_field_ids: list[str] = Field(min_length=1)
    inference: bool = True
    confidence: float = Field(ge=0, le=1)
    corrected_by_person: bool = False


class Connection(BaseModel):
    schema_version: Literal["connection.v1"] = "connection.v1"
    connection_id: str
    person_id: str
    provider_id: str
    profile: Literal["oauth-pkce", "smart-fhir", "financial-sandbox", "local-folder", "bounded-mcp"]
    scopes: list[str]
    token_handle: str | None = None
    cursor_handle: str | None = None
    status: Literal["pending", "active", "expired", "revoked", "error"] = "pending"
    read_only: bool = True
    consent_expires_at: datetime | None = None

    @model_validator(mode="after")
    def require_read_only(self) -> "Connection":
        if not self.read_only:
            raise ValueError("life operations connections must be read-only")
        return self


class SyncReceipt(BaseModel):
    schema_version: Literal["sync-receipt.v1"] = "sync-receipt.v1"
    receipt_id: str
    connection_id: str
    person_id: str
    started_at: datetime
    completed_at: datetime | None = None
    cursor_before: str | None = None
    cursor_after: str | None = None
    observed: int = Field(default=0, ge=0)
    imported: int = Field(default=0, ge=0)
    duplicates: int = Field(default=0, ge=0)
    status: Literal["running", "complete", "partial", "failed", "consent_required"] = "running"


class DomainPackage(BaseModel):
    schema_version: Literal["domain-package.v1"] = "domain-package.v1"
    package_id: str
    person_id: str
    domain: Literal["household", "health", "finance", "learning", "care", "other"]
    record_ids: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


class AttentionItem(BaseModel):
    schema_version: Literal["attention-item.v1"] = "attention-item.v1"
    item_id: str
    person_id: str
    summary: str
    source_ids: list[str] = Field(min_length=1)
    risk: Literal["informational", "low", "medium", "high"]
    requires_person: bool = True


class Brief(BaseModel):
    schema_version: Literal["brief.v1"] = "brief.v1"
    brief_id: str
    person_id: str
    title: str
    item_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


class DomainRecord(BaseModel):
    schema_version: Literal["life-domain-record.v1"] = "life-domain-record.v1"
    record_id: str
    person_id: str
    space_id: str
    domain: Literal["household", "health", "finance", "care", "benefits", "insurance", "continuity"]
    record_type: str
    facts: dict[str, Any]
    source_ids: list[str] = Field(min_length=1)
    evidence_status: Literal["observed", "self-reported", "inferred", "confirmed"]
    confidence: float = Field(ge=0, le=1)
    shared: bool = False
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def inference_cannot_confirm_diagnosis(self) -> "DomainRecord":
        if self.domain == "health" and self.record_type == "condition" and self.evidence_status == "inferred":
            if self.facts.get("clinical_status") == "confirmed":
                raise ValueError("an inferred condition cannot become a confirmed diagnosis")
        return self


class DomainLink(BaseModel):
    schema_version: Literal["life-domain-link.v1"] = "life-domain-link.v1"
    link_id: str
    person_id: str
    left_record_id: str
    right_record_id: str
    purpose: str = Field(min_length=3)
    allowed_fields: list[str] = Field(min_length=1)
    recipient_ids: list[str] = Field(default_factory=list)
    approved_by_person: bool
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def require_person_approval(self) -> "DomainLink":
        if not self.approved_by_person:
            raise ValueError("cross-domain links require person approval")
        return self


class ExternalActionDraft(BaseModel):
    schema_version: Literal["life-action-draft.v1"] = "life-action-draft.v1"
    draft_id: str
    person_id: str
    action_type: str
    domain_record_ids: list[str] = Field(min_length=1)
    recipients: list[str] = Field(default_factory=list)
    disclosed_fields: list[str] = Field(default_factory=list)
    content: str
    status: Literal["draft", "approved", "cancelled"] = "draft"
    executable: Literal[False] = False


class SafetyOutcome(BaseModel):
    schema_version: Literal["life-safety-outcome.v1"] = "life-safety-outcome.v1"
    outcome_id: str
    person_id: str
    domain: Literal["health", "finance"]
    severity: Literal["routine", "prompt", "urgent", "emergency"]
    guidance: str
    source_ids: list[str] = Field(min_length=1)
    deterministic_rule: str
    dismisses_professional_care: Literal[False] = False


class PilotMetric(BaseModel):
    name: str
    value: float
    unit: str
    target: float
    passed: bool


class PilotReport(BaseModel):
    schema_version: Literal["life-operations-pilot.v1"] = "life-operations-pilot.v1"
    pilot_id: str
    cohort: Literal["synthetic-household", "synthetic-health", "synthetic-finance", "opt-in-human"]
    opted_in: bool
    metrics: list[PilotMetric]
    boundary_incidents: int = Field(ge=0)
    unsafe_actions: int = Field(ge=0)
    supported_package_decision: Literal["hold", "approve", "reject"] = "hold"
    generated_at: datetime = Field(default_factory=utc_now)


class LifeOperationDomain(str, Enum):
    HOUSEHOLD = "household"
    HEALTH = "health"
    FINANCE = "finance"
    CROSS_DOMAIN = "cross-domain"


PROHIBITED_ACTIONS: dict[LifeOperationDomain, frozenset[str]] = {
    LifeOperationDomain.HOUSEHOLD: frozenset({"physical_actuation", "purchase", "schedule_service"}),
    LifeOperationDomain.HEALTH: frozenset({
        "diagnose", "prescribe", "change_medication", "cancel_clinical_care", "submit_medical_order"
    }),
    LifeOperationDomain.FINANCE: frozenset({
        "transfer_funds", "trade_security", "open_credit", "change_beneficiary", "file_tax_return",
        "close_account", "submit_dispute"
    }),
    LifeOperationDomain.CROSS_DOMAIN: frozenset({"widen_disclosure", "destroy_independent_source"}),
}


def authorize_life_operation(domain: LifeOperationDomain, action: str) -> bool:
    """Fail closed for high-consequence health and finance operations."""
    return action not in PROHIBITED_ACTIONS[domain]
