"""Versioned contracts for policy-governed memory and rebuildable derived views."""

from __future__ import annotations

import base64
import json
import re
from hashlib import sha256
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .governed_context import utc_now


DOMAIN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
FOUNDATION_DOMAINS = ("core-private", "health", "financial", "household-shared")
TaxonomyLevel = Literal["tag", "subdomain", "security-domain"]


class MemoryContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


def validate_domain_id(value: str) -> str:
    normalized = value.strip().lower()
    if not DOMAIN_PATTERN.fullmatch(normalized):
        raise ValueError("data domain must be a lowercase hyphenated identifier")
    return normalized


class DataDomainDefinition(MemoryContract):
    """Open-vocabulary domain definition; domain IDs are deliberately not an enum."""

    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    domain_id: str
    display_name: str
    description: str
    parent_domain_id: str | None = None
    origin: Literal["system", "person", "usage", "update"]
    status: Literal["proposed", "active", "deprecated"] = "proposed"
    separate_key_required: bool = True
    created_at: datetime = Field(default_factory=utc_now)

    _domain = field_validator("domain_id")(validate_domain_id)
    _parent = field_validator("parent_domain_id")(lambda value: validate_domain_id(value) if value else value)


class TaxonomyUsageSignal(MemoryContract):
    """Content-free evidence that a person's vocabulary may need to evolve."""

    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    signal_id: str
    candidate_domain_id: str
    current_domain_ids: tuple[str, ...] = ()
    signal_type: Literal[
        "repeated-request", "classification-correction", "distinct-audience",
        "policy-friction", "retention-friction", "sharing-friction",
    ]
    suggested_level: TaxonomyLevel
    observed_at: datetime = Field(default_factory=utc_now)
    source_reference: str | None = None

    _candidate = field_validator("candidate_domain_id")(validate_domain_id)

    @field_validator("current_domain_ids")
    @classmethod
    def current_domains_are_valid(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(validate_domain_id(value) for value in values)


class TaxonomyProposal(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    proposal_id: str
    candidate: DataDomainDefinition
    proposed_level: TaxonomyLevel
    evidence_count: int = Field(ge=1)
    distinct_days: int = Field(ge=1)
    evidence_types: tuple[str, ...]
    rationale: str
    benefits: tuple[str, ...]
    affected_record_ids: tuple[str, ...] = ()
    status: Literal["pending", "approved", "declined", "deferred", "withdrawn"] = "pending"
    requires_explicit_approval: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    cooldown_until: datetime | None = None

    @model_validator(mode="after")
    def remains_advisory(self) -> "TaxonomyProposal":
        if not self.requires_explicit_approval:
            raise ValueError("taxonomy proposals must require explicit approval")
        if self.candidate.status != "proposed":
            raise ValueError("proposal candidates cannot already be active")
        return self


class TaxonomyDecision(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    decision_id: str
    proposal_id: str
    decision: Literal["approve", "decline", "defer"]
    migration_scope: Literal["none", "selected", "all"] = "none"
    selected_record_ids: tuple[str, ...] = ()
    explicit_confirmation: bool = False
    reason: str | None = None
    decided_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def approval_is_explicit_and_scoped(self) -> "TaxonomyDecision":
        if self.decision == "approve" and not self.explicit_confirmation:
            raise ValueError("taxonomy activation requires explicit confirmation")
        if self.migration_scope == "selected" and not self.selected_record_ids:
            raise ValueError("selected migration requires record IDs")
        if self.decision != "approve" and self.migration_scope != "none":
            raise ValueError("only approval may request migration")
        return self


class TaxonomyActivationReceipt(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    receipt_id: str
    proposal_id: str
    decision_id: str
    domain: DataDomainDefinition
    migration_scope: Literal["none", "selected", "all"] = "none"
    migration_status: Literal["not-started", "partial", "complete"] = "not-started"
    migrated_record_ids: tuple[str, ...] = ()
    activated_at: datetime = Field(default_factory=utc_now)


class TaxonomyProposalPreview(MemoryContract):
    """Modality-neutral copy for a person-facing taxonomy decision."""

    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    proposal_id: str
    prompt: str
    summary: str
    why_now: tuple[str, ...]
    would_change: tuple[str, ...]
    would_not_change: tuple[str, ...]
    choices: tuple[Literal["approve", "defer", "decline"], ...] = ("approve", "defer", "decline")
    requires_security_review: bool
    generated_at: datetime = Field(default_factory=utc_now)


class TaxonomySecurityReview(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    review_id: str
    proposal_id: str
    decision: Literal["approve", "deny"]
    policy_version: str
    separate_key_boundary: bool
    retention_reviewed: bool
    sharing_reviewed: bool
    disclosure_reviewed: bool
    rationale: str
    reviewed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def approved_review_covers_every_boundary(self) -> "TaxonomySecurityReview":
        if self.decision == "approve" and not all((
            self.separate_key_boundary, self.retention_reviewed,
            self.sharing_reviewed, self.disclosure_reviewed,
        )):
            raise ValueError("security-domain approval must review every policy boundary")
        return self


class SignedTaxonomyPolicyIssuance(MemoryContract):
    """Short-lived authorization whose Ed25519 signature proves policy-service origin."""

    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    issuance_id: str
    issuer_service: Literal["unison-policy"] = "unison-policy"
    owner_person_id: str
    proposal_id: str
    review: TaxonomySecurityReview
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    key_id: str
    signature: str = ""

    @model_validator(mode="after")
    def binds_review_and_lifetime(self) -> "SignedTaxonomyPolicyIssuance":
        if self.review.proposal_id != self.proposal_id:
            raise ValueError("policy issuance must bind the reviewed proposal")
        if self.expires_at <= self.issued_at:
            raise ValueError("policy issuance must expire after it is issued")
        return self

    def signing_payload(self) -> bytes:
        return json.dumps(self.model_dump(mode="json", exclude={"signature"}),
                          sort_keys=True, separators=(",", ":")).encode()

    def sign(self, private_key: Ed25519PrivateKey) -> "SignedTaxonomyPolicyIssuance":
        signature = base64.urlsafe_b64encode(private_key.sign(self.signing_payload())).decode()
        return self.model_copy(update={"signature": signature})

    def verify(self, public_key: Ed25519PublicKey, *, owner_person_id: str,
               proposal_id: str, now: datetime | None = None) -> TaxonomySecurityReview:
        if self.owner_person_id != owner_person_id or self.proposal_id != proposal_id:
            raise ValueError("policy issuance is not bound to this person and proposal")
        if (now or utc_now()) >= self.expires_at:
            raise ValueError("policy issuance has expired")
        try:
            public_key.verify(base64.urlsafe_b64decode(self.signature), self.signing_payload())
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("policy issuance signature is invalid") from exc
        return self.review


class TaxonomyMigrationPreview(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    preview_id: str
    proposal_id: str
    domain_id: str
    source_domain_ids: tuple[str, ...]
    record_revisions: dict[str, int]
    classification_change: str
    key_boundary_change: str
    reversible: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    confirmation_digest: str

    _domain = field_validator("domain_id")(validate_domain_id)


class TaxonomyMigrationCommand(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    preview_id: str
    confirmation_digest: str
    explicit_confirmation: bool

    @model_validator(mode="after")
    def requires_confirmation(self) -> "TaxonomyMigrationCommand":
        if not self.explicit_confirmation:
            raise ValueError("taxonomy migration requires explicit confirmation")
        return self


class TaxonomyMigrationReceipt(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    migration_id: str
    preview_id: str
    proposal_id: str
    domain_id: str
    migrated_record_ids: tuple[str, ...]
    status: Literal["complete", "rolled-back"] = "complete"
    rollback_until: datetime
    completed_at: datetime = Field(default_factory=utc_now)


class TaxonomyRollbackReceipt(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    rollback_id: str
    migration_id: str
    restored_record_ids: tuple[str, ...]
    rolled_back_at: datetime = Field(default_factory=utc_now)


def taxonomy_preview_digest(payload: dict) -> str:
    """Stable digest used to bind confirmation to the exact content-free preview."""
    import json
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AlgorithmProvenance(MemoryContract):
    algorithm_id: str
    algorithm_version: str
    model_id: str | None = None
    model_revision: str | None = None


class MemoryRetrievalRequest(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    space_ids: tuple[str, ...]
    data_domains: tuple[str, ...]
    purpose: str
    query: str = ""
    token_budget: int = Field(default=2048, ge=1, le=131072)
    audience: tuple[str, ...] = ()
    allow_remote: bool = False

    @field_validator("data_domains")
    @classmethod
    def domains_are_valid(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("retrieval requires at least one data domain")
        return tuple(validate_domain_id(value) for value in values)

    @model_validator(mode="after")
    def authority_is_explicit(self) -> "MemoryRetrievalRequest":
        if not self.space_ids or not self.purpose.strip():
            raise ValueError("retrieval requires explicit spaces and purpose")
        return self


class DerivedViewDescriptor(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    view_id: str
    view_kind: Literal["embedding", "summary", "cache", "graph-edge"]
    source_record_id: str
    source_revision: int = Field(ge=1)
    space_id: str
    data_domains: tuple[str, ...]
    index_namespace: str
    algorithm: AlgorithmProvenance
    created_at: datetime = Field(default_factory=utc_now)


class DerivedViewInvalidationReceipt(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    receipt_id: str
    view_id: str
    source_record_id: str
    source_revision: int = Field(ge=1)
    reason: Literal["correction", "deletion", "retention-expiry", "membership-revocation", "key-rotation"]
    invalidated_at: datetime = Field(default_factory=utc_now)


class DerivedViewRebuildJob(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    job_id: str
    owner_person_id: str
    source_record_id: str
    source_revision: int = Field(ge=1)
    view_kind: Literal["embedding", "summary", "cache", "graph-edge"]
    target_algorithm: AlgorithmProvenance
    target_namespace: str
    state: Literal["pending", "running", "complete", "failed", "cancelled"] = "pending"
    attempts: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1, le=20)
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    last_error: str | None = None
    cancel_requested: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class EmbeddingMigrationPlan(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    migration_id: str
    owner_person_id: str
    source_algorithm: AlgorithmProvenance
    target_algorithm: AlgorithmProvenance
    source_namespace: str
    target_namespace: str
    strategy: Literal["dual-index-rebuild-and-swap"] = "dual-index-rebuild-and-swap"
    state: Literal["rebuilding", "ready", "cutover", "rolled-back"] = "rebuilding"
    total_jobs: int = Field(ge=0)
    completed_jobs: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class AuthorizedContextPacket(MemoryContract):
    contract_version: Literal["unison.memory.v1"] = "unison.memory.v1"
    purpose: str
    space_ids: tuple[str, ...]
    data_domains: tuple[str, ...]
    token_budget: int
    records: tuple[dict, ...]
    citations: tuple[str, ...]
    contains_inferences: bool = False
    disclosure_allowed: bool = False
    remote_allowed: bool = False


__all__ = [
    "AlgorithmProvenance", "AuthorizedContextPacket", "DataDomainDefinition",
    "DerivedViewDescriptor", "DerivedViewInvalidationReceipt", "DerivedViewRebuildJob",
    "EmbeddingMigrationPlan", "FOUNDATION_DOMAINS",
    "MemoryRetrievalRequest", "TaxonomyActivationReceipt", "TaxonomyDecision",
    "TaxonomyLevel", "TaxonomyMigrationCommand", "TaxonomyMigrationPreview",
    "TaxonomyMigrationReceipt", "TaxonomyProposal", "TaxonomyProposalPreview",
    "TaxonomyRollbackReceipt", "TaxonomySecurityReview", "SignedTaxonomyPolicyIssuance", "TaxonomyUsageSignal",
    "taxonomy_preview_digest", "validate_domain_id",
]
