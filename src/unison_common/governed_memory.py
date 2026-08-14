"""Versioned contracts for policy-governed memory and rebuildable derived views."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .governed_context import utc_now


DOMAIN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
FOUNDATION_DOMAINS = ("core-private", "health", "financial", "household-shared")


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
    "DerivedViewDescriptor", "DerivedViewInvalidationReceipt", "FOUNDATION_DOMAINS",
    "MemoryRetrievalRequest", "validate_domain_id",
]
