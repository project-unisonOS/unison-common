"""Canonical Phase 3 trust-governance contracts.

These types deliberately reject incomplete authority.  Services may add evidence,
but they must not invent a missing principal, purpose, audience, space, assurance,
or data classification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence
from uuid import uuid4


CONTRACT_VERSION = "unison.trust.v1"


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    MINIMIZE = "minimize"
    ASK = "ask"
    STEP_UP = "step-up"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssuranceLevel(str, Enum):
    LOCAL_UNLOCKED = "local-unlocked"
    REMOTE_AUTHENTICATED = "remote-authenticated"
    STRONG = "strong"
    HARDWARE = "hardware"


REQUIRED_AUTHORITY_FIELDS = (
    "principal_id", "assistant_id", "purpose", "audience", "space_id",
    "assurance", "data_classes", "action",
)


@dataclass(frozen=True)
class TrustRequest:
    principal_id: str
    assistant_id: str
    purpose: str
    audience: tuple[str, ...]
    space_id: str
    assurance: str
    data_classes: tuple[str, ...]
    action: str
    channel: str = "local"
    recipient_ids: tuple[str, ...] = ()
    requested_fields: tuple[str, ...] = ()
    capability_id: str | None = None
    relationship: str | None = None
    provenance: tuple[str, ...] = ()
    untrusted_input: bool = False
    estimated_cost: str | None = None
    risk_level: str = "low"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TrustRequest":
        missing = [name for name in REQUIRED_AUTHORITY_FIELDS if not value.get(name)]
        if missing:
            raise ValueError("incomplete authority: " + ", ".join(missing))
        audience = value["audience"]
        data_classes = value["data_classes"]
        if isinstance(audience, str) or not isinstance(audience, Sequence):
            raise ValueError("audience must be a non-empty list")
        if isinstance(data_classes, str) or not isinstance(data_classes, Sequence):
            raise ValueError("data_classes must be a non-empty list")
        return cls(
            principal_id=str(value["principal_id"]),
            assistant_id=str(value["assistant_id"]),
            purpose=str(value["purpose"]),
            audience=tuple(str(v) for v in audience),
            space_id=str(value["space_id"]),
            assurance=str(value["assurance"]),
            data_classes=tuple(str(v) for v in data_classes),
            action=str(value["action"]),
            channel=str(value.get("channel", "local")),
            recipient_ids=tuple(str(v) for v in value.get("recipient_ids", ())),
            requested_fields=tuple(str(v) for v in value.get("requested_fields", ())),
            capability_id=value.get("capability_id"),
            relationship=value.get("relationship"),
            provenance=tuple(str(v) for v in value.get("provenance", ())),
            untrusted_input=bool(value.get("untrusted_input", False)),
            estimated_cost=value.get("estimated_cost"),
            risk_level=str(value.get("risk_level", "low")),
        )


@dataclass(frozen=True)
class DisclosureDecision:
    outcome: DecisionOutcome
    reason_code: str
    explanation: str
    request_id: str = field(default_factory=lambda: str(uuid4()))
    contract_version: str = CONTRACT_VERSION
    disclosed_fields: tuple[str, ...] = ()
    redacted_fields: tuple[str, ...] = ()
    confirmation_id: str | None = None
    required_assurance: str | None = None
    reversible: bool = False
    consequence: str = "No external action was taken."
    alternatives: tuple[str, ...] = ()
    expires_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["outcome"] = self.outcome.value
        return value


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    principal_id: str
    assistant_id: str
    capability_id: str
    actions: tuple[str, ...]
    purposes: tuple[str, ...]
    audiences: tuple[str, ...]
    data_classes: tuple[str, ...]
    space_ids: tuple[str, ...]
    recipient_ids: tuple[str, ...] = ()
    max_risk: RiskLevel = RiskLevel.LOW
    max_cost: str = "0"
    execution_location: str = "device"
    expires_at: str | None = None
    revoked_at: str | None = None
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapabilityGrant":
        required = ("grant_id", "principal_id", "assistant_id", "capability_id",
                    "actions", "purposes", "audiences", "data_classes", "space_ids")
        missing = [name for name in required if not value.get(name)]
        if missing:
            raise ValueError("incomplete capability grant: " + ", ".join(missing))
        return cls(**{**value, "actions": tuple(value["actions"]),
                      "purposes": tuple(value["purposes"]),
                      "audiences": tuple(value["audiences"]),
                      "data_classes": tuple(value["data_classes"]),
                      "space_ids": tuple(value["space_ids"]),
                      "recipient_ids": tuple(value.get("recipient_ids", ())),
                      "max_risk": RiskLevel(value.get("max_risk", "low"))})
