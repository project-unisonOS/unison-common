"""Canonical Phase 5 Channel Gateway contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ChannelModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChannelDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class ChannelAssurance(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DeliveryState(str, Enum):
    RECEIVED = "received"
    DRAFT = "draft"
    QUEUED = "queued"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ProviderPrivacyMetadata(ChannelModel):
    provider: str
    provider_reads_content: bool
    provider_retains_content: bool
    retention_summary: str
    provider_receives_identifiers: tuple[str, ...] = ()
    end_to_end_encrypted_to_node: bool = False
    monetizes_personal_data: bool | None = None
    policy_url: str
    reviewed_at: datetime


class ChannelCapabilities(ChannelModel):
    text: bool = True
    attachments: bool = False
    buttons: bool = False
    edits: bool = False
    delivery_receipts: bool = False
    maximum_text_length: int = Field(default=4096, ge=1, le=1_000_000)
    supports_concise_mode: bool = True
    supports_simplified_language: bool = True
    supports_cancel: bool = True


class ChannelBinding(ChannelModel):
    version: str = "5.0"
    binding_id: str
    person_id: str
    assistant_instance_id: str
    provider: str
    provider_account_id: str
    external_subject_hash: str
    assurance: ChannelAssurance = ChannelAssurance.LOW
    status: str = Field(pattern="^(active|revoked|reassigned)$")
    paired_at: datetime
    revoked_at: datetime | None = None


class NormalizedChannelEnvelope(ChannelModel):
    version: str = "5.0"
    event_id: str
    provider: str
    provider_account_id: str
    direction: ChannelDirection
    external_subject: str
    external_thread_id: str
    provider_event_id: str
    occurred_at: datetime
    received_at: datetime = Field(default_factory=utc_now)
    nonce: str = Field(min_length=16, max_length=256)
    text: str = Field(default="", max_length=4096)
    attachment_references: tuple[str, ...] = ()
    assurance: ChannelAssurance = ChannelAssurance.LOW
    capabilities: ChannelCapabilities
    privacy: ProviderPrivacyMetadata
    delivery_state: DeliveryState = DeliveryState.RECEIVED
    bound_person_id: str | None = None
    bound_assistant_instance_id: str | None = None
    purpose: str = "remote-assistant-text"
    sensitive_action_requested: bool = False
    recovery_action_requested: bool = False
    step_up_required: bool = False

    @model_validator(mode="after")
    def enforce_channel_boundary(self) -> "NormalizedChannelEnvelope":
        if self.provider != self.privacy.provider:
            raise ValueError("provider privacy metadata must match envelope provider")
        if self.direction is ChannelDirection.INBOUND and self.delivery_state is not DeliveryState.RECEIVED:
            raise ValueError("inbound envelopes start in received state")
        if self.assurance is ChannelAssurance.LOW and (
            self.sensitive_action_requested or self.recovery_action_requested
        ) and not self.step_up_required:
            raise ValueError("low-assurance sensitive or recovery requests require step-up")
        if self.attachment_references and not self.capabilities.attachments:
            raise ValueError("attachments are not supported by this channel profile")
        return self


class PairingChallenge(ChannelModel):
    version: str = "5.0"
    challenge_id: str
    person_id: str
    provider: str
    provider_account_id: str
    code_hash: str
    expires_at: datetime
    minimum_local_assurance: ChannelAssurance = ChannelAssurance.HIGH
    status: str = Field(default="pending", pattern="^(pending|used|expired|revoked)$")


class SemanticChannelOutcome(ChannelModel):
    version: str = "5.0"
    status: str
    concise_text: str
    simplified_text: str
    privacy_notice: str
    confirmation_required: bool = False
    step_up_required: bool = False
    cancellable: bool = True
    recovery_guidance: str
    actions: tuple[str, ...] = ("cancel", "help")

