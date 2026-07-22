from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from unison_common.channel import (
    ChannelAssurance,
    ChannelCapabilities,
    ChannelDirection,
    NormalizedChannelEnvelope,
    ProviderPrivacyMetadata,
)


def telegram_privacy():
    return ProviderPrivacyMetadata(
        provider="telegram",
        provider_reads_content=True,
        provider_retains_content=True,
        retention_summary="Pending bot updates may be retained for up to 24 hours.",
        provider_receives_identifiers=("telegram_user_id", "chat_id", "bot_id"),
        end_to_end_encrypted_to_node=False,
        monetizes_personal_data=None,
        policy_url="https://telegram.org/privacy",
        reviewed_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
    )


def test_low_assurance_sensitive_request_requires_step_up():
    base = dict(
        event_id="event-1", provider="telegram", provider_account_id="bot-1",
        direction=ChannelDirection.INBOUND, external_subject="1001",
        external_thread_id="1001", provider_event_id="42",
        occurred_at=datetime.now(timezone.utc), nonce="telegram-update-42",
        text="change my recovery key", assurance=ChannelAssurance.LOW,
        capabilities=ChannelCapabilities(), privacy=telegram_privacy(),
        sensitive_action_requested=True,
    )
    with pytest.raises(ValidationError, match="require step-up"):
        NormalizedChannelEnvelope(**base)
    assert NormalizedChannelEnvelope(**base, step_up_required=True).step_up_required


def test_provider_metadata_and_attachment_capability_fail_closed():
    privacy = telegram_privacy().model_copy(update={"provider": "other"})
    with pytest.raises(ValidationError, match="must match"):
        NormalizedChannelEnvelope(
            event_id="event-2", provider="telegram", provider_account_id="bot-1",
            direction="inbound", external_subject="1001", external_thread_id="1001",
            provider_event_id="43", occurred_at=datetime.now(timezone.utc),
            nonce="telegram-update-43", attachment_references=("file-1",),
            capabilities=ChannelCapabilities(), privacy=privacy,
        )

