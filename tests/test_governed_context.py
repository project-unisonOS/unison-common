from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from unison_common.governed_context import (
    ContextSpace,
    MemoryGovernance,
    MemoryKind,
    MemoryRecord,
    PersonalCharter,
    SemanticPrivacyState,
    SpaceKind,
)


def test_private_space_requires_assistant_instance():
    with pytest.raises(ValidationError):
        ContextSpace(
            space_id="space-1",
            kind=SpaceKind.PRIVATE,
            owner_person_id="person-1",
            name="Private",
            purpose="personal assistance",
            key_handle="key-1",
        )


def test_inference_requires_uncertainty_and_defaults_private():
    with pytest.raises(ValidationError):
        MemoryRecord(
            record_id="record-1",
            owner_person_id="person-1",
            space_id="space-1",
            kind=MemoryKind.INFERRED_HYPOTHESIS,
            content={"claim": "possibly prefers tea"},
            provenance="assistant inference",
            confidence=1.0,
        )

    policy = MemoryGovernance()
    assert policy.allow_disclosure is False
    assert policy.allow_backup is False
    assert policy.allow_sync is False


def test_ephemeral_policy_can_express_retention():
    policy = MemoryGovernance(retention_until=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert policy.retention_until is not None


def test_charter_blocks_third_party_objectives_by_default():
    charter = PersonalCharter(
        charter_id="charter-1",
        person_id="person-1",
        principles=("Protect my time", "Support meaningful relationships"),
        origin="person",
    )
    assert "third_party_engagement" in charter.prohibited_objectives


def test_semantic_privacy_state_is_explicit():
    state = SemanticPrivacyState(
        active_space_ids=("space-1",),
        space_kinds=(SpaceKind.PRIVATE,),
        purpose="answer",
    )
    assert state.disclosure_allowed is False
    assert state.ambiguous_context is False
