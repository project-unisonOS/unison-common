from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from unison_common import (
    InteractionProfile,
    ProfilePreference,
    SemanticAction,
    SemanticExperience,
    SemanticNode,
    SemanticNodeKind,
    SemanticRelationship,
    SituationalOverride,
)


def test_semantic_experience_preserves_required_meaning_and_actions():
    sem = SemanticExperience(
        experience_id="bill-1", trace_id="trace-1", purpose="explain bill", outcome="Bill increased by $18",
        nodes=[
            SemanticNode(node_id="increase", kind=SemanticNodeKind.VALUE, label="Increase", value={"amount": "18.00", "currency": "USD"}, required=True, exact=True),
            SemanticNode(node_id="cause", kind=SemanticNodeKind.TREND, label="Weekday heating", relationships=[SemanticRelationship(predicate="contributes_to", target_node_id="increase")]),
        ],
        actions=[SemanticAction(action_id="review", label="Review daily comparison", capability="energy.review", consequence="Shows daily usage", reversible=True)],
        privacy={"space_id": "private-alex", "disclosure": "local-only"},
    )
    restored = SemanticExperience.model_validate_json(sem.model_dump_json())
    assert restored.nodes[0].exact is True
    assert restored.actions[0].action_id == "review"
    assert restored.privacy["disclosure"] == "local-only"


def test_semantic_contract_rejects_unknown_and_dangling_content():
    with pytest.raises(ValidationError):
        SemanticExperience(experience_id="x", trace_id="t", purpose="p", outcome="o", unknown=True)
    with pytest.raises(ValidationError, match="unknown nodes"):
        SemanticExperience(
            experience_id="x", trace_id="t", purpose="p", outcome="o",
            nodes=[SemanticNode(node_id="a", kind="entity", label="A", relationships=[{"predicate": "next", "target_node_id": "missing"}])],
        )


def test_interaction_profile_requires_inferred_approval_and_expires_overrides():
    with pytest.raises(ValidationError, match="explicit approval"):
        ProfilePreference(preference_id="p1", key="output", value="conversation", origin="inferred", provenance="observation")
    now = datetime.now(timezone.utc)
    profile = InteractionProfile(
        person_id="alex",
        preferences=[ProfilePreference(preference_id="p1", key="detail", value="normal", origin="explicit", provenance="person")],
        situational_overrides=[SituationalOverride(override_id="o1", key="detail", value="brief", reason="driving", expires_at=now + timedelta(minutes=5))],
    )
    assert profile.effective_preferences(now)["detail"] == "brief"
    assert profile.effective_preferences(now + timedelta(minutes=6))["detail"] == "normal"
