import pytest

from unison_common.trust_governance import CapabilityGrant, DecisionOutcome, DisclosureDecision, TrustRequest


def test_unknown_authority_property_fails_closed():
    with pytest.raises(ValueError, match="incomplete authority"):
        TrustRequest.from_mapping({"principal_id": "p1"})


def test_decision_is_owner_readable_and_versioned():
    decision = DisclosureDecision(DecisionOutcome.DENY, "unknown-purpose", "I did not share this because the purpose is unknown.")
    assert decision.to_dict()["contract_version"] == "unison.trust.v1"
    assert decision.to_dict()["consequence"] == "No external action was taken."


def test_incomplete_grant_is_disabled():
    with pytest.raises(ValueError, match="incomplete capability grant"):
        CapabilityGrant.from_mapping({"grant_id": "legacy"})
