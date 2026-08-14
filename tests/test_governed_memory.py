import pytest
from pydantic import ValidationError

from unison_common.governed_context import MemoryGovernance
from unison_common.governed_memory import (
    DataDomainDefinition, MemoryRetrievalRequest, TaxonomyDecision,
    TaxonomyProposal, TaxonomyUsageSignal,
)


def test_domains_are_open_vocabulary_and_can_originate_from_usage():
    legal = DataDomainDefinition(
        domain_id="legal", display_name="Legal", description="Legal matters and records",
        origin="usage", status="proposed",
    )
    assert legal.domain_id == "legal"
    assert legal.origin == "usage"


def test_governance_requires_key_domain_to_be_in_record_domains():
    policy = MemoryGovernance(data_domains=("health",), key_domain="health")
    assert policy.data_domains == ("health",)
    with pytest.raises(ValidationError):
        MemoryGovernance(data_domains=("health",), key_domain="financial")


def test_retrieval_requires_explicit_spaces_domains_and_purpose():
    request = MemoryRetrievalRequest(
        space_ids=("private-alice-health",), data_domains=("health",),
        purpose="prepare visit", token_budget=1024,
    )
    assert request.allow_remote is False
    with pytest.raises(ValidationError):
        MemoryRetrievalRequest(space_ids=(), data_domains=("health",), purpose="answer")


def test_taxonomy_signal_contract_cannot_carry_raw_content():
    with pytest.raises(ValidationError):
        TaxonomyUsageSignal(
            signal_id="signal-1", candidate_domain_id="legal",
            signal_type="repeated-request", suggested_level="security-domain",
            raw_content="private conversation",
        )


def test_taxonomy_proposal_is_advisory_and_activation_is_explicit():
    candidate = DataDomainDefinition(
        domain_id="legal", display_name="Legal", description="Legal matters", origin="usage",
    )
    proposal = TaxonomyProposal(
        proposal_id="proposal-1", candidate=candidate, proposed_level="security-domain",
        evidence_count=3, distinct_days=2, evidence_types=("repeated-request",),
        rationale="Repeated usage", benefits=("separate policy boundary",),
    )
    assert proposal.status == "pending"
    with pytest.raises(ValidationError):
        TaxonomyDecision(
            decision_id="decision-1", proposal_id=proposal.proposal_id, decision="approve",
        )
