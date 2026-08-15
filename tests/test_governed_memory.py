import pytest
from pydantic import ValidationError

from unison_common.governed_context import MemoryGovernance
from unison_common.governed_memory import (
    DataDomainDefinition, MemoryRetrievalRequest, TaxonomyDecision,
    TaxonomyMigrationCommand, TaxonomyProposal, TaxonomySecurityReview,
    TaxonomyUsageSignal,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import timedelta
from unison_common.governed_context import utc_now
from unison_common.governed_memory import SignedTaxonomyPolicyIssuance, TaxonomySecurityReview


def test_policy_issuance_is_signed_person_bound_and_expiring():
    key = Ed25519PrivateKey.generate()
    review = TaxonomySecurityReview(review_id="r1", proposal_id="p1", decision="approve",
        policy_version="2026.08", separate_key_boundary=True, retention_reviewed=True,
        sharing_reviewed=True, disclosure_reviewed=True, rationale="isolated")
    issuance = SignedTaxonomyPolicyIssuance(issuance_id="i1", owner_person_id="alice",
        proposal_id="p1", review=review, expires_at=utc_now() + timedelta(minutes=5),
        key_id="policy-1").sign(key)
    assert issuance.verify(key.public_key(), owner_person_id="alice", proposal_id="p1") == review
    with pytest.raises(ValueError, match="bound"):
        issuance.verify(key.public_key(), owner_person_id="bob", proposal_id="p1")


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


def test_security_review_and_migration_both_fail_closed():
    with pytest.raises(ValidationError):
        TaxonomySecurityReview(
            review_id="review-1", proposal_id="proposal-1", decision="approve",
            policy_version="policy-1", separate_key_boundary=True,
            retention_reviewed=True, sharing_reviewed=False, disclosure_reviewed=True,
            rationale="incomplete review",
        )
    with pytest.raises(ValidationError):
        TaxonomyMigrationCommand(
            preview_id="preview-1", confirmation_digest="digest", explicit_confirmation=False,
        )
