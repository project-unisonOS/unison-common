import pytest
from pydantic import ValidationError

from unison_common.governed_context import MemoryGovernance
from unison_common.governed_memory import DataDomainDefinition, MemoryRetrievalRequest


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
