import pytest
from pydantic import ValidationError

from unison_common.contracts.v1 import (
    Connection,
    DerivedRecord,
    DomainLink,
    DomainRecord,
    LifeOperationDomain,
    ProvenanceRegion,
    SourceObject,
    authorize_life_operation,
)


def test_source_is_bound_to_person_space_and_region_provenance_is_explicit():
    source = SourceObject(
        source_id="src-1", person_id="person-a", space_id="private-a",
        import_session_id="import-1", media_type="application/pdf", filename="statement.pdf",
        checksum_sha256="a" * 64, size_bytes=24,
    )
    region = ProvenanceRegion(page=1, bounding_box=(0.1, 0.2, 0.8, 0.9))
    assert source.visibility == "private"
    assert region.page == 1


def test_derived_record_requires_source_fields():
    with pytest.raises(ValidationError):
        DerivedRecord(
            record_id="r", person_id="p", space_id="s", kind="balance",
            value=5, source_field_ids=[], confidence=0.8,
        )


def test_connection_rejects_write_authority():
    with pytest.raises(ValidationError):
        Connection(
            connection_id="c", person_id="p", provider_id="fixture",
            profile="oauth-pkce", scopes=["records.read"], read_only=False,
        )


def test_health_and_finance_prohibited_actions_fail_closed():
    assert not authorize_life_operation(LifeOperationDomain.HEALTH, "diagnose")
    assert not authorize_life_operation(LifeOperationDomain.FINANCE, "transfer_funds")
    assert authorize_life_operation(LifeOperationDomain.HEALTH, "summarize_record")


def test_inferred_condition_cannot_become_confirmed_diagnosis():
    with pytest.raises(ValidationError):
        DomainRecord(record_id="r", person_id="p", space_id="health:p", domain="health",
                     record_type="condition", facts={"clinical_status": "confirmed"}, source_ids=["s"],
                     evidence_status="inferred", confidence=0.5)


def test_cross_domain_link_requires_explicit_person_approval():
    with pytest.raises(ValidationError):
        DomainLink(link_id="l", person_id="p", left_record_id="a", right_record_id="b",
                   purpose="claim preparation", allowed_fields=["date"], approved_by_person=False)
