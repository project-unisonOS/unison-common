import pytest
from pydantic import ValidationError

from unison_common import GoldenSemanticJourney, ModelCompatibilityMatrix, ModelHardwareQualification


def test_real_comparison_data_requires_explicit_approval():
    with pytest.raises(ValidationError, match="approval"):
        GoldenSemanticJourney(journey_id="real", synthetic=False, required_fact_ids=[], required_node_ids=[], action_ids=[], provenance_source_ids=[])


def qualification(**changes):
    data = {
        "model_ref": "m@1", "runtime_ref": "r@1", "hardware_profile": "developer",
        "evidence_kind": "synthetic", "processor": "fixture", "architecture": "x86_64",
        "ram_mb": 4096, "storage_mb": 10000, "latency_ms": {"conversation": 100},
        "concurrent_workloads": 2, "offline_passed": True, "update_passed": True,
        "rollback_passed": True, "semantic_quality_passed": True, "safe_fallback_passed": True,
    }
    data.update(changes)
    return ModelHardwareQualification.model_validate(data)


def test_synthetic_evidence_cannot_claim_support():
    with pytest.raises(ValidationError, match="physical-device"):
        qualification(supported=True)


def test_compatibility_supported_list_is_derived_from_evidence():
    record = qualification()
    with pytest.raises(ValidationError, match="derive"):
        ModelCompatibilityMatrix(records=[record], supported_model_refs=["m@1"], truthful_notice="Synthetic only")
    matrix = ModelCompatibilityMatrix(records=[record], supported_model_refs=[], truthful_notice="Synthetic only")
    assert matrix.supported_model_refs == []
