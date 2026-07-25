import pytest
from pydantic import ValidationError

from unison_common import ModelManifest, ModelSemanticProposal, ModelTaskRequirement


BASE = {
    "model_id": "local-small", "version": "1", "artifact_digest": "sha256:" + "a" * 64,
    "source": "local", "provenance": ["publisher"], "runtime": "ollama", "runtime_version": "1",
    "tasks": ["interpretation"], "modalities": ["text"], "languages": ["en"],
    "context_tokens": 4096, "structured_output": True,
    "hardware": {"architectures": ["x86_64"], "min_ram_mb": 1024},
    "execution_location": "device", "provider": "ollama", "license": "Apache-2.0",
    "license_approved": True, "privacy": {"retention": "none"},
    "measured_quality": {"interpretation": .9}, "measured_latency_ms": {"interpretation": 100},
    "approved_risk": ["low"], "supported": True,
}


def test_manifest_and_task_taxonomy_are_strict():
    assert ModelManifest.model_validate(BASE).tasks[0].value == "interpretation"
    with pytest.raises(ValidationError):
        ModelTaskRequirement(task="self-nominated-task")


def test_model_proposal_requires_provenance_and_is_always_untrusted():
    with pytest.raises(ValidationError):
        ModelSemanticProposal(operation_id="o", model_id="m", model_version="1", source_state_versions={}, provenance=[])
    with pytest.raises(ValidationError):
        ModelSemanticProposal(operation_id="o", model_id="m", model_version="1", source_state_versions={}, provenance=[{"source_id": "s", "source_type": "document"}], untrusted=False)
