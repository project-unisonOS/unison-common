import pytest
from pydantic import ValidationError

from unison_common import ModelManifest, ModelSemanticProposal, ModelTaskRequirement, SignedModelManifest


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


def test_signed_manifest_accepts_ed25519_without_weakening_legacy_hmac_shape():
    manifest = ModelManifest.model_validate(BASE)
    assert SignedModelManifest(
        manifest=manifest,
        key_id="release-2026",
        algorithm="ed25519",
        signature="a" * 128,
    ).algorithm == "ed25519"
    with pytest.raises(ValidationError):
        SignedModelManifest(
            manifest=manifest,
            key_id="release-2026",
            algorithm="ed25519",
            signature="a" * 64,
        )
