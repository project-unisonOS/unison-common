import pytest
from unison_common.resolution import *

def test_resolution_attempt_is_bounded_and_content_free_operationally():
    route = ResolutionRoute(route_id="r1", kind="known-deterministic", state="selected")
    attempt = ResolutionAttempt(attempt_id="a1", owner_person_id="alice", assistant_instance_id="ua",
        purpose="repair guidance", risk="medium", requested_result_class="guidance",
        authorized_space_ids=("private",), authorized_domain_ids=("household",),
        budget=ResolutionBudget(time_seconds=300, model_calls=2, tool_calls=10), routes=(route,),
        structural_fingerprint="a" * 64)
    assert attempt.budget.external_disclosures == 0

def test_candidate_cannot_self_promote_or_execute():
    values = dict(candidate_id="c1", scope="person-local", candidate_kind="skill",
        structural_fingerprint="b" * 64, evidence_attempt_ids=("a1", "a2"),
        invariant_steps=("retrieve", "compose"), parameter_schema={}, authority_requirements=("person",),
        privacy_requirements=("local",), modality_requirements=("conversation", "braille"),
        failure_modes=("source unavailable",), expected_benefit="lower latency")
    with pytest.raises(ValueError, match="signed review"):
        DeterminizationCandidate(**values, executable=True)
    with pytest.raises(ValueError, match="explicitly executable"):
        DeterminizationCandidate(**values, state="promoted")

def test_pilot_signal_requires_opt_in_and_consistent_candidate_rating():
    values = dict(signal_id="signal-1", attempt_id="attempt-1",
        participant_id="participant-1", usefulness="useful", outcome="complete",
        elapsed_seconds=10, interaction_turns=1, clarification_count=0,
        correction_count=0)
    with pytest.raises(ValueError, match="explicit opt-in"):
        ResolutionPilotSignal(**values, opted_in=False)
    with pytest.raises(ValueError, match="candidate relevance"):
        ResolutionPilotSignal(**values, opted_in=True, candidate_relevant=True)

def test_modality_adapter_manifest_is_directional_and_sem_bound():
    values = dict(adapter_id="sign-reference", modality="sign",
        sem_versions=("sem.v1",), expression_versions=("sign-expression.v1",),
        capability_ids=("sign.compose",), required_permissions=("camera:session",),
        fallback_modalities=("conversation",), package_digest="sha256:" + "a" * 64,
        signer_id="unison-modality-review")
    manifest = ModalityAdapterManifest(**values, input_supported=True, output_supported=True)
    assert manifest.modality == "sign"
    with pytest.raises(ValueError, match="input or output"):
        ModalityAdapterManifest(**values, input_supported=False, output_supported=False)
