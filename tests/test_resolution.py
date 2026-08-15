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
