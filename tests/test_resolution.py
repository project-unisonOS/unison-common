import pytest
from datetime import timedelta
from unison_common.resolution import *
from unison_common.governed_context import utc_now

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

def test_candidate_requires_repeated_distinct_evidence():
    values = dict(candidate_id="c2", scope="person-local", candidate_kind="skill",
        structural_fingerprint="b" * 64, invariant_steps=("retrieve",),
        parameter_schema={}, authority_requirements=("person",),
        privacy_requirements=("local",), modality_requirements=("conversation",),
        failure_modes=("unavailable",), expected_benefit="repeatability")
    with pytest.raises(ValueError, match="two distinct"):
        DeterminizationCandidate(**values, evidence_attempt_ids=("a1",))
    with pytest.raises(ValueError, match="two distinct"):
        DeterminizationCandidate(**values, evidence_attempt_ids=("a1", "a1"))

def test_pilot_enrollment_keeps_telemetry_under_active_consent():
    values = dict(enrollment_id="enroll-1", owner_person_id="alice",
        consent_grant_id="grant-1", scopes=("content-free-outcomes",), retention_days=30)
    assert PilotEnrollment(**values, telemetry_enabled=True).status == "active"
    with pytest.raises(ValueError, match="active consent"):
        PilotEnrollment(**values, status="deleted", telemetry_enabled=True)
    with pytest.raises(ValueError, match="timestamp"):
        PilotEnrollment(**values, status="revoked")

def test_pilot_boundary_incident_forces_pause_or_stop():
    values = dict(review_id="review-1", owner_person_id="alice", reviewer_id="reviewer",
        attempts=3, candidate_suggestions=1, boundary_incidents=1, reason="boundary review")
    with pytest.raises(ValueError, match="pause or stop"):
        PilotReviewDecision(**values, decision="continue")
    assert PilotReviewDecision(**values, decision="pause").decision == "pause"

def test_headless_session_is_modality_native_and_expiring():
    now = utc_now()
    values = dict(session_id="session-1", owner_person_id="alice", client_id="iphone",
        transport="lan", input_modalities=("conversation",),
        output_modalities=("braille",), reconnect_token_digest="sha256:" + "c" * 64,
        updated_at=now, expires_at=now + timedelta(minutes=15))
    assert HeadlessInteractionSession(**values).output_modalities == ("braille",)
    with pytest.raises(ValueError, match="input and output"):
        HeadlessInteractionSession(**{**values, "input_modalities": ()})
    with pytest.raises(ValueError, match="expire in the future"):
        HeadlessInteractionSession(**{**values, "expires_at": now})

def test_candidate_canary_is_synthetic_and_rollback_is_receipted():
    values = dict(canary_id="canary-1", candidate_id="candidate-1", owner_person_id="alice",
        package_digest="d" * 64, authority_ids=("authority-1",), prior_route_id="route-1")
    with pytest.raises(ValueError, match="must be synthetic"):
        CandidateCanaryRecord(**values, synthetic=False, outcome="passed")
    with pytest.raises(ValueError, match="requires a receipt"):
        CandidateCanaryRecord(**values, synthetic=True, outcome="rolled-back")
    assert CandidateCanaryRecord(**values, synthetic=True, outcome="passed").outcome == "passed"
