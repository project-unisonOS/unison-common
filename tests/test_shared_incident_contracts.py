from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from unison_common.contracts.v1 import (
    EvidenceRecord,
    HouseholdIncident,
    IncidentAssignment,
    IncidentTimelineEvent,
    KnowledgeProcedure,
    OfflineKnowledgePack,
    ResolutionAttempt,
    ResolutionBudget,
    SensorObservation,
    StructuralFingerprint,
)


NOW = datetime(2026, 8, 14, tzinfo=timezone.utc)


def observation(**changes):
    value = {
        "observation_id": "obs-1",
        "sensor_id": "sensor-1",
        "source_sequence": 1,
        "observed_at": NOW,
        "received_at": NOW + timedelta(seconds=1),
        "state": "probable-leak",
        "value": True,
        "unit": "boolean",
        "confidence": 0.9,
        "fresh_until": NOW + timedelta(minutes=5),
        "integrity_state": "verified",
        "device_health": "healthy",
    }
    value.update(changes)
    return SensorObservation(**value)


def event(event_id, state, minute, *, rule=None, sources=None):
    return IncidentTimelineEvent(
        event_id=event_id,
        state=state,
        occurred_at=NOW + timedelta(minutes=minute),
        actor_id="unison",
        reason=f"enter {state}",
        source_ids=sources or ["obs-1"],
        deterministic_rule=rule,
    )


def fingerprint():
    return StructuralFingerprint(
        contract_types=["household-incident.v1"],
        tool_kinds=["equipment.lookup"],
        route_kinds=["deterministic", "local-inference"],
        risk_class="medium",
        outcome_shape="incident-guidance",
    )


def test_sensor_observation_enforces_time_integrity_and_confidence():
    assert observation().source_sequence == 1
    with pytest.raises(ValidationError, match="predate"):
        observation(received_at=NOW - timedelta(seconds=1))
    with pytest.raises(ValidationError, match="stale"):
        observation(fresh_until=NOW)
    with pytest.raises(ValidationError):
        observation(confidence=1.1)


def test_evidence_requires_sources_conflicts_and_uncertainty():
    confirmed = EvidenceRecord(evidence_id="e1", claim="sensor is wet", state="confirmed", source_ids=["obs-1"])
    assert confirmed.state.value == "confirmed"
    with pytest.raises(ValidationError, match="at least one source"):
        EvidenceRecord(evidence_id="e2", claim="sensor is wet", state="stale", uncertainty="expired")
    with pytest.raises(ValidationError, match="conflict references"):
        EvidenceRecord(evidence_id="e3", claim="sensor is wet", state="conflicting", source_ids=["a"], uncertainty="two readings")
    missing = EvidenceRecord(evidence_id="e4", claim="valve state", state="missing", uncertainty="not observed")
    assert missing.source_ids == []


def test_offline_pack_requires_real_digest_stop_rules_and_review_window():
    pack = OfflineKnowledgePack(
        pack_id="water-us-wa",
        version="1",
        region="US-WA",
        language="en-US",
        authority="reviewed source",
        source_ids=["source-1"],
        effective_at=NOW,
        review_by=NOW + timedelta(days=30),
        hazards=["electrical-contact"],
        stop_rules=["stop-if-electrical-contact"],
        procedures=[KnowledgeProcedure(procedure_id="isolate", purpose="safe isolation", steps=["Stop if unsafe."])],
        digest="sha256:" + "a" * 64,
        signature_key_id="key-1",
        signature="fixture-signature",
    )
    assert pack.stop_rules
    with pytest.raises(ValidationError):
        pack.model_copy(update={"digest": "fixture"}).model_validate(pack.model_copy(update={"digest": "fixture"}).model_dump())
    with pytest.raises(ValidationError, match="review date"):
        OfflineKnowledgePack(**{**pack.model_dump(), "review_by": NOW})


def test_assignment_is_workflow_bound_and_never_physically_actuates():
    assignment = IncidentAssignment(
        assignment_id="a1",
        incident_id="i1",
        workflow_step_id="step-1",
        assignee_person_id="person-jordan",
        action="record simulated manual shutoff",
        created_at=NOW,
        source_ids=["procedure-1"],
    )
    assert assignment.physical_actuation is False
    with pytest.raises(ValidationError):
        IncidentAssignment(**{**assignment.model_dump(), "physical_actuation": True})
    with pytest.raises(ValidationError, match="acknowledgement time"):
        IncidentAssignment(**{**assignment.model_dump(), "state": "completed", "completed_at": NOW})


def test_incident_accepts_legal_timeline_and_rejects_model_shortcuts():
    timeline = [
        event("t1", "observed", 0),
        event("t2", "assessing", 1),
        event("t3", "action-needed", 2),
        event("t4", "isolating", 3),
        event("t5", "monitoring", 4),
        event("t6", "recovered", 10),
    ]
    incident = HouseholdIncident(
        incident_id="i1",
        space_id="shared:incident-1",
        kind="water-leak",
        state="recovered",
        severity="prompt",
        source_ids=["obs-1"],
        facts=[EvidenceRecord(evidence_id="e1", claim="sensor is wet", state="confirmed", source_ids=["obs-1"])],
        timeline=timeline,
    )
    assert incident.state.value == "recovered"
    with pytest.raises(ValidationError, match="illegal incident transition"):
        HouseholdIncident(**{**incident.model_dump(), "timeline": [event("t1", "observed", 0), event("t2", "recovered", 1)]})
    with pytest.raises(ValidationError):
        HouseholdIncident(**{**incident.model_dump(), "physical_actuation_allowed": True})


def test_escalation_requires_deterministic_rule():
    base = {
        "incident_id": "i1",
        "space_id": "shared:incident-1",
        "kind": "water-leak",
        "state": "escalated",
        "severity": "emergency",
        "source_ids": ["obs-1"],
    }
    with pytest.raises(ValidationError, match="deterministic rule"):
        HouseholdIncident(**base, timeline=[event("t1", "observed", 0), event("t2", "escalated", 1, sources=["obs-1"])])
    incident = HouseholdIncident(
        **base,
        timeline=[event("t1", "observed", 0), event("t2", "escalated", 1, rule="water-contacts-energized-equipment")],
    )
    assert incident.timeline[-1].deterministic_rule


def test_resolution_attempt_supports_novel_partial_progress_without_external_disclosure():
    attempt = ResolutionAttempt(
        attempt_id="attempt-1",
        outcome_id="outcome-1",
        person_id="person-alex",
        assistant_instance_id="assistant-alex",
        purpose="answer a novel incident question",
        risk="medium",
        authorized_space_ids=["shared:incident-1"],
        routes_considered=["deterministic", "local-inference"],
        state="partial",
        partial_artifact_ids=["artifact-safe-checks"],
        recovery="resume when a fresh sensor observation is available",
        budget=ResolutionBudget(max_seconds=30, max_model_calls=1, max_external_calls=0, max_cost=0, max_disclosed_fields=0),
        structural_fingerprint=fingerprint(),
    )
    assert attempt.state == "partial"
    assert attempt.structural_fingerprint.contains_person_content is False
    with pytest.raises(ValidationError):
        StructuralFingerprint(**{**fingerprint().model_dump(), "contains_person_content": True})
    with pytest.raises(ValidationError, match="cannot budget external disclosure"):
        ResolutionAttempt(**{**attempt.model_dump(), "budget": {**attempt.budget.model_dump(), "max_disclosed_fields": 1}})


def test_strict_contracts_reject_unknown_authority_fields():
    with pytest.raises(ValidationError):
        observation(model_may_mark_safe=True)
