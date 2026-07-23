from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from unison_common.workflows import (
    TaskPlan,
    WorkflowKind,
    WorkflowRecord,
    WorkflowStep,
    validate_ranking_signals,
)


def test_task_plan_requires_context_and_declared_external_disclosure():
    with pytest.raises(ValueError):
        TaskPlan(
            person_id="person-a",
            assistant_id="assistant-a",
            kind=WorkflowKind.CALENDAR_COORDINATION,
            purpose="schedule",
            context_space_ids=("private-a",),
            idempotency_key="one",
            steps=(
                WorkflowStep(
                    step_id="calendar",
                    capability="calendar",
                    action="create",
                    provider="fake",
                    external_call=True,
                ),
            ),
        )


def test_workflow_schema_matches_models():
    plan = TaskPlan(
        person_id="person-a",
        assistant_id="assistant-a",
        kind=WorkflowKind.EMAIL_TRIAGE_DRAFT,
        purpose="triage",
        context_space_ids=("private-a",),
        idempotency_key="two",
        steps=(
            WorkflowStep(
                step_id="mail",
                capability="mail",
                action="draft",
                provider="fake",
                external_call=True,
                disclosed_fields=("recipient", "subject", "body"),
            ),
        ),
    )
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "assistant-workflow.v1.schema.json").read_text()
    )
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        plan.model_dump(mode="json")
    )


def test_canonical_and_packaged_workflow_schemas_match():
    root = Path(__file__).parents[1]
    canonical = json.loads((root / "schemas" / "assistant-workflow.v1.schema.json").read_text())
    packaged = json.loads(
        (root / "src" / "unison_common" / "schemas" / "assistant-workflow.v1.schema.json").read_text()
    )
    assert packaged == canonical


def test_commercial_and_engagement_ranking_signals_are_rejected():
    validate_ranking_signals({"time_returned": 1.0, "reliability": 0.9})
    for signal in ("advertising", "engagement", "sponsored", "provider_lock_in"):
        with pytest.raises(ValueError):
            validate_ranking_signals({signal: 1.0})


def test_record_replay_contract_rejects_personal_data():
    with pytest.raises(ValueError):
        WorkflowRecord(
            fixture_id="bad",
            provider_kind="mail",
            request={},
            response={},
            contains_personal_data=True,
        )
