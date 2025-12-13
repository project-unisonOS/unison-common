import uuid

from unison_common.contracts.v1 import ActionEnvelope, Intent, Plan, PlannerOutput


def test_planner_output_conforms_to_contract():
    action = ActionEnvelope(
        action_id=str(uuid.uuid4()),
        kind="tool",
        name="tool.echo",
        args={"text": "hello"},
        risk_level="low",
    )
    plan = Plan(intent=Intent(name="echo", goal="Echo input"), actions=[action])
    out = PlannerOutput(plan=plan, rationale="stub")

    dumped = out.model_dump(mode="json")
    assert dumped["schema_version"] == "planner-output.v1"
    assert dumped["plan"]["schema_version"] == "plan.v1"
    assert dumped["plan"]["actions"][0]["schema_version"] == "action-envelope.v1"

