from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field

from .actions import ActionEnvelope


class IntentSession(BaseModel):
    schema_version: Literal["intent-session.v1"] = "intent-session.v1"
    session_id: str = Field(..., description="Interaction/session identifier.")
    trace_id: str = Field(..., description="Trace id for the current interaction.")
    person_id: Optional[str] = None
    created_at_unix_ms: int = Field(..., description="Unix time (ms) when created.")


class Intent(BaseModel):
    schema_version: Literal["intent.v1"] = "intent.v1"
    name: str = Field(..., description="Canonical intent name (e.g., 'echo', 'workflow.design').")
    goal: Optional[str] = Field(default=None, description="Human-readable goal statement.")
    constraints: Dict[str, Any] = Field(default_factory=dict, description="Planner constraints.")
    slots: Dict[str, Any] = Field(default_factory=dict, description="Structured extracted parameters.")


class Plan(BaseModel):
    schema_version: Literal["plan.v1"] = "plan.v1"
    intent: Intent
    actions: list[ActionEnvelope] = Field(default_factory=list)


class RouterOutput(BaseModel):
    schema_version: Literal["router-output.v1"] = "router-output.v1"
    classified_intent: Optional[str] = Field(default=None, description="Coarse intent classification label.")
    planner_hint: Dict[str, Any] = Field(default_factory=dict, description="Model/latency budget hints.")


class PlannerOutput(BaseModel):
    schema_version: Literal["planner-output.v1"] = "planner-output.v1"
    plan: Plan
    rationale: Optional[str] = Field(default=None, description="Optional explanation for debugging.")

