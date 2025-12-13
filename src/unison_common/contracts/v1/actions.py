from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    schema_version: Literal["policy-decision.v1"] = "policy-decision.v1"
    allowed: bool = Field(..., description="Whether the action is permitted.")
    reason: Optional[str] = Field(default=None, description="Human-readable rationale for allow/deny.")
    require_confirmation: bool = Field(default=False, description="Whether a confirmation UX is required.")
    required_scopes: list[str] = Field(default_factory=list, description="Scopes required to allow this action.")


class ActionEnvelope(BaseModel):
    """
    Orchestrator action proposal/execution request.

    This is distinct from the existing actuation action-envelope; it can represent both
    deterministic local tools and VDI tasks, and can later be compiled into actuation envelopes.
    """

    schema_version: Literal["action-envelope.v1"] = "action-envelope.v1"
    action_id: str = Field(..., description="Unique action identifier (UUID recommended).")
    kind: Literal["tool", "vdi", "io", "storage", "context"] = Field(
        ..., description="High-level execution category."
    )
    name: str = Field(..., description="Tool/task name (e.g., 'tool.echo', 'vdi.navigate').")
    args: Dict[str, Any] = Field(default_factory=dict, description="JSON arguments for the action.")
    idempotency_key: Optional[str] = Field(
        default=None, description="Optional idempotency key to dedupe execution."
    )
    risk_level: Literal["low", "medium", "high"] = Field(default="low")
    policy_context: Dict[str, Any] = Field(
        default_factory=dict, description="Policy-relevant metadata (scopes, consent ref, justification)."
    )


class ActionResult(BaseModel):
    schema_version: Literal["action-result.v1"] = "action-result.v1"
    action_id: str
    ok: bool
    result: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

