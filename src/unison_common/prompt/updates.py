from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from .errors import PromptUpdateError
from .json_patch import apply_patch
from .schema import validate_doc

Risk = Literal["low", "medium", "high"]
Target = Literal["identity", "priorities"]


def classify_risk(ops: List[Dict[str, Any]], target: Target) -> Risk:
    # Conservative, explicit mapping: changes that touch privacy/tool boundaries are high.
    for op in ops:
        path = op.get("path", "")
        if not isinstance(path, str):
            continue
        if path.startswith("/privacy") or path.startswith("/tool_boundaries"):
            return "high"
        if path.startswith("/anti_sycophancy") or path.startswith("/communication"):
            return "medium"
        if path.startswith("/current_goals") or path.startswith("/focus_areas") or path.startswith("/verbosity"):
            return "low"
    return "medium" if target == "identity" else "low"


def apply_update(
    *,
    doc: Dict[str, Any],
    schema: Dict[str, Any],
    ops: List[Dict[str, Any]],
) -> Dict[str, Any]:
    next_doc = apply_patch(doc, ops)
    result = validate_doc(next_doc, schema)
    if not result.ok:
        raise PromptUpdateError("schema validation failed: " + "; ".join(result.errors))
    return next_doc


@dataclass(frozen=True)
class PromptUpdateProposal:
    proposal_id: str
    target: Target
    ops: List[Dict[str, Any]]
    rationale: str
    model_risk: Risk
    engine_risk: Risk
    created_at: float


def new_proposal(
    proposal_id: str,
    *,
    target: Target,
    ops: List[Dict[str, Any]],
    rationale: str,
    model_risk: Risk,
) -> PromptUpdateProposal:
    engine_risk = classify_risk(ops, target)
    return PromptUpdateProposal(
        proposal_id=proposal_id,
        target=target,
        ops=ops,
        rationale=rationale,
        model_risk=model_risk,
        engine_risk=engine_risk,
        created_at=time.time(),
    )

