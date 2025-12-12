from __future__ import annotations

import json
from pathlib import Path

import pytest

from unison_common.prompt.engine import PromptEngine
from unison_common.prompt.errors import PromptUpdateError


def test_prompt_engine_initializes_and_compiles(tmp_path: Path) -> None:
    engine = PromptEngine.for_person(person_id="u1", root=str(tmp_path / "{person_id}"))
    compiled = engine.compile(session_context={"task": "hello"})
    assert "Unison Base Policy" in compiled.markdown
    assert '"task":"hello"' in compiled.markdown
    assert engine.layout.active_prompt_path.exists()


def test_prompt_engine_propose_and_apply_low_risk_update(tmp_path: Path) -> None:
    engine = PromptEngine.for_person(person_id="u1", root=str(tmp_path / "{person_id}"))
    engine.compile(session_context={"task": "x"})
    proposal = engine.propose_update(
        target="priorities",
        ops=[{"op": "replace", "path": "/verbosity", "value": "concise"}],
        rationale="Be more concise.",
        risk="low",
    )
    res = engine.apply_update(proposal, approved=False)
    assert res["ok"] is True
    data = json.loads(engine.layout.priorities_path.read_text(encoding="utf-8"))
    assert data["verbosity"] == "concise"


def test_prompt_engine_blocks_unapproved_high_risk_update(tmp_path: Path) -> None:
    engine = PromptEngine.for_person(person_id="u1", root=str(tmp_path / "{person_id}"))
    proposal = engine.propose_update(
        target="identity",
        ops=[{"op": "replace", "path": "/privacy/stance", "value": "balanced"}],
        rationale="Relax privacy stance.",
        risk="high",
    )
    with pytest.raises(PromptUpdateError):
        engine.apply_update(proposal, approved=False)

