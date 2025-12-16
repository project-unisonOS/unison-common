from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from unison_common.phase1_trace import sha256_text

from .engine import PromptEngine


@dataclass(frozen=True)
class PromptInjection:
    system_prompt: str
    config_path: str
    config_hash: str


def compile_injected_system_prompt(
    *,
    person_id: Optional[str],
    session_id: str,
    intent: str,
    session_context: Optional[Dict[str, Any]] = None,
) -> PromptInjection:
    """
    Compile a user-editable system prompt and return correlation metadata.

    Callers must not log prompt content; use `config_path` and `config_hash`.
    """

    merged = dict(session_context or {})
    merged.setdefault("intent", intent)
    merged.setdefault("session_id", session_id)
    merged.setdefault("person_id", person_id or "anonymous")
    merged.setdefault("timestamp", time.time())

    try:
        engine = PromptEngine.for_person(person_id=person_id)
        compiled = engine.compile(session_context=merged)
        system_prompt = compiled.markdown
        config_path = str(engine.layout.active_prompt_path)
        config_hash = sha256_text(system_prompt)
        return PromptInjection(system_prompt=system_prompt, config_path=config_path, config_hash=config_hash)
    except Exception:
        system_prompt = "You are UnisonOS."
        return PromptInjection(system_prompt=system_prompt, config_path="unavailable", config_hash=sha256_text(system_prompt))


__all__ = ["PromptInjection", "compile_injected_system_prompt"]

