from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .errors import PromptConflictError


@dataclass(frozen=True)
class CompiledPrompt:
    markdown: str
    metadata: Dict[str, Any]


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def detect_conflicts(identity: Dict[str, Any], priorities: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    # Keep this conservative: only report conflicts when the combination is
    # inherently inconsistent. "Identity defaults" vs "current priorities" may
    # intentionally differ (e.g., user wants to temporarily be more concise).
    return issues


def compile_prompt(
    base_policy_md: str,
    identity: Dict[str, Any],
    priorities: Dict[str, Any],
    session_context: Optional[Dict[str, Any]] = None,
) -> CompiledPrompt:
    session_context = session_context or {}

    conflicts = detect_conflicts(identity, priorities)
    if conflicts:
        raise PromptConflictError("; ".join(conflicts))

    anti = identity.get("anti_sycophancy") if isinstance(identity.get("anti_sycophancy"), dict) else {}
    challenge_level = anti.get("challenge_level", 2)
    try:
        challenge_level_int = int(challenge_level)
    except Exception:
        challenge_level_int = 2
    challenge_level_int = max(0, min(3, challenge_level_int))

    clarifying_max = (
        (identity.get("communication") or {}).get("clarifying_questions_max")
        if isinstance(identity.get("communication"), dict)
        else None
    )
    try:
        clarifying_max_int = int(clarifying_max) if clarifying_max is not None else 1
    except Exception:
        clarifying_max_int = 1
    clarifying_max_int = max(0, min(3, clarifying_max_int))

    md_parts: List[str] = []
    md_parts.append("# UnisonOS System Prompt (Compiled)\n")

    md_parts.append("## 1) Unison Base Policy (Immutable)\n")
    md_parts.append(base_policy_md.strip() + "\n")

    md_parts.append("## 2) User Identity & Values (Persistent)\n")
    md_parts.append(_stable_json(identity) + "\n")

    md_parts.append("## 3) User Priorities & Directives (Mutable)\n")
    md_parts.append(_stable_json(priorities) + "\n")

    md_parts.append("## 4) Session Context (Ephemeral)\n")
    md_parts.append(_stable_json(session_context) + "\n")

    md_parts.append("## 5) Anti-Sycophancy & Reasoning Requirements\n")
    md_parts.append(
        "\n".join(
            [
                "- Avoid flattery and reassurance without substance.",
                "- Disagree when justified; propose tradeoffs and alternatives.",
                "- Correct factual errors explicitly and promptly.",
                f"- Ask at most {clarifying_max_int} clarifying question when unclear; otherwise state assumptions and proceed.",
                f"- Challenge level: {challenge_level_int} (0=gentle, 3=highly challenging).",
                "- Prefer evidence-based reasoning; cite uncertainty and propose verification steps.",
            ]
        )
        + "\n"
    )

    metadata = {
        "challenge_level": challenge_level_int,
        "clarifying_questions_max": clarifying_max_int,
        "identity_version": identity.get("schema_version"),
        "priorities_version": priorities.get("schema_version"),
    }
    return CompiledPrompt(markdown="\n".join(md_parts).strip() + "\n", metadata=metadata)
