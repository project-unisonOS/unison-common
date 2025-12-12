from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from importlib import resources


@dataclass(frozen=True)
class PromptDefaults:
    base_policy: str
    identity: Dict[str, Any]
    priorities: Dict[str, Any]
    identity_schema: Dict[str, Any]
    priorities_schema: Dict[str, Any]


def _read_text(package: str, name: str) -> str:
    return resources.files(package).joinpath(name).read_text(encoding="utf-8")


def _read_json(package: str, name: str) -> Dict[str, Any]:
    return json.loads(_read_text(package, name))


def load_defaults() -> PromptDefaults:
    pkg = "unison_common.schemas.prompt"
    return PromptDefaults(
        base_policy=_read_text(pkg, "unison_base.md"),
        identity=_read_json(pkg, "identity.default.json"),
        priorities=_read_json(pkg, "priorities.default.json"),
        identity_schema=_read_json(pkg, "identity.schema.json"),
        priorities_schema=_read_json(pkg, "priorities.schema.json"),
    )


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

