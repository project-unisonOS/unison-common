from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .errors import PromptUpdateError


@dataclass(frozen=True)
class PatchOp:
    op: str
    path: str
    value: Any | None = None


def _parse_pointer(path: str) -> List[str]:
    if not path.startswith("/"):
        raise PromptUpdateError(f"invalid JSON Pointer path: {path!r}")
    if path == "/":
        return []
    parts = path.lstrip("/").split("/")
    return [p.replace("~1", "/").replace("~0", "~") for p in parts]


def _get_parent(doc: Any, tokens: List[str]) -> Tuple[Any, str]:
    if not tokens:
        raise PromptUpdateError("path points to document root; not supported for this operation")
    parent = doc
    for t in tokens[:-1]:
        if isinstance(parent, dict):
            if t not in parent:
                raise PromptUpdateError(f"path not found: /{'/'.join(tokens)}")
            parent = parent[t]
        else:
            raise PromptUpdateError(f"non-object encountered at {t!r}")
    return parent, tokens[-1]


def apply_patch(doc: Dict[str, Any], ops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Minimal RFC6902 JSON Patch support for object documents.

    Supported ops: add, replace, remove. Arrays are not supported.
    """
    out: Dict[str, Any] = _deepcopy(doc)
    for raw in ops:
        if not isinstance(raw, dict):
            raise PromptUpdateError("patch operations must be objects")
        op = raw.get("op")
        path = raw.get("path")
        if not isinstance(op, str) or not isinstance(path, str):
            raise PromptUpdateError("patch op requires 'op' and 'path' strings")
        tokens = _parse_pointer(path)
        parent, key = _get_parent(out, tokens)
        if not isinstance(parent, dict):
            raise PromptUpdateError("only object parents supported")

        if op in ("add", "replace"):
            if "value" not in raw:
                raise PromptUpdateError(f"{op} requires 'value'")
            parent[key] = raw["value"]
        elif op == "remove":
            if key not in parent:
                raise PromptUpdateError(f"path not found for remove: {path}")
            del parent[key]
        else:
            raise PromptUpdateError(f"unsupported op: {op!r}")
    return out


def _deepcopy(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _deepcopy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deepcopy(v) for v in obj]
    return obj

