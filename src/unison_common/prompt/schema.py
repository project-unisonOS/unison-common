from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

try:
    import jsonschema
    from jsonschema import Draft7Validator

    _JSONSCHEMA_AVAILABLE = True
except Exception:  # pragma: no cover
    Draft7Validator = None  # type: ignore
    _JSONSCHEMA_AVAILABLE = False

from .errors import PromptSchemaError


@dataclass(frozen=True)
class SchemaValidationResult:
    ok: bool
    errors: List[str]


def validate_doc(doc: Dict[str, Any], schema: Dict[str, Any]) -> SchemaValidationResult:
    if not _JSONSCHEMA_AVAILABLE:
        raise PromptSchemaError("jsonschema package is required for prompt schema validation")
    try:
        Draft7Validator.check_schema(schema)  # type: ignore[union-attr]
        validator = Draft7Validator(schema)  # type: ignore[call-arg]
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    except Exception as exc:
        raise PromptSchemaError(str(exc)) from exc
    if errors:
        rendered = []
        for e in errors:
            path = "/" + "/".join(str(p) for p in e.path) if e.path else "/"
            rendered.append(f"{path}: {e.message}")
        return SchemaValidationResult(ok=False, errors=rendered)
    return SchemaValidationResult(ok=True, errors=[])
