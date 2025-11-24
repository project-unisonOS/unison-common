from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import jsonschema


def _load_schema() -> Dict[str, Any]:
    with resources.files("unison_common.schemas").joinpath("multimodal_manifest.schema.json").open(
        "r", encoding="utf-8"
    ) as f:
        return json.load(f)


_SCHEMA = _load_schema()


def validate_manifest(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a manifest against the bundled schema."""
    jsonschema.validate(data, _SCHEMA)
    return data


class CapabilityClient:
    """Fetches and caches the multimodal capability manifest."""

    def __init__(self, url: str, timeout: float = 2.0) -> None:
        self.url = url
        self.timeout = timeout
        self.manifest: Dict[str, Any] = {"modalities": {"displays": [{}]}}
        self.last_error: Optional[str] = None

    def refresh(self) -> Dict[str, Any]:
        """Refresh manifest from URL or local file path."""
        try:
            if self.url.startswith("file://") or Path(self.url).exists():
                path = Path(self.url.replace("file://", ""))
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                resp = httpx.get(self.url, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
            validate_manifest(data)
            # Preserve original content (with IDs) after validation
            self.manifest = data
            self.last_error = None
        except Exception as exc:  # pragma: no cover - network or schema errors
            self.last_error = str(exc)
        return self.manifest

    def modality_count(self, modality: str) -> int:
        items = self.manifest.get("modalities", {}).get(modality, [])
        if isinstance(items, list):
            return len(items)
        return 0

    @classmethod
    def from_env(cls) -> "CapabilityClient":
        url = os.getenv("MULTIMODAL_MANIFEST_URL", "http://orchestrator:8080/capabilities")
        return cls(url)
