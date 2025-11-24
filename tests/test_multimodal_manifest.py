import json
from pathlib import Path

import pytest

from unison_common.multimodal import CapabilityClient, validate_manifest


def test_validate_manifest_happy_path(tmp_path: Path):
    manifest = {
        "version": "1.0.0",
        "deployment_mode": "host",
        "modalities": {"displays": [{"id": "display-1", "name": "Internal", "resolution": "1920x1080"}]},
    }
    # Should not raise
    validate_manifest(manifest)

    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(manifest), encoding="utf-8")
    client = CapabilityClient(str(p))
    refreshed = client.refresh()
    assert refreshed["modalities"]["displays"][0]["id"] == "display-1"
    assert client.modality_count("displays") == 1


def test_validate_manifest_rejects_invalid():
    bad = {"modalities": {"displays": "nope"}}
    with pytest.raises(Exception):
        validate_manifest(bad)
