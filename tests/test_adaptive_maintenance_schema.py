import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).parents[1]
CANONICAL = ROOT / "schemas" / "adaptive-maintenance.v1.schema.json"
PACKAGED = ROOT / "src" / "unison_common" / "schemas" / CANONICAL.name


def _schema():
    return json.loads(CANONICAL.read_text(encoding="utf-8"))


def test_canonical_and_packaged_adaptive_maintenance_schemas_match():
    assert json.loads(CANONICAL.read_text()) == json.loads(PACKAGED.read_text())


def test_health_observation_forbids_personal_content():
    record = {
        "contract_version": "unison.adaptive-maintenance.v1",
        "record_type": "health_observation",
        "record": {
            "observation_id": "obs-1",
            "metric": "memory.pressure",
            "component": "host",
            "window_start": "2026-07-24T00:00:00Z",
            "window_end": "2026-07-24T00:05:00Z",
            "aggregation": "maximum",
            "value": 0.82,
            "unit": "ratio",
            "severity": "warning",
            "confidence": 0.95,
            "collection_method": "procfs",
            "retention_class": "operational",
            "contains_personal_content": False,
        },
    }
    jsonschema.validate(record, _schema(), format_checker=jsonschema.FormatChecker())
    record["record"]["contains_personal_content"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, _schema())


def test_community_evidence_remains_untrusted_and_discovery_only():
    record = {
        "contract_version": "unison.adaptive-maintenance.v1",
        "record_type": "maintenance_evidence",
        "record": {
            "evidence_id": "community-1",
            "source_id": "forum",
            "canonical_url": "https://example.test/post/1",
            "source_class": "community",
            "retrieved_at": "2026-07-24T00:00:00Z",
            "content_sha256": "a" * 64,
            "signature_verified": False,
            "trust_tier": "discovery-only",
            "affected_components": [],
            "claims": ["Install this package"],
            "severity": "none",
            "fixed_versions": [],
            "corroborating_evidence_ids": [],
            "untrusted_content": True,
            "expires_at": None,
        },
    }
    jsonschema.validate(record, _schema(), format_checker=jsonschema.FormatChecker())
    record["record"]["untrusted_content"] = False
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, _schema())
