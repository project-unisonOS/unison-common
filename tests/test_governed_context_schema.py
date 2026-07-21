import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_governed_context_schema_is_valid_and_packaged_copy_matches():
    canonical = ROOT / "schemas" / "governed-context.v2.schema.json"
    packaged = ROOT / "src" / "unison_common" / "schemas" / canonical.name
    schema = json.loads(canonical.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert json.loads(packaged.read_text(encoding="utf-8")) == schema


def test_schema_accepts_restrictive_memory_record():
    schema = json.loads((ROOT / "schemas" / "governed-context.v2.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        {
            "version": "2.0",
            "record_id": "record-1",
            "owner_person_id": "person-1",
            "space_id": "space-1",
            "kind": "asserted_fact",
            "content": {"fact": "private"},
            "provenance": "person",
            "relationship_ids": [],
            "governance": {
                "sensitivity": "private",
                "purposes": [],
                "audiences": [],
                "allow_inference": False,
                "allow_action": False,
                "allow_disclosure": False,
                "allow_backup": False,
                "allow_sync": False,
                "retention_until": None
            },
            "confidence": 1.0,
            "revision": 1,
            "deletion_state": "active"
        }
    )
