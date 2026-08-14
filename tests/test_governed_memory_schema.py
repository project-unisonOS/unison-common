import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_governed_memory_schema_is_valid_and_packaged_copy_matches():
    canonical = ROOT / "schemas" / "governed-memory.v1.schema.json"
    packaged = ROOT / "src" / "unison_common" / "schemas" / canonical.name
    schema = json.loads(canonical.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert json.loads(packaged.read_text(encoding="utf-8")) == schema
