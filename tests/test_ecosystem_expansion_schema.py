import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).parents[1]


def _contract():
    return {
        "version": "unison.ecosystem-expansion.v1",
        "semantic_outcome": {
            "outcome_id": "outcome-1",
            "text": "Your draft is ready.",
            "privacy": "private",
            "urgency": "polite",
            "actions": [
                {"id": "confirm", "label": "Review draft", "kind": "confirm"},
                {"id": "cancel", "label": "Cancel", "kind": "cancel"},
            ],
        },
        "available_modalities": ["visual", "captions", "keyboard"],
        "preferences": {
            "required": ["captions"],
            "avoided": ["speech"],
            "reduced_motion": True,
            "high_contrast": True,
            "simplified_language": False,
        },
        "selected_outputs": ["visual", "captions"],
        "fallbacks": [
            {"when_unavailable": "visual", "use": "captions", "preserves_actions": True}
        ],
    }


def test_ecosystem_contract_is_packaged_identically():
    canonical = ROOT / "schemas" / "ecosystem-expansion.v1.schema.json"
    packaged = ROOT / "src" / "unison_common" / "schemas" / canonical.name
    assert json.loads(canonical.read_text()) == json.loads(packaged.read_text())


def test_semantic_modality_contract_accepts_equivalent_fallback():
    schema = json.loads((ROOT / "schemas" / "ecosystem-expansion.v1.schema.json").read_text())
    jsonschema.validate(_contract(), schema)


def test_fallback_cannot_drop_semantic_actions():
    schema = json.loads((ROOT / "schemas" / "ecosystem-expansion.v1.schema.json").read_text())
    contract = _contract()
    contract["fallbacks"][0]["preserves_actions"] = False
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(contract, schema)
