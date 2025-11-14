import inspect
from typing import Dict, Any, get_origin

import pytest

from unison_common import validate_event_envelope, EnvelopeValidationError


@pytest.mark.contract
def test_validate_event_envelope_signature():
    """Ensure validate_event_envelope maintains its public signature."""
    sig = inspect.signature(validate_event_envelope)
    assert list(sig.parameters.keys()) == ["envelope"]
    annotation = sig.return_annotation
    if annotation is inspect._empty:
        pytest.skip("validate_event_envelope is missing return annotations")
    origin = get_origin(annotation)
    assert annotation in (Dict[str, Any], dict) or origin in (Dict, dict)


@pytest.mark.contract
def test_validate_event_envelope_required_fields():
    """The validator must enforce EventEnvelope required fields."""
    valid = {
        "timestamp": "2025-11-13T00:00:00Z",
        "source": "contract-test",
        "intent": "echo",
        "payload": {"message": "hello"},
    }
    sanitized = validate_event_envelope(valid)
    assert sanitized["payload"]["message"] == "hello"

    with pytest.raises(EnvelopeValidationError):
        validate_event_envelope({"intent": "echo"})
