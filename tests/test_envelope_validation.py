import pytest
from unison_common import validate_event_envelope, EnvelopeValidationError


def test_rejects_unknown_field():
    env = {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "tester",
        "intent": "do.thing",
        "payload": {},
        "extra": 1,
    }
    with pytest.raises(EnvelopeValidationError):
        validate_event_envelope(env)


def test_accepts_minimal_valid():
    env = {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "tester",
        "intent": "do.thing",
        "payload": {},
    }
    out = validate_event_envelope(env)
    assert out["intent"] == "do.thing"
