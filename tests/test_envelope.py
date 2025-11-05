import pytest
from unison_common import validate_event_envelope, EnvelopeValidationError

def test_valid_envelope():
    env = {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "io-speech",
        "intent": "PLAY_MEDIA",
        "payload": {"media": "news radio"},
        "auth_scope": "user.local.explicit",
        "safety_context": {"target": "local-audio"}
    }
    out = validate_event_envelope(env)
    # Should return a sanitized copy
    assert out == {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "io-speech",
        "intent": "PLAY_MEDIA",
        "payload": {"media": "news radio"},
        "auth_scope": "user.local.explicit",
        "safety_context": {}  # target field removed as it's not in allowed list
    }

def test_missing_field():
    env = {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "io-speech",
        "payload": {}
    }
    with pytest.raises(EnvelopeValidationError):
        validate_event_envelope(env)

def test_wrong_type_payload():
    env = {
        "timestamp": "2025-10-25T00:00:00Z",
        "source": "io-speech",
        "intent": "PLAY_MEDIA",
        "payload": "not an object"
    }
    with pytest.raises(EnvelopeValidationError):
        validate_event_envelope(env)
