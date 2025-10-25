from typing import Any, Dict

class EnvelopeValidationError(ValueError):
    """Raised when an event envelope fails structural validation."""
    pass

REQUIRED_FIELDS = ["timestamp", "source", "intent", "payload"]

def validate_event_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(envelope, dict):
        raise EnvelopeValidationError("Event must be an object")

    for field in REQUIRED_FIELDS:
        if field not in envelope:
            raise EnvelopeValidationError(f"Missing required field '{field}'")

    if not isinstance(envelope["timestamp"], str):
        raise EnvelopeValidationError("timestamp must be string (ISO 8601)")

    if not isinstance(envelope["source"], str):
        raise EnvelopeValidationError("source must be string")

    if not isinstance(envelope["intent"], str):
        raise EnvelopeValidationError("intent must be string")

    if not isinstance(envelope["payload"], dict):
        raise EnvelopeValidationError("payload must be object")

    if "auth_scope" in envelope and envelope["auth_scope"] is not None:
        if not isinstance(envelope["auth_scope"], str):
            raise EnvelopeValidationError("auth_scope must be string if provided")

    if "safety_context" in envelope and envelope["safety_context"] is not None:
        if not isinstance(envelope["safety_context"], dict):
            raise EnvelopeValidationError("safety_context must be object if provided")

    return envelope
