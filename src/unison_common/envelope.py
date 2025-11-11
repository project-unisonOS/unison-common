from typing import Any, Dict, List
import re
import json
import bleach
import logging

logger = logging.getLogger(__name__)

class EnvelopeValidationError(ValueError):
    """Raised when an event envelope fails structural validation."""
    pass

# Import schema validation if available
try:
    from .schema_validation import (
        validate_envelope_schema, 
        validate_envelope_schema_with_details,
        is_schema_validation_available,
        SchemaValidationError
    )
    SCHEMA_VALIDATION_AVAILABLE = is_schema_validation_available()
except ImportError:
    SCHEMA_VALIDATION_AVAILABLE = False
    SchemaValidationError = EnvelopeValidationError

# Security constants
REQUIRED_FIELDS = ["timestamp", "source", "intent", "payload"]
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB
MAX_STRING_LENGTH = 10000
MAX_NESTED_DEPTH = 10

# Validation patterns
INTENT_PATTERN = re.compile(r'^[a-zA-Z0-9\._-]+$')
SOURCE_PATTERN = re.compile(r'^[a-zA-Z0-9\._-]+$')
TIMESTAMP_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$')
AUTH_SCOPE_PATTERN = re.compile(r'^[a-zA-Z0-9:._-]+$')

# Dangerous patterns to block
DANGEROUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',                # JavaScript URLs
    r'on\w+\s*=',                 # Event handlers
    r'expression\s*\(',           # CSS expressions
]

def sanitize_string(value: str) -> str:
    """Sanitize string values to prevent injection attacks"""
    if not isinstance(value, str):
        return value
    
    # Remove potentially dangerous HTML/JS
    cleaned = bleach.clean(value, tags=[], strip=True, attributes=[])
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE | re.DOTALL):
            logger.warning(f"Potentially dangerous content detected and blocked: {pattern}")
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.DOTALL)
    
    # Truncate if too long
    if len(cleaned) > MAX_STRING_LENGTH:
        logger.warning(f"String truncated from {len(cleaned)} to {MAX_STRING_LENGTH} characters")
        cleaned = cleaned[:MAX_STRING_LENGTH]
    
    # Remove null bytes and control characters
    cleaned = ''.join(char for char in cleaned if ord(char) >= 32 or char in '\n\r\t')
    
    return cleaned

def sanitize_dict(d: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """Recursively sanitize dictionary values"""
    if depth > MAX_NESTED_DEPTH:
        raise EnvelopeValidationError("Payload nested too deeply")
    
    sanitized = {}
    for key, value in d.items():
        # Sanitize keys
        if isinstance(key, str):
            clean_key = sanitize_string(key)
            if len(clean_key) > 100:  # Reasonable key length limit
                clean_key = clean_key[:100]
        else:
            clean_key = str(key)[:100]
        
        # Sanitize values based on type
        if isinstance(value, str):
            sanitized[clean_key] = sanitize_string(value)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_dict(value, depth + 1)
        elif isinstance(value, list):
            sanitized[clean_key] = sanitize_list(value, depth + 1)
        elif isinstance(value, (int, float, bool)):
            sanitized[clean_key] = value
        else:
            # Convert other types to string and sanitize
            sanitized[clean_key] = sanitize_string(str(value))
    
    return sanitized

def sanitize_list(lst: List[Any], depth: int = 0) -> List[Any]:
    """Recursively sanitize list values"""
    if depth > MAX_NESTED_DEPTH:
        raise EnvelopeValidationError("Payload nested too deeply")
    
    sanitized = []
    for item in lst:
        if isinstance(item, str):
            sanitized.append(sanitize_string(item))
        elif isinstance(item, dict):
            sanitized.append(sanitize_dict(item, depth + 1))
        elif isinstance(item, list):
            sanitized.append(sanitize_list(item, depth + 1))
        elif isinstance(item, (int, float, bool)):
            sanitized.append(item)
        else:
            sanitized.append(sanitize_string(str(item)))
    
    # Limit list size to prevent DoS
    if len(sanitized) > 1000:
        logger.warning(f"List truncated from {len(sanitized)} to 1000 items")
        sanitized = sanitized[:1000]
    
    return sanitized

def validate_field_length(value: str, field_name: str, max_length: int = MAX_STRING_LENGTH):
    """Validate field length"""
    if len(value) > max_length:
        raise EnvelopeValidationError(f"{field_name} exceeds maximum length of {max_length}")

def validate_timestamp(timestamp: str) -> str:
    """Validate and sanitize timestamp"""
    if not isinstance(timestamp, str):
        raise EnvelopeValidationError("timestamp must be string (ISO 8601)")
    
    # Basic ISO 8601 validation
    if not TIMESTAMP_PATTERN.match(timestamp):
        raise EnvelopeValidationError("timestamp must be valid ISO 8601 format")
    
    # Sanitize timestamp
    clean_timestamp = sanitize_string(timestamp)
    validate_field_length(clean_timestamp, "timestamp", 50)
    
    return clean_timestamp

def validate_source(source: str) -> str:
    """Validate and sanitize source"""
    if not isinstance(source, str):
        raise EnvelopeValidationError("source must be string")
    
    if not SOURCE_PATTERN.match(source):
        raise EnvelopeValidationError("source contains invalid characters")
    
    clean_source = sanitize_string(source)
    validate_field_length(clean_source, "source", 100)
    
    return clean_source

def validate_intent(intent: str) -> str:
    """Validate and sanitize intent"""
    if not isinstance(intent, str):
        raise EnvelopeValidationError("intent must be string")
    
    if not INTENT_PATTERN.match(intent):
        raise EnvelopeValidationError("intent contains invalid characters")
    
    # Check for intent length
    if len(intent) > 200:
        raise EnvelopeValidationError("intent exceeds maximum length of 200")
    
    clean_intent = sanitize_string(intent)
    
    # Additional validation for common attack patterns
    if any(pattern in clean_intent.lower() for pattern in ['<script', 'javascript:', 'data:']):
        raise EnvelopeValidationError("intent contains potentially dangerous content")
    
    return clean_intent

def validate_payload(payload: Any) -> Dict[str, Any]:
    """Validate and sanitize payload"""
    if not isinstance(payload, dict):
        raise EnvelopeValidationError("payload must be object")
    
    # Check payload size
    payload_json = json.dumps(payload, separators=(',', ':'))
    if len(payload_json.encode('utf-8')) > MAX_PAYLOAD_SIZE:
        raise EnvelopeValidationError(f"payload too large (max {MAX_PAYLOAD_SIZE} bytes)")
    
    # Sanitize payload
    sanitized_payload = sanitize_dict(payload)
    
    return sanitized_payload

def validate_auth_scope(auth_scope: Any) -> str:
    """Validate and sanitize auth_scope"""
    if auth_scope is None:
        return None
    
    if not isinstance(auth_scope, str):
        raise EnvelopeValidationError("auth_scope must be string if provided")
    
    if not AUTH_SCOPE_PATTERN.match(auth_scope):
        raise EnvelopeValidationError("auth_scope contains invalid characters")
    
    clean_auth_scope = sanitize_string(auth_scope)
    validate_field_length(clean_auth_scope, "auth_scope", 100)
    
    return clean_auth_scope

def validate_safety_context(safety_context: Any) -> Dict[str, Any]:
    """Validate and sanitize safety_context"""
    if safety_context is None:
        return None
    
    if not isinstance(safety_context, dict):
        raise EnvelopeValidationError("safety_context must be object if provided")
    
    # Known safety context fields
    allowed_safety_fields = {
        "data_classification", "sensitivity_level", "retention_policy",
        "access_required", "compliance_flags", "privacy_level"
    }
    
    # Sanitize and validate safety context
    sanitized_context = sanitize_dict(safety_context)
    
    # Only allow known safety fields
    for field in list(sanitized_context.keys()):
        if field not in allowed_safety_fields:
            logger.warning(f"Unknown safety_context field '{field}' removed")
            del sanitized_context[field]
    
    # Validate data classification if present
    if "data_classification" in sanitized_context:
        valid_classifications = ["public", "internal", "confidential", "restricted"]
        classification = sanitized_context["data_classification"]
        if classification not in valid_classifications:
            raise EnvelopeValidationError(f"Invalid data_classification: {classification}")
    
    return sanitized_context

def validate_event_envelope(envelope: Dict[str, Any], *, allow_unknown: bool = False) -> Dict[str, Any]:
    """
    Validate and sanitize event envelope with enhanced security checks
    
    Args:
        envelope: Raw event envelope
        
    Returns:
        Sanitized and validated envelope
        
    Raises:
        EnvelopeValidationError: If validation fails
    """
    if not isinstance(envelope, dict):
        raise EnvelopeValidationError("Event must be an object")
    
    # Check for excessive number of fields
    if len(envelope) > 20:
        raise EnvelopeValidationError("Too many top-level fields")
    
    # Validate required fields
    missing_fields = [field for field in REQUIRED_FIELDS if field not in envelope]
    if missing_fields:
        raise EnvelopeValidationError(f"Missing required field(s): {', '.join(missing_fields)}")
    
    # Validate and sanitize each field
    sanitized_envelope = {}
    
    try:
        # Timestamp
        sanitized_envelope["timestamp"] = validate_timestamp(envelope["timestamp"])
        
        # Source
        sanitized_envelope["source"] = validate_source(envelope["source"])
        
        # Intent
        sanitized_envelope["intent"] = validate_intent(envelope["intent"])
        
        # Payload
        sanitized_envelope["payload"] = validate_payload(envelope["payload"])
        
        # Optional auth_scope
        if "auth_scope" in envelope:
            sanitized_envelope["auth_scope"] = validate_auth_scope(envelope["auth_scope"])
        
        # Optional safety_context
        if "safety_context" in envelope:
            sanitized_envelope["safety_context"] = validate_safety_context(envelope["safety_context"])
        
    except Exception as e:
        if isinstance(e, EnvelopeValidationError):
            raise
        logger.error(f"Unexpected error during envelope validation: {e}")
        raise EnvelopeValidationError("Envelope validation failed")
    
    allowed_fields = set(REQUIRED_FIELDS + ["auth_scope", "safety_context"])
    unknown_fields = set(envelope.keys()) - allowed_fields
    # Reject unknown top-level fields unless explicitly allowed
    if not allow_unknown:
        if unknown_fields:
            raise EnvelopeValidationError(f"Unknown top-level fields not allowed: {unknown_fields}")
    else:
        # Preserve unknown fields (sanitized) so JSON Schema can validate them
        for k in unknown_fields:
            v = envelope[k]
            if isinstance(v, str):
                sanitized_envelope[k] = sanitize_string(v)
            elif isinstance(v, dict):
                sanitized_envelope[k] = sanitize_dict(v)
            elif isinstance(v, list):
                sanitized_envelope[k] = sanitize_list(v)
            elif isinstance(v, (int, float, bool)):
                sanitized_envelope[k] = v
            else:
                sanitized_envelope[k] = sanitize_string(str(v))
    
    # Log validation for security monitoring
    logger.info(f"Envelope validated successfully", extra={
        "intent": sanitized_envelope["intent"],
        "source": sanitized_envelope["source"],
        "payload_size": len(json.dumps(sanitized_envelope["payload"]))
    })
    
    return sanitized_envelope

def validate_event_envelope_with_schema(envelope: Dict[str, Any], 
                                      use_schema_validation: bool = True) -> Dict[str, Any]:
    """
    Validate event envelope using both programmatic and JSON Schema validation
    
    Args:
        envelope: Raw event envelope
        use_schema_validation: Whether to use JSON Schema validation (default: True)
        
    Returns:
        Sanitized and validated envelope
        
    Raises:
        EnvelopeValidationError: If validation fails
        SchemaValidationError: If schema validation fails
    """
    # First, perform programmatic validation and sanitization
    # Allow unknown fields so JSON Schema can report on them (or be ignored when disabled)
    sanitized_envelope = validate_event_envelope(envelope, allow_unknown=True)
    
    # Then, perform JSON Schema validation if available and requested
    if use_schema_validation and SCHEMA_VALIDATION_AVAILABLE:
        try:
            validate_envelope_schema(sanitized_envelope)
            logger.debug("Envelope passed both programmatic and schema validation")
        except SchemaValidationError as e:
            logger.warning(f"Schema validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected schema validation error: {e}")
            raise EnvelopeValidationError(f"Schema validation failed: {e}")
    elif use_schema_validation and not SCHEMA_VALIDATION_AVAILABLE:
        logger.warning("JSON Schema validation requested but not available - using programmatic validation only")
    
    return sanitized_envelope

def validate_event_envelope_with_details(envelope: Dict[str, Any], 
                                       use_schema_validation: bool = True) -> Dict[str, Any]:
    """
    Validate event envelope and return detailed validation results
    
    Args:
        envelope: Raw event envelope
        use_schema_validation: Whether to use JSON Schema validation (default: True)
        
    Returns:
        Dictionary with validation results including errors if any
    """
    results = {
        "valid": False,
        "programmatic_errors": [],
        "schema_errors": [],
        "sanitized_envelope": None
    }
    
    # Programmatic validation
    try:
        # Allow unknown fields so JSON Schema can report on them (or be ignored when disabled)
        sanitized_envelope = validate_event_envelope(envelope, allow_unknown=True)
        results["sanitized_envelope"] = sanitized_envelope
    except EnvelopeValidationError as e:
        results["programmatic_errors"].append(str(e))
        logger.warning(f"Programmatic validation failed: {e}")
        return results
    
    # Schema validation
    if use_schema_validation and SCHEMA_VALIDATION_AVAILABLE:
        try:
            schema_results = validate_envelope_schema_with_details(sanitized_envelope)
            results["schema_errors"] = schema_results["errors"]
        except Exception as e:
            results["schema_errors"].append(f"Schema validation error: {e}")
            logger.warning(f"Schema validation failed: {e}")
    elif use_schema_validation and not SCHEMA_VALIDATION_AVAILABLE:
        logger.warning("JSON Schema validation requested but not available")
    
    # Final result
    results["valid"] = len(results["programmatic_errors"]) == 0 and len(results["schema_errors"]) == 0
    
    if results["valid"]:
        logger.info("Envelope passed all validation checks")
    else:
        logger.warning(f"Envelope validation failed with {len(results['programmatic_errors'])} programmatic errors and {len(results['schema_errors'])} schema errors")
    
    return results

def validate_batch_envelopes(envelopes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Validate a batch of event envelopes
    
    Args:
        envelopes: List of event envelopes
        
    Returns:
        List of validated envelopes
        
    Raises:
        EnvelopeValidationError: If any envelope fails validation
    """
    if not isinstance(envelopes, list):
        raise EnvelopeValidationError("Batch must be a list")
    
    if len(envelopes) > 100:  # Reasonable batch size limit
        raise EnvelopeValidationError("Batch size exceeds maximum of 100 envelopes")
    
    validated_envelopes = []
    for i, envelope in enumerate(envelopes):
        try:
            validated_envelope = validate_event_envelope(envelope)
            validated_envelopes.append(validated_envelope)
        except EnvelopeValidationError as e:
            raise EnvelopeValidationError(f"Envelope {i} validation failed: {str(e)}")
    
    return validated_envelopes
