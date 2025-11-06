"""
Tests for JSON Schema validation functionality

This test suite covers JSON Schema validation, integration with programmatic validation,
and contract testing capabilities.
"""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from unison_common.schema_validation import (
    EnvelopeSchemaValidator,
    SchemaValidationError,
    validate_envelope_schema,
    validate_envelope_schema_with_details,
    is_schema_validation_available,
    get_envelope_schema,
    generate_envelope_documentation,
    get_schema_validator,
)

from unison_common.envelope import (
    validate_event_envelope_with_schema,
    validate_event_envelope_with_details,
    EnvelopeValidationError,
)


class TestSchemaValidationAvailability:
    """Test schema validation availability checks"""
    
    def test_is_schema_validation_available(self):
        """Test that schema validation is available"""
        assert is_schema_validation_available() == True
    
    def test_validator_initialization(self):
        """Test validator initialization"""
        validator = EnvelopeSchemaValidator()
        assert validator is not None
        assert "event-envelope" in validator.list_schemas()


class TestEnvelopeSchemaValidator:
    """Test the EnvelopeSchemaValidator class"""
    
    def test_validator_initialization(self):
        """Test validator initialization with default schemas"""
        validator = EnvelopeSchemaValidator()
        
        schemas = validator.list_schemas()
        assert "event-envelope" in schemas
        
        schema = validator.get_schema("event-envelope")
        assert schema is not None
        assert schema["type"] == "object"
        assert "timestamp" in schema["required"]
    
    def test_load_schema_from_file(self):
        """Test loading schema from file"""
        validator = EnvelopeSchemaValidator()
        
        # Test loading the event envelope schema
        schema_path = Path(__file__).parent.parent.parent / "schemas" / "event-envelope.json"
        if schema_path.exists():
            validator.load_schema("test-envelope", schema_path)
            assert "test-envelope" in validator.list_schemas()
        else:
            pytest.skip("Schema file not found")
    
    def test_add_schema_programmatically(self):
        """Test adding schema programmatically"""
        validator = EnvelopeSchemaValidator()
        
        test_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "test_field": {
                    "type": "string",
                    "minLength": 1
                }
            },
            "required": ["test_field"]
        }
        
        validator.add_schema("test-schema", test_schema)
        assert "test-schema" in validator.list_schemas()
    
    def test_add_invalid_schema(self):
        """Test adding invalid schema raises error"""
        validator = EnvelopeSchemaValidator()
        
        invalid_schema = {
            "type": "invalid-type"
        }
        
        with pytest.raises(SchemaValidationError):
            validator.add_schema("invalid-schema", invalid_schema)
    
    def test_validate_valid_envelope(self):
        """Test validating a valid envelope"""
        validator = get_schema_validator()
        
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {
                "message": "Hello world",
                "data": {"key": "value"}
            }
        }
        
        result = validator.validate(valid_envelope, "event-envelope")
        assert result == valid_envelope
    
    def test_validate_invalid_envelope(self):
        """Test validating an invalid envelope"""
        validator = get_schema_validator()
        
        invalid_envelope = {
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
            # Missing required timestamp
        }
        
        with pytest.raises(SchemaValidationError) as exc_info:
            validator.validate(invalid_envelope, "event-envelope")
        
        assert "timestamp" in str(exc_info.value)
    
    def test_validate_with_details_valid(self):
        """Test detailed validation with valid envelope"""
        validator = get_schema_validator()
        
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validator.validate_with_details(valid_envelope, "event-envelope")
        
        assert result["valid"] is True
        assert result["errors"] == []
        assert result["data"] == valid_envelope
    
    def test_validate_with_details_invalid(self):
        """Test detailed validation with invalid envelope"""
        validator = get_schema_validator()
        
        invalid_envelope = {
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
            # Missing required timestamp
        }
        
        result = validator.validate_with_details(invalid_envelope, "event-envelope")
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert result["data"] is None
        
        # Check error details
        error = result["errors"][0]
        assert "path" in error
        assert "message" in error
        assert "failed_value" in error
    
    def test_validate_unknown_schema(self):
        """Test validating against unknown schema"""
        validator = get_schema_validator()
        
        with pytest.raises(SchemaValidationError):
            validator.validate({}, "unknown-schema")
    
    def test_generate_documentation(self):
        """Test schema documentation generation"""
        validator = get_schema_validator()
        
        doc = validator.generate_schema_documentation("event-envelope")
        
        assert isinstance(doc, str)
        assert "Unison Event Envelope" in doc
        assert "Required Properties" in doc
        assert "timestamp" in doc
        assert "source" in doc
        assert "intent" in doc
        assert "payload" in doc


class TestSchemaValidationFunctions:
    """Test schema validation convenience functions"""
    
    def test_validate_envelope_schema_valid(self):
        """Test validate_envelope_schema with valid envelope"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validate_envelope_schema(valid_envelope)
        assert result == valid_envelope
    
    def test_validate_envelope_schema_invalid(self):
        """Test validate_envelope_schema with invalid envelope"""
        invalid_envelope = {
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        with pytest.raises(SchemaValidationError):
            validate_envelope_schema(invalid_envelope)
    
    def test_validate_envelope_schema_with_details(self):
        """Test validate_envelope_schema_with_details"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validate_envelope_schema_with_details(valid_envelope)
        assert result["valid"] is True
        assert result["errors"] == []
    
    def test_get_envelope_schema(self):
        """Test get_envelope_schema function"""
        schema = get_envelope_schema()
        
        assert isinstance(schema, dict)
        assert schema["type"] == "object"
        assert "timestamp" in schema["required"]
    
    def test_generate_envelope_documentation(self):
        """Test generate_envelope_documentation function"""
        doc = generate_envelope_documentation()
        
        assert isinstance(doc, str)
        assert "Unison Event Envelope" in doc
        assert "Required Properties" in doc


class TestIntegratedValidation:
    """Test integration between programmatic and schema validation"""
    
    def test_validate_event_envelope_with_schema_valid(self):
        """Test integrated validation with valid envelope"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validate_event_envelope_with_schema(valid_envelope)
        assert result["source"] == "io-speech"
        assert result["intent"] == "transcribe.audio"
    
    def test_validate_event_envelope_with_schema_invalid_programmatic(self):
        """Test integrated validation with programmatic validation failure"""
        invalid_envelope = {
            "timestamp": "invalid-timestamp",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        with pytest.raises(EnvelopeValidationError):
            validate_event_envelope_with_schema(invalid_envelope)
    
    def test_validate_event_envelope_with_schema_invalid_schema(self):
        """Test integrated validation with schema validation failure"""
        invalid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"},
            "unknown_field": "should not be allowed"
        }
        
        with pytest.raises(SchemaValidationError):
            validate_event_envelope_with_schema(invalid_envelope)
    
    def test_validate_event_envelope_with_schema_disabled(self):
        """Test integrated validation with schema validation disabled"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"},
            "unknown_field": "would fail schema validation"
        }
        
        # Should pass with schema validation disabled
        result = validate_event_envelope_with_schema(valid_envelope, use_schema_validation=False)
        assert result["source"] == "io-speech"
    
    def test_validate_event_envelope_with_details_valid(self):
        """Test detailed validation with valid envelope"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validate_event_envelope_with_details(valid_envelope)
        
        assert result["valid"] is True
        assert result["programmatic_errors"] == []
        assert result["schema_errors"] == []
        assert result["sanitized_envelope"] is not None
    
    def test_validate_event_envelope_with_details_programmatic_errors(self):
        """Test detailed validation with programmatic errors"""
        invalid_envelope = {
            "timestamp": "invalid-timestamp",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        result = validate_event_envelope_with_details(invalid_envelope)
        
        assert result["valid"] is False
        assert len(result["programmatic_errors"]) > 0
        assert result["sanitized_envelope"] is None
    
    def test_validate_event_envelope_with_details_schema_errors(self):
        """Test detailed validation with schema errors"""
        invalid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"},
            "unknown_field": "not allowed"
        }
        
        result = validate_event_envelope_with_details(invalid_envelope)
        
        assert result["valid"] is False
        assert len(result["programmatic_errors"]) == 0
        assert len(result["schema_errors"]) > 0


class TestContractTesting:
    """Test contract testing capabilities"""
    
    def test_envelope_contract_compliance(self):
        """Test that example envelopes comply with the contract"""
        validator = get_schema_validator()
        
        # Test various valid envelope examples
        valid_envelopes = [
            {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {
                    "audio_url": "https://example.com/audio.wav",
                    "language": "en-US"
                }
            },
            {
                "timestamp": "2025-01-15T10:31:15.123Z",
                "source": "echo-skill",
                "intent": "skill.response",
                "payload": {
                    "message": "Hello world",
                    "confidence": 0.95,
                    "metadata": {"processing_time_ms": 150}
                },
                "auth_scope": "skill:execute",
                "safety_context": {
                    "data_classification": "internal",
                    "sensitivity_level": "low",
                    "access_required": "basic"
                }
            }
        ]
        
        for envelope in valid_envelopes:
            result = validator.validate_with_details(envelope, "event-envelope")
            assert result["valid"] is True, f"Envelope should be valid: {envelope}"
    
    def test_envelope_contract_violations(self):
        """Test detection of contract violations"""
        validator = get_schema_validator()
        
        # Test various contract violations
        invalid_envelopes = [
            {
                # Missing required timestamp
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            },
            {
                # Invalid timestamp format
                "timestamp": "not-a-timestamp",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            },
            {
                # Invalid source characters
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "invalid source!",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            },
            {
                # Unknown field
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"},
                "unknown_field": "should not exist"
            }
        ]
        
        for envelope in invalid_envelopes:
            result = validator.validate_with_details(envelope, "event-envelope")
            assert result["valid"] is False, f"Envelope should be invalid: {envelope}"
            assert len(result["errors"]) > 0
    
    def test_safety_context_validation(self):
        """Test safety context field validation"""
        validator = get_schema_validator()
        
        # Valid safety context
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello"},
            "safety_context": {
                "data_classification": "confidential",
                "sensitivity_level": "high",
                "retention_policy": "standard",
                "access_required": "enhanced",
                "compliance_flags": ["HIPAA", "GDPR"],
                "privacy_level": "sensitive"
            }
        }
        
        result = validator.validate_with_details(valid_envelope, "event-envelope")
        assert result["valid"] is True
        
        # Invalid data classification
        invalid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello"},
            "safety_context": {
                "data_classification": "invalid_classification"
            }
        }
        
        result = validator.validate_with_details(invalid_envelope, "event-envelope")
        assert result["valid"] is False
        assert any("data_classification" in error["message"] for error in result["errors"])


class TestSchemaValidationEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_nested_payload_validation(self):
        """Test validation of deeply nested payloads"""
        validator = get_schema_validator()
        
        # Valid nested payload
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "complex.data",
            "payload": {
                "level1": {
                    "level2": {
                        "level3": {
                            "data": "deep value"
                        }
                    }
                }
            }
        }
        
        result = validator.validate_with_details(valid_envelope, "event-envelope")
        assert result["valid"] is True
    
    def test_payload_size_validation(self):
        """Test payload size constraints"""
        validator = get_schema_validator()
        
        # Large payload (should be validated by programmatic validation)
        large_payload = {"data": "x" * 2000}  # Large but within reasonable limits
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "large.payload",
            "payload": large_payload
        }
        
        # Schema validation should pass (size is handled by programmatic validation)
        result = validator.validate_with_details(valid_envelope, "event-envelope")
        assert result["valid"] is True
    
    def test_special_characters_in_payload(self):
        """Test handling of special characters in payload"""
        validator = get_schema_validator()
        
        envelope_with_special_chars = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "special.chars",
            "payload": {
                "unicode": "Hello 世界 🌍",
                "special": "Special chars: !@#$%^&*()",
                "quotes": 'Single "double" quotes',
                "newlines": "Line 1\nLine 2\tTabbed"
            }
        }
        
        result = validator.validate_with_details(envelope_with_special_chars, "event-envelope")
        assert result["valid"] is True
    
    def test_null_and_optional_fields(self):
        """Test handling of null and optional fields"""
        validator = get_schema_validator()
        
        # Envelope with optional fields as null
        envelope_with_nulls = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "test.nulls",
            "payload": {"message": "Hello"},
            "auth_scope": None,
            "safety_context": None
        }
        
        result = validator.validate_with_details(envelope_with_nulls, "event-envelope")
        assert result["valid"] is True


class TestMockSchemaValidation:
    """Test behavior when jsonschema is not available"""
    
    @patch('unison_common.schema_validation.JSONSCHEMA_AVAILABLE', False)
    def test_schema_validation_unavailable(self):
        """Test behavior when jsonschema is not available"""
        with pytest.raises(ImportError):
            EnvelopeSchemaValidator()
    
    @patch('unison_common.envelope.SCHEMA_VALIDATION_AVAILABLE', False)
    def test_integrated_validation_fallback(self):
        """Test integrated validation fallback when schema validation unavailable"""
        valid_envelope = {
            "timestamp": "2025-01-15T10:30:00Z",
            "source": "io-speech",
            "intent": "transcribe.audio",
            "payload": {"message": "Hello world"}
        }
        
        # Should fall back to programmatic validation only
        result = validate_event_envelope_with_schema(valid_envelope, use_schema_validation=True)
        assert result["source"] == "io-speech"
        
        # Detailed validation should indicate schema validation not available
        result = validate_event_envelope_with_details(valid_envelope, use_schema_validation=True)
        assert result["valid"] is True  # Programmatic validation passes
        assert result["sanitized_envelope"] is not None
