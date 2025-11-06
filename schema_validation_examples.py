#!/usr/bin/env python3
"""
Envelope Schema Validation Examples

This script demonstrates comprehensive usage of JSON Schema validation
for Unison event envelopes, including validation, error handling, and integration.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List

# Add the src directory to the path so we can import unison_common
sys.path.insert(0, str(Path(__file__).parent / "src"))

from unison_common import (
    validate_event_envelope,
    validate_event_envelope_with_schema,
    validate_event_envelope_with_details,
    validate_envelope_schema,
    validate_envelope_schema_with_details,
    is_schema_validation_available,
    get_envelope_schema,
    generate_envelope_documentation,
    EnvelopeValidationError,
    SchemaValidationError,
)


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def print_result(result: Dict[str, Any], title: str = "Result"):
    """Print validation results in a readable format"""
    print(f"\n📊 {title}:")
    print(f"   Valid: {'✅' if result.get('valid', True) else '❌'}")
    
    if 'programmatic_errors' in result and result['programmatic_errors']:
        print("   Programmatic Errors:")
        for error in result['programmatic_errors']:
            print(f"     ❌ {error}")
    
    if 'schema_errors' in result and result['schema_errors']:
        print("   Schema Errors:")
        for error in result['schema_errors']:
            if isinstance(error, dict):
                print(f"     ❌ {error.get('path', 'unknown')}: {error.get('message', 'unknown message')}")
            else:
                print(f"     ❌ {error}")
    
    if result.get('sanitized_envelope'):
        print("   Sanitized Envelope:")
        print(f"     Source: {result['sanitized_envelope'].get('source', 'N/A')}")
        print(f"     Intent: {result['sanitized_envelope'].get('intent', 'N/A')}")
        print(f"     Payload Size: {len(json.dumps(result['sanitized_envelope'].get('payload', {})))} chars")


def example_1_basic_validation():
    """Example 1: Basic envelope validation"""
    print_section("Example 1: Basic Envelope Validation")
    
    # Valid envelope
    valid_envelope = {
        "timestamp": "2025-01-15T10:30:00Z",
        "source": "io-speech",
        "intent": "transcribe.audio",
        "payload": {
            "audio_url": "https://storage.example.com/audio/123.wav",
            "language": "en-US",
            "format": "wav"
        }
    }
    
    print("📋 Testing valid envelope:")
    print(json.dumps(valid_envelope, indent=2))
    
    try:
        # Programmatic validation only
        result = validate_event_envelope(valid_envelope)
        print("\n✅ Programmatic validation passed")
        print(f"   Sanitized source: {result['source']}")
        print(f"   Sanitized intent: {result['intent']}")
        
        # Schema validation only
        schema_result = validate_envelope_schema(valid_envelope)
        print("\n✅ Schema validation passed")
        
        # Integrated validation
        integrated_result = validate_event_envelope_with_schema(valid_envelope)
        print("\n✅ Integrated validation passed")
        print(f"   Final source: {integrated_result['source']}")
        
    except (EnvelopeValidationError, SchemaValidationError) as e:
        print(f"\n❌ Validation failed: {e}")


def example_2_detailed_validation():
    """Example 2: Detailed validation with error reporting"""
    print_section("Example 2: Detailed Validation with Error Reporting")
    
    # Invalid envelope (missing timestamp)
    invalid_envelope = {
        "source": "io-speech",
        "intent": "transcribe.audio",
        "payload": {
            "audio_url": "https://storage.example.com/audio/123.wav",
            "language": "en-US"
        }
        # Missing required timestamp
    }
    
    print("📋 Testing invalid envelope (missing timestamp):")
    print(json.dumps(invalid_envelope, indent=2))
    
    # Detailed validation
    result = validate_event_envelope_with_details(invalid_envelope)
    print_result(result, "Detailed Validation Result")
    
    # Schema-only detailed validation
    schema_result = validate_envelope_schema_with_details(invalid_envelope)
    print_result(schema_result, "Schema-Only Validation Result")


def example_3_schema_violations():
    """Example 3: Various schema violations"""
    print_section("Example 3: Schema Violation Examples")
    
    violations = [
        {
            "name": "Invalid timestamp format",
            "envelope": {
                "timestamp": "not-a-timestamp",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            }
        },
        {
            "name": "Invalid source characters",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "invalid source!",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            }
        },
        {
            "name": "Unknown field",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"},
                "unknown_field": "should not exist"
            }
        },
        {
            "name": "Invalid safety context",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"},
                "safety_context": {
                    "data_classification": "invalid_classification"
                }
            }
        }
    ]
    
    for violation in violations:
        print(f"\n📋 Testing: {violation['name']}")
        print(json.dumps(violation['envelope'], indent=2))
        
        result = validate_event_envelope_with_details(violation['envelope'])
        print_result(result, f"Validation for {violation['name']}")


def example_4_safety_context_validation():
    """Example 4: Safety context validation"""
    print_section("Example 4: Safety Context Validation")
    
    # Valid safety context
    valid_envelope = {
        "timestamp": "2025-01-15T10:30:00Z",
        "source": "io-speech",
        "intent": "transcribe.audio",
        "payload": {
            "audio_url": "https://storage.example.com/audio/123.wav",
            "language": "en-US",
            "transcript": "Hello world"
        },
        "auth_scope": "audio:process",
        "safety_context": {
            "data_classification": "confidential",
            "sensitivity_level": "medium",
            "retention_policy": "30-days",
            "access_required": "enhanced",
            "compliance_flags": ["HIPAA", "GDPR"],
            "privacy_level": "sensitive"
        }
    }
    
    print("📋 Testing envelope with comprehensive safety context:")
    print(json.dumps(valid_envelope, indent=2))
    
    try:
        result = validate_event_envelope_with_schema(valid_envelope)
        print("\n✅ Safety context validation passed")
        print(f"   Data Classification: {result['safety_context']['data_classification']}")
        print(f"   Sensitivity Level: {result['safety_context']['sensitivity_level']}")
        print(f"   Compliance Flags: {result['safety_context']['compliance_flags']}")
        
    except (EnvelopeValidationError, SchemaValidationError) as e:
        print(f"\n❌ Safety context validation failed: {e}")


def example_5_contract_compliance():
    """Example 5: Contract compliance testing"""
    print_section("Example 5: Contract Compliance Testing")
    
    # Example envelopes from different services
    service_envelopes = [
        {
            "service": "Speech Input Service",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {
                    "audio_url": "https://storage.example.com/audio/123.wav",
                    "language": "en-US",
                    "format": "wav",
                    "duration_seconds": 15.5
                }
            }
        },
        {
            "service": "Echo Skill Service",
            "envelope": {
                "timestamp": "2025-01-15T10:31:15.123Z",
                "source": "echo-skill",
                "intent": "skill.response",
                "payload": {
                    "message": "Hello, how can I help you today?",
                    "confidence": 0.95,
                    "metadata": {
                        "processing_time_ms": 150,
                        "model_version": "v2.1"
                    }
                },
                "auth_scope": "skill:execute",
                "safety_context": {
                    "data_classification": "internal",
                    "sensitivity_level": "low",
                    "access_required": "basic"
                }
            }
        },
        {
            "service": "Context Graph Service",
            "envelope": {
                "timestamp": "2025-01-15T10:32:30Z",
                "source": "context-graph",
                "intent": "context.update",
                "payload": {
                    "user_id": "user-123",
                    "context_key": "preference.language",
                    "context_value": "en-US",
                    "metadata": {
                        "updated_by": "user-preference-service",
                        "ttl_seconds": 86400
                    }
                },
                "auth_scope": "context:write",
                "safety_context": {
                    "data_classification": "internal",
                    "sensitivity_level": "medium",
                    "access_required": "basic"
                }
            }
        }
    ]
    
    print("📋 Testing contract compliance across services...")
    
    all_compliant = True
    for service_data in service_envelopes:
        service_name = service_data["service"]
        envelope = service_data["envelope"]
        
        print(f"\n🔍 Testing {service_name}:")
        
        try:
            # Validate with both programmatic and schema checks
            result = validate_event_envelope_with_schema(envelope)
            
            # Get detailed validation results
            detailed = validate_event_envelope_with_details(envelope)
            
            if detailed["valid"]:
                print(f"   ✅ {service_name} is compliant")
                print(f"      Source: {result['source']}")
                print(f"      Intent: {result['intent']}")
                print(f"      Payload fields: {len(result['payload'])}")
            else:
                print(f"   ❌ {service_name} has validation issues")
                all_compliant = False
                
        except Exception as e:
            print(f"   ❌ {service_name} validation failed: {e}")
            all_compliant = False
    
    print(f"\n📊 Contract Compliance Summary:")
    print(f"   {'✅' if all_compliant else '❌'} All services compliant: {all_compliant}")


def example_6_error_handling_patterns():
    """Example 6: Error handling patterns"""
    print_section("Example 6: Error Handling Patterns")
    
    print("📋 Demonstrating error handling patterns...")
    
    # Function to safely validate envelopes
    def safe_validate_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Safely validate an envelope with comprehensive error handling"""
        try:
            # Try integrated validation first
            validated = validate_event_envelope_with_schema(envelope)
            return {
                "success": True,
                "validated_envelope": validated,
                "errors": []
            }
            
        except SchemaValidationError as schema_error:
            # Schema validation failed - get detailed errors
            try:
                detailed = validate_envelope_schema_with_details(envelope)
                return {
                    "success": False,
                    "validated_envelope": None,
                    "errors": detailed["errors"],
                    "error_type": "schema"
                }
            except Exception as e:
                return {
                    "success": False,
                    "validated_envelope": None,
                    "errors": [f"Schema validation error: {e}"],
                    "error_type": "schema"
                }
                
        except EnvelopeValidationError as prog_error:
            # Programmatic validation failed
            return {
                "success": False,
                "validated_envelope": None,
                "errors": [str(prog_error)],
                "error_type": "programmatic"
            }
            
        except Exception as unexpected_error:
            # Unexpected error
            return {
                "success": False,
                "validated_envelope": None,
                "errors": [f"Unexpected error: {unexpected_error}"],
                "error_type": "unexpected"
            }
    
    # Test with various envelopes
    test_envelopes = [
        {
            "name": "Valid envelope",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            }
        },
        {
            "name": "Missing timestamp",
            "envelope": {
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"}
            }
        },
        {
            "name": "Unknown field",
            "envelope": {
                "timestamp": "2025-01-15T10:30:00Z",
                "source": "io-speech",
                "intent": "transcribe.audio",
                "payload": {"message": "Hello"},
                "extra_field": "not allowed"
            }
        }
    ]
    
    for test_case in test_envelopes:
        print(f"\n🔍 Testing: {test_case['name']}")
        result = safe_validate_envelope(test_case['envelope'])
        
        if result["success"]:
            print(f"   ✅ Validation successful")
            print(f"      Source: {result['validated_envelope']['source']}")
        else:
            print(f"   ❌ Validation failed ({result['error_type']})")
            for error in result["errors"]:
                if isinstance(error, dict):
                    print(f"      - {error.get('path', 'unknown')}: {error.get('message', 'unknown')}")
                else:
                    print(f"      - {error}")


def example_7_schema_information():
    """Example 7: Schema information and documentation"""
    print_section("Example 7: Schema Information and Documentation")
    
    print("📋 Schema validation availability:")
    print(f"   Available: {'✅' if is_schema_validation_available() else '❌'}")
    
    if is_schema_validation_available():
        print("\n📋 Schema information:")
        schema = get_envelope_schema()
        print(f"   Title: {schema.get('title', 'Unknown')}")
        print(f"   Description: {schema.get('description', 'No description')[:100]}...")
        print(f"   Required fields: {', '.join(schema.get('required', []))}")
        print(f"   Total properties: {len(schema.get('properties', {}))}")
        
        print("\n📋 Generating documentation...")
        doc = generate_envelope_documentation()
        print(f"   Documentation length: {len(doc)} characters")
        print("   First 200 characters:")
        print(f"   {doc[:200]}...")


def main():
    """Main function to run all examples"""
    print("🚀 Unison Envelope Schema Validation Examples")
    print("=" * 60)
    
    # Check if schema validation is available
    if not is_schema_validation_available():
        print("❌ JSON Schema validation is not available.")
        print("   Please install the jsonschema package: pip install jsonschema")
        sys.exit(1)
    
    try:
        # Run all examples
        example_1_basic_validation()
        example_2_detailed_validation()
        example_3_schema_violations()
        example_4_safety_context_validation()
        example_5_contract_compliance()
        example_6_error_handling_patterns()
        example_7_schema_information()
        
        print_section("Summary")
        print("🎉 All examples completed successfully!")
        print("\n📋 Key takeaways:")
        print("   ✅ JSON Schema validation provides structural validation")
        print("   ✅ Programmatic validation provides security sanitization")
        print("   ✅ Integrated validation combines both approaches")
        print("   ✅ Detailed error reporting helps with debugging")
        print("   ✅ Contract testing ensures service compatibility")
        print("   ✅ Safety context validation supports compliance")
        
        print("\n🔧 Next steps:")
        print("   1. Integrate validation into your service endpoints")
        print("   2. Add contract tests to your CI/CD pipeline")
        print("   3. Use detailed validation for debugging")
        print("   4. Customize safety context for your compliance needs")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Examples interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
