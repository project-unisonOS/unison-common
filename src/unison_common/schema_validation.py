"""
JSON Schema validation for Unison event envelopes

This module provides JSON Schema-based validation for event envelopes,
complementing the existing programmatic validation with standardized schema validation.
"""

import json
import os
from typing import Any, Dict, List, Optional
from pathlib import Path
import logging

try:
    import jsonschema
    from jsonschema import Draft7Validator, ValidationError, SchemaError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    Draft7Validator = None
    ValidationError = Exception
    SchemaError = Exception

from .envelope import EnvelopeValidationError

logger = logging.getLogger(__name__)

# Default schema directory
SCHEMA_DIR = Path(__file__).parent.parent / "schemas"

class SchemaValidationError(EnvelopeValidationError):
    """Raised when JSON Schema validation fails"""
    pass

class EnvelopeSchemaValidator:
    """
    JSON Schema validator for event envelopes
    
    Provides standardized schema validation with caching and error reporting.
    """
    
    def __init__(self, schema_dir: Optional[Path] = None):
        """
        Initialize the schema validator
        
        Args:
            schema_dir: Directory containing schema files (defaults to built-in schemas)
        """
        if not JSONSCHEMA_AVAILABLE:
            raise ImportError("jsonschema package is required for schema validation")
        
        self.schema_dir = schema_dir or SCHEMA_DIR
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._validators: Dict[str, Draft7Validator] = {}
        
        # Load default schemas
        self._load_default_schemas()
    
    def _load_default_schemas(self):
        """Load default schemas from the schemas directory"""
        if not self.schema_dir.exists():
            logger.warning(f"Schema directory not found: {self.schema_dir}")
            return
        
        # Load event envelope schema
        event_schema_path = self.schema_dir / "event-envelope.json"
        if event_schema_path.exists():
            self.load_schema("event-envelope", event_schema_path)
        else:
            logger.warning(f"Event envelope schema not found: {event_schema_path}")
    
    def load_schema(self, name: str, schema_path: Path):
        """
        Load a JSON schema from file
        
        Args:
            name: Schema name/identifier
            schema_path: Path to schema file
        """
        try:
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
            
            # Validate the schema itself
            Draft7Validator.check_schema(schema)
            
            # Create validator
            validator = Draft7Validator(schema)
            
            self._schemas[name] = schema
            self._validators[name] = validator
            
            logger.info(f"Loaded schema '{name}' from {schema_path}")
            
        except Exception as e:
            logger.error(f"Failed to load schema '{name}' from {schema_path}: {e}")
            raise SchemaValidationError(f"Invalid schema file: {e}")
    
    def add_schema(self, name: str, schema: Dict[str, Any]):
        """
        Add a schema programmatically
        
        Args:
            name: Schema name/identifier
            schema: JSON schema dictionary
        """
        try:
            # Validate the schema
            Draft7Validator.check_schema(schema)
            
            # Create validator
            validator = Draft7Validator(schema)
            
            self._schemas[name] = schema
            self._validators[name] = validator
            
            logger.info(f"Added schema '{name}' programmatically")
            
        except Exception as e:
            logger.error(f"Failed to add schema '{name}': {e}")
            raise SchemaValidationError(f"Invalid schema: {e}")
    
    def validate(self, data: Any, schema_name: str = "event-envelope") -> Dict[str, Any]:
        """
        Validate data against a schema
        
        Args:
            data: Data to validate
            schema_name: Name of schema to use (default: event-envelope)
            
        Returns:
            Validated data
            
        Raises:
            SchemaValidationError: If validation fails
        """
        if schema_name not in self._validators:
            raise SchemaValidationError(f"Schema '{schema_name}' not loaded")
        
        validator = self._validators[schema_name]
        
        try:
            # Validate the data
            validator.validate(data)
            
            logger.debug(f"Data validated successfully against schema '{schema_name}'")
            return data
            
        except ValidationError as e:
            # Create detailed error message
            error_path = " -> ".join(str(p) for p in e.absolute_path) if e.absolute_path else "root"
            error_msg = f"Schema validation failed at '{error_path}': {e.message}"
            
            logger.warning(f"Schema validation error: {error_msg}")
            raise SchemaValidationError(error_msg)
        
        except Exception as e:
            logger.error(f"Unexpected validation error: {e}")
            raise SchemaValidationError(f"Validation failed: {e}")
    
    def validate_with_details(self, data: Any, schema_name: str = "event-envelope") -> Dict[str, Any]:
        """
        Validate data and return detailed validation results
        
        Args:
            data: Data to validate
            schema_name: Name of schema to use
            
        Returns:
            Dictionary with validation results including errors if any
        """
        if schema_name not in self._validators:
            return {
                "valid": False,
                "errors": [f"Schema '{schema_name}' not loaded"],
                "data": None
            }
        
        validator = self._validators[schema_name]
        errors = []
        
        # Collect all validation errors
        for error in validator.iter_errors(data):
            error_path = " -> ".join(str(p) for p in error.absolute_path) if error.absolute_path else "root"
            errors.append({
                "path": error_path,
                "message": error.message,
                "schema_path": " -> ".join(str(p) for p in error.schema_path) if error.schema_path else None,
                "failed_value": error.instance
            })
        
        is_valid = len(errors) == 0
        
        if is_valid:
            logger.debug(f"Data validated successfully against schema '{schema_name}'")
        else:
            logger.warning(f"Schema validation found {len(errors)} error(s)")
        
        return {
            "valid": is_valid,
            "errors": errors,
            "data": data if is_valid else None
        }
    
    def get_schema(self, schema_name: str = "event-envelope") -> Dict[str, Any]:
        """
        Get a loaded schema
        
        Args:
            schema_name: Name of schema
            
        Returns:
            Schema dictionary
        """
        if schema_name not in self._schemas:
            raise SchemaValidationError(f"Schema '{schema_name}' not loaded")
        
        return self._schemas[schema_name]
    
    def list_schemas(self) -> List[str]:
        """
        List all loaded schema names
        
        Returns:
            List of schema names
        """
        return list(self._schemas.keys())
    
    def generate_schema_documentation(self, schema_name: str = "event-envelope") -> str:
        """
        Generate human-readable documentation for a schema
        
        Args:
            schema_name: Name of schema
            
        Returns:
            Markdown documentation string
        """
        if schema_name not in self._schemas:
            raise SchemaValidationError(f"Schema '{schema_name}' not loaded")
        
        schema = self._schemas[schema_name]
        
        doc = f"# {schema.get('title', schema_name)}\n\n"
        doc += f"{schema.get('description', 'No description available')}\n\n"
        
        # Document required properties
        if 'required' in schema and 'properties' in schema:
            doc += "## Required Properties\n\n"
            for prop in schema['required']:
                if prop in schema['properties']:
                    prop_schema = schema['properties'][prop]
                    doc += f"### {prop}\n\n"
                    doc += f"**Type:** {prop_schema.get('type', 'unknown')}\n\n"
                    if 'description' in prop_schema:
                        doc += f"**Description:** {prop_schema['description']}\n\n"
                    if 'pattern' in prop_schema:
                        doc += f"**Pattern:** `{prop_schema['pattern']}`\n\n"
                    if 'enum' in prop_schema:
                        doc += f"**Allowed values:** {', '.join(f'`{v}`' for v in prop_schema['enum'])}\n\n"
                    if 'minLength' in prop_schema or 'maxLength' in prop_schema:
                        doc += f"**Length:** "
                        if 'minLength' in prop_schema:
                            doc += f"min {prop_schema['minLength']}"
                        if 'maxLength' in prop_schema:
                            if 'minLength' in prop_schema:
                                doc += ", "
                            doc += f"max {prop_schema['maxLength']}"
                        doc += "\n\n"
        
        # Document optional properties
        if 'properties' in schema:
            optional_props = [p for p in schema['properties'] if p not in schema.get('required', [])]
            if optional_props:
                doc += "## Optional Properties\n\n"
                for prop in optional_props:
                    prop_schema = schema['properties'][prop]
                    doc += f"### {prop}\n\n"
                    doc += f"**Type:** {prop_schema.get('type', 'unknown')}\n\n"
                    if 'description' in prop_schema:
                        doc += f"**Description:** {prop_schema['description']}\n\n"
                    if 'pattern' in prop_schema:
                        doc += f"**Pattern:** `{prop_schema['pattern']}`\n\n"
                    if 'enum' in prop_schema:
                        doc += f"**Allowed values:** {', '.join(f'`{v}`' for v in prop_schema['enum'])}\n\n"
        
        # Add examples if available
        if 'examples' in schema:
            doc += "## Examples\n\n"
            for i, example in enumerate(schema['examples']):
                doc += f"### Example {i + 1}\n\n"
                doc += "```json\n"
                doc += json.dumps(example, indent=2)
                doc += "\n```\n\n"
        
        return doc

# Global validator instance
_global_validator: Optional[EnvelopeSchemaValidator] = None

def get_schema_validator() -> EnvelopeSchemaValidator:
    """
    Get the global schema validator instance
    
    Returns:
        EnvelopeSchemaValidator instance
    """
    global _global_validator
    
    if _global_validator is None:
        if not JSONSCHEMA_AVAILABLE:
            raise ImportError("jsonschema package is required for schema validation")
        _global_validator = EnvelopeSchemaValidator()
    
    return _global_validator

def validate_envelope_schema(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate an event envelope using JSON Schema
    
    Args:
        envelope: Event envelope to validate
        
    Returns:
        Validated envelope
        
    Raises:
        SchemaValidationError: If validation fails
    """
    validator = get_schema_validator()
    return validator.validate(envelope, "event-envelope")

def validate_envelope_schema_with_details(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate an event envelope and return detailed results
    
    Args:
        envelope: Event envelope to validate
        
    Returns:
        Validation results with detailed error information
    """
    validator = get_schema_validator()
    return validator.validate_with_details(envelope, "event-envelope")

def is_schema_validation_available() -> bool:
    """
    Check if JSON Schema validation is available
    
    Returns:
        True if jsonschema package is available
    """
    return JSONSCHEMA_AVAILABLE

def get_envelope_schema() -> Dict[str, Any]:
    """
    Get the event envelope JSON Schema
    
    Returns:
        JSON Schema dictionary
    """
    validator = get_schema_validator()
    return validator.get_schema("event-envelope")

def generate_envelope_documentation() -> str:
    """
    Generate documentation for the event envelope schema
    
    Returns:
        Markdown documentation string
    """
    validator = get_schema_validator()
    return validator.generate_schema_documentation("event-envelope")
