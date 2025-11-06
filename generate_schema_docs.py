#!/usr/bin/env python3
"""
Schema Documentation Generator

This script generates comprehensive documentation for JSON schemas,
including validation rules, examples, and integration guides.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime


def load_schema(schema_path: Path) -> Dict[str, Any]:
    """Load JSON schema from file"""
    with open(schema_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_property_docs(prop_name: str, prop_schema: Dict[str, Any], level: int = 3) -> str:
    """Generate documentation for a schema property"""
    heading = "#" * level
    doc = f"{heading} {prop_name}\n\n"
    
    # Type and description
    doc += f"**Type:** `{prop_schema.get('type', 'unknown')}`\n\n"
    
    if 'description' in prop_schema:
        doc += f"**Description:** {prop_schema['description']}\n\n"
    
    # Constraints
    constraints = []
    
    if 'pattern' in prop_schema:
        constraints.append(f"**Pattern:** `{prop_schema['pattern']}`")
    
    if 'format' in prop_schema:
        constraints.append(f"**Format:** `{prop_schema['format']}`")
    
    if 'enum' in prop_schema:
        enum_values = ', '.join(f'`{v}`' for v in prop_schema['enum'])
        constraints.append(f"**Allowed values:** {enum_values}")
    
    if 'minLength' in prop_schema or 'maxLength' in prop_schema:
        length_constraint = "**Length:** "
        if 'minLength' in prop_schema:
            length_constraint += f"min {prop_schema['minLength']}"
        if 'maxLength' in prop_schema:
            if 'minLength' in prop_schema:
                length_constraint += ", "
            length_constraint += f"max {prop_schema['maxLength']}"
        constraints.append(length_constraint)
    
    if 'minimum' in prop_schema or 'maximum' in prop_schema:
        number_constraint = "**Range:** "
        if 'minimum' in prop_schema:
            number_constraint += f"min {prop_schema['minimum']}"
        if 'maximum' in prop_schema:
            if 'minimum' in prop_schema:
                number_constraint += ", "
            number_constraint += f"max {prop_schema['maximum']}"
        constraints.append(number_constraint)
    
    if 'minItems' in prop_schema or 'maxItems' in prop_schema:
        items_constraint = "**Items:** "
        if 'minItems' in prop_schema:
            items_constraint += f"min {prop_schema['minItems']}"
        if 'maxItems' in prop_schema:
            if 'minItems' in prop_schema:
                items_constraint += ", "
            items_constraint += f"max {prop_schema['maxItems']}"
        constraints.append(items_constraint)
    
    if 'required' in prop_schema and prop_name == 'properties':
        constraints.append(f"**Required fields:** {', '.join(f'`{f}`' for f in prop_schema['required'])}")
    
    if constraints:
        doc += "\n".join(constraints) + "\n\n"
    
    # Nested properties
    if 'properties' in prop_schema:
        doc += "**Nested Properties:**\n\n"
        for nested_name, nested_schema in prop_schema['properties'].items():
            doc += generate_property_docs(nested_name, nested_schema, level + 1)
    
    # Array items
    if 'items' in prop_schema and isinstance(prop_schema['items'], dict):
        doc += "**Array Items:**\n\n"
        doc += generate_property_docs("items", prop_schema['items'], level + 1)
    
    return doc


def generate_schema_docs(schema: Dict[str, Any]) -> str:
    """Generate comprehensive documentation for a schema"""
    doc = f"# {schema.get('title', 'Schema Documentation')}\n\n"
    
    # Description
    if 'description' in schema:
        doc += f"{schema['description']}\n\n"
    
    # Schema metadata
    doc += "## Schema Information\n\n"
    doc += f"- **Schema ID:** `{schema.get('$id', 'Not specified')}`\n"
    doc += f"- **JSON Schema Version:** `{schema.get('$schema', 'Not specified')}`\n"
    doc += f"- **Type:** `{schema.get('type', 'unknown')}`\n"
    doc += f"- **Generated:** {datetime.now().isoformat()}\n\n"
    
    # Validation rules overview
    doc += "## Validation Rules\n\n"
    
    if 'required' in schema:
        doc += f"**Required Fields:** {', '.join(f'`{f}`' for f in schema['required'])}\n\n"
    
    if 'additionalProperties' in schema:
        doc += f"**Additional Properties:** {'Allowed' if schema['additionalProperties'] else 'Not Allowed'}\n\n"
    
    if 'maxProperties' in schema:
        doc += f"**Maximum Properties:** {schema['maxProperties']}\n\n"
    
    # Properties documentation
    if 'properties' in schema:
        doc += "## Properties\n\n"
        
        # Separate required and optional
        required_props = schema.get('required', [])
        
        doc += "### Required Properties\n\n"
        for prop_name in required_props:
            if prop_name in schema['properties']:
                doc += generate_property_docs(prop_name, schema['properties'][prop_name])
        
        optional_props = [p for p in schema['properties'] if p not in required_props]
        if optional_props:
            doc += "### Optional Properties\n\n"
            for prop_name in optional_props:
                doc += generate_property_docs(prop_name, schema['properties'][prop_name])
    
    # Examples
    if 'examples' in schema:
        doc += "## Examples\n\n"
        for i, example in enumerate(schema['examples'], 1):
            doc += f"### Example {i}\n\n"
            doc += "```json\n"
            doc += json.dumps(example, indent=2)
            doc += "\n```\n\n"
    
    # Usage notes
    doc += generate_usage_notes(schema)
    
    return doc


def generate_usage_notes(schema: Dict[str, Any]) -> str:
    """Generate usage notes and best practices"""
    doc = "## Usage Notes\n\n"
    
    doc += "### Validation\n\n"
    doc += "This schema is used to validate event envelopes in the Unison platform. "
    doc += "Validation ensures:\n\n"
    doc += "- **Data Integrity:** All required fields are present and correctly formatted\n"
    doc += "- **Type Safety:** Field values match expected types and constraints\n"
    doc += "- **Security:** Input is sanitized and validated against injection attacks\n"
    doc += "- **Compatibility:** Envelopes conform to the expected contract\n\n"
    
    doc += "### Integration\n\n"
    doc += "The schema validation integrates with programmatic validation:\n\n"
    doc += "```python\n"
    doc += "from unison_common import (\n"
    doc += "    validate_event_envelope_with_schema,\n"
    doc += "    validate_envelope_schema\n"
    doc += ")\n\n"
    doc += "# Validate with both programmatic and schema checks\n"
    doc += "validated = validate_event_envelope_with_schema(envelope)\n\n"
    doc += "# Or validate with schema only\n"
    doc += "validate_envelope_schema(envelope)\n"
    doc += "```\n\n"
    
    doc += "### Error Handling\n\n"
    doc += "Validation errors provide detailed information:\n\n"
    doc += "```python\n"
    doc += "from unison_common import validate_envelope_schema_with_details\n\n"
    doc += "result = validate_envelope_schema_with_details(envelope)\n"
    doc += "if not result['valid']:\n"
    doc += "    for error in result['errors']:\n"
    doc += "        print(f\"Error at {error['path']}: {error['message']}\")\n"
    doc += "```\n\n"
    
    doc += "### Best Practices\n\n"
    doc += "- **Timestamps:** Use ISO 8601 format with UTC timezone\n"
    doc += "- **Sources:** Use alphanumeric characters, dots, hyphens, and underscores only\n"
    doc += "- **Intents:** Follow naming convention: `service.action` or `category.operation`\n"
    doc += "- **Payloads:** Keep payloads under 1MB for performance\n"
    doc += "- **Safety Context:** Include appropriate data classification for compliance\n\n"
    
    return doc


def generate_contract_test_docs() -> str:
    """Generate contract testing documentation"""
    doc = "# Contract Testing Guide\n\n"
    doc += "This guide covers contract testing for Unison event envelopes using JSON Schema validation.\n\n"
    
    doc += "## Overview\n\n"
    doc += "Contract testing ensures that event envelopes conform to the expected schema and validation rules. "
    doc += "This prevents integration issues between services and maintains data consistency across the platform.\n\n"
    
    doc += "## Test Categories\n\n"
    doc += "### 1. Schema Validation Tests\n\n"
    doc += "- Verify schema structure and constraints\n"
    doc += "- Test required and optional field validation\n"
    doc += "- Validate data type and format enforcement\n\n"
    
    doc += "### 2. Integration Tests\n\n"
    doc += "- Test schema validation with programmatic validation\n"
    doc += "- Verify error handling and reporting\n"
    doc += "- Validate fallback behavior when schema validation unavailable\n\n"
    
    doc += "### 3. Contract Compliance Tests\n\n"
    doc += "- Test example envelopes from the schema\n"
    doc += "- Verify real-world envelope compliance\n"
    doc += "- Test edge cases and error conditions\n\n"
    
    doc += "### 4. Error Handling Tests\n\n"
    doc += "- Test detection of invalid envelopes\n"
    doc += "- Verify detailed error reporting\n"
    doc += "- Test error message clarity and usefulness\n\n"
    
    doc += "## Running Tests\n\n"
    doc += "### Local Testing\n\n"
    doc += "```bash\n"
    doc += "# Run schema validation tests\n"
    doc += "cd unison-common\n"
    doc += "python -m pytest tests/test_schema_validation.py -v\n\n"
    doc += "# Run contract compliance tests\n"
    doc += "python -m pytest tests/test_schema_validation.py::TestContractTesting -v\n"
    doc += "```\n\n"
    
    doc += "### CI/CD Testing\n\n"
    doc += "Contract tests run automatically in GitHub Actions when:\n"
    doc += "- Schema files are modified\n"
    doc += "- Validation code is changed\n"
    doc += "- Tests are updated\n\n"
    
    doc += "## Test Data\n\n"
    doc += "### Valid Envelopes\n\n"
    doc += "```json\n"
    doc += "{\n"
    doc += '  "timestamp": "2025-01-15T10:30:00Z",\n'
    doc += '  "source": "io-speech",\n'
    doc += '  "intent": "transcribe.audio",\n'
    doc += '  "payload": {\n'
    doc += '    "audio_url": "https://example.com/audio.wav",\n'
    doc += '    "language": "en-US"\n'
    doc += "  }\n"
    doc += "}\n"
    doc += "```\n\n"
    
    doc += "### Invalid Envelopes\n\n"
    doc += "```json\n"
    doc += "{\n"
    doc += '  "source": "io-speech",\n'
    doc += '  "intent": "transcribe.audio",\n'
    doc += '  "payload": {"message": "Missing timestamp"}\n'
    doc += "}\n"
    doc += "```\n\n"
    
    doc += "## Adding New Tests\n\n"
    doc += "When adding new envelope types or validation rules:\n\n"
    doc += "1. **Update Schema:** Modify the JSON schema in `schemas/event-envelope.json`\n"
    doc += "2. **Add Examples:** Include new examples in the schema\n"
    doc += "3. **Write Tests:** Add test cases in `tests/test_schema_validation.py`\n"
    doc += "4. **Update Documentation:** Regenerate this documentation\n\n"
    
    return doc


def main():
    """Main documentation generation function"""
    schema_dir = Path(__file__).parent.parent / "schemas"
    output_dir = Path(__file__).parent.parent
    
    # Find schema files
    schema_files = list(schema_dir.glob("*.json"))
    
    if not schema_files:
        print("❌ No schema files found in schemas/ directory")
        sys.exit(1)
    
    print(f"📝 Found {len(schema_files)} schema file(s)")
    
    # Generate documentation for each schema
    for schema_file in schema_files:
        print(f"📋 Processing {schema_file.name}...")
        
        try:
            schema = load_schema(schema_file)
            docs = generate_schema_docs(schema)
            
            # Save documentation
            output_file = output_dir / f"{schema_file.stem}_documentation.md"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(docs)
            
            print(f"✅ Generated {output_file}")
            
        except Exception as e:
            print(f"❌ Error processing {schema_file.name}: {e}")
            sys.exit(1)
    
    # Generate contract testing guide
    print("📋 Generating contract testing guide...")
    contract_docs = generate_contract_test_docs()
    
    contract_file = output_dir / "CONTRACT_TESTING.md"
    with open(contract_file, 'w', encoding='utf-8') as f:
        f.write(contract_docs)
    
    print(f"✅ Generated {contract_file}")
    
    # Generate summary
    print("\n🎉 Documentation generation completed!")
    print("📄 Generated files:")
    
    for schema_file in schema_files:
        output_file = output_dir / f"{schema_file.stem}_documentation.md"
        print(f"   - {output_file}")
    
    print(f"   - {contract_file}")
    
    print("\n📋 Next steps:")
    print("1. Review the generated documentation")
    print("2. Commit the documentation files")
    print("3. Update service integration guides")
    print("4. Share with development team")


if __name__ == "__main__":
    main()
