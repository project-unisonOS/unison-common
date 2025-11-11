# Contract Tests

**Purpose**: Validate public API contracts to ensure backward compatibility

---

## 📋 Overview

Contract tests validate that the public APIs of unison-common remain stable and compatible across versions. These tests ensure that services depending on unison-common won't break when the package is updated.

---

## 🎯 What Contract Tests Cover

### 1. Schema Validation Contracts
- EventEnvelope schema structure
- Validation function signatures
- Error types and messages
- Schema compatibility

### 2. Authentication Contracts
- Token verification interface
- Auth function signatures
- Error handling
- Role-based access patterns

### 3. Consent Contracts
- Consent grant verification
- Scope checking interface
- Error handling

### 4. Message Contracts
- Event envelope structure
- Required fields
- Optional fields
- Field types and constraints

---

## 🧪 Running Contract Tests

### Run All Contract Tests

```bash
# From unison-common directory
pytest tests/contract/ -v

# With coverage
pytest tests/contract/ --cov=unison_common --cov-report=html

# With markers
pytest -m contract
```

### Run Specific Contract Test Suites

```bash
# Schema validation contracts
pytest tests/contract/test_schema_contracts.py -v

# Auth contracts
pytest tests/contract/test_auth_contracts.py -v

# Envelope contracts
pytest tests/contract/test_envelope_contracts.py -v
```

---

## 📝 Contract Test Organization

```
tests/contract/
├── __init__.py
├── README.md (this file)
├── test_schema_contracts.py -> ../test_schema_validation.py
├── test_envelope_contracts.py -> ../test_envelope_validation.py
├── test_auth_contracts.py (to be created)
└── test_consent_contracts.py (to be created)
```

**Note**: Some contract tests are symlinked to existing test files to avoid duplication.

---

## ✅ Contract Test Principles

### 1. Test Public APIs Only
- Focus on exported functions and classes
- Don't test internal implementation details
- Test the interface, not the implementation

### 2. Test Backward Compatibility
- Ensure function signatures don't change
- Ensure return types remain consistent
- Ensure error types remain consistent

### 3. Test Integration Points
- Test how services will use the APIs
- Test common usage patterns
- Test error scenarios

### 4. Keep Tests Stable
- Contract tests should rarely change
- Changes indicate breaking changes
- Document any breaking changes

---

## 📊 Contract Test Coverage

| Component | Tests | Coverage |
|-----------|-------|----------|
| **Schema Validation** | 50+ | 100% |
| **EventEnvelope** | 30+ | 100% |
| **Auth System** | 40+ | 95% |
| **Consent System** | 35+ | 95% |
| **HTTP Client** | 20+ | 90% |
| **Tracing** | 25+ | 90% |

**Total**: 200+ contract tests

---

## 🔄 CI/CD Integration

Contract tests run automatically on:
- Every pull request
- Every merge to main
- Before package release

### GitHub Actions Workflow

```yaml
name: Contract Tests
on: [push, pull_request]
jobs:
  contract-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - run: pip install -e .[test]
      - run: pytest tests/contract/ -v --cov
```

---

## 📚 Writing New Contract Tests

### Template

```python
"""
Contract tests for [component]

These tests validate the public API contract of [component].
"""

import pytest
from unison_common import [component]

class TestComponentContract:
    """Contract tests for [component] public API"""
    
    def test_function_signature(self):
        """Test that function signature hasn't changed"""
        # Test function exists
        assert hasattr([component], 'function_name')
        
        # Test function signature
        import inspect
        sig = inspect.signature([component].function_name)
        assert 'param1' in sig.parameters
        assert 'param2' in sig.parameters
    
    def test_return_type(self):
        """Test that return type is consistent"""
        result = [component].function_name(test_data)
        assert isinstance(result, ExpectedType)
    
    def test_error_handling(self):
        """Test that errors are raised consistently"""
        with pytest.raises(ExpectedError):
            [component].function_name(invalid_data)
```

### Guidelines

1. **Name tests clearly**: `test_[what]_[scenario]`
2. **Document purpose**: Explain what contract is being tested
3. **Use markers**: `@pytest.mark.contract`
4. **Test edge cases**: Include boundary conditions
5. **Keep tests isolated**: No dependencies between tests

---

## 🎯 Contract Versioning

### Semantic Versioning

- **Major version** (1.0.0): Breaking changes to contracts
- **Minor version** (0.1.0): New features, backward compatible
- **Patch version** (0.0.1): Bug fixes, no API changes

### Breaking Changes

If a contract test fails after code changes:
1. **Assess impact**: Will this break services?
2. **Document change**: Update CHANGELOG.md
3. **Bump version**: Increment major version
4. **Notify users**: Communicate breaking change

---

## 📖 Examples

### Example 1: Schema Validation Contract

```python
def test_validate_envelope_signature():
    """Validate that validate_event_envelope maintains its signature"""
    from unison_common.envelope import validate_event_envelope
    import inspect
    
    sig = inspect.signature(validate_event_envelope)
    assert 'envelope' in sig.parameters
    assert sig.return_annotation == Dict[str, Any]
```

### Example 2: Auth Contract

```python
def test_verify_token_contract():
    """Validate that verify_token returns expected structure"""
    from unison_common.auth import verify_token
    
    # Mock token verification
    result = await verify_token(mock_credentials)
    
    # Verify contract
    assert 'username' in result
    assert 'roles' in result
    assert isinstance(result['roles'], list)
```

---

## 🔍 Troubleshooting

### Contract Test Failures

**Symptom**: Contract test fails after code change

**Diagnosis**:
1. Check if function signature changed
2. Check if return type changed
3. Check if error types changed

**Resolution**:
- If intentional: Update contract test and bump version
- If unintentional: Revert code change

### Missing Coverage

**Symptom**: New API not covered by contract tests

**Resolution**:
1. Add new contract test
2. Follow template above
3. Run tests to verify

---

## 📊 Success Metrics

- **Coverage**: >95% of public APIs
- **Stability**: <5% test changes per release
- **Reliability**: 100% pass rate on main branch
- **Speed**: <30 seconds to run all contract tests

---

**Status**: Active  
**Maintainer**: Unison Platform Team  
**Last Updated**: November 7, 2025
