"""
Simple validation tests for consent module (M5.2)
Run with: python tests/test_consent_simple.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from unison_common.consent import ConsentScopes, clear_consent_cache


def test_consent_scopes_defined():
    """Test that all consent scopes are properly defined"""
    print("Testing ConsentScopes definitions...")
    
    assert hasattr(ConsentScopes, 'INGEST_WRITE'), "Missing INGEST_WRITE scope"
    assert hasattr(ConsentScopes, 'REPLAY_READ'), "Missing REPLAY_READ scope"
    assert hasattr(ConsentScopes, 'REPLAY_WRITE'), "Missing REPLAY_WRITE scope"
    assert hasattr(ConsentScopes, 'REPLAY_DELETE'), "Missing REPLAY_DELETE scope"
    assert hasattr(ConsentScopes, 'ADMIN_ALL'), "Missing ADMIN_ALL scope"
    
    # Verify scope format
    assert ConsentScopes.INGEST_WRITE == "unison.ingest.write"
    assert ConsentScopes.REPLAY_READ == "unison.replay.read"
    assert ConsentScopes.REPLAY_WRITE == "unison.replay.write"
    assert ConsentScopes.REPLAY_DELETE == "unison.replay.delete"
    assert ConsentScopes.ADMIN_ALL == "unison.admin.all"
    
    print("✅ All consent scopes defined correctly")


def test_cache_functions():
    """Test cache management functions"""
    print("\nTesting cache management...")
    
    # Should not raise any errors
    clear_consent_cache()
    
    print("✅ Cache management functions work")


def test_imports():
    """Test that all required functions can be imported"""
    print("\nTesting imports...")
    
    try:
        from unison_common.consent import (
            ConsentScopes,
            verify_consent_grant,
            require_consent,
            check_consent_header,
            clear_consent_cache,
        )
        print("✅ All consent functions can be imported")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        raise


def test_module_structure():
    """Test that consent module has expected structure"""
    print("\nTesting module structure...")
    
    import unison_common.consent as consent_module
    
    # Check for expected functions
    expected_functions = [
        'verify_consent_grant',
        'require_consent',
        'check_consent_header',
        'clear_consent_cache',
    ]
    
    for func_name in expected_functions:
        assert hasattr(consent_module, func_name), f"Missing function: {func_name}"
    
    # Check for ConsentScopes class
    assert hasattr(consent_module, 'ConsentScopes'), "Missing ConsentScopes class"
    
    print("✅ Module structure is correct")


def run_all_tests():
    """Run all validation tests"""
    print("=" * 60)
    print("M5.2 Consent Module Validation Tests")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_consent_scopes_defined,
        test_cache_functions,
        test_module_structure,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ Test failed: {test.__name__}")
            print(f"   Error: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
