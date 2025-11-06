#!/usr/bin/env python3
"""
Simple validation script for unison-common package structure

This script validates that all required files are present and correctly structured.
"""

import os
from pathlib import Path


def validate_package_structure():
    """Validate that the package has the correct structure"""
    print("🔍 Validating package structure...")
    
    required_files = [
        "pyproject.toml",
        "README.md", 
        "MANIFEST.in",
        "src/unison_common/__init__.py",
        "src/unison_common/py.typed"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
        else:
            print(f"✅ {file_path}")
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    
    print("✅ All required files present")
    return True


def validate_pyproject_toml():
    """Validate pyproject.toml structure"""
    print("🔍 Validating pyproject.toml...")
    
    try:
        with open("pyproject.toml", "r") as f:
            content = f.read()
        
        required_sections = [
            "[build-system]",
            "[project]",
            "version =",
            "name = \"unison-common\"",
            "dependencies = ["
        ]
        
        for section in required_sections:
            if section not in content:
                print(f"❌ Missing required section: {section}")
                return False
            else:
                print(f"✅ Found: {section}")
        
        # Check version is 0.1.0
        if "version = \"0.1.0\"" not in content:
            print("❌ Version should be 0.1.0")
            return False
        
        print("✅ pyproject.toml validation passed")
        return True
        
    except Exception as e:
        print(f"❌ Error reading pyproject.toml: {e}")
        return False


def validate_module_exports():
    """Validate that __init__.py exports all required modules"""
    print("🔍 Validating module exports...")
    
    try:
        with open("src/unison_common/__init__.py", "r") as f:
            content = f.read()
        
        required_exports = [
            "__version__",
            "validate_event_envelope",
            "verify_token",
            "TracingConfig",
            "IdempotencyConfig",
            "ReplayConfig",
            "ReplayManager"
        ]
        
        for export in required_exports:
            if export not in content:
                print(f"❌ Missing export: {export}")
                return False
            else:
                print(f"✅ Found export: {export}")
        
        print("✅ Module exports validation passed")
        return True
        
    except Exception as e:
        print(f"❌ Error reading __init__.py: {e}")
        return False


def validate_documentation():
    """Validate documentation files"""
    print("🔍 Validating documentation...")
    
    doc_files = [
        "README.md",
        "PUBLISHING.md"
    ]
    
    for doc_file in doc_files:
        if Path(doc_file).exists():
            size = Path(doc_file).stat().st_size
            print(f"✅ {doc_file} ({size} bytes)")
        else:
            print(f"❌ Missing documentation: {doc_file}")
            return False
    
    print("✅ Documentation validation passed")
    return True


def validate_test_structure():
    """Validate test structure"""
    print("🔍 Validating test structure...")
    
    test_dir = Path("tests")
    if not test_dir.exists():
        print("❌ tests directory not found")
        return False
    
    test_files = list(test_dir.glob("test_*.py"))
    if not test_files:
        print("❌ No test files found")
        return False
    
    for test_file in test_files:
        print(f"✅ {test_file.name}")
    
    print(f"✅ Found {len(test_files)} test files")
    return True


def main():
    """Main validation function"""
    print("🚀 Starting unison-common package validation...")
    
    validations = [
        validate_package_structure,
        validate_pyproject_toml,
        validate_module_exports,
        validate_documentation,
        validate_test_structure
    ]
    
    all_passed = True
    for validation in validations:
        if not validation():
            all_passed = False
        print()  # Add spacing
    
    if all_passed:
        print("🎉 All validations passed!")
        print("📦 Package is ready for publishing!")
        print("\n📋 Next steps:")
        print("1. Run: python -m build")
        print("2. Run: python -m twine check dist/*")
        print("3. Run: python publish.py --repository-url YOUR_PYPI_URL")
    else:
        print("❌ Some validations failed!")
        print("🔧 Please fix the issues before publishing.")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
