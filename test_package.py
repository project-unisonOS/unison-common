#!/usr/bin/env python3
"""
Test script to validate unison-common package build and functionality

This script tests that the package can be built, installed, and imported correctly.
"""

import sys
import os
import subprocess
import tempfile
import shutil
from pathlib import Path


def run_command(cmd, check=True, capture_output=False, cwd=None):
    """Run a shell command and return the result"""
    print(f"🔧 Running: {' '.join(cmd)}")
    if capture_output:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True, cwd=cwd)
        return result.stdout.strip(), result.stderr.strip()
    else:
        subprocess.run(cmd, check=check, cwd=cwd)
        return None, None


def test_package_build():
    """Test that the package builds successfully"""
    print("🏗️  Testing package build...")
    
    # Clean previous builds
    dirs_to_clean = ["build", "dist", "*.egg-info"]
    for pattern in dirs_to_clean:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    
    # Build the package
    run_command([sys.executable, "-m", "build"])
    print("✅ Package built successfully")
    
    # Check that files were created
    dist_files = list(Path("dist").glob("*"))
    if not dist_files:
        raise Exception("No files found in dist/ directory")
    
    print(f"📦 Built files: {[f.name for f in dist_files]}")
    return dist_files


def test_package_check():
    """Test that the package passes twine check"""
    print("🔍 Testing package check...")
    
    run_command([sys.executable, "-m", "twine", "check", "dist/*"])
    print("✅ Package check passed")


def test_package_installation():
    """Test that the package can be installed in a temporary environment"""
    print("📥 Testing package installation...")
    
    # Create temporary directory for test installation
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_venv = Path(temp_dir) / "test_venv"
        
        # Create virtual environment
        run_command([sys.executable, "-m", "venv", str(temp_venv)])
        
        # Determine python executable in venv
        if os.name == "nt":  # Windows
            venv_python = temp_venv / "Scripts" / "python.exe"
            venv_pip = temp_venv / "Scripts" / "pip.exe"
        else:  # Unix-like
            venv_python = temp_venv / "bin" / "python"
            venv_pip = temp_venv / "bin" / "pip"
        
        # Install the package
        dist_files = list(Path("dist").glob("*.whl")) + list(Path("dist").glob("*.tar.gz"))
        if not dist_files:
            raise Exception("No wheel or source distribution found")
        
        # Install the wheel (prefer wheel over source)
        wheel_file = next((f for f in dist_files if f.suffix == ".whl"), dist_files[0])
        run_command([str(venv_pip), "install", str(wheel_file)])
        print("✅ Package installed successfully")
        
        # Test imports
        test_imports(venv_python)


def test_imports(python_executable):
    """Test that all major modules can be imported"""
    print("🧪 Testing module imports...")
    
    test_modules = [
        "unison_common",
        "unison_common.auth",
        "unison_common.tracing", 
        "unison_common.idempotency",
        "unison_common.idempotency_middleware",
        "unison_common.replay_store",
        "unison_common.replay_endpoints",
        "unison_common.http_client",
        "unison_common.envelope"
    ]
    
    for module in test_modules:
        try:
            stdout, _ = run_command([str(python_executable), "-c", f"import {module}"], 
                                  capture_output=True)
            print(f"✅ {module}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to import {module}: {e}")
            raise


def test_basic_functionality():
    """Test basic functionality of key components"""
    print("🔧 Testing basic functionality...")
    
    # Test auth utilities
    try:
        run_command([sys.executable, "-c", """
import sys
sys.path.insert(0, 'src')
from unison_common.auth import verify_token, SecurityContext
print("✅ Auth imports work")
"""])
    except subprocess.CalledProcessError:
        print("❌ Auth functionality test failed")
        raise
    
    # Test tracing utilities
    try:
        run_command([sys.executable, "-c", """
import sys
sys.path.insert(0, 'src')
from unison_common.tracing import TracingConfig, get_trace_context
print("✅ Tracing imports work")
"""])
    except subprocess.CalledProcessError:
        print("❌ Tracing functionality test failed")
        raise
    
    # Test idempotency utilities
    try:
        run_command([sys.executable, "-c", """
import sys
sys.path.insert(0, 'src')
from unison_common.idempotency import IdempotencyConfig, validate_idempotency_key
print("✅ Idempotency imports work")
"""])
    except subprocess.CalledProcessError:
        print("❌ Idempotency functionality test failed")
        raise
    
    # Test replay utilities
    try:
        run_command([sys.executable, "-c", """
import sys
sys.path.insert(0, 'src')
from unison_common.replay_store import ReplayConfig, ReplayManager
print("✅ Replay imports work")
"""])
    except subprocess.CalledProcessError:
        print("❌ Replay functionality test failed")
        raise


def test_version_consistency():
    """Test that version is consistent across files"""
    print("🔍 Testing version consistency...")
    
    # Read version from pyproject.toml
    with open("pyproject.toml", "r") as f:
        content = f.read()
    
    version = None
    for line in content.split('\n'):
        if line.strip().startswith('version ='):
            version = line.split('=')[1].strip().strip('"\'')
            break
    
    if not version:
        raise Exception("Version not found in pyproject.toml")
    
    print(f"📦 Found version: {version}")
    
    # Test that version can be imported
    try:
        run_command([sys.executable, "-c", f"""
import sys
sys.path.insert(0, 'src')
from unison_common import __version__
assert __version__ == "{version}"
print("✅ Version consistency check passed")
"""])
    except subprocess.CalledProcessError:
        print("❌ Version consistency check failed")
        raise


def main():
    """Main test function"""
    print("🚀 Starting unison-common package validation...")
    
    try:
        # Change to unison-common directory
        script_dir = Path(__file__).parent
        os.chdir(script_dir)
        
        # Run tests
        test_version_consistency()
        test_basic_functionality()
        dist_files = test_package_build()
        test_package_check()
        test_package_installation()
        
        print("\n🎉 All package validation tests passed!")
        print("📦 Package is ready for publishing!")
        print(f"📋 Built files: {[f.name for f in dist_files]}")
        
    except Exception as e:
        print(f"\n❌ Package validation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
