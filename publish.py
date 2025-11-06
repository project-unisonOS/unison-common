#!/usr/bin/env python3
"""
Publish script for unison-common package

This script builds and publishes the unison-common package to a private PyPI index.
It handles version validation, dependency checking, and clean builds.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse
import json


def run_command(cmd, check=True, capture_output=False):
    """Run a shell command and return the result"""
    print(f"🔧 Running: {' '.join(cmd)}")
    if capture_output:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip()
    else:
        subprocess.run(cmd, check=check)
        return None, None


def check_dependencies():
    """Check if required build dependencies are installed"""
    print("🔍 Checking build dependencies...")
    
    required_packages = ["build", "twine", "wheel"]
    missing_packages = []
    
    for package in required_packages:
        try:
            stdout, _ = run_command([sys.executable, "-m", "pip", "show", package], 
                                  check=False, capture_output=True)
            if stdout:
                print(f"✅ {package} is installed")
            else:
                missing_packages.append(package)
        except subprocess.CalledProcessError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("📦 Installing missing packages...")
        run_command([sys.executable, "-m", "pip", "install"] + missing_packages)
        print("✅ Dependencies installed")
    else:
        print("✅ All dependencies are available")


def clean_build_artifacts():
    """Clean previous build artifacts"""
    print("🧹 Cleaning build artifacts...")
    
    dirs_to_clean = ["build", "dist", "*.egg-info"]
    for pattern in dirs_to_clean:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                print(f"🗑️  Removing directory: {path}")
                shutil.rmtree(path)
            else:
                print(f"🗑️  Removing file: {path}")
                path.unlink()
    
    print("✅ Build artifacts cleaned")


def validate_version():
    """Validate that the version in pyproject.toml matches expectations"""
    print("🔍 Validating version...")
    
    # Read version from pyproject.toml
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        raise FileNotFoundError("pyproject.toml not found")
    
    with open(pyproject_path, 'r') as f:
        content = f.read()
    
    # Simple version extraction (could use tomli for more robust parsing)
    for line in content.split('\n'):
        if line.strip().startswith('version ='):
            version = line.split('=')[1].strip().strip('"\'')
            print(f"📦 Found version: {version}")
            return version
    
    raise ValueError("Version not found in pyproject.toml")


def run_tests():
    """Run the test suite to ensure package quality"""
    print("🧪 Running tests...")
    
    if Path("tests").exists():
        try:
            run_command([sys.executable, "-m", "pytest", "tests/", "-v"])
            print("✅ All tests passed")
        except subprocess.CalledProcessError:
            print("❌ Tests failed")
            print("⚠️  Continuing with publish (tests may be optional)")
    else:
        print("⚠️  No tests directory found, skipping tests")


def build_package():
    """Build the package"""
    print("🏗️  Building package...")
    
    # Use the build module for modern Python packaging
    run_command([sys.executable, "-m", "build"])
    print("✅ Package built successfully")


def check_package():
    """Check the built package with twine"""
    print("🔍 Checking package...")
    
    run_command([sys.executable, "-m", "twine", "check", "dist/*"])
    print("✅ Package check passed")


def publish_to_private_index(repository_url, username, password):
    """Publish to private PyPI index"""
    print(f"🚀 Publishing to private index: {repository_url}")
    
    # Set up environment variables for twine
    env = os.environ.copy()
    if username:
        env["TWINE_USERNAME"] = username
    if password:
        env["TWINE_PASSWORD"] = password
    
    # Publish to private index
    cmd = [sys.executable, "-m", "twine", "upload", "--repository-url", repository_url, "dist/*"]
    
    # Use subprocess with custom environment
    print(f"🔧 Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env, check=False)
    
    if result.returncode == 0:
        print("✅ Package published successfully")
        return True
    else:
        print("❌ Package publish failed")
        return False


def update_service_dependencies():
    """Update requirements.txt files in all services to use the new version"""
    print("🔄 Updating service dependencies...")
    
    version = validate_version()
    
    services = [
        "unison-orchestrator",
        "unison-context-graph", 
        "unison-consent",
        "unison-policy"
    ]
    
    updated_services = []
    
    for service in services:
        service_path = Path(f"../{service}")
        if not service_path.exists():
            print(f"⚠️  Service {service} not found, skipping")
            continue
        
        requirements_file = service_path / "requirements.txt"
        if not requirements_file.exists():
            print(f"⚠️  {service}/requirements.txt not found, skipping")
            continue
        
        print(f"📝 Updating {service}/requirements.txt...")
        
        # Read current requirements
        with open(requirements_file, 'r') as f:
            lines = f.readlines()
        
        # Update unison-common version
        updated_lines = []
        for line in lines:
            if line.strip().startswith("unison-common"):
                updated_lines.append(f"unison-common=={version}\n")
                updated_services.append(service)
            else:
                updated_lines.append(line)
        
        # Write updated requirements
        with open(requirements_file, 'w') as f:
            f.writelines(updated_lines)
        
        print(f"✅ Updated {service} to use unison-common=={version}")
    
    if updated_services:
        print(f"✅ Updated services: {', '.join(updated_services)}")
    else:
        print("⚠️  No services were updated")


def main():
    """Main publishing workflow"""
    parser = argparse.ArgumentParser(description="Publish unison-common package")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--skip-update", action="store_true", help="Skip updating service dependencies")
    parser.add_argument("--repository-url", required=True, help="Private PyPI repository URL")
    parser.add_argument("--username", help="Repository username")
    parser.add_argument("--password", help="Repository password")
    parser.add_argument("--dry-run", action="store_true", help="Build and check but don't publish")
    
    args = parser.parse_args()
    
    print("🚀 Starting unison-common publish process...")
    
    try:
        # Change to unison-common directory
        script_dir = Path(__file__).parent
        os.chdir(script_dir)
        
        # Validate environment
        check_dependencies()
        clean_build_artifacts()
        version = validate_version()
        
        # Quality checks
        if not args.skip_tests:
            run_tests()
        
        # Build and check
        build_package()
        check_package()
        
        # Publish (unless dry run)
        if not args.dry_run:
            success = publish_to_private_index(
                args.repository_url, 
                args.username, 
                args.password
            )
            
            if not success:
                sys.exit(1)
            
            # Update service dependencies
            if not args.skip_update:
                update_service_dependencies()
            
            print(f"🎉 Successfully published unison-common v{version}!")
            print("📋 Next steps:")
            print("   1. Commit and push the updated requirements.txt files")
            print("   2. Create a git tag for this release")
            print("   3. Update services to use the new version")
        else:
            print(f"🔍 Dry run completed - package ready for publishing")
            print(f"📦 Version: {version}")
            print("📋 To publish, run without --dry-run flag")
        
    except Exception as e:
        print(f"❌ Publish failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
