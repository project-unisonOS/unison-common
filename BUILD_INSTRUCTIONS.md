# unison-common Package Build Instructions

**Date**: November 7, 2025  
**Version**: 0.1.0

---

## 📦 Building the Package

### Prerequisites

```bash
# Install build tools
pip install build twine

# Verify installation
python -m build --version
```

---

## 🔨 Build Steps

### 1. Clean Previous Builds

```bash
cd unison-common

# Remove old build artifacts
rm -rf dist/ build/ src/unison_common.egg-info/

# On Windows PowerShell:
Remove-Item -Recurse -Force dist, build, src/unison_common.egg-info -ErrorAction SilentlyContinue
```

### 2. Build the Package

```bash
# Build both wheel and source distribution
python -m build

# This creates:
# - dist/unison_common-0.1.0-py3-none-any.whl (wheel)
# - dist/unison-common-0.1.0.tar.gz (source)
```

### 3. Verify the Build

```bash
# Check what's in the wheel
python -m zipfile -l dist/unison_common-0.1.0-py3-none-any.whl

# Expected contents:
# - unison_common/*.py (all modules)
# - unison_common/py.typed
# - schemas/*.json (schema files)
# - unison_common-0.1.0.dist-info/ (metadata)
```

---

## ✅ Testing the Package

### Test Installation

```bash
# Create a test virtual environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate

# Install the built package
pip install dist/unison_common-0.1.0-py3-none-any.whl

# Test imports
python -c "from unison_common import validate_event_envelope; print('✓ Import successful')"
python -c "from unison_common.auth import verify_token; print('✓ Auth import successful')"
python -c "from unison_common.schema_validation import EnvelopeSchemaValidator; print('✓ Schema validation import successful')"

# Verify schemas are included
python -c "from pathlib import Path; import unison_common; pkg_path = Path(unison_common.__file__).parent; print('Schemas:', list((pkg_path.parent / 'schemas').glob('*.json')))"

# Deactivate and clean up
deactivate
rm -rf test_env
```

---

## 📤 Distribution Options

### Option A: Local File Distribution (Simplest)

**Use Case**: Development, testing, local deployment

```bash
# Services install directly from file
pip install /path/to/unison-common/dist/unison_common-0.1.0-py3-none-any.whl

# Or in requirements.txt:
# /path/to/unison-common/dist/unison_common-0.1.0-py3-none-any.whl
```

**Pros**: Simple, no infrastructure needed  
**Cons**: Requires file path, not suitable for CI/CD

---

### Option B: Private PyPI with devpi (Recommended)

**Use Case**: Team development, CI/CD

#### Setup devpi Server

```bash
# Install devpi
pip install devpi-server devpi-client

# Initialize and start server
devpi-init
devpi-server --start --host=0.0.0.0 --port=3141

# Configure client
devpi use http://localhost:3141
devpi login root --password=''
devpi index -c dev
devpi use root/dev
```

#### Upload Package

```bash
cd unison-common

# Upload to devpi
devpi upload dist/*

# Verify upload
devpi list unison-common
```

#### Install from devpi

```bash
# Install from private PyPI
pip install unison-common==0.1.0 --index-url http://localhost:3141/root/dev/+simple/

# Or in requirements.txt:
# --index-url http://localhost:3141/root/dev/+simple/
# unison-common==0.1.0
```

**Pros**: Standard PyPI workflow, supports CI/CD  
**Cons**: Requires running server

---

### Option C: GitHub Packages (Production)

**Use Case**: Production deployment, public/private repos

#### Configure GitHub Package Registry

```bash
# Create .pypirc
cat > ~/.pypirc << EOF
[distutils]
index-servers =
    github

[github]
repository = https://upload.pypi.org/legacy/
username = __token__
password = <GITHUB_TOKEN>
EOF
```

#### Upload to GitHub

```bash
# Upload with twine
python -m twine upload --repository github dist/*
```

#### Install from GitHub

```bash
# Install from GitHub Packages
pip install unison-common==0.1.0 --index-url https://pypi.pkg.github.com/project-unisonOS/simple/

# Or in requirements.txt:
# --index-url https://pypi.pkg.github.com/project-unisonOS/simple/
# unison-common==0.1.0
```

**Pros**: Integrated with GitHub, supports CI/CD  
**Cons**: Requires GitHub token, more complex setup

---

## 🔄 Updating Services

### Update requirements.txt

**Before**:
```txt
# unison-orchestrator/requirements.txt
-e ../unison-common
```

**After (Option A - Local)**:
```txt
# unison-orchestrator/requirements.txt
/path/to/unison-common/dist/unison_common-0.1.0-py3-none-any.whl
```

**After (Option B - devpi)**:
```txt
# unison-orchestrator/requirements.txt
--index-url http://localhost:3141/root/dev/+simple/
unison-common==0.1.0
```

**After (Option C - GitHub)**:
```txt
# unison-orchestrator/requirements.txt
--index-url https://pypi.pkg.github.com/project-unisonOS/simple/
unison-common==0.1.0
```

### Services to Update (14 total)

1. unison-orchestrator
2. unison-storage
3. unison-policy
4. unison-auth
5. unison-consent
6. unison-context
7. unison-inference
8. unison-intent-graph
9. unison-context-graph
10. unison-experience-renderer
11. unison-agent-vdi
12. unison-io-core
13. unison-io-speech
14. unison-io-vision

### Test Each Service

```bash
cd unison-orchestrator

# Reinstall dependencies
pip install -r requirements.txt

# Run tests
pytest

# Start service
python -m src.server
```

---

## 🐳 Docker Considerations

### Update Dockerfiles

If services have Dockerfiles that reference unison-common:

**Before**:
```dockerfile
COPY ../unison-common /app/unison-common
RUN pip install -e /app/unison-common
```

**After (Option A)**:
```dockerfile
COPY unison-common/dist/unison_common-0.1.0-py3-none-any.whl /tmp/
RUN pip install /tmp/unison_common-0.1.0-py3-none-any.whl
```

**After (Option B/C)**:
```dockerfile
# No changes needed - pip install from requirements.txt
RUN pip install -r requirements.txt
```

---

## 📊 Verification Checklist

After updating all services:

- [ ] Package builds successfully
- [ ] Package installs without errors
- [ ] All imports work correctly
- [ ] Schemas are accessible
- [ ] All 14 services updated
- [ ] All services install successfully
- [ ] All services pass tests
- [ ] All services start without errors
- [ ] No `-e ../unison-common` in any requirements.txt
- [ ] Docker builds work (if applicable)

---

## 🔧 Troubleshooting

### Import Errors

```python
# If imports fail, check package installation
import unison_common
print(unison_common.__file__)  # Should show installed location
print(unison_common.__version__)  # Should show 0.1.0
```

### Missing Schemas

```python
# Verify schemas are included
from pathlib import Path
import unison_common

pkg_path = Path(unison_common.__file__).parent
schema_path = pkg_path.parent / 'schemas'
print(f"Schema path: {schema_path}")
print(f"Schemas found: {list(schema_path.glob('*.json'))}")
```

### Version Conflicts

```bash
# Check installed version
pip show unison-common

# Uninstall and reinstall
pip uninstall unison-common -y
pip install unison-common==0.1.0
```

---

## 📝 Next Steps

1. ✅ Build package
2. ✅ Test installation
3. ⏳ Choose distribution method
4. ⏳ Update all 14 services
5. ⏳ Test all services
6. ⏳ Update CI/CD
7. ⏳ Document changes

---

## 🎯 Recommended Approach

**For Development**: Use Option A (local files) initially  
**For Team**: Set up Option B (devpi)  
**For Production**: Use Option C (GitHub Packages)

**Start with Option A**, test thoroughly, then migrate to Option B or C.

---

**Status**: Ready to build  
**Estimated Time**: 30 minutes for build + test  
**Next**: Run `python -m build` in unison-common directory
