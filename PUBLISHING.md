# unison-common Publishing Guide

This guide covers how to publish the `unison-common` package to a private PyPI index and update all dependent services.

## 📦 Package Overview

`unison-common` is the shared library that provides common functionality across all Unison services, including:

- Authentication and authorization utilities
- Distributed tracing components
- Idempotency middleware
- Event replay functionality
- HTTP client utilities
- Envelope validation

## 🚀 Publishing Methods

### 1. Automated GitHub Actions (Recommended)

#### Using Manual Workflow Dispatch

1. **Navigate to GitHub Actions**: Go to the Actions tab in the unison-common repository
2. **Select Publish Workflow**: Choose "Publish unison-common" from the workflow list
3. **Click "Run workflow"**: Fill in the required parameters:
   - **Version**: The version to publish (e.g., `0.1.0`)
   - **Repository URL**: Your private PyPI repository URL
   - **Skip Tests**: Optional, skip running tests
   - **Skip Update**: Optional, skip updating service dependencies
   - **Dry Run**: Optional, build and check without publishing

#### Using Git Tags

```bash
# Create and push a version tag
git tag -a "unison-common-v0.1.0" -m "Release unison-common v0.1.0"
git push origin "unison-common-v0.1.0"
```

### 2. Local Publishing

#### Prerequisites

```bash
# Install build dependencies
pip install build twine wheel
```

#### Using the Publish Script

```bash
# Navigate to unison-common directory
cd unison-common

# Run the publish script
python publish.py \
  --repository-url "https://your-private-pypi.com/simple/" \
  --username "your-username" \
  --password "your-password"
```

#### Manual Publishing

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build the package
python -m build

# Check the package
python -m twine check dist/*

# Publish to private index
python -m twine upload \
  --repository-url "https://your-private-pypi.com/simple/" \
  --username "your-username" \
  --password "your-password" \
  dist/*
```

## 🔧 Configuration

### Required Secrets

For automated publishing, configure these repository secrets:

- **`PRIVATE_PYPI_URL`**: Your private PyPI repository URL
- **`PRIVATE_PYPI_USERNAME`**: Repository username
- **`PRIVATE_PYPI_PASSWORD`**: Repository password or API token

### Setting up Secrets

1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Add each of the required secrets above

## 📋 Version Management

### Version Format

Use semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Updating Version

Edit `pyproject.toml`:

```toml
[project]
name = "unison-common"
version = "0.1.0"  # Update this line
```

### Version Validation

The publish script automatically validates that the version exists and is properly formatted.

## 🔄 Service Updates

### Automatic Updates

When publishing via GitHub Actions, the workflow automatically updates `requirements.txt` files in:

- `unison-orchestrator/requirements.txt`
- `unison-context-graph/requirements.txt`
- `unison-consent/requirements.txt`
- `unison-policy/requirements.txt`

### Manual Updates

If you need to update manually:

```bash
# Update each service's requirements.txt
sed -i 's/unison-common==.*/unison-common==0.1.0/' ../unison-orchestrator/requirements.txt
sed -i 's/unison-common==.*/unison-common==0.1.0/' ../unison-context-graph/requirements.txt
sed -i 's/unison-common==.*/unison-common==0.1.0/' ../unison-consent/requirements.txt
sed -i 's/unison-common==.*/unison-common==0.1.0/' ../unison-policy/requirements.txt
```

## 🧪 Testing Before Publishing

### Local Testing

```bash
# Run the test suite
cd unison-common
python -m pytest tests/ -v

# Build and check locally
python -m build
python -m twine check dist/*
```

### Dry Run Mode

Test the entire publishing process without actually publishing:

```bash
python publish.py \
  --repository-url "https://your-private-pypi.com/simple/" \
  --dry-run
```

Or use GitHub Actions with the "Dry run" option enabled.

## 📊 Package Contents

The published package includes:

- **Source code**: All modules in `src/unison_common/`
- **Type information**: `py.typed` file for type checking
- **Dependencies**: All required dependencies specified in `pyproject.toml`
- **Metadata**: Package information, URLs, and classifiers

### Package Structure

```
unison-common-0.1.0.tar.gz
├── src/
│   └── unison_common/
│       ├── __init__.py
│       ├── auth.py
│       ├── tracing.py
│       ├── idempotency.py
│       ├── idempotency_middleware.py
│       ├── replay_store.py
│       ├── replay_endpoints.py
│       ├── http_client.py
│       ├── envelope.py
│       └── py.typed
├── pyproject.toml
├── README.md
├── LICENSE
└── MANIFEST.in
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Build Failures

```bash
# Clean and rebuild
rm -rf build/ dist/ *.egg-info/
python -m build
```

#### 2. Test Failures

```bash
# Check test environment
python -m pytest tests/ -v --tb=short

# Install test dependencies
pip install -e .[test]
```

#### 3. Upload Failures

```bash
# Check package before upload
python -m twine check dist/*

# Verify repository credentials
python -m twine upload --repository-url "https://your-pypi.com/simple/" dist/*
```

#### 4. Version Conflicts

```bash
# Check current version
grep "version = " pyproject.toml

# Ensure version is not already published
python -m twine check dist/*
```

### Debug Mode

Run the publish script with verbose output:

```bash
python -u publish.py --repository-url "https://your-pypi.com/simple/"
```

## 📈 Release Checklist

### Before Publishing

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Version number updated in `pyproject.toml`
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Dependencies are up-to-date
- [ ] Package builds successfully
- [ ] Package passes twine check

### After Publishing

- [ ] Git tag created and pushed
- [ ] Service dependencies updated
- [ ] Services tested with new version
- [ ] GitHub release created (optional)
- [ ] Documentation updated with new version info

## 🏷️ Release Process Example

### Publishing v0.1.0

```bash
# 1. Update version
cd unison-common
sed -i 's/version = ".*"/version = "0.1.0"/' pyproject.toml

# 2. Run tests
python -m pytest tests/ -v

# 3. Build and check
python -m build
python -m twine check dist/*

# 4. Publish
python publish.py \
  --repository-url "https://your-private-pypi.com/simple/" \
  --username "your-username" \
  --password "your-password"

# 5. Create git tag
git tag -a "unison-common-v0.1.0" -m "Release unison-common v0.1.0"
git push origin "unison-common-v0.1.0"

# 6. Test in services
cd ../unison-orchestrator
pip install -r requirements.txt
python -c "import unison_common; print(unison_common.__version__)"
```

## 🔐 Security Considerations

- **Credentials**: Store PyPI credentials as GitHub secrets, not in code
- **Access Control**: Limit publishing permissions to trusted maintainers
- **Package Verification**: Always check packages before publishing
- **Dependency Scanning**: Regularly scan for security vulnerabilities

## 📚 Additional Resources

- [Python Packaging Guide](https://packaging.python.org/)
- [Twine Documentation](https://twine.readthedocs.io/)
- [PyPI Documentation](https://pypi.org/help/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
