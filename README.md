# unison-common

Shared Python utilities for the Unison platform.

This package is intended to be imported by all Unison services (orchestrator, context, storage, policy, etc).

## Status
Core library (active) — shared middleware/utilities consumed by Python services.

## 📦 Package Information

**Version**: 0.1.0  
**Python**: >=3.12  
**License**: Apache-2.0  

## 🚀 Features

### Core Components

- **Authentication & Authorization**: JWT verification, role-based access control, security utilities
- **Distributed Tracing**: OpenTelemetry integration, correlation ID propagation, trace context management
- **Idempotency**: Request deduplication, middleware for FastAPI, Redis and memory stores
- **Event Replay**: Envelope storage, trace replay functionality, session management
- **HTTP Client**: Retry logic, tracing integration, error handling
- **Envelope Validation**: Schema validation, shape and required field checking

### Current Contents

- Event envelope validation (shape and required fields) aligned with `unison-docs/dev/specs/event-envelope.schema.json`
- Authentication middleware and JWT utilities
- Distributed tracing with OpenTelemetry
- Idempotency middleware for duplicate request prevention
- Event replay store and endpoints
- HTTP client with retry and tracing
- Security utilities and rate limiting

## 📥 Installation

### From Private PyPI

```bash
pip install unison-common==0.1.0 \
  --index-url https://your-private-pypi.com/simple/
```

### From Source

```bash
git clone https://github.com/project-unisonOS/unison.git
cd unison/unison-common
pip install -e .
```

### With Test Dependencies

```bash
pip install -e .[test]
```

## Testing
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -e .[test]
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```

## 🔧 Usage

### Authentication

```python
from unison_common import verify_token, require_admin
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/admin")
async def admin_endpoint(current_user: dict = Depends(require_admin)):
    return {"message": "Admin access granted", "user": current_user}
```

### Distributed Tracing

```python
from unison_common import (
    initialize_tracing, 
    TracingConfig,
    trace_async_span,
    get_trace_context
)

# Initialize tracing
config = TracingConfig()
config.service_name = "my-service"
initialize_tracing(config)

# Use in endpoints
@app.get("/api/data")
@trace_async_span("my_service.get_data")
async def get_data():
    trace_context = get_trace_context()
    return {"trace_id": trace_context.trace_id}
```

### Idempotency

```python
from unison_common import (
    IdempotencyMiddleware,
    initialize_idempotency,
    IdempotencyConfig
)

# Initialize idempotency
config = IdempotencyConfig()
config.default_ttl_seconds = 24 * 60 * 60  # 24 hours
initialize_idempotency(config)

# Add middleware to FastAPI
app.add_middleware(IdempotencyMiddleware, ttl_seconds=24 * 60 * 60)
```

### Event Replay

```python
from unison_common import (
    store_processing_envelope,
    get_replay_manager
)

# Store envelope during processing
store_processing_envelope(
    envelope_data={"message": "hello", "source": "api"},
    trace_id="trace-123",
    correlation_id="corr-456",
    event_type="api_request",
    source="my-service",
    user_id="user-123"
)

# Replay functionality
manager = get_replay_manager()
history = manager.get_replay_history("trace-123")
```

### Context Baton (per-request capability token)

```python
from unison_common import BatonService, BatonMiddleware
from fastapi import FastAPI

service = BatonService()
token = service.issue(
    subject="person-123",
    scopes=["ingest", "replay"],
    audience=["orchestrator"],
    ttl_seconds=300,
)

app = FastAPI()
# Validates signature/expiry when X-Context-Baton header is present
app.add_middleware(BatonMiddleware, service=service, required_scopes=["ingest"])
```

Keys are stored at `BATON_KEY_PATH` (default `/tmp/unison_baton_ed25519.pem`).
Tokens are Ed25519-signed JSON envelopes containing subject, scopes, audience,
TTL, provenance, and optional metadata.

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_tracing.py -v
python -m pytest tests/test_idempotency.py -v
python -m pytest tests/test_replay.py -v

# Run with coverage
python -m pytest tests/ --cov=unison_common --cov-report=html
```

## 📚 Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/project-unisonOS/unison.git
cd unison/unison-common

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .[test]

# Install development tools
pip install black flake8 mypy pytest-cov
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Run all quality checks
python -m pytest tests/ && black --check src/ tests/ && flake8 src/ tests/ && mypy src/
```

## 🚀 Publishing

### Automated Publishing

The package can be published automatically using GitHub Actions:

1. Go to Actions → "Publish unison-common"
2. Click "Run workflow"
3. Fill in version and repository URL
4. Choose whether to run as dry run

See [PUBLISHING.md](./PUBLISHING.md) for detailed instructions.

### Manual Publishing

```bash
# Build package
python -m build

# Check package
python -m twine check dist/*

# Publish to private index
python -m twine upload \
  --repository-url https://your-private-pypi.com/simple/ \
  --username your-username \
  --password your-password \
  dist/*
```

## 📋 Dependencies

### Runtime Dependencies

- `fastapi>=0.115.0` - Web framework
- `httpx>=0.27.2` - HTTP client
- `python-jose[cryptography]>=3.3.0` - JWT handling
- `bleach>=6.0.0` - HTML sanitization
- `redis>=5.0.0` - Redis client
- `opentelemetry-*>=1.21.0` - Distributed tracing

### Development Dependencies

- `pytest>=8.3.3` - Testing framework
- `pytest-asyncio>=0.24.0` - Async testing support

## 🔗 Related Projects

- [unison-orchestrator](../unison-orchestrator/) - Main orchestration service
- [unison-context-graph](../unison-context-graph/) - Context management service
- [unison-consent](../unison-consent/) - Consent management service
- [unison-policy](../unison-policy/) - Policy management service

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/project-unisonOS/unison/issues)
- **Documentation**: [Project Documentation](https://github.com/project-unisonOS/unison/blob/main/README.md)
- **Discussions**: [GitHub Discussions](https://github.com/project-unisonOS/unison/discussions)
