"""
unison-common - Shared Python utilities for the Unison platform
"""

__version__ = "0.1.0"

from .envelope import (
    validate_event_envelope,
    EnvelopeValidationError,
    validate_batch_envelopes,
    validate_event_envelope_with_schema,
    validate_event_envelope_with_details,
)

from .schema_validation import (
    validate_envelope_schema,
    validate_envelope_schema_with_details,
    is_schema_validation_available,
    get_envelope_schema,
    generate_envelope_documentation,
    EnvelopeSchemaValidator,
    SchemaValidationError,
)

from .auth import (
    verify_token,
    verify_service_token,
    require_roles,
    require_role,
    require_admin,
    require_operator,
    require_developer,
    require_user,
    create_service_token,
    verify_service_token_locally,
    SecurityContext,
    get_security_context,
    rate_limit,
    add_security_headers,
    get_cors_config,
    create_auth_middleware,
    AuthError,
    PermissionError,
)

from .idempotency import (
    IdempotencyConfig,
    IdempotencyRecord,
    IdempotencyManager,
    MemoryIdempotencyStore,
    RedisIdempotencyStore,
    get_idempotency_manager,
    initialize_idempotency,
    validate_idempotency_key,
    extract_idempotency_key,
)

from .idempotency_middleware import (
    IdempotencyMiddleware,
    IdempotencyKeyRequiredMiddleware,
    add_idempotency_headers,
    create_idempotency_response,
)

from .replay_store import (
    ReplayConfig,
    StoredEnvelope,
    ReplaySession,
    ReplayManager,
    MemoryReplayStore,
    get_replay_manager,
    initialize_replay,
)

from .replay_endpoints import (
    replay_trace_by_id,
    get_replay_history,
    get_trace_summary,
    list_traces,
    delete_trace,
    get_replay_statistics,
    get_replay_session,
    store_processing_envelope,
)

__all__ = [
    "validate_event_envelope",
    "EnvelopeValidationError",
    "validate_batch_envelopes",
    "validate_event_envelope_with_schema",
    "validate_event_envelope_with_details",
    "validate_envelope_schema",
    "validate_envelope_schema_with_details",
    "is_schema_validation_available",
    "get_envelope_schema",
    "generate_envelope_documentation",
    "EnvelopeSchemaValidator",
    "SchemaValidationError",
    "verify_token",
    "verify_service_token",
    "require_roles",
    "require_role",
    "require_admin",
    "require_operator",
    "require_developer",
    "require_user",
    "create_service_token",
    "verify_service_token_locally",
    "SecurityContext",
    "get_security_context",
    "rate_limit",
    "add_security_headers",
    "get_cors_config",
    "create_auth_middleware",
    "AuthError",
    "PermissionError",
    "IdempotencyConfig",
    "IdempotencyRecord",
    "IdempotencyManager",
    "MemoryIdempotencyStore",
    "RedisIdempotencyStore",
    "get_idempotency_manager",
    "initialize_idempotency",
    "validate_idempotency_key",
    "extract_idempotency_key",
    "IdempotencyMiddleware",
    "IdempotencyKeyRequiredMiddleware",
    "add_idempotency_headers",
    "create_idempotency_response",
    "ReplayConfig",
    "StoredEnvelope",
    "ReplaySession",
    "ReplayManager",
    "MemoryReplayStore",
    "get_replay_manager",
    "initialize_replay",
    "replay_trace_by_id",
    "get_replay_history",
    "get_trace_summary",
    "list_traces",
    "delete_trace",
    "get_replay_statistics",
    "get_replay_session",
    "store_processing_envelope",
]
