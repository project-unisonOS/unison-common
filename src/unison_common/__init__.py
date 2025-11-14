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

from .consent import (
    ConsentScopes,
    verify_consent_grant,
    require_consent,
    check_consent_header,
    clear_consent_cache,
)

from .performance import (
    HTTPConnectionPool,
    get_http_client,
    get_sync_http_client,
    ResponseCache,
    get_auth_cache,
    get_policy_cache,
    cached,
    RateLimiter,
    get_user_rate_limiter,
    get_endpoint_rate_limiter,
    PerformanceMonitor,
    get_performance_monitor,
)

from .monitoring import (
    PrometheusMetrics,
    get_prometheus_metrics,
    HealthCheck,
    HealthStatus,
    initialize_health_check,
    get_health_check,
    log_metric,
    log_event,
    log_error,
)

from .auth_rs256 import (
    JWKSClient,
    RS256TokenVerifier,
    initialize_verifier,
    get_verifier,
    verify_token,
    verify_token_safe,
)

from .consent_rs256 import (
    ConsentVerifier,
    initialize_consent_verifier,
    get_consent_verifier,
    verify_consent_grant as verify_consent_grant_rs256,
    check_consent_header as check_consent_header_rs256,
    ConsentScopes as ConsentScopesRS256,
)

from .tracing_middleware import (
    TracingMiddleware,
    format_traceparent,
    get_request_id,
    add_request_id_to_logs,
)

from .http_client_tracing import (
    TracingHTTPClient,
    create_tracing_client,
)

from .durability import (
    DurabilityConfig,
    DurabilityManager,
    DurabilityMetrics,
    PIIScrubber,
    RecoveryManager,
    TTLManager,
    WALManager,
)

from .datetime_utils import (
    now_utc,
    isoformat_utc,
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
    "ConsentScopes",
    "verify_consent_grant",
    "require_consent",
    "check_consent_header",
    "clear_consent_cache",
    "HTTPConnectionPool",
    "get_http_client",
    "get_sync_http_client",
    "ResponseCache",
    "get_auth_cache",
    "get_policy_cache",
    "cached",
    "RateLimiter",
    "get_user_rate_limiter",
    "get_endpoint_rate_limiter",
    "PerformanceMonitor",
    "get_performance_monitor",
    "PrometheusMetrics",
    "get_prometheus_metrics",
    "HealthCheck",
    "HealthStatus",
    "initialize_health_check",
    "get_health_check",
    "log_metric",
    "log_event",
    "log_error",
    "JWKSClient",
    "RS256TokenVerifier",
    "initialize_verifier",
    "get_verifier",
    "verify_token",
    "verify_token_safe",
    "ConsentVerifier",
    "initialize_consent_verifier",
    "get_consent_verifier",
    "verify_consent_grant_rs256",
    "check_consent_header_rs256",
    "ConsentScopesRS256",
    "TracingMiddleware",
    "format_traceparent",
    "get_request_id",
    "add_request_id_to_logs",
    "TracingHTTPClient",
    "create_tracing_client",
    "DurabilityConfig",
    "DurabilityManager",
    "DurabilityMetrics",
    "PIIScrubber",
    "RecoveryManager",
    "TTLManager",
    "WALManager",
    "now_utc",
    "isoformat_utc",
]
