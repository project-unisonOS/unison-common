"""
Distributed tracing and correlation utilities for Unison platform
"""

import uuid
import time
import logging
import os
import inspect
from typing import Dict, Any, Optional, List
from contextlib import contextmanager
from functools import wraps
import httpx

from opentelemetry import trace, context, baggage
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.propagate import inject, extract, set_global_textmap
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.propagators.jaeger import JaegerPropagator
from opentelemetry import baggage as otel_baggage

logger = logging.getLogger(__name__)


def _format_traceparent_from_context(span_context=None, trace_id_override: Optional[str] = None) -> str:
    """Create a traceparent header string from a span context or explicit trace id."""
    if span_context and getattr(span_context, "is_valid", False):
        trace_id = format(span_context.trace_id, "032x")
        span_id = format(span_context.span_id, "016x")
        trace_flags = format(span_context.trace_flags, "02x")
    else:
        trace_id = (trace_id_override or uuid.uuid4().hex).replace("-", "")[:32].ljust(32, "0")
        span_id = uuid.uuid4().hex[:16]
        trace_flags = "01"

    return f"00-{trace_id}-{span_id}-{trace_flags}"

class TracingConfig:
    """Configuration for OpenTelemetry tracing"""
    
    def __init__(
        self,
        service_name: Optional[str] = None,
        service_version: Optional[str] = None,
        environment: Optional[str] = None,
        jaeger_endpoint: Optional[str] = None,
        otlp_endpoint: Optional[str] = None,
        sample_rate: Optional[float] = None,
        enabled: Optional[bool] = None,
        propagator: Optional[str] = None,
    ):
        self.service_name = service_name or os.getenv("OTEL_SERVICE_NAME", "unison-service")
        self.service_version = service_version or os.getenv("OTEL_SERVICE_VERSION", "1.0.0")
        self.environment = environment or os.getenv("OTEL_ENVIRONMENT", "development")
        self.jaeger_endpoint = jaeger_endpoint or os.getenv("OTEL_JAEGER_ENDPOINT", "http://jaeger:14268/api/traces")
        self.otlp_endpoint = otlp_endpoint or os.getenv("OTEL_OTLP_ENDPOINT", "http://jaeger:4317")
        self.sample_rate = float(sample_rate if sample_rate is not None else os.getenv("OTEL_SAMPLE_RATE", "1.0"))
        self.enabled = enabled if enabled is not None else os.getenv("OTEL_ENABLED", "true").lower() == "true"
        self.propagator = propagator or os.getenv("OTEL_PROPAGATOR", "b3")  # tracecontext, b3, or jaeger

class TraceContext:
    """Trace context for correlation and distributed tracing"""
    
    def __init__(self, trace_id: str = None, span_id: str = None, 
                 parent_span_id: str = None, baggage: Dict[str, Any] = None):
        self.trace_id = trace_id or str(uuid.uuid4())
        self.span_id = span_id or str(uuid.uuid4())[:16]
        self.parent_span_id = parent_span_id
        self.baggage = baggage or {}
        self.start_time = time.time()
        
    def to_headers(self) -> Dict[str, str]:
        """Convert trace context to HTTP headers"""
        headers = {
            "X-Request-Id": self.trace_id,
            "X-Trace-Id": self.trace_id,
            "X-Span-Id": self.span_id,
        }
        
        if self.parent_span_id:
            headers["X-Parent-Span-Id"] = self.parent_span_id
        
        # Add baggage items
        for key, value in self.baggage.items():
            headers[f"X-Baggage-{key}"] = str(value)
        
        return headers
    
    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "TraceContext":
        """Create trace context from HTTP headers"""
        # Prefer W3C traceparent/baggage when present
        carrier = {k.lower(): v for k, v in headers.items()}
        ctx = extract(carrier)
        span_ctx = trace.get_current_span(ctx).get_span_context()
        ot_baggage = otel_baggage.get_all(context=ctx)
        baggage_map = {k: v for k, v in ot_baggage.items()}

        # Custom baggage header (user_id=123,foo=bar)
        baggage_header = headers.get("baggage") or headers.get("Baggage") or ""
        for part in baggage_header.split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                baggage_map[k.strip()] = v.strip()

        # Also honor custom X-Baggage-* if present
        for key, value in headers.items():
            normalized = key.lower()
            if normalized.startswith("x-baggage-"):
                baggage_key = key.split("-", 2)[-1] if "-" in key else normalized[11:]
                baggage_map[baggage_key] = value

        # Prefer explicit headers for IDs when provided
        trace_id = headers.get("X-Trace-Id") or headers.get("X-Request-Id")
        span_id = headers.get("X-Span-Id")
        # Parse explicit traceparent if provided to seed trace id
        tp_header = headers.get("traceparent") or headers.get("Traceparent")
        if not trace_id and tp_header:
            parts = tp_header.split("-")
            if len(parts) >= 3:
                trace_id = parts[1]
                if len(parts) > 2:
                    span_id = span_id or parts[2]
        if not trace_id and span_ctx and span_ctx.is_valid:
            trace_id = format(span_ctx.trace_id, "032x")
            span_id = span_id or format(span_ctx.span_id, "016x")
        parent_span_id = headers.get("X-Parent-Span-Id")

        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage_map,
        )

class DistributedTracer:
    """Main distributed tracing class"""
    
    def __init__(self, config: TracingConfig = None):
        self.config = config or TracingConfig()
        self._tracer = None
        self._initialized = False
        
        if self.config.enabled:
            self._initialize_tracing()
    
    def _initialize_tracing(self):
        """Initialize OpenTelemetry tracing"""
        try:
            # Configure resource with semantic attributes
            resource = Resource.create({
                ResourceAttributes.SERVICE_NAME: self.config.service_name,
                ResourceAttributes.SERVICE_VERSION: self.config.service_version,
                ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.config.environment,
            })

            # Configure sampler from sample_rate (0.0-1.0)
            ratio = max(0.0, min(1.0, float(self.config.sample_rate)))
            sampler = ParentBased(TraceIdRatioBased(ratio))

            # Set up tracer provider (allow override so tests can reconfigure)
            new_provider = TracerProvider(resource=resource, sampler=sampler)
            try:
                trace.set_tracer_provider(new_provider, log_warnings=False)  # type: ignore[arg-type]
            except TypeError:
                # Older versions do not support log_warnings
                trace.set_tracer_provider(new_provider)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to set tracer provider cleanly, forcing override: %s", exc)
                try:
                    trace._TRACER_PROVIDER = new_provider  # type: ignore[attr-defined]
                except Exception:
                    pass
            tracer_provider = trace.get_tracer_provider()
            attrs = getattr(getattr(tracer_provider, "resource", None), "attributes", {}) or {}
            if attrs.get(ResourceAttributes.SERVICE_NAME) != self.config.service_name:
                try:
                    trace._TRACER_PROVIDER = new_provider  # type: ignore[attr-defined]
                    tracer_provider = new_provider
                except Exception:
                    pass
            
            # Configure propagator
            if self.config.propagator == "b3":
                set_global_textmap(B3MultiFormat())
            elif self.config.propagator == "jaeger":
                set_global_textmap(JaegerPropagator())
            else:
                # Default to W3C tracecontext
                set_global_textmap(TraceContextTextMapPropagator())
            
            # Set up exporters (skip during tests to avoid hanging on shutdown)
            disable_exporter = os.getenv("PYTEST_CURRENT_TEST") is not None or os.getenv(
                "UNISON_DISABLE_OTEL_EXPORTER", "false"
            ).lower() == "true"
            if self.config.otlp_endpoint and not disable_exporter:
                otlp_exporter = OTLPSpanExporter(
                    endpoint=self.config.otlp_endpoint,
                    insecure=True
                )
                tracer_provider.add_span_processor(
                    BatchSpanProcessor(otlp_exporter)
                )
            
            # Get tracer
            self._tracer = tracer_provider.get_tracer(self.config.service_name, self.config.service_version)
            
            self._initialized = True
            logger.info(f"OpenTelemetry tracing initialized for {self.config.service_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry tracing: {e}")
            self.config.enabled = False
    
    def create_trace_context(self, headers: Dict[str, str] = None) -> TraceContext:
        """Create or extract trace context"""
        if headers:
            return TraceContext.from_headers(headers)
        return TraceContext()
    
    def start_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, attributes: Dict[str, Any] = None) -> trace.Span:
        """Start a new span"""
        if not self._initialized:
            return NoOpSpan()
        
        return self._tracer.start_span(
            name=name,
            kind=kind,
            attributes=attributes or {}
        )
    
    @contextmanager
    def span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, attributes: Dict[str, Any] = None):
        """Context manager for spans"""
        span = self.start_span(name, kind, attributes)
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise
        finally:
            span.end()
    
    def inject_headers(self, headers: Dict[str, str] = None) -> Dict[str, str]:
        """Inject trace context into headers"""
        carrier = dict(headers) if headers else {}
        incoming_request_id = carrier.get("x-request-id") or carrier.get("X-Request-Id")

        if self._initialized:
            try:
                inject(carrier)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Skipping OpenTelemetry header inject: %s", exc)

        current_span = trace.get_current_span()
        span_ctx = current_span.get_span_context() if current_span else None
        span_ctx_valid = bool(span_ctx and getattr(span_ctx, "is_valid", False))

        # Ensure traceparent is always present for downstream services
        if "traceparent" not in carrier:
            carrier["traceparent"] = _format_traceparent_from_context(span_ctx, trace_id_override=incoming_request_id)

        # Always add our custom correlation headers
        trace_context_obj = self.create_trace_context(carrier)
        request_id = incoming_request_id or trace_context_obj.trace_id
        carrier.setdefault("x-request-id", request_id)
        carrier.setdefault("X-Request-Id", request_id)
        carrier.setdefault("x-trace-id", request_id)
        carrier.setdefault("X-Trace-Id", request_id)

        # Keep span id aligned with current span if available
        if span_ctx_valid:
            carrier.setdefault("X-Span-Id", format(span_ctx.span_id, "016x"))
        else:
            carrier.setdefault("X-Span-Id", trace_context_obj.span_id)

        return carrier
    
    def extract_context(self, headers: Dict[str, str]) -> TraceContext:
        """Extract trace context from headers"""
        if not self._initialized:
            return self.create_trace_context(headers)
        
        # Extract OpenTelemetry context
        ctx = extract(headers)
        
        # Create our trace context
        return self.create_trace_context(headers)

class NoOpSpan:
    """No-op span for when tracing is disabled"""
    
    def set_attribute(self, key, value):
        pass
    
    def set_status(self, status):
        pass
    
    def record_exception(self, exception):
        pass
    
    def end(self):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

# Global tracer instance
_tracer = None

def get_tracer() -> DistributedTracer:
    """Get global tracer instance"""
    global _tracer
    if _tracer is None:
        _tracer = DistributedTracer()
    return _tracer

def initialize_tracing(config: TracingConfig = None):
    """Initialize global tracing"""
    global _tracer
    _tracer = DistributedTracer(config)

def instrument_fastapi(app):
    """Instrument FastAPI application"""
    if get_tracer()._initialized:
        FastAPIInstrumentor.instrument_app(app)

def instrument_httpx():
    """Instrument HTTPX client"""
    if not get_tracer()._initialized:
        return

    if not inspect.isclass(httpx.AsyncClient):
        logger.warning("HTTPX instrumentation skipped: httpx.AsyncClient patched to non-class")
        return

    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

    HTTPXClientInstrumentor().instrument()

def trace_span(name: str = None, kind: SpanKind = SpanKind.INTERNAL):
    """Decorator for tracing functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            span_name = name or f"{func.__module__}.{func.__name__}"
            
            with tracer.span(span_name, kind) as span:
                # Add function attributes
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

def trace_async_span(name: str = None, kind: SpanKind = SpanKind.INTERNAL):
    """Decorator for tracing async functions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            span_name = name or f"{func.__module__}.{func.__name__}"
            
            with tracer.span(span_name, kind) as span:
                # Add function attributes
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                return await func(*args, **kwargs)
        
        return wrapper
    return decorator

def add_span_attributes(attributes: Dict[str, Any]):
    """Add attributes to current span"""
    span = trace.get_current_span()
    if span and span.is_recording():
        for key, value in attributes.items():
            span.set_attribute(key, value)

def add_span_event(name: str, attributes: Dict[str, Any] = None):
    """Add event to current span"""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.add_event(name, attributes or {})

def set_span_error(error: Exception, message: str = None):
    """Set current span as error"""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_status(Status(StatusCode.ERROR, message or str(error)))
        span.record_exception(error)

def set_span_ok(message: str = None):
    """Set current span as OK"""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_status(Status(StatusCode.OK, message))

class CorrelationMiddleware:
    """FastAPI middleware for correlation ID handling"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Extract correlation ID from headers
            headers = dict(scope.get("headers", []))
            
            # Convert bytes to strings
            str_headers = {}
            for key, value in headers.items():
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                str_headers[key] = value
            
            # Get or create correlation ID
            correlation_id = (
                str_headers.get("x-request-id") or 
                str_headers.get("x-trace-id") or 
                str(uuid.uuid4())
            )
            
            # Add to state for access in endpoints
            scope["state"] = scope.get("state", {})
            scope["state"]["correlation_id"] = correlation_id
            scope["state"]["trace_context"] = get_tracer().create_trace_context(str_headers)
        
        await self.app(scope, receive, send)

def get_correlation_id(request) -> str:
    """Get correlation ID from FastAPI request"""
    return getattr(request.state, "correlation_id", None) or str(uuid.uuid4())

def get_trace_context(request) -> TraceContext:
    """Get trace context from FastAPI request"""
    state = getattr(request, "state", None)
    if isinstance(state, dict):
        ctx = state.get("trace_context")
    else:
        ctx = getattr(state, "trace_context", None)
    return ctx or TraceContext()

# Utility functions for common tracing patterns
def trace_http_request(method: str, url: str, status_code: int, 
                      duration_ms: float, headers: Dict[str, str] = None):
    """Trace HTTP request"""
    attributes = {
        "http.method": method,
        "http.url": url,
        "http.status_code": status_code,
        "http.duration_ms": duration_ms
    }
    
    if headers:
        for key, value in headers.items():
            if key.lower().startswith("x-"):
                attributes[f"http.header.{key.lower()}"] = value
    
    add_span_attributes(attributes)

def trace_service_call(service_name: str, operation: str, 
                      duration_ms: float, success: bool = True,
                      error: str = None):
    """Trace service call"""
    attributes = {
        "service.name": service_name,
        "service.operation": operation,
        "service.duration_ms": duration_ms,
        "service.success": success
    }
    
    if error:
        attributes["service.error"] = error
    
    add_span_attributes(attributes)

def trace_database_operation(query_type: str, table: str, 
                           duration_ms: float, success: bool = True,
                           error: str = None):
    """Trace database operation"""
    attributes = {
        "db.type": "redis",
        "db.operation": query_type,
        "db.table": table,
        "db.duration_ms": duration_ms,
        "db.success": success
    }
    
    if error:
        attributes["db.error"] = error
    
    add_span_attributes(attributes)
