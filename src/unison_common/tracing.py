"""
Distributed tracing and correlation utilities for Unison platform
"""

import uuid
import time
import logging
import os
from typing import Dict, Any, Optional, List
from contextlib import contextmanager
from functools import wraps

from opentelemetry import trace, context, baggage
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.propagate import inject, extract
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.propagators.jaeger import JaegerPropagator

logger = logging.getLogger(__name__)

class TracingConfig:
    """Configuration for OpenTelemetry tracing"""
    
    def __init__(self):
        self.service_name = os.getenv("OTEL_SERVICE_NAME", "unison-service")
        self.service_version = os.getenv("OTEL_SERVICE_VERSION", "1.0.0")
        self.environment = os.getenv("OTEL_ENVIRONMENT", "development")
        self.jaeger_endpoint = os.getenv("OTEL_JAEGER_ENDPOINT", "http://jaeger:14268/api/traces")
        self.otlp_endpoint = os.getenv("OTEL_OTLP_ENDPOINT", "http://jaeger:4317")
        self.sample_rate = float(os.getenv("OTEL_SAMPLE_RATE", "1.0"))
        self.enabled = os.getenv("OTEL_ENABLED", "true").lower() == "true"
        self.propagator = os.getenv("OTEL_PROPAGATOR", "b3")  # b3, jaeger, or tracecontext

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
        trace_id = headers.get("X-Request-Id") or headers.get("X-Trace-Id")
        span_id = headers.get("X-Span-Id")
        parent_span_id = headers.get("X-Parent-Span-Id")
        
        # Extract baggage items
        baggage = {}
        for key, value in headers.items():
            if key.startswith("X-Baggage-"):
                baggage_key = key[11:]  # Remove "X-Baggage-" prefix
                baggage[baggage_key] = value
        
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage
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
            # Set up tracer provider
            trace.set_tracer_provider(TracerProvider())
            tracer_provider = trace.get_tracer_provider()
            
            # Configure propagator
            if self.config.propagator == "b3":
                from opentelemetry.propagate import set_global_textmap
                set_global_textmap(B3MultiFormat())
            elif self.config.propagator == "jaeger":
                from opentelemetry.propagate import set_global_textmap
                set_global_textmap(JaegerPropagator())
            
            # Set up exporters
            if self.config.jaeger_endpoint:
                jaeger_exporter = JaegerExporter(
                    endpoint=self.config.jaeger_endpoint,
                    collector_endpoint=self.config.jaeger_endpoint,
                )
                tracer_provider.add_span_processor(
                    BatchSpanProcessor(jaeger_exporter)
                )
            
            if self.config.otlp_endpoint:
                otlp_exporter = OTLPSpanExporter(
                    endpoint=self.config.otlp_endpoint,
                    insecure=True
                )
                tracer_provider.add_span_processor(
                    BatchSpanProcessor(otlp_exporter)
                )
            
            # Get tracer
            self._tracer = trace.get_tracer(
                self.config.service_name,
                self.config.service_version
            )
            
            self._initialized = True
            logger.info(f"OpenTelemetry tracing initialized for {self.config.service_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry tracing: {e}")
            self.config.enabled = False
    
    def create_trace_context(self, headers: Dict[str, str] = None) -> TraceContext:
        """Create or extract trace context"""
        if headers:
            return TraceContext.from_headers(headers)
        else:
            return TraceContext()
    
    def start_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   attributes: Dict[str, Any] = None) -> trace.Span:
        """Start a new span"""
        if not self._initialized:
            return NoOpSpan()
        
        return self._tracer.start_span(
            name=name,
            kind=kind,
            attributes=attributes or {}
        )
    
    @contextmanager
    def span(self, name: str, kind: SpanKind = SpanKind.INTERNAL,
             attributes: Dict[str, Any] = None):
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
        if not headers:
            headers = {}
        
        if self._initialized:
            inject(headers)
        
        # Always add our custom correlation headers
        trace_context = self.create_trace_context(headers)
        headers.update(trace_context.to_headers())
        
        return headers
    
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
    if get_tracer()._initialized:
        HTTPXClientInstrumentor.instrument()

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
    return request.state.get("correlation_id") or str(uuid.uuid4())

def get_trace_context(request) -> TraceContext:
    """Get trace context from FastAPI request"""
    return request.state.get("trace_context") or TraceContext()

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
