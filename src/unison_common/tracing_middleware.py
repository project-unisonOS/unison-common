"""
Distributed tracing middleware for Unison platform (P0.3)

Handles x-request-id generation and W3C traceparent propagation.
"""

import uuid
import logging
from typing import Callable, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from opentelemetry import trace
from opentelemetry.trace import SpanKind
from opentelemetry.propagate import extract

from unison_common.tracing import _format_traceparent_from_context

logger = logging.getLogger(__name__)


class TracingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for distributed tracing with x-request-id and traceparent.
    
    Features:
    - Generates x-request-id if not present
    - Extracts and propagates W3C traceparent
    - Adds request ID to all logs
    - Creates spans for incoming requests
    """
    
    def __init__(self, app, service_name: str = "unison-service"):
        """
        Initialize tracing middleware.
        
        Args:
            app: FastAPI application
            service_name: Name of the service for tracing
        """
        super().__init__(app)
        self.service_name = service_name
        self.tracer = trace.get_tracer(__name__)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with tracing.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
        
        Returns:
            Response with tracing headers
        """
        # Generate or extract x-request-id
        request_id = request.headers.get("x-request-id")
        if not request_id:
            request_id = str(uuid.uuid4())
            logger.debug(f"Generated x-request-id: {request_id}")
        
        # Store request ID in request state for access in handlers
        request.state.request_id = request_id
        
        # Extract upstream context (supports both traceparent and configured propagator)
        carrier = {k.lower(): v for k, v in request.headers.items()}
        otel_ctx = extract(carrier)
        traceparent = request.headers.get("traceparent")
        
        # Create span for this request
        span_name = f"{request.method} {request.url.path}"
        
        with self.tracer.start_as_current_span(
            span_name,
            context=otel_ctx,
            kind=SpanKind.SERVER
        ) as span:
            # Add span attributes
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", str(request.url))
            span.set_attribute("http.route", request.url.path)
            span.set_attribute("service.name", self.service_name)
            span.set_attribute("request.id", request_id)
            
            # Add client info if available
            if request.client:
                span.set_attribute("http.client_ip", request.client.host)
            
            # Add user agent if available
            user_agent = request.headers.get("user-agent")
            if user_agent:
                span.set_attribute("http.user_agent", user_agent)
            
            # Log incoming request with trace info
            logger.info(
                f"Incoming request: {request.method} {request.url.path}",
                extra={
                    "request_id": request_id,
                    "traceparent": traceparent,
                    "method": request.method,
                    "path": request.url.path
                }
            )
            
            try:
                # Process request
                response = await call_next(request)
                
                # Add tracing headers to response
                response.headers["x-request-id"] = request_id
                response.headers["X-Request-Id"] = request_id
                
                # Get current span context for traceparent
                span_context = span.get_span_context()
                traceparent_header = _format_traceparent_from_context(span_context, trace_id_override=request_id)
                response.headers["traceparent"] = traceparent_header
                
                # Add status to span
                span.set_attribute("http.status_code", response.status_code)
                
                # Log response
                logger.info(
                    f"Response: {response.status_code}",
                    extra={
                        "request_id": request_id,
                        "status_code": response.status_code
                    }
                )
                
                return response
                
            except Exception as e:
                # Log error with trace info
                logger.error(
                    f"Request failed: {str(e)}",
                    extra={
                        "request_id": request_id,
                        "error": str(e)
                    },
                    exc_info=True
                )
                
                # Record exception in span
                span.record_exception(e)
                span.set_attribute("error", True)
                
                raise


def format_traceparent(span_context) -> str:
    """
    Format W3C traceparent header from span context.
    
    Format: 00-{trace_id}-{span_id}-{trace_flags}
    
    Args:
        span_context: OpenTelemetry span context
    
    Returns:
        Formatted traceparent string
    """
    trace_id = format(span_context.trace_id, '032x')
    span_id = format(span_context.span_id, '016x')
    trace_flags = format(span_context.trace_flags, '02x')
    
    return f"00-{trace_id}-{span_id}-{trace_flags}"


def get_request_id(request: Request) -> Optional[str]:
    """
    Get request ID from request state.
    
    Args:
        request: FastAPI request
    
    Returns:
        Request ID if available
    """
    return getattr(request.state, "request_id", None)


def add_request_id_to_logs(request_id: str):
    """
    Add request ID to log context.
    
    This is a helper for adding request ID to all log messages
    in the current context.
    
    Args:
        request_id: Request ID to add to logs
    """
    # This would typically use contextvars or similar
    # For now, just return a dict for extra parameter
    return {"request_id": request_id}
