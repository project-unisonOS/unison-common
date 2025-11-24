"""
HTTP client with automatic tracing header propagation (P0.3)
"""

import httpx
import logging
import uuid
from typing import Optional, Dict, Any
from opentelemetry import trace
from opentelemetry.trace import SpanKind

logger = logging.getLogger(__name__)


class TracingHTTPClient:
    """
    HTTP client that automatically propagates tracing headers.
    
    Features:
    - Propagates x-request-id
    - Propagates W3C traceparent
    - Creates spans for outbound requests
    - Logs all HTTP calls with trace info
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        request_id: Optional[str] = None
    ):
        """
        Initialize tracing HTTP client.
        
        Args:
            base_url: Base URL for requests
            timeout: Request timeout in seconds
            request_id: Request ID to propagate
        """
        self.base_url = base_url
        self.timeout = timeout
        self.request_id = request_id
        self.tracer = trace.get_tracer(__name__)
    
    def _get_tracing_headers(self) -> Dict[str, str]:
        """
        Get headers for tracing propagation.
        
        Returns:
            Dict of tracing headers
        """
        headers = {}
        
        # Add x-request-id if available
        if self.request_id:
            headers["x-request-id"] = self.request_id
        
        # Add traceparent from current span
        current_span = trace.get_current_span()
        span_context = current_span.get_span_context() if current_span else None
        if span_context and span_context.is_valid:
            trace_id = format(span_context.trace_id, '032x')
            span_id = format(span_context.span_id, '016x')
            trace_flags = format(span_context.trace_flags, '02x')
            traceparent = f"00-{trace_id}-{span_id}-{trace_flags}"
            headers["traceparent"] = traceparent
        else:
            # Synthesize a traceparent when no span is active so downstream always sees one
            trace_id = uuid.uuid4().hex
            span_id = uuid.uuid4().hex[:16]
            headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
        
        return headers
    
    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make GET request with tracing.
        
        Args:
            url: Request URL
            params: Query parameters
            headers: Additional headers
            **kwargs: Additional httpx arguments
        
        Returns:
            HTTP response
        """
        return await self._request("GET", url, params=params, headers=headers, **kwargs)
    
    async def post(
        self,
        url: str,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make POST request with tracing.
        
        Args:
            url: Request URL
            json: JSON body
            data: Form data
            headers: Additional headers
            **kwargs: Additional httpx arguments
        
        Returns:
            HTTP response
        """
        return await self._request("POST", url, json=json, data=data, headers=headers, **kwargs)
    
    async def put(
        self,
        url: str,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make PUT request with tracing.
        
        Args:
            url: Request URL
            json: JSON body
            headers: Additional headers
            **kwargs: Additional httpx arguments
        
        Returns:
            HTTP response
        """
        return await self._request("PUT", url, json=json, headers=headers, **kwargs)
    
    async def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make DELETE request with tracing.
        
        Args:
            url: Request URL
            headers: Additional headers
            **kwargs: Additional httpx arguments
        
        Returns:
            HTTP response
        """
        return await self._request("DELETE", url, headers=headers, **kwargs)
    
    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """
        Make HTTP request with tracing.
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: httpx arguments
        
        Returns:
            HTTP response
        """
        # Merge tracing headers with provided headers
        tracing_headers = self._get_tracing_headers()
        provided_headers = kwargs.pop("headers", {})
        headers = {**tracing_headers, **provided_headers}
        
        # Resolve full URL
        full_url = url if url.startswith("http") else f"{self.base_url}{url}"
        
        # Create span for outbound request
        span_name = f"HTTP {method} {url}"
        
        with self.tracer.start_as_current_span(
            span_name,
            kind=SpanKind.CLIENT
        ) as span:
            # Add span attributes
            span.set_attribute("http.method", method)
            span.set_attribute("http.url", full_url)
            span.set_attribute("span.kind", "client")
            
            if self.request_id:
                span.set_attribute("request.id", self.request_id)
            
            # Log outbound request
            logger.debug(
                f"Outbound request: {method} {full_url}",
                extra={
                    "request_id": self.request_id,
                    "method": method,
                    "url": full_url,
                    "headers": headers
                }
            )
            
            try:
                # Make request
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.request(
                        method,
                        full_url,
                        headers=headers,
                        **kwargs
                    )
                
                # Add response info to span
                span.set_attribute("http.status_code", response.status_code)
                
                # Log response
                logger.debug(
                    f"Outbound response: {response.status_code}",
                    extra={
                        "request_id": self.request_id,
                        "status_code": response.status_code
                    }
                )
                
                return response
                
            except Exception as e:
                # Log error
                logger.error(
                    f"Outbound request failed: {str(e)}",
                    extra={
                        "request_id": self.request_id,
                        "error": str(e)
                    },
                    exc_info=True
                )
                
                # Record exception in span
                span.record_exception(e)
                span.set_attribute("error", True)
                
                raise


def create_tracing_client(
    base_url: Optional[str] = None,
    timeout: float = 30.0,
    request_id: Optional[str] = None
) -> TracingHTTPClient:
    """
    Create HTTP client with tracing support.
    
    Args:
        base_url: Base URL for requests
        timeout: Request timeout
        request_id: Request ID to propagate
    
    Returns:
        TracingHTTPClient instance
    """
    return TracingHTTPClient(base_url, timeout, request_id)
