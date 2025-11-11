import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing
from unison_common.http_client_tracing import TracingHTTPClient
from opentelemetry import trace
from opentelemetry.trace import SpanKind


def create_app():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="test-service")

    @app.get("/ping")
    def ping():
        return {"ok": True}

    return app


def test_tracing_middleware_adds_response_headers():
    initialize_tracing()
    app = create_app()
    client = TestClient(app)

    # No headers provided
    r = client.get("/ping")
    assert r.status_code == 200
    # Middleware should add correlation and trace headers
    assert "x-request-id" in r.headers
    assert "traceparent" in r.headers


def test_tracing_http_client_injects_headers():
    initialize_tracing()

    tracer = trace.get_tracer(__name__)
    # Create a span context to ensure traceparent is set
    with tracer.start_as_current_span("test-span", kind=SpanKind.CLIENT):
        client = TracingHTTPClient(request_id="req-123")
        headers = client._get_tracing_headers()  # using internal method for unit test

        assert headers.get("x-request-id") == "req-123"
        assert "traceparent" in headers and isinstance(headers["traceparent"], str) and len(headers["traceparent"]) > 0
