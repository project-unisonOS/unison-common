import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
from opentelemetry import trace
from opentelemetry.trace import SpanKind


def create_echo_app():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="test-echo")

    @app.get("/echo-headers")
    def echo_headers(request: Request):
        # Return subset of headers we care about
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
        }

    return app


def test_incoming_headers_propagate_through_middleware():
    initialize_tracing()
    tracer = get_tracer()

    # Create headers via tracer injection within an active client span
    with trace.get_tracer(__name__).start_as_current_span("test-client", kind=SpanKind.CLIENT):
        headers = tracer.inject_headers({})

    app = create_echo_app()
    client = TestClient(app)

    r = client.get("/echo-headers", headers=headers)
    assert r.status_code == 200

    body = r.json()
    # Server should receive the injected headers
    injected_request_id = headers.get("x-request-id") or headers.get("X-Request-Id")
    assert body.get("x-request-id") == injected_request_id
    assert isinstance(body.get("traceparent"), str) and len(body.get("traceparent")) > 0
