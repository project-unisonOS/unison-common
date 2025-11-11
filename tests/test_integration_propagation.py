import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
import httpx


def make_downstream_app():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="downstream")

    @app.get("/down")
    async def down(request: Request):
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
        }

    return app


def make_upstream_app(down_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="upstream")

    @app.get("/up")
    async def up(request: Request):
        # Inject tracing headers (includes x-request-id from current context)
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        # Explicitly forward incoming request id for correlation
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        # Call downstream using in-memory ASGI transport
        transport = httpx.ASGITransport(app=down_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://down.local") as client:
            r = await client.get("/down", headers=headers)
            return r.json()

    return app


@pytest.mark.anyio
async def test_end_to_end_header_propagation():
    initialize_tracing()
    down_app = make_downstream_app()
    up_app = make_upstream_app(down_app)

    client = TestClient(up_app)

    # Provide a stable request id on ingress
    req_id = "test-corr-123"
    r = client.get("/up", headers={"x-request-id": req_id})
    assert r.status_code == 200
    body = r.json()

    # Downstream should see the same request id and a valid traceparent
    assert body.get("x-request-id") == req_id
    assert isinstance(body.get("traceparent"), str) and len(body.get("traceparent")) > 0
