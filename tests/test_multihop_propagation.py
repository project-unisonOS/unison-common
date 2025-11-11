import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
import httpx


def make_context_app():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="context")

    @app.get("/ctx")
    async def ctx(request: Request):
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
        }

    return app


def make_policy_app(context_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="policy")

    @app.get("/pol")
    async def pol(request: Request):
        # Forward incoming headers with tracer injection
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        transport = httpx.ASGITransport(app=context_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://context.local") as client:
            r = await client.get("/ctx", headers=headers)
            payload = r.json()
            # Echo back what context observed so orchestrator test can assert
            return payload

    return app


def make_orchestrator_app(policy_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="orchestrator")

    @app.get("/orch")
    async def orch(request: Request):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        transport = httpx.ASGITransport(app=policy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://policy.local") as client:
            r = await client.get("/pol", headers=headers)
            return r.json()

    return app


@pytest.mark.anyio
async def test_multihop_header_propagation_orchestrator_policy_context():
    initialize_tracing()
    ctx_app = make_context_app()
    pol_app = make_policy_app(ctx_app)
    orch_app = make_orchestrator_app(pol_app)

    client = TestClient(orch_app)

    req_id = "golden-path-req-1"
    r = client.get("/orch", headers={"x-request-id": req_id})
    assert r.status_code == 200
    body = r.json()

    # Context observed headers should match the orchestrator's incoming x-request-id and have a traceparent
    assert body.get("x-request-id") == req_id
    assert isinstance(body.get("traceparent"), str) and len(body.get("traceparent")) > 0
