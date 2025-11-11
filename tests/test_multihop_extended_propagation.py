import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
import httpx


def parse_trace_id(tp: str) -> str:
    # traceparent format: version-traceid-spanid-flags
    # example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    try:
        parts = tp.split("-")
        if len(parts) >= 4:
            return parts[1]
    except Exception:
        pass
    return None


def make_storage_app():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="storage")

    @app.get("/st")
    async def st(request: Request):
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
        }

    return app


def make_context_app(storage_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="context")

    @app.get("/ctx")
    async def ctx(request: Request):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        # Call storage
        transport = httpx.ASGITransport(app=storage_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://storage.local") as client:
            rs = await client.get("/st", headers=headers)
            storage_obs = rs.json()

        # Return both what context saw (request) and storage observation
        return {
            "context": {
                "x-request-id": request.headers.get("x-request-id"),
                "traceparent": request.headers.get("traceparent"),
            },
            "storage": storage_obs,
        }

    return app


def make_policy_app(context_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="policy")

    @app.get("/pol")
    async def pol(request: Request):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        transport = httpx.ASGITransport(app=context_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://context.local") as client:
            rc = await client.get("/ctx", headers=headers)
            payload = rc.json()
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
            rp = await client.get("/pol", headers=headers)
            return rp.json()

    return app


@pytest.mark.anyio
async def test_multihop_extended_orchestrator_policy_context_storage():
    initialize_tracing()
    storage_app = make_storage_app()
    context_app = make_context_app(storage_app)
    policy_app = make_policy_app(context_app)
    orch_app = make_orchestrator_app(policy_app)

    client = TestClient(orch_app)

    req_id = "golden-path-req-extended"
    r = client.get("/orch", headers={"x-request-id": req_id})
    assert r.status_code == 200
    body = r.json()

    # Extract observations
    ctx_obs = body.get("context", {})
    st_obs = body.get("storage", {})

    # All hops should see the same request id
    assert ctx_obs.get("x-request-id") == req_id
    assert st_obs.get("x-request-id") == req_id

    # All hops should have a traceparent with the same trace-id
    ctx_tp = ctx_obs.get("traceparent")
    st_tp = st_obs.get("traceparent")
    assert isinstance(ctx_tp, str) and len(ctx_tp) > 0
    assert isinstance(st_tp, str) and len(st_tp) > 0

    ctx_tid = parse_trace_id(ctx_tp)
    st_tid = parse_trace_id(st_tp)
    assert ctx_tid is not None and st_tid is not None
    assert ctx_tid == st_tid
