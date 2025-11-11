import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
import httpx


def parse_trace_id(tp: str) -> str:
    try:
        parts = tp.split("-")
        if len(parts) >= 4:
            return parts[1]
    except Exception:
        pass
    return None


def make_provider_stub():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="provider-stub")

    @app.post("/chat")
    async def chat(request: Request):
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
        }

    return app


def make_inference_app(provider_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="inference")

    @app.get("/infer")
    async def infer(request: Request):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        transport = httpx.ASGITransport(app=provider_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://provider.local") as client:
            r = await client.post("/chat", headers=headers, json={"prompt": "hi"})
            return r.json()

    return app


def make_orchestrator_app(inf_app: FastAPI):
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

        transport = httpx.ASGITransport(app=inf_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://inference.local") as client:
            r = await client.get("/infer", headers=headers)
            return r.json()

    return app


@pytest.mark.anyio
async def test_multihop_inference_header_propagation():
    initialize_tracing()
    provider_app = make_provider_stub()
    inf_app = make_inference_app(provider_app)
    orch_app = make_orchestrator_app(inf_app)

    client = TestClient(orch_app)

    req_id = "golden-path-req-inference"
    r = client.get("/orch", headers={"x-request-id": req_id})
    assert r.status_code == 200
    body = r.json()

    # Provider observed headers should match orchestrator's x-request-id and have traceparent
    assert body.get("x-request-id") == req_id
    assert isinstance(body.get("traceparent"), str) and len(body.get("traceparent")) > 0
