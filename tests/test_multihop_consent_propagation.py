import pytest
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import httpx

from unison_common.tracing_middleware import TracingMiddleware
from unison_common.tracing import initialize_tracing, get_tracer
from unison_common.consent import require_consent, ConsentScopes, clear_consent_cache


def make_consent_service():
    app = FastAPI()

    @app.post("/introspect")
    async def introspect(request: Request):
        body = await request.json()
        token = body.get("token")
        if token == "valid-basic":
            return JSONResponse({"active": True, "sub": "user1", "scopes": [ConsentScopes.REPLAY_READ]})
        if token == "valid-admin":
            return JSONResponse({"active": True, "sub": "admin", "scopes": [ConsentScopes.ADMIN_ALL]})
        if token == "inactive":
            return JSONResponse({"active": False})
        return JSONResponse({"active": True, "scopes": []})

    return app


def make_downstream_service():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="downstream")

    @app.get("/data")
    async def data():
        return {"ok": True}

    return app


def make_mid_service(down_app: FastAPI, consent_transport: httpx.ASGITransport):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="mid")

    # Require consent here
    @app.get("/mid")
    async def mid(
        consent=Depends(require_consent([ConsentScopes.REPLAY_READ]))
    ):
        # Call downstream after consent passes
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        transport = httpx.ASGITransport(app=down_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://down.local") as client:
            rd = await client.get("/data", headers=headers)
            return rd.json()

    return app


def make_upstream_service(mid_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="upstream")

    @app.get("/start")
    async def start(request: Request):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        # Forward Authorization header if present (consent token)
        if request.headers.get("authorization"):
            headers["authorization"] = request.headers["authorization"]
        transport = httpx.ASGITransport(app=mid_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://mid.local") as client:
            rm = await client.get("/mid", headers=headers)
            if rm.status_code != 200:
                return JSONResponse(status_code=rm.status_code, content=rm.json())
            return rm.json()

    return app


def make_context_service_with_consent():
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="context-consent")

    @app.get("/ctx-consent")
    async def ctx_consent(
        request: Request,
        consent=Depends(require_consent([ConsentScopes.REPLAY_READ]))
    ):
        return {
            "x-request-id": request.headers.get("x-request-id"),
            "traceparent": request.headers.get("traceparent"),
            "consent": {
                "sub": consent.get("sub"),
                "scopes": consent.get("scopes", []),
            },
        }

    return app


def make_policy_service_with_consent(context_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="policy-consent")

    @app.get("/policy-consent")
    async def policy_consent(
        request: Request,
        consent=Depends(require_consent([ConsentScopes.REPLAY_READ]))
    ):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        # Forward consent tokens downstream
        auth_header = request.headers.get("authorization")
        if auth_header:
            headers["authorization"] = auth_header
        consent_header = request.headers.get("x-consent-grant") or request.headers.get("X-Consent-Grant")
        if consent_header:
            headers["x-consent-grant"] = consent_header
            headers["X-Consent-Grant"] = consent_header

        transport = httpx.ASGITransport(app=context_app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://context-consent.local"
        ) as client:
            response = await client.get("/ctx-consent", headers=headers)
            return response.json()

    return app


def make_orchestrator_service_with_consent(policy_app: FastAPI):
    app = FastAPI()
    app.add_middleware(TracingMiddleware, service_name="orchestrator-consent")

    @app.get("/orchestrate")
    async def orchestrate(
        request: Request,
        consent=Depends(require_consent([ConsentScopes.REPLAY_READ]))
    ):
        tracer = get_tracer()
        headers = tracer.inject_headers({})
        incoming_req_id = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
        if incoming_req_id:
            headers["x-request-id"] = incoming_req_id
            headers["X-Request-Id"] = incoming_req_id

        auth_header = request.headers.get("authorization")
        if auth_header:
            headers["authorization"] = auth_header
        consent_header = request.headers.get("x-consent-grant") or request.headers.get("X-Consent-Grant")
        if consent_header:
            headers["x-consent-grant"] = consent_header
            headers["X-Consent-Grant"] = consent_header

        transport = httpx.ASGITransport(app=policy_app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://policy-consent.local"
        ) as client:
            response = await client.get("/policy-consent", headers=headers)
            return response.json()

    return app


@pytest.mark.anyio
async def test_multihop_consent_allow_and_deny(monkeypatch):
    clear_consent_cache()
    initialize_tracing()

    # Consent stub
    consent_app = make_consent_service()
    consent_transport = httpx.ASGITransport(app=consent_app)

    # Patch AsyncClient to always use our consent ASGI transport, since
    # verify_consent_grant uses absolute URLs and would otherwise hit network.
    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", consent_transport)
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    down_app = make_downstream_service()
    mid_app = make_mid_service(down_app, consent_transport)
    up_app = make_upstream_service(mid_app)

    client = TestClient(up_app)

    # 1) Allowed with valid-basic (has REPLAY_READ)
    r_ok = client.get("/start", headers={"Authorization": "Bearer valid-basic"})
    assert r_ok.status_code == 200
    assert r_ok.json() == {"ok": True}

    # 2) Denied with missing scope
    r_denied = client.get("/start", headers={"Authorization": "Bearer none"})
    assert r_denied.status_code == 403

    # 3) Allowed with admin
    r_admin = client.get("/start", headers={"Authorization": "Bearer valid-admin"})
    assert r_admin.status_code == 200
    assert r_admin.json() == {"ok": True}


@pytest.mark.anyio
async def test_orchestrator_policy_context_tracing_and_consent(monkeypatch):
    clear_consent_cache()
    initialize_tracing()

    consent_app = make_consent_service()
    consent_transport = httpx.ASGITransport(app=consent_app)

    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", consent_transport)
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    ctx_app = make_context_service_with_consent()
    pol_app = make_policy_service_with_consent(ctx_app)
    orch_app = make_orchestrator_service_with_consent(pol_app)

    client = TestClient(orch_app)
    req_id = "orch-policy-context-req"

    ok_response = client.get(
        "/orchestrate",
        headers={
            "Authorization": "Bearer valid-basic",
            "x-request-id": req_id,
        },
    )
    assert ok_response.status_code == 200
    body = ok_response.json()
    assert body.get("x-request-id") == req_id
    assert isinstance(body.get("traceparent"), str) and len(body["traceparent"]) > 0
    assert body["consent"]["sub"] == "user1"
    assert ConsentScopes.REPLAY_READ in body["consent"]["scopes"]

    denied_response = client.get("/orchestrate", headers={"Authorization": "Bearer none"})
    assert denied_response.status_code == 403
