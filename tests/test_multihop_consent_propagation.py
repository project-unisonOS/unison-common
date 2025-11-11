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
