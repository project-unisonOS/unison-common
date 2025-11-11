import pytest
import asyncio
import os
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import httpx

from unison_common.consent import require_consent, ConsentScopes, clear_consent_cache, check_consent_header


class MockAsyncClient(httpx.AsyncClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def make_consent_service(state):
    app = FastAPI()

    @app.post("/introspect")
    async def introspect(request: Request):
        state["calls"] += 1
        body = await request.json()
        token = body.get("token")
        # Tokens encode behavior
        if token == "valid-basic":
            return JSONResponse({"active": True, "sub": "user1", "scopes": [ConsentScopes.INGEST_WRITE]})
        if token == "valid-admin":
            return JSONResponse({"active": True, "sub": "admin", "scopes": [ConsentScopes.ADMIN_ALL]})
        if token == "inactive":
            return JSONResponse({"active": False})
        return JSONResponse({"active": True, "scopes": []})

    return app


@pytest.mark.anyio
async def test_require_consent_valid_and_caching(monkeypatch):
    clear_consent_cache()
    state = {"calls": 0}
    consent_app = make_consent_service(state)

    transport = httpx.ASGITransport(app=consent_app)

    # Monkeypatch AsyncClient to always use our ASGITransport and base_url
    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        kwargs.setdefault("base_url", "http://consent.local")
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    # Build a tiny app using the dependency
    app = FastAPI()

    @app.get("/ingest")
    async def ingest(consent=Depends(require_consent([ConsentScopes.INGEST_WRITE]))):
        return {"ok": True, "sub": consent.get("sub")}

    client = TestClient(app)

    # First call hits consent
    r1 = client.get("/ingest", headers={"Authorization": "Bearer valid-basic"})
    assert r1.status_code == 200
    assert state["calls"] == 1

    # Second call uses cache (no additional consent call)
    r2 = client.get("/ingest", headers={"Authorization": "Bearer valid-basic"})
    assert r2.status_code == 200
    assert state["calls"] == 1


@pytest.mark.anyio
async def test_require_consent_missing_scope(monkeypatch):
    clear_consent_cache()
    state = {"calls": 0}
    consent_app = make_consent_service(state)
    transport = httpx.ASGITransport(app=consent_app)

    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        kwargs.setdefault("base_url", "http://consent.local")
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    app = FastAPI()

    @app.get("/replay")
    async def replay(consent=Depends(require_consent([ConsentScopes.REPLAY_READ]))):
        return {"ok": True}

    client = TestClient(app)

    r = client.get("/replay", headers={"Authorization": "Bearer valid-basic"})
    assert r.status_code == 403
    assert state["calls"] == 1


@pytest.mark.anyio
async def test_require_consent_admin_allows_all(monkeypatch):
    clear_consent_cache()
    state = {"calls": 0}
    consent_app = make_consent_service(state)
    transport = httpx.ASGITransport(app=consent_app)

    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        kwargs.setdefault("base_url", "http://consent.local")
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    app = FastAPI()

    @app.get("/admin")
    async def admin(consent=Depends(require_consent([ConsentScopes.REPLAY_DELETE]))):
        return {"ok": True}

    client = TestClient(app)

    r = client.get("/admin", headers={"Authorization": "Bearer valid-admin"})
    assert r.status_code == 200
    assert state["calls"] == 1


@pytest.mark.anyio
async def test_check_consent_header_helper(monkeypatch):
    clear_consent_cache()
    state = {"calls": 0}
    consent_app = make_consent_service(state)
    transport = httpx.ASGITransport(app=consent_app)

    orig_async_client = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        kwargs.setdefault("base_url", "http://consent.local")
        return orig_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)

    headers = {"X-Consent-Grant": "valid-basic"}
    grant = await check_consent_header(headers, [ConsentScopes.INGEST_WRITE])
    assert grant and grant.get("active")
    assert state["calls"] == 1
