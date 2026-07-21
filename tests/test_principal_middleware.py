from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import unison_common.principal_middleware as middleware_module
from unison_common.principal_middleware import PrincipalBindingMiddleware, get_bound_principal


def _claims(person="person-alice", audience="context"):
    now = int(time.time())
    return {
        "sub": f"principal-{person}",
        "principal_id": f"principal-{person}",
        "principal_kind": "person",
        "person_id": person,
        "assistant_instance_id": f"assistant-{person}",
        "household_id": "household-one",
        "membership_id": f"membership-{person}",
        "roles": ["adult-member"],
        "aud": [audience],
        "auth_method": "passkey",
        "assurance": "high",
        "session_id": f"session-{person}",
        "key_handle": f"key-{person}",
        "credential_namespace": f"credential-{person}",
        "data_namespace": f"data-{person}",
        "cache_namespace": f"cache-{person}",
        "index_namespace": f"index-{person}",
        "jti": f"token-{person}",
        "iat": now - 1,
        "exp": now + 300,
    }


def _app(monkeypatch, claims=None, active=True):
    claims = claims or _claims()

    async def verify(_credentials):
        return claims

    async def introspect(_token):
        return {"valid": active, "claims": claims}

    monkeypatch.setattr(middleware_module, "verify_token", verify)
    monkeypatch.setattr(middleware_module, "verify_token_with_auth_service", introspect)

    app = FastAPI()
    app.add_middleware(
        PrincipalBindingMiddleware,
        service_name="context",
        public_paths={"/health"},
        path_identity_patterns={r"/profile/(?P<person_id>[^/]+)": "person_id"},
    )

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/profile/{person_id}")
    def profile(person_id: str, request: Request):
        principal = get_bound_principal(request)
        return {"person_id": principal.person_id, "namespace": principal.data_namespace}

    return app


def test_public_health_does_not_require_identity(monkeypatch):
    client = TestClient(_app(monkeypatch))
    assert client.get("/health").status_code == 200


def test_missing_token_and_dependency_outage_fail_closed(monkeypatch):
    client = TestClient(_app(monkeypatch, active=False))
    assert client.post("/profile/person-alice", json={}).status_code == 401
    assert client.post("/profile/person-alice", json={}, headers={"Authorization": "Bearer token"}).status_code == 403


def test_path_query_and_nested_body_forgery_are_denied(monkeypatch):
    client = TestClient(_app(monkeypatch))
    headers = {"Authorization": "Bearer token"}
    assert client.post("/profile/person-bob", json={}, headers=headers).status_code == 403
    assert client.post("/profile/person-alice?person_id=person-bob", json={}, headers=headers).status_code == 403
    assert client.post(
        "/profile/person-alice",
        json={"payload": {"context": {"person_id": "person-bob"}}},
        headers=headers,
    ).status_code == 403


def test_bound_request_uses_server_namespace(monkeypatch):
    client = TestClient(_app(monkeypatch))
    response = client.post(
        "/profile/person-alice",
        json={"person_id": "person-alice"},
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == 200
    assert response.json() == {"person_id": "person-alice", "namespace": "data-person-alice"}
    assert response.headers["X-Unison-API-Version"] == "1"
    assert response.headers["X-Unison-Principal-Contract"] == "1"


def test_wrong_workload_audience_is_denied(monkeypatch):
    workload = _claims(audience="storage")
    workload.update(
        principal_kind="workload",
        person_id=None,
        assistant_instance_id=None,
        household_id=None,
        membership_id=None,
        key_handle=None,
        credential_namespace=None,
        data_namespace=None,
        cache_namespace=None,
        index_namespace=None,
    )
    client = TestClient(_app(monkeypatch, claims=workload))
    response = client.post(
        "/profile/person-alice",
        json={},
        headers={"Authorization": "Bearer token"},
    )
    assert response.status_code == 403
