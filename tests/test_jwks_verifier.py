import os
import json
import base64
import types
import pytest
import httpx

from unison_common import auth as auth_mod


class MockResponse:
    def __init__(self, status_code: int, json_data: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
        self.text = json.dumps(self._json)

    def json(self):
        return self._json

    def raise_for_status(self):
        if 400 <= self.status_code:
            raise httpx.HTTPStatusError("error", request=None, response=None)


class AsyncClientStub:
    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None):
        self.calls.append({"url": url, "headers": headers or {}})
        if self._replies:
            return self._replies.pop(0)
        return MockResponse(500, {})


def b64url_int(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


@pytest.mark.anyio
async def test_jwks_cache_and_etag(monkeypatch):
    # Reset cache
    auth_mod._jwks_cache["keys"] = None
    auth_mod._jwks_cache["expires"] = 0
    auth_mod._jwks_cache["etag"] = None

    # First response: 200 with ETag
    jwks1 = {"keys": [{"kid": "kid-1", "kty": "RSA", "n": b64url_int(65537), "e": b64url_int(3)}]}
    r1 = MockResponse(200, jwks1, headers={"etag": 'W/"kid-1-1"'})
    # Second response: 304 Not Modified
    r2 = MockResponse(304, None, headers={})

    client_stub = AsyncClientStub([r1, r2])
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=...: client_stub)

    # Fetch and cache
    jwks_fetched = await auth_mod.get_jwks()
    assert jwks_fetched == jwks1
    assert auth_mod._jwks_cache["etag"] == 'W/"kid-1-1"'
    calls_after_first = len(client_stub.calls)
    assert calls_after_first == 1

    # Force expire then fetch, expect 304 and cache reused
    auth_mod._jwks_cache["expires"] = 0
    jwks_again = await auth_mod.get_jwks()
    assert jwks_again == jwks1
    assert len(client_stub.calls) == 2
    # Ensure If-None-Match header sent
    assert client_stub.calls[1]["headers"].get("If-None-Match") == 'W/"kid-1-1"'


@pytest.mark.anyio
async def test_unknown_kid_triggers_force_refresh(monkeypatch):
    # Reset cache
    auth_mod._jwks_cache["keys"] = None
    auth_mod._jwks_cache["expires"] = 0
    auth_mod._jwks_cache["etag"] = None

    # First JWKS without target kid
    jwks_old = {"keys": [{"kid": "old", "kty": "RSA", "n": b64url_int(17), "e": b64url_int(3)}]}
    # Second JWKS with target kid
    jwks_new = {"keys": [{"kid": "new", "kty": "RSA", "n": b64url_int(19), "e": b64url_int(3)}]}

    r1 = MockResponse(200, jwks_old, headers={"etag": 'W/"old-1"'})
    r2 = MockResponse(200, jwks_new, headers={"etag": 'W/"new-1"'})

    client_stub = AsyncClientStub([r1, r2])
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=...: client_stub)

    # Mock header decode to choose kid 'new'
    monkeypatch.setattr(auth_mod.jwt, "get_unverified_header", lambda token: {"kid": "new"})
    # Skip actual RSA key construction and jwt decoding
    monkeypatch.setattr(auth_mod, "construct_rsa_public_key", lambda jwk: "PEM")

    captured = {}

    def fake_decode(token, key, **kwargs):
        captured.update({"token": token, "key": key, "kwargs": kwargs})
        return {"sub": "user"}

    monkeypatch.setattr(auth_mod.jwt, "decode", fake_decode)

    payload = await auth_mod.verify_rs256_token_locally("dummy-token")
    assert payload.get("sub") == "user"
    # Two network calls: initial JWKS + refresh
    assert len(client_stub.calls) == 2


@pytest.mark.anyio
async def test_issuer_audience_enforced(monkeypatch):
    # Reset cache
    auth_mod._jwks_cache["keys"] = None
    auth_mod._jwks_cache["expires"] = 0

    # Provide JWKS containing the kid we need
    jwks = {"keys": [{"kid": "kid-xyz", "kty": "RSA", "n": b64url_int(23), "e": b64url_int(3)}]}
    r = MockResponse(200, jwks, headers={})
    client_stub = AsyncClientStub([r])
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=...: client_stub)

    # Set env flags
    monkeypatch.setenv("UNISON_AUTH_ISSUER", "unison-auth")
    monkeypatch.setenv("UNISON_AUTH_AUDIENCE", "unison")
    # Reload module constants
    monkeypatch.setattr(auth_mod, "EXPECTED_ISSUER", os.getenv("UNISON_AUTH_ISSUER"))
    monkeypatch.setattr(auth_mod, "EXPECTED_AUDIENCE", os.getenv("UNISON_AUTH_AUDIENCE"))

    # Mock header decode
    monkeypatch.setattr(auth_mod.jwt, "get_unverified_header", lambda token: {"kid": "kid-xyz"})
    monkeypatch.setattr(auth_mod, "construct_rsa_public_key", lambda jwk: "PEM")

    seen = {}

    def fake_decode(token, key, **kwargs):
        seen.update(kwargs)
        return {"sub": "user"}

    monkeypatch.setattr(auth_mod.jwt, "decode", fake_decode)

    payload = await auth_mod.verify_rs256_token_locally("dummy")
    assert payload.get("sub") == "user"
    # Ensure issuer/audience were passed through
    assert seen.get("issuer") == "unison-auth"
    assert seen.get("audience") == "unison"
