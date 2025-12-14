import os

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from unison_common.auth import create_service_token, verify_token


@pytest.mark.asyncio
async def test_verify_token_accepts_hs256_service_token(monkeypatch):
    monkeypatch.setenv("UNISON_SERVICE_SECRET", "test-service-secret")
    monkeypatch.setenv("UNISON_ALLOW_HS256_SERVICE_TOKENS", "true")
    # create_service_token reads SERVICE_SECRET at import-time; set directly as fallback by passing secret.
    token = create_service_token("io-speech", service_secret="test-service-secret")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    data = await verify_token(creds)
    assert "service" in data.get("roles", [])
    assert data.get("username") == "service-io-speech"


@pytest.mark.asyncio
async def test_verify_token_rejects_hs256_without_opt_in(monkeypatch):
    from unison_common import auth as auth_module

    monkeypatch.setenv("UNISON_SERVICE_SECRET", "test-service-secret")
    monkeypatch.setenv("UNISON_ALLOW_HS256_SERVICE_TOKENS", "true")
    token = create_service_token("io-speech", service_secret="test-service-secret")

    monkeypatch.setenv("UNISON_ALLOW_HS256_SERVICE_TOKENS", "false")
    async def fake_verify(_: str):
        return None

    monkeypatch.setattr(auth_module, "verify_token_with_auth_service", fake_verify)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(Exception):
        await verify_token(creds)
