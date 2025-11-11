import time
import threading
import pytest

from unison_common import auth as auth_mod


def test_background_jwks_refresh_monkeypatched(monkeypatch):
    # Arrange: set a short refresh interval
    monkeypatch.setenv("UNISON_AUTH_JWKS_REFRESH_SECONDS", "1")
    monkeypatch.setattr(auth_mod, "JWKS_REFRESH_SECONDS", 1, raising=False)

    calls = {"count": 0}

    async def fake_get_jwks(force_refresh: bool = False):
        calls["count"] += 1
        return {"keys": []}

    monkeypatch.setattr(auth_mod, "get_jwks", fake_get_jwks)

    # Act: start refresher
    auth_mod.start_jwks_background_refresh()
    # Wait briefly to allow at least one tick
    time.sleep(1.5)

    # Assert: get_jwks has been called at least once by refresher
    assert calls["count"] >= 1
