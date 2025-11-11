import pytest
import types
import httpx

from unison_common.http_client import http_get_json_with_retry, http_post_json_with_retry, _inject_tracing_headers


class MockResp:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
    def json(self):
        return self._body


class ClientStub:
    def __init__(self, timeout=None):
        # sequence is injected by test via attribute
        self._sequence = []
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def get(self, url, headers=None):
        self.calls.append(("GET", url, dict(headers or {})))
        return self._pop()
    def post(self, url, headers=None, json=None):
        self.calls.append(("POST", url, dict(headers or {}), json))
        return self._pop()
    def put(self, url, headers=None, json=None):
        self.calls.append(("PUT", url, dict(headers or {}), json))
        return self._pop()
    def _pop(self):
        if not self._sequence:
            return MockResp(500, {})
        item = self._sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.mark.parametrize("method", ["GET", "POST", "PUT"])
def test_retry_on_5xx_then_success(monkeypatch, method):
    # Patch client
    stub = ClientStub()
    stub._sequence = [MockResp(500, {"err": 1}), MockResp(200, {"ok": True})]
    monkeypatch.setattr(httpx, "Client", lambda timeout=None: stub)
    # Ensure tracing headers injected and preserved
    monkeypatch.setattr(
        "unison_common.http_client._inject_tracing_headers",
        lambda hdrs=None: {**(hdrs or {}), "x-test": "ok"},
    )
    if method == "GET":
        ok, status, body = http_get_json_with_retry("h", "80", "/p", max_retries=2, base_delay=0.0, max_delay=0.0)
    elif method == "POST":
        ok, status, body = http_post_json_with_retry("h", "80", "/p", {"a": 1}, max_retries=2, base_delay=0.0, max_delay=0.0)
    else:
        from unison_common.http_client import http_put_json_with_retry
        ok, status, body = http_put_json_with_retry("h", "80", "/p", {"a": 1}, max_retries=2, base_delay=0.0, max_delay=0.0)
    assert ok is True and status == 200 and body == {"ok": True}
    # Two calls
    assert len(stub.calls) == 2
    # Header preserved across retries
    assert stub.calls[0][2].get("x-test") == "ok"
    assert stub.calls[1][2].get("x-test") == "ok"


def test_retry_on_connect_error_then_success(monkeypatch):
    stub = ClientStub()
    stub._sequence = [httpx.ConnectError("boom"), MockResp(200, {"ok": True})]
    monkeypatch.setattr(httpx, "Client", lambda timeout=None: stub)
    monkeypatch.setattr(
        "unison_common.http_client._inject_tracing_headers",
        lambda hdrs=None: {**(hdrs or {}), "x-test": "ok"},
    )
    ok, status, body = http_get_json_with_retry("h", "80", "/p", max_retries=2, base_delay=0.0, max_delay=0.0)
    assert ok is True and status == 200 and body == {"ok": True}
    assert len(stub.calls) == 2
    assert stub.calls[0][2].get("x-test") == "ok"
    assert stub.calls[1][2].get("x-test") == "ok"


def test_non_retryable_status_stops(monkeypatch):
    stub = ClientStub()
    stub._sequence = [MockResp(400, {"err": "bad"})]
    monkeypatch.setattr(httpx, "Client", lambda timeout=None: stub)
    ok, status, body = http_get_json_with_retry("h", "80", "/p", max_retries=3, base_delay=0.0, max_delay=0.0)
    assert ok is False and status == 400
    # Only one call
    assert len(stub.calls) == 1
