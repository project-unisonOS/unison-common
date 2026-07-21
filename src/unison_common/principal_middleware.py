"""FastAPI/Starlette enforcement for Phase 1 trusted principal binding."""

from __future__ import annotations

import json
import os
import re
from contextvars import ContextVar
from collections.abc import Mapping
from typing import Any, Iterable

from fastapi.security import HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .auth import verify_token, verify_token_with_auth_service
from .principal import PrincipalContext, assert_identity_hints, principal_context_from_claims


DEFAULT_PUBLIC_PATHS = frozenset(
    {
        "/",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/favicon.ico",
    }
)

_principal_token: ContextVar[str | None] = ContextVar("unison_principal_token", default=None)
_principal_context: ContextVar[PrincipalContext | None] = ContextVar("unison_principal_context", default=None)


def _identity_sources(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for nested in value.values():
            yield from _identity_sources(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _identity_sources(nested)


class PrincipalBindingMiddleware(BaseHTTPMiddleware):
    """Authenticate, introspect, audience-check, and reject forged hints."""

    def __init__(
        self,
        app,
        *,
        service_name: str,
        public_paths: Iterable[str] = DEFAULT_PUBLIC_PATHS,
        public_prefixes: Iterable[str] = ("/static/",),
        path_identity_patterns: Mapping[str, str] | None = None,
        allow_test_bypass: bool = False,
    ):
        super().__init__(app)
        self.service_name = service_name
        self.public_paths = frozenset(public_paths)
        self.public_prefixes = tuple(public_prefixes)
        self.allow_test_bypass = allow_test_bypass
        self.path_identity_patterns = dict(path_identity_patterns or {})

    def _is_public(self, path: str) -> bool:
        return path in self.public_paths or any(path.startswith(prefix) for prefix in self.public_prefixes)

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or self._is_public(request.url.path):
            return await call_next(request)
        if self.allow_test_bypass and os.getenv("UNISON_PRINCIPAL_BINDING_TEST_BYPASS", "false").lower() == "true":
            return await call_next(request)

        authorization = request.headers.get("authorization", "")
        scheme, _, raw_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw_token:
            return JSONResponse({"detail": "A trusted principal token is required"}, status_code=401)
        try:
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_token)
            claims = await verify_token(credentials)
            active = await verify_token_with_auth_service(raw_token)
            if not active or not active.get("valid"):
                raise ValueError("principal session is not active")
            claims = dict(active.get("claims") or claims)
            context = principal_context_from_claims(claims, expected_audience=self.service_name)

            query = dict(request.query_params)
            sources: list[Mapping[str, Any]] = [query]
            for pattern, field in self.path_identity_patterns.items():
                match = re.fullmatch(pattern, request.url.path)
                if match:
                    sources.append({field: match.group(field)})
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                raw_body = await request.body()
                if raw_body:
                    parsed = json.loads(raw_body)
                    sources.extend(_identity_sources(parsed))
            assert_identity_hints(context, *sources)
        except Exception:
            return JSONResponse(
                {"detail": "Authentication or principal binding failed"},
                status_code=403,
            )
        request.state.principal_context = context
        request.state.principal_token = raw_token
        token = _principal_token.set(raw_token)
        context_token = _principal_context.set(context)
        try:
            response = await call_next(request)
            response.headers["X-Unison-API-Version"] = "1"
            response.headers["X-Unison-Principal-Contract"] = "1"
            return response
        finally:
            _principal_context.reset(context_token)
            _principal_token.reset(token)


def get_bound_principal(request: Request) -> PrincipalContext:
    context = getattr(request.state, "principal_context", None)
    if not isinstance(context, PrincipalContext):
        raise RuntimeError("protected route executed without trusted principal context")
    return context


def get_current_principal_token() -> str | None:
    return _principal_token.get()


def get_current_principal() -> PrincipalContext | None:
    return _principal_context.get()


__all__ = ["DEFAULT_PUBLIC_PATHS", "PrincipalBindingMiddleware", "get_bound_principal", "get_current_principal", "get_current_principal_token"]
