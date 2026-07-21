"""Canonical Phase 1 principal and trusted-request contracts.

Identity hints remain useful routing inputs, but they never grant authority.  A
``PrincipalContext`` is created only from verified token claims issued by the
Personal Data and Trust Store and is then used to bind or reject those hints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, MutableMapping

import os

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import security, verify_token, verify_token_with_auth_service


class PrincipalKind(str, Enum):
    PERSON = "person"
    WORKLOAD = "workload"
    DEVICE = "device"
    CHANNEL = "channel"


class AssuranceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    HARDWARE = "hardware"


class PrincipalContext(BaseModel):
    """Server-derived authority available to a protected operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "1.0"
    principal_id: str
    principal_kind: PrincipalKind
    person_id: str | None = None
    assistant_instance_id: str | None = None
    household_id: str | None = None
    membership_id: str | None = None
    device_principal_id: str | None = None
    channel_identity_id: str | None = None
    login_handle: str | None = None
    display_name: str | None = None
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    audience: tuple[str, ...] = ()
    auth_method: str
    assurance: AssuranceLevel
    session_id: str | None = None
    delegation_id: str | None = None
    delegated_by: str | None = None
    key_handle: str | None = None
    credential_namespace: str | None = None
    data_namespace: str | None = None
    cache_namespace: str | None = None
    index_namespace: str | None = None
    token_id: str
    issued_at: int
    expires_at: int
    trace_id: str | None = None

    @field_validator(
        "principal_id",
        "person_id",
        "assistant_instance_id",
        "household_id",
        "membership_id",
        "device_principal_id",
        "channel_identity_id",
        "session_id",
        "token_id",
        "key_handle",
        "credential_namespace",
        "data_namespace",
        "cache_namespace",
        "index_namespace",
    )
    @classmethod
    def _non_blank_identifiers(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("identity identifiers must not be blank")
        return value

    @model_validator(mode="after")
    def _required_authority(self) -> "PrincipalContext":
        if self.expires_at <= self.issued_at:
            raise ValueError("principal context expiration must follow issuance")
        if self.principal_kind is PrincipalKind.PERSON:
            required = {
                "person_id": self.person_id,
                "assistant_instance_id": self.assistant_instance_id,
                "household_id": self.household_id,
                "membership_id": self.membership_id,
                "key_handle": self.key_handle,
                "credential_namespace": self.credential_namespace,
                "data_namespace": self.data_namespace,
                "cache_namespace": self.cache_namespace,
                "index_namespace": self.index_namespace,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError(f"person principal missing authority fields: {', '.join(missing)}")
        if self.principal_kind is PrincipalKind.WORKLOAD and not self.audience:
            raise ValueError("workload principal requires an audience")
        return self

    def permits_audience(self, service: str) -> bool:
        return service in self.audience

    def as_forwarded_claims(self) -> dict[str, Any]:
        """Return the canonical, non-secret claims for an internal envelope."""
        return self.model_dump(mode="json")


class TrustedRequestEnvelope(BaseModel):
    """Canonical request after authentication and server-side binding."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    request_id: str
    trace_id: str
    principal: PrincipalContext
    purpose: str
    audience: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    requested_capability: str | None = None
    risk: str = "normal"
    confirmation_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


_HINT_FIELDS = {
    "principal_id",
    "person_id",
    "user_id",
    "assistant_instance_id",
    "assistant_id",
    "household_id",
    "membership_id",
    "device_principal_id",
    "channel_identity_id",
}


def _expected_hint(context: PrincipalContext, field: str) -> str | None:
    if field == "user_id":
        return context.person_id if context.principal_kind is PrincipalKind.PERSON else context.principal_id
    if field == "assistant_id":
        return context.assistant_instance_id
    return getattr(context, field, None)


def assert_identity_hints(
    context: PrincipalContext,
    *sources: Mapping[str, Any] | None,
) -> None:
    """Reject any caller identity hint that disagrees with trusted authority."""
    for source in sources:
        if not source:
            continue
        for field in _HINT_FIELDS:
            supplied = source.get(field)
            if supplied is None:
                continue
            expected = _expected_hint(context, field)
            if expected is None or str(supplied) != expected:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"identity hint '{field}' does not match the authenticated principal",
                )


def bind_identity(
    payload: Mapping[str, Any] | None,
    context: PrincipalContext,
) -> dict[str, Any]:
    """Return a copy stamped from trusted authority after validating hints."""
    data: dict[str, Any] = dict(payload or {})
    nested = data.get("payload") if isinstance(data.get("payload"), Mapping) else None
    request_context = data.get("context") if isinstance(data.get("context"), Mapping) else None
    assert_identity_hints(context, data, nested, request_context)
    if context.person_id:
        data["person_id"] = context.person_id
    data["principal_id"] = context.principal_id
    if context.assistant_instance_id:
        data["assistant_instance_id"] = context.assistant_instance_id
    if context.household_id:
        data["household_id"] = context.household_id
    return data


def principal_context_from_claims(
    claims: Mapping[str, Any],
    *,
    expected_audience: str | None = None,
    now: int | None = None,
) -> PrincipalContext:
    """Build a context from already cryptographically verified JWT claims."""
    issued_at = int(claims.get("iat") or 0)
    expires_at = int(claims.get("exp") or 0)
    current = int(datetime.now(timezone.utc).timestamp()) if now is None else now
    if not issued_at or not expires_at or expires_at <= current:
        raise ValueError("principal claims are expired or missing token times")

    raw_audience = claims.get("aud") or claims.get("audience") or ()
    if isinstance(raw_audience, str):
        audience = (raw_audience,)
    else:
        audience = tuple(str(item) for item in raw_audience)
    if expected_audience and expected_audience not in audience:
        raise ValueError("principal token audience does not include this service")

    raw_roles = claims.get("roles") or ()
    raw_scopes = claims.get("scopes") or claims.get("scope") or ()
    if isinstance(raw_scopes, str):
        raw_scopes = raw_scopes.split()

    return PrincipalContext(
        principal_id=str(claims.get("principal_id") or claims.get("sub") or ""),
        principal_kind=claims.get("principal_kind") or "person",
        person_id=claims.get("person_id"),
        assistant_instance_id=claims.get("assistant_instance_id"),
        household_id=claims.get("household_id"),
        membership_id=claims.get("membership_id"),
        device_principal_id=claims.get("device_principal_id"),
        channel_identity_id=claims.get("channel_identity_id"),
        login_handle=claims.get("login_handle"),
        display_name=claims.get("display_name"),
        roles=tuple(str(item) for item in raw_roles),
        scopes=tuple(str(item) for item in raw_scopes),
        audience=audience,
        auth_method=str(claims.get("auth_method") or "unknown"),
        assurance=claims.get("assurance") or "low",
        session_id=claims.get("session_id"),
        delegation_id=claims.get("delegation_id"),
        delegated_by=claims.get("delegated_by"),
        key_handle=claims.get("key_handle"),
        credential_namespace=claims.get("credential_namespace"),
        data_namespace=claims.get("data_namespace"),
        cache_namespace=claims.get("cache_namespace"),
        index_namespace=claims.get("index_namespace"),
        token_id=str(claims.get("jti") or ""),
        issued_at=issued_at,
        expires_at=expires_at,
        trace_id=claims.get("trace_id"),
    )


def require_principal_context(expected_audience: str | None = None):
    """FastAPI dependency that accepts only a complete trusted principal."""

    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> PrincipalContext:
        try:
            claims = await verify_token(credentials)
            require_introspection = os.getenv(
                "UNISON_PRINCIPAL_INTROSPECTION_REQUIRED", "true"
            ).lower() in {"1", "true", "yes", "on"}
            if require_introspection:
                active = await verify_token_with_auth_service(credentials.credentials)
                if not active or not active.get("valid"):
                    raise ValueError("principal session is not active")
                claims = dict(active.get("claims") or claims)
            context = principal_context_from_claims(
                claims,
                expected_audience=expected_audience,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication token lacks a valid principal binding",
            ) from exc
        request.state.principal_context = context
        return context

    return dependency


def partition_key(context: PrincipalContext, resource: str, identifier: str) -> str:
    """Create a cache/index key rooted in the server-issued namespace."""
    namespace = context.data_namespace or context.principal_id
    return f"{namespace}:{resource}:{identifier}"


def redact_principal_for_log(context: PrincipalContext) -> dict[str, Any]:
    """Return identifiers safe for audit correlation; never include key material."""
    return {
        "principal_id": context.principal_id,
        "principal_kind": context.principal_kind.value,
        "person_id": context.person_id,
        "assistant_instance_id": context.assistant_instance_id,
        "household_id": context.household_id,
        "session_id": context.session_id,
        "token_id": context.token_id,
        "trace_id": context.trace_id,
    }


__all__ = [
    "AssuranceLevel",
    "PrincipalContext",
    "PrincipalKind",
    "TrustedRequestEnvelope",
    "assert_identity_hints",
    "bind_identity",
    "partition_key",
    "principal_context_from_claims",
    "redact_principal_for_log",
    "require_principal_context",
]
