"""
Context baton SDK: issue, verify, and append provenance for per-request tokens.

Tokens are Ed25519-signed envelopes carrying scopes, subject, audience, TTL,
and provenance entries. Encryption of payload is optional; for now we sign the
plaintext JSON. The token format is:

    base64url(json_payload) + "." + base64url(signature)
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from contextvars import ContextVar


class BatonError(Exception):
    """Raised when a baton is invalid or cannot be verified."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_current_baton: ContextVar[Optional[str]] = ContextVar("current_baton", default=None)


def set_current_baton(token: Optional[str]) -> None:
    _current_baton.set(token)


def get_current_baton() -> Optional[str]:
    return _current_baton.get()


@dataclass
class Baton:
    subject: str
    scopes: List[str]
    audience: List[str]
    issuer: str
    ttl_seconds: int = 300
    issued_at: datetime = field(default_factory=_utcnow)
    expires_at: datetime = field(default_factory=lambda: _utcnow() + timedelta(minutes=5))
    provenance: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sub": self.subject,
            "scopes": self.scopes,
            "aud": self.audience,
            "iss": self.issuer,
            "ttl": self.ttl_seconds,
            "iat": self.issued_at.isoformat(),
            "exp": self.expires_at.isoformat(),
            "prov": self.provenance,
            "meta": self.metadata,
            "sig": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Baton":
        return cls(
            subject=data["sub"],
            scopes=data.get("scopes", []),
            audience=data.get("aud", []),
            issuer=data.get("iss", "unknown"),
            ttl_seconds=int(data.get("ttl", 300)),
            issued_at=datetime.fromisoformat(data["iat"]),
            expires_at=datetime.fromisoformat(data["exp"]),
            provenance=data.get("prov", []),
            metadata=data.get("meta", {}),
            signature=data.get("sig"),
        )


class BatonKeyStore:
    """File-based Ed25519 key store."""

    def __init__(self, path: Optional[Path] = None) -> None:
        default_path = Path(os.getenv("BATON_KEY_PATH", "/tmp/unison_baton_ed25519.pem"))
        self.path = path or default_path
        self._priv: Optional[Ed25519PrivateKey] = None
        self._pub: Optional[Ed25519PublicKey] = None
        self._load_or_create()

    def _load_or_create(self) -> None:
        if self.path.exists():
            data = self.path.read_bytes()
            self._priv = serialization.load_pem_private_key(data, password=None)
            self._pub = self._priv.public_key()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._priv = Ed25519PrivateKey.generate()
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.path.write_bytes(pem)
        self._pub = self._priv.public_key()

    @property
    def private_key(self) -> Ed25519PrivateKey:
        assert self._priv is not None
        return self._priv

    @property
    def public_key(self) -> Ed25519PublicKey:
        assert self._pub is not None
        return self._pub


class BatonService:
    """High-level baton issuer/verifier."""

    def __init__(self, keystore: Optional[BatonKeyStore] = None) -> None:
        self.keystore = keystore or BatonKeyStore()

    def issue(
        self,
        subject: str,
        scopes: List[str],
        audience: List[str],
        issuer: str = "unison",
        ttl_seconds: int = 300,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        issued_at = _utcnow()
        baton = Baton(
            subject=subject,
            scopes=scopes,
            audience=audience,
            issuer=issuer,
            ttl_seconds=ttl_seconds,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
            metadata=metadata or {},
        )
        payload = baton.to_dict()
        token = self._sign(payload)
        return token

    def verify(self, token: str, required_scopes: Optional[List[str]] = None, audience: Optional[str] = None) -> Baton:
        payload = self._verify_signature(token)
        baton = Baton.from_dict(payload)

        now = _utcnow()
        if now > baton.expires_at:
            raise BatonError("Baton expired")

        if required_scopes:
            missing = [s for s in required_scopes if s not in baton.scopes]
            if missing:
                raise BatonError(f"Missing scopes: {','.join(missing)}")

        if audience and audience not in baton.audience:
            raise BatonError("Audience mismatch")

        return baton

    def append_provenance(self, token: str, entry: Dict[str, Any]) -> str:
        payload = self._verify_signature(token)
        baton = Baton.from_dict(payload)
        baton.provenance.append(entry)
        baton.metadata["touched_at"] = _utcnow().isoformat()
        return self._sign(baton.to_dict())

    # --- internal helpers ---
    def _sign(self, payload: Dict[str, Any]) -> str:
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig = self.keystore.private_key.sign(payload_json)
        return f"{_b64url(payload_json)}.{_b64url(sig)}"

    def _verify_signature(self, token: str) -> Dict[str, Any]:
        if "." not in token:
            raise BatonError("Malformed baton")
        payload_b64, sig_b64 = token.split(".", 1)
        payload_bytes = _b64url_decode(payload_b64)
        sig_bytes = _b64url_decode(sig_b64)
        try:
            self.keystore.public_key.verify(sig_bytes, payload_bytes)
        except InvalidSignature as exc:
            raise BatonError("Invalid signature") from exc
        payload = json.loads(payload_bytes.decode("utf-8"))
        return payload


# FastAPI middleware adapter
class BatonMiddleware:
    def __init__(self, app, service: Optional[BatonService] = None, required_scopes: Optional[List[str]] = None):
        self.app = app
        self.service = service or BatonService()
        self.required_scopes = required_scopes or []

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        header_value = headers.get(b"x-context-baton")
        if header_value:
            token = header_value.decode("utf-8")
            try:
                self.service.verify(token, required_scopes=self.required_scopes)
                set_current_baton(token)
            except BatonError:
                # Reject early with 401
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"detail": "invalid or expired baton"}',
                    }
                )
                return
        await self.app(scope, receive, send)
