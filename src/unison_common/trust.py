"""Opaque key and credential broker interfaces for principal-isolated services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.fernet import Fernet


@dataclass(frozen=True)
class NamespaceSet:
    credential: str
    data: str
    cache: str
    index: str


class KeyBroker(Protocol):
    def encrypt(self, *, key_handle: str, plaintext: bytes, associated_data: bytes = b"") -> bytes: ...
    def decrypt(self, *, key_handle: str, ciphertext: bytes, associated_data: bytes = b"") -> bytes: ...


class CredentialBroker(Protocol):
    def resolve_for_task(
        self,
        *,
        credential_namespace: str,
        credential_handle: str,
        capability_id: str,
        task_id: str,
    ) -> str: ...


class LocalDevelopmentKeyBroker:
    """Deterministic per-handle envelope keys for local migration/testing.

    Production deployments replace this with a TPM/HSM-backed implementation.
    The root secret and derived keys are never exposed through the API.
    """

    def __init__(self, root_secret: bytes):
        if len(root_secret) < 32:
            raise ValueError("local key broker root must contain at least 32 bytes")
        self._root_secret = root_secret

    def _fernet(self, key_handle: str, associated_data: bytes) -> Fernet:
        digest = hmac.new(
            self._root_secret,
            key_handle.encode("utf-8") + b"\x00" + associated_data,
            hashlib.sha256,
        ).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, *, key_handle: str, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        return self._fernet(key_handle, associated_data).encrypt(plaintext)

    def decrypt(self, *, key_handle: str, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        return self._fernet(key_handle, associated_data).decrypt(ciphertext)


def read_secret_setting(name: str, default: str = "") -> str:
    """Read a secret from ``NAME_FILE`` before the legacy direct environment value."""
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)


__all__ = ["CredentialBroker", "KeyBroker", "LocalDevelopmentKeyBroker", "NamespaceSet", "read_secret_setting"]
