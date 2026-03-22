from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Sequence, Tuple

import httpx
from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .errors import ModelPackInvalidError, ModelPackMissingError


_MANIFEST_FILENAME = "models.manifest.json"
_MANIFEST_SIGNATURE_FILENAME = "models.manifest.sig.json"
_MANIFEST_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "modelpack" / "manifest.v1.schema.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_relpath(rel: str) -> Path:
    p = Path(rel)
    if p.is_absolute():
        raise ModelPackInvalidError(f"manifest contains absolute path: {rel}")
    if any(part in {"..", ""} for part in p.parts):
        raise ModelPackInvalidError(f"manifest contains unsafe path: {rel}")
    return p


def _load_manifest_schema() -> Draft202012Validator:
    try:
        raw = json.loads(_MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        raise ModelPackInvalidError(f"unable to read modelpack schema: {_MANIFEST_SCHEMA_PATH}: {exc}") from exc
    return Draft202012Validator(raw)


def _host_compat() -> tuple[str, str]:
    os_name = platform.system().lower()
    arch = platform.machine().lower()
    if arch in {"x86_64", "amd64"}:
        arch = "amd64"
    if arch in {"aarch64", "arm64"}:
        arch = "arm64"
    return os_name, arch


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _require_signature() -> bool:
    # Signature enforcement remains opt-in until signed packs and public keys are
    # shipped across the supported install path.
    return os.getenv("UNISON_MODEL_PACK_REQUIRE_SIGNATURE", "false").lower() in {"1", "true", "yes", "on"}


def _load_pubkeys(pubkeys_dir: Path) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    if not pubkeys_dir.exists():
        return keys
    for p in sorted(pubkeys_dir.glob("*.pub")):
        try:
            key = load_pem_public_key(p.read_bytes())
            if isinstance(key, Ed25519PublicKey):
                keys[p.stem] = key
        except Exception:
            continue
    return keys


def _verify_manifest_signature(*, manifest: Dict[str, Any], signature_obj: Dict[str, Any]) -> None:
    key_id = str(signature_obj.get("key_id") or "")
    algorithm = str(signature_obj.get("algorithm") or "")
    sig_b64 = str(signature_obj.get("signature") or "")
    if not key_id or not algorithm or not sig_b64:
        raise ModelPackInvalidError("invalid manifest signature object (missing key_id/algorithm/signature)")
    if algorithm.lower() != "ed25519":
        raise ModelPackInvalidError(f"unsupported signature algorithm: {algorithm}")
    pubkeys_dir = Path(os.getenv("UNISON_MODEL_PACK_PUBKEYS_DIR", "/etc/unison/keys/updates/models")).expanduser().resolve()
    pubkeys = _load_pubkeys(pubkeys_dir)
    if not pubkeys:
        raise ModelPackInvalidError("model pack signature required but no public keys are configured")
    key = pubkeys.get(key_id)
    if key is None:
        raise ModelPackInvalidError(f"unknown model pack signing key_id: {key_id}")
    try:
        sig = base64.b64decode(sig_b64)
        key.verify(sig, _canonical_json_bytes(manifest))
    except Exception as exc:
        raise ModelPackInvalidError(f"model pack manifest signature verification failed: {exc}") from exc


ModelPackEventSink = Callable[[str, Dict[str, Any], str], None]


@dataclass(frozen=True)
class PackRef:
    pack_id: str
    pack_version: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    missing: list[str]
    invalid: list[str]


@dataclass(frozen=True)
class ModelPackResolver:
    """
    Model pack resolver: install + verify + lookup.

    Storage layout (default base dir: /var/lib/unison/models):
    - <base>/
      - packs/<pack_id>/<pack_version>/models.manifest.json
      - (payload files written at paths from manifest `files[].path`)
    """

    base_dir: Path

    @classmethod
    def from_env(cls) -> "ModelPackResolver":
        base = os.getenv("UNISON_MODEL_DIR", "/var/lib/unison/models")
        return cls(base_dir=Path(base).expanduser().resolve())

    def _packs_dir(self) -> Path:
        return self.base_dir / "packs"

    def _installed_manifest_path(self, ref: PackRef) -> Path:
        return self._packs_dir() / ref.pack_id / ref.pack_version / _MANIFEST_FILENAME

    def _emit(self, sink: ModelPackEventSink | None, event_type: str, payload: Dict[str, Any], level: str = "info") -> None:
        if sink is None:
            return
        sink(event_type, payload, level)

    def list_packs(self) -> list[PackRef]:
        packs: list[PackRef] = []
        root = self._packs_dir()
        if not root.exists():
            return packs
        for pack_id_dir in root.iterdir():
            if not pack_id_dir.is_dir():
                continue
            for ver_dir in pack_id_dir.iterdir():
                if (ver_dir / _MANIFEST_FILENAME).exists():
                    packs.append(PackRef(pack_id=pack_id_dir.name, pack_version=ver_dir.name))
        packs.sort(key=lambda r: (r.pack_id, r.pack_version))
        return packs

    def read_manifest(self, ref: PackRef) -> Dict[str, Any]:
        path = self._installed_manifest_path(ref)
        if not path.exists():
            raise ModelPackMissingError(f"model pack not installed: {ref.pack_id}@{ref.pack_version}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ModelPackInvalidError(f"invalid installed manifest: {path}: {exc}") from exc

    def _validate_manifest(self, manifest: Dict[str, Any]) -> None:
        validator = _load_manifest_schema()
        errors = sorted(validator.iter_errors(manifest), key=lambda e: e.path)
        if errors:
            msg = "; ".join(["/".join([str(p) for p in e.path]) + ": " + e.message for e in errors[:8]])
            raise ModelPackInvalidError(f"manifest schema validation failed: {msg}")

        compat = manifest.get("compat") if isinstance(manifest.get("compat"), dict) else {}
        allow_os = compat.get("os") if isinstance(compat.get("os"), list) else []
        allow_arch = compat.get("arch") if isinstance(compat.get("arch"), list) else []
        host_os, host_arch = _host_compat()
        if allow_os and host_os not in {str(x).lower() for x in allow_os}:
            raise ModelPackInvalidError(f"pack incompatible with host os: {host_os}")
        if allow_arch and host_arch not in {str(x).lower() for x in allow_arch}:
            raise ModelPackInvalidError(f"pack incompatible with host arch: {host_arch}")

        pack = manifest.get("pack") if isinstance(manifest.get("pack"), dict) else {}
        pack_id = str(pack.get("id") or "")
        pack_version = str(pack.get("version") or "")
        required_prefix = Path("packs") / pack_id / pack_version if pack_id and pack_version else None

        for f in manifest.get("files") or []:
            rel = _safe_relpath(str(f.get("path")))
            if required_prefix and not str(rel).startswith(str(required_prefix) + os.sep):
                raise ModelPackInvalidError(
                    f"pack files must live under {required_prefix}/ for side-by-side installs (got {rel})"
                )

        for m in manifest.get("models") or []:
            _safe_relpath(str(m.get("install_relpath")))

    def verify_pack(self, *, ref: PackRef, sink: ModelPackEventSink | None = None) -> VerifyResult:
        self._emit(sink, "modelpack.verify.started", {"pack_id": ref.pack_id, "pack_version": ref.pack_version}, "info")
        manifest = self.read_manifest(ref)
        self._validate_manifest(manifest)

        missing: list[str] = []
        invalid: list[str] = []

        for f in manifest.get("files") or []:
            rel = str(f.get("path"))
            expected_sha = str(f.get("sha256"))
            expected_size = f.get("size_bytes")
            target = self.base_dir / _safe_relpath(rel)
            if not target.exists():
                missing.append(rel)
                continue
            if isinstance(expected_size, int) and expected_size >= 0 and target.stat().st_size != expected_size:
                invalid.append(rel)
                continue
            if expected_sha and _sha256_file(target) != expected_sha:
                invalid.append(rel)

        ok = not missing and not invalid
        self._emit(
            sink,
            "modelpack.verify.finished",
            {"pack_id": ref.pack_id, "pack_version": ref.pack_version, "ok": ok, "missing": len(missing), "invalid": len(invalid)},
            "info" if ok else "warn",
        )
        return VerifyResult(ok=ok, missing=missing, invalid=invalid)

    def get_model_path(self, *, model_id: str) -> Path:
        for ref in self.list_packs():
            manifest = self.read_manifest(ref)
            for m in manifest.get("models") or []:
                if not isinstance(m, dict):
                    continue
                if m.get("model_id") == model_id:
                    rel = _safe_relpath(str(m.get("install_relpath")))
                    return (self.base_dir / rel).resolve()
        raise ModelPackMissingError(f"model_id not found in installed packs: {model_id}")

    def ensure_required_pack(self, *, ref: PackRef, sink: ModelPackEventSink | None = None) -> None:
        self._emit(sink, "modelpack.required", {"pack_id": ref.pack_id, "pack_version": ref.pack_version}, "info")
        try:
            res = self.verify_pack(ref=ref, sink=sink)
        except ModelPackMissingError:
            self._emit(sink, "modelpack.missing", {"pack_id": ref.pack_id, "pack_version": ref.pack_version}, "error")
            raise
        if not res.ok:
            self._emit(
                sink,
                "modelpack.invalid",
                {"pack_id": ref.pack_id, "pack_version": ref.pack_version, "missing": res.missing[:5], "invalid": res.invalid[:5]},
                "error",
            )
            raise ModelPackInvalidError(f"model pack invalid: {ref.pack_id}@{ref.pack_version}")
        self._emit(sink, "modelpack.present", {"pack_id": ref.pack_id, "pack_version": ref.pack_version}, "info")

    def install_from_path(self, *, pack_path: str, sink: ModelPackEventSink | None = None) -> PackRef:
        src = Path(pack_path).expanduser().resolve()
        if not src.exists():
            raise ModelPackMissingError(f"pack not found: {src}")

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._packs_dir().mkdir(parents=True, exist_ok=True)

        self._emit(sink, "modelpack.install.started", {"path": str(src)}, "info")
        with tempfile.TemporaryDirectory(prefix="unison-modelpack-") as td:
            tmp = Path(td)
            if src.is_dir():
                unpack_dir = src
            else:
                unpack_dir = tmp / "unpacked"
                unpack_dir.mkdir(parents=True, exist_ok=True)
                if str(src).endswith((".tar.gz", ".tgz")):
                    with tarfile.open(src, "r:gz") as tf:
                        base = unpack_dir.resolve()
                        for member in tf.getmembers():
                            member_path = (unpack_dir / member.name).resolve()
                            if not str(member_path).startswith(str(base)):
                                raise ModelPackInvalidError(f"unsafe path in tar member: {member.name}")
                        tf.extractall(unpack_dir)
                else:
                    raise ModelPackInvalidError("unsupported pack format (expected directory or .tar.gz/.tgz)")

            manifest_path = unpack_dir / _MANIFEST_FILENAME
            if not manifest_path.exists():
                raise ModelPackInvalidError(f"missing {_MANIFEST_FILENAME} in pack")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise ModelPackInvalidError(f"invalid manifest json: {exc}") from exc

            self._validate_manifest(manifest)
            if _require_signature():
                sig_path = unpack_dir / _MANIFEST_SIGNATURE_FILENAME
                if not sig_path.exists():
                    raise ModelPackInvalidError(f"missing {_MANIFEST_SIGNATURE_FILENAME} (signature required)")
                try:
                    sig_obj = json.loads(sig_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    raise ModelPackInvalidError(f"invalid manifest signature json: {exc}") from exc
                if not isinstance(sig_obj, dict):
                    raise ModelPackInvalidError("invalid manifest signature (expected object)")
                _verify_manifest_signature(manifest=manifest, signature_obj=sig_obj)
            pack = manifest.get("pack") if isinstance(manifest.get("pack"), dict) else {}
            ref = PackRef(pack_id=str(pack.get("id")), pack_version=str(pack.get("version")))
            if not ref.pack_id or not ref.pack_version:
                raise ModelPackInvalidError("manifest missing pack.id or pack.version")

            # Verify pack payload before copy.
            for f in manifest.get("files") or []:
                rel = _safe_relpath(str(f.get("path")))
                expected_sha = str(f.get("sha256"))
                expected_size = f.get("size_bytes")
                source_file = unpack_dir / rel
                if not source_file.exists():
                    raise ModelPackInvalidError(f"pack missing file listed in manifest: {rel}")
                if isinstance(expected_size, int) and expected_size >= 0 and source_file.stat().st_size != expected_size:
                    raise ModelPackInvalidError(f"pack file size mismatch: {rel}")
                if expected_sha and _sha256_file(source_file) != expected_sha:
                    raise ModelPackInvalidError(f"pack file sha256 mismatch: {rel}")

            # Copy payload into place.
            for f in manifest.get("files") or []:
                rel = _safe_relpath(str(f.get("path")))
                src_file = unpack_dir / rel
                dst_file = self.base_dir / rel
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)

            # Store manifest under packs/<id>/<version>/models.manifest.json
            installed_manifest = self._installed_manifest_path(ref)
            installed_manifest.parent.mkdir(parents=True, exist_ok=True)
            installed_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        self._emit(sink, "modelpack.install.finished", {"pack_id": ref.pack_id, "pack_version": ref.pack_version}, "info")
        return ref

    def install_from_url(self, *, url_or_alias: str, sink: ModelPackEventSink | None = None) -> PackRef:
        value = (url_or_alias or "").strip()
        if not value:
            raise ModelPackInvalidError("missing url/alias")

        url = value
        if "://" not in url:
            alias_map_raw = os.getenv("UNISON_MODEL_PACK_ALIAS_MAP_JSON", "").strip()
            if not alias_map_raw:
                raise ModelPackInvalidError("alias provided but UNISON_MODEL_PACK_ALIAS_MAP_JSON is not set")
            try:
                alias_map = json.loads(alias_map_raw)
            except Exception as exc:
                raise ModelPackInvalidError(f"invalid UNISON_MODEL_PACK_ALIAS_MAP_JSON: {exc}") from exc
            url = str(alias_map.get(value) or "").strip()
            if not url:
                raise ModelPackInvalidError(f"unknown model pack alias: {value}")

        with tempfile.TemporaryDirectory(prefix="unison-modelpack-download-") as td:
            dst = Path(td) / "pack.tgz"
            with httpx.stream("GET", url, timeout=60.0, follow_redirects=True) as r:
                r.raise_for_status()
                with dst.open("wb") as f:
                    for chunk in r.iter_bytes():
                        f.write(chunk)
            return self.install_from_path(pack_path=str(dst), sink=sink)
