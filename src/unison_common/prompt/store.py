from __future__ import annotations

import hashlib
import json
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import PromptUpdateError
from .layout import PromptLayout
from .resources import ensure_parent_dir


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


@dataclass
class PromptStore:
    layout: PromptLayout

    def ensure_layout(self) -> None:
        self.layout.base_dir.mkdir(parents=True, exist_ok=True)
        self.layout.user_dir.mkdir(parents=True, exist_ok=True)
        self.layout.schema_dir.mkdir(parents=True, exist_ok=True)
        self.layout.compiled_dir.mkdir(parents=True, exist_ok=True)
        self.layout.history_dir.mkdir(parents=True, exist_ok=True)
        self.layout.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def write_text_atomic(self, path: Path, text: str) -> None:
        ensure_parent_dir(path)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)

    def read_json(self, path: Path) -> Dict[str, Any]:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except FileNotFoundError as exc:
            raise PromptUpdateError(f"missing config file: {path}") from exc
        except Exception as exc:
            raise PromptUpdateError(f"invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise PromptUpdateError(f"expected JSON object in {path}")
        return data

    def write_json_atomic(self, path: Path, data: Dict[str, Any]) -> None:
        self.write_text_atomic(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def fingerprint(self) -> str:
        """
        Hash all layer inputs except session context.
        """
        parts: list[str] = []
        for p in [
            self.layout.base_policy_path,
            self.layout.identity_path,
            self.layout.priorities_path,
            self.layout.identity_schema_path,
            self.layout.priorities_schema_path,
        ]:
            if p.exists():
                parts.append(_sha256_bytes(p.read_bytes()))
            else:
                parts.append("missing:" + str(p))
        return _sha256_text("|".join(parts))

    def snapshot(self, reason: str) -> Path:
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        out = self.layout.snapshots_dir / f"{ts}.tar"
        root = self.layout.root
        try:
            with tarfile.open(out, "w") as tf:
                tf.add(root, arcname="prompt")
                info = tarfile.TarInfo(name="prompt/_snapshot_reason.txt")
                payload = reason.encode("utf-8")
                info.size = len(payload)
                info.mtime = int(time.time())
                tf.addfile(info, fileobj=_BytesIO(payload))
        except Exception as exc:
            raise PromptUpdateError(f"snapshot failed: {exc}") from exc
        return out

    def rollback(self, snapshot_path: Path) -> None:
        if not snapshot_path.exists():
            raise PromptUpdateError(f"snapshot not found: {snapshot_path}")
        root = self.layout.root
        try:
            # Extract into a temp dir then replace root to avoid partial restores.
            tmp_root = root.parent / (root.name + ".rollback_tmp")
            if tmp_root.exists():
                _rmtree(tmp_root)
            tmp_root.mkdir(parents=True, exist_ok=True)
            with tarfile.open(snapshot_path, "r") as tf:
                tf.extractall(tmp_root)
            extracted = tmp_root / "prompt"
            if not extracted.exists():
                raise PromptUpdateError("snapshot missing prompt root")
            if root.exists():
                _rmtree(root)
            extracted.replace(root)
            _rmtree(tmp_root)
        except PromptUpdateError:
            raise
        except Exception as exc:
            raise PromptUpdateError(f"rollback failed: {exc}") from exc

    def append_audit_log(self, entry: Dict[str, Any]) -> None:
        ensure_parent_dir(self.layout.changes_log_path)
        line = json.dumps(entry, sort_keys=True) + "\n"
        with self.layout.changes_log_path.open("a", encoding="utf-8") as f:
            f.write(line)


class _BytesIO:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


def _rmtree(path: Path) -> None:
    for child in path.rglob("*"):
        if child.is_file() or child.is_symlink():
            child.unlink(missing_ok=True)
    for child in sorted([p for p in path.rglob("*") if p.is_dir()], reverse=True):
        child.rmdir()
    path.rmdir()

