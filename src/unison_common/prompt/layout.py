from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .constants import (
    ACTIVE_PROMPT_FILENAME,
    BASE_POLICY_FILENAME,
    CHANGES_LOG_FILENAME,
    DEFAULT_PROMPT_ROOT,
    DEFAULT_PROMPT_ROOT_ENV,
    IDENTITY_FILENAME,
    IDENTITY_SCHEMA_FILENAME,
    PRIORITIES_FILENAME,
    PRIORITIES_SCHEMA_FILENAME,
)


@dataclass(frozen=True)
class PromptLayout:
    root: Path

    @property
    def base_dir(self) -> Path:
        return self.root / "base"

    @property
    def user_dir(self) -> Path:
        return self.root / "user"

    @property
    def schema_dir(self) -> Path:
        return self.user_dir / "schema"

    @property
    def compiled_dir(self) -> Path:
        return self.root / "compiled"

    @property
    def history_dir(self) -> Path:
        return self.root / "history"

    @property
    def snapshots_dir(self) -> Path:
        return self.root / "snapshots"

    @property
    def base_policy_path(self) -> Path:
        return self.base_dir / BASE_POLICY_FILENAME

    @property
    def identity_path(self) -> Path:
        return self.user_dir / IDENTITY_FILENAME

    @property
    def priorities_path(self) -> Path:
        return self.user_dir / PRIORITIES_FILENAME

    @property
    def identity_schema_path(self) -> Path:
        return self.schema_dir / IDENTITY_SCHEMA_FILENAME

    @property
    def priorities_schema_path(self) -> Path:
        return self.schema_dir / PRIORITIES_SCHEMA_FILENAME

    @property
    def active_prompt_path(self) -> Path:
        return self.compiled_dir / ACTIVE_PROMPT_FILENAME

    @property
    def changes_log_path(self) -> Path:
        return self.history_dir / CHANGES_LOG_FILENAME


def resolve_prompt_root(root: str | None, person_id: str | None = None) -> Path:
    """
    Resolve prompt root directory.

    Supports simple templating: if the configured root contains `{person_id}`,
    it will be replaced at runtime.
    """
    raw = root or os.getenv(DEFAULT_PROMPT_ROOT_ENV) or DEFAULT_PROMPT_ROOT
    if person_id and "{person_id}" in raw:
        raw = raw.replace("{person_id}", person_id)
    return Path(os.path.expanduser(raw)).resolve()

