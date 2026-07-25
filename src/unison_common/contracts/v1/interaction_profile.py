from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProfilePreference(StrictContract):
    preference_id: str = Field(min_length=1)
    key: str = Field(min_length=1)
    value: Any
    origin: Literal["explicit", "observed", "inferred", "migrated"]
    state: Literal["proposed", "approved", "rejected"] = "approved"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def inferred_changes_start_proposed(self) -> "ProfilePreference":
        if self.origin == "inferred" and self.state == "approved" and self.provenance != "person-approved":
            raise ValueError("inferred adaptations require explicit approval")
        return self


class SituationalOverride(StrictContract):
    override_id: str
    key: str
    value: Any
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime


class InteractionProfile(StrictContract):
    schema_version: Literal["interaction-profile.v1"] = "interaction-profile.v1"
    person_id: str = Field(min_length=1)
    revision: int = Field(default=1, ge=1)
    preferred_inputs: list[str] = Field(default_factory=list)
    preferred_outputs: list[str] = Field(default_factory=list)
    unavailable_modalities: list[str] = Field(default_factory=list)
    needs: dict[str, Any] = Field(default_factory=dict)
    preferences: list[ProfilePreference] = Field(default_factory=list)
    device_associations: list[dict[str, Any]] = Field(default_factory=list)
    situational_overrides: list[SituationalOverride] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def effective_preferences(self, now: datetime | None = None) -> dict[str, Any]:
        at = now or datetime.now(timezone.utc)
        effective = {
            pref.key: pref.value
            for pref in self.preferences
            if pref.state == "approved" and (pref.expires_at is None or pref.expires_at > at)
        }
        for override in self.situational_overrides:
            if override.expires_at > at:
                effective[override.key] = override.value
        return effective

