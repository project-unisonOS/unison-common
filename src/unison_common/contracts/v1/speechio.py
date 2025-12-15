from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


AsrProfile = Literal["fast", "accurate"]
TtsProfile = Literal["lightweight", "natural"]


class EndpointingPolicy(BaseModel):
    hangover_ms: int = Field(default=700, ge=0, description="Silence hangover before finalizing.")
    min_utterance_ms: int = Field(default=250, ge=0, description="Ignore utterances shorter than this.")
    max_utterance_ms: int = Field(default=10_000, ge=0, description="Force-finalize at this duration.")


class BargeInPolicy(BaseModel):
    enabled: bool = True
    hard_interrupt_on_vad: bool = True


class SpeechCapabilities(BaseModel):
    schema_version: Literal["speech-capabilities.v1"] = "speech-capabilities.v1"
    streaming_partials: bool = False
    local_asr: bool = False
    neural_tts: bool = False
    barge_in: bool = False
    endpointing: bool = False
    engines: Dict[str, Any] = Field(default_factory=dict, description="Engine inventory/details (best-effort).")


class SpeechStatus(BaseModel):
    schema_version: Literal["speech-status.v1"] = "speech-status.v1"
    ready: bool = False
    reason: Optional[str] = None
    active_asr_profile: Optional[AsrProfile] = None
    active_tts_profile: Optional[TtsProfile] = None
    chosen_asr_engine: Optional[str] = None
    chosen_tts_engine: Optional[str] = None


TranscriptEventType = Literal["vad_start", "partial", "final", "vad_end", "error"]


class TranscriptEvent(BaseModel):
    schema_version: Literal["transcript-event.v1"] = "transcript-event.v1"
    type: TranscriptEventType
    ts_monotonic_ns: Optional[int] = None

    text: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    engine: Optional[str] = None
    profile: Optional[AsrProfile] = None
    attrs: Dict[str, Any] = Field(default_factory=dict)


class SpeakOptions(BaseModel):
    profile: TtsProfile = "lightweight"
    rate: Optional[float] = Field(default=None, ge=0.1, le=4.0)
    voice: Optional[str] = None
    volume: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    allow_barge_in: Optional[bool] = None


class SpeakResult(BaseModel):
    schema_version: Literal["speak-result.v1"] = "speak-result.v1"
    ok: bool = True
    engine: Optional[str] = None
    profile: Optional[TtsProfile] = None
    audio_url: Optional[str] = None
    error: Optional[str] = None

