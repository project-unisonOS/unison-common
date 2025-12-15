from __future__ import annotations

from typing import AsyncIterable, Optional, Protocol

from unison_common.contracts.v1.speechio import (
    AsrProfile,
    BargeInPolicy,
    EndpointingPolicy,
    SpeakOptions,
    SpeakResult,
    SpeechCapabilities,
    SpeechStatus,
    TranscriptEvent,
)


class SpeechIO(Protocol):
    """
    SpeechIO adapter interface (v1).

    This is an orchestrator-facing abstraction over speech capture (ASR/VAD)
    and speech synthesis (TTS), designed to keep orchestration policy stable
    while implementations swap (local engines, remote services, multimodal models).
    """

    async def initialize(self, config: dict) -> None: ...

    def getCapabilities(self) -> SpeechCapabilities: ...

    def getStatus(self) -> SpeechStatus: ...

    async def startCapture(
        self,
        *,
        asr_profile: AsrProfile,
        endpointing: EndpointingPolicy,
        locale: Optional[str] = None,
        streaming_facade: bool = True,
    ) -> AsyncIterable[TranscriptEvent]: ...

    async def stopCapture(self) -> None: ...

    async def speak(self, text: str, options: SpeakOptions) -> SpeakResult: ...

    async def stopSpeaking(self, reason: Optional[str] = None) -> None: ...

    async def setActiveProfiles(self, *, asr_profile: AsrProfile, tts_profile: str) -> None: ...


__all__ = [
    "AsrProfile",
    "BargeInPolicy",
    "EndpointingPolicy",
    "SpeakOptions",
    "SpeakResult",
    "SpeechCapabilities",
    "SpeechIO",
    "SpeechStatus",
    "TranscriptEvent",
]

