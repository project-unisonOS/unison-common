"""
Unison prompt engine (model-agnostic).

This package owns the persistent, user-editable prompt layers that get compiled
into an active system prompt at runtime.
"""

from .engine import PromptEngine
from .injection import PromptInjection, compile_injected_system_prompt

__all__ = ["PromptEngine", "PromptInjection", "compile_injected_system_prompt"]
