"""
Unison prompt engine (model-agnostic).

This package owns the persistent, user-editable prompt layers that get compiled
into an active system prompt at runtime.
"""

from .engine import PromptEngine

__all__ = ["PromptEngine"]

