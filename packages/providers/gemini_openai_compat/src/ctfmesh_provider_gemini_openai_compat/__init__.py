"""Sealed Gemini OpenAI-compatible adapter for proposal-only CTF triage."""

from .triage import (
    GEMINI_OPENAI_COMPAT_BASE_URL,
    GEMINI_OPENAI_COMPAT_PATH,
    GeminiOpenAICompatTriageClient,
)

__all__ = [
    "GEMINI_OPENAI_COMPAT_BASE_URL",
    "GEMINI_OPENAI_COMPAT_PATH",
    "GeminiOpenAICompatTriageClient",
]
