"""Gemini adapter with a sealed OpenAI-compatible chat-completions endpoint."""

from __future__ import annotations

from ctfmesh_provider_base import TriageCompletion, TriageRequest
from ctfmesh_provider_openai_compatible._chat import (
    AsyncChatCompletionsTransport,
    ChatCompletionsTriageClient,
    HttpxChatCompletionsTransport,
)

# These reviewed constants are deliberately not request/config fields.  A
# browser operator can choose a model, but cannot redirect a Gemini key to an
# arbitrary host through CTFMesh.
GEMINI_OPENAI_COMPAT_BASE_URL = "https://generativelanguage.googleapis.com"
GEMINI_OPENAI_COMPAT_PATH = "/v1beta/openai/chat/completions"


class GeminiOpenAICompatTriageClient:
    """One-shot Gemini JSON-mode adapter; local validation remains authoritative."""

    name = "gemini-openai-compat"

    def __init__(
        self,
        transport: AsyncChatCompletionsTransport | None = None,
        *,
        proxy_url: str | None = None,
    ) -> None:
        if transport is not None and proxy_url is not None:
            raise ValueError("transport and proxy_url cannot be configured together")
        self._transport = transport or HttpxChatCompletionsTransport(
            base_url=GEMINI_OPENAI_COMPAT_BASE_URL,
            path=GEMINI_OPENAI_COMPAT_PATH,
            proxy_url=proxy_url,
        )
        self._client = ChatCompletionsTriageClient(self._transport, provider_name=self.name)

    def __repr__(self) -> str:
        return "GeminiOpenAICompatTriageClient()"

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        return await self._client.triage(
            request,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
