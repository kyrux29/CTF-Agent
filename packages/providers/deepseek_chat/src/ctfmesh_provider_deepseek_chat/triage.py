"""DeepSeek adapter with a sealed chat-completions endpoint."""

from __future__ import annotations

from ctfmesh_provider_base import TriageCompletion, TriageRequest
from ctfmesh_provider_openai_compatible._chat import (
    AsyncChatCompletionsTransport,
    ChatCompletionsTriageClient,
    HttpxChatCompletionsTransport,
)

# The provider's chat surface is reviewed at code review time.  No request,
# model output, or UI field can alter this host or route.
DEEPSEEK_CHAT_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_CHAT_PATH = "/chat/completions"


class DeepSeekChatTriageClient:
    """One-shot DeepSeek JSON-mode adapter; local validation remains authoritative."""

    name = "deepseek-chat"

    def __init__(
        self,
        transport: AsyncChatCompletionsTransport | None = None,
        *,
        proxy_url: str | None = None,
    ) -> None:
        if transport is not None and proxy_url is not None:
            raise ValueError("transport and proxy_url cannot be configured together")
        self._transport = transport or HttpxChatCompletionsTransport(
            base_url=DEEPSEEK_CHAT_BASE_URL,
            path=DEEPSEEK_CHAT_PATH,
            proxy_url=proxy_url,
        )
        self._client = ChatCompletionsTriageClient(self._transport, provider_name=self.name)

    def __repr__(self) -> str:
        return "DeepSeekChatTriageClient()"

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
