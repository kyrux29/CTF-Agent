"""Fixed, one-shot provider sessions for archive triage.

The registry is intentionally small and code-owned.  It is not a generic MCP
or model-plugin loader: an operator can choose a reviewed provider identifier
and exact model ID, but cannot direct a credential to a custom URL, inject
headers, or enable provider tools.  Every call gets a fresh client/transport
so provider credentials never become application configuration.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from ctfmesh_provider_base import TriageBackend
from ctfmesh_provider_deepseek_chat import DeepSeekChatTriageClient
from ctfmesh_provider_gemini_openai_compat import GeminiOpenAICompatTriageClient
from ctfmesh_provider_openai_responses import (
    HttpxResponsesTransport,
    OpenAIResponsesTriageClient,
)


class ArchiveTriageProvider(StrEnum):
    """The exact server-side adapters the archive UI may select."""

    OPENAI_RESPONSES = "openai-responses"
    GEMINI_OPENAI_COMPAT = "gemini-openai-compat"
    DEEPSEEK_CHAT = "deepseek-chat"


class ProviderOutputContract(StrEnum):
    """How strongly a provider can enforce structured output on its wire API."""

    STRICT_SCHEMA = "strict_schema"
    JSON_VALIDATED = "json_validated"


@dataclass(frozen=True, slots=True)
class ArchiveTriageProviderDescriptor:
    """Public, non-secret facts needed to make the UI boundary understandable."""

    id: ArchiveTriageProvider
    label: str
    key_label: str
    output_contract: ProviderOutputContract


@dataclass(slots=True)
class ArchiveTriageProviderSession:
    """A fresh backend and its explicit close operation for one API request."""

    descriptor: ArchiveTriageProviderDescriptor
    backend: TriageBackend
    _close: Callable[[], Awaitable[None]]

    async def aclose(self) -> None:
        """Release only request-local network resources; no secret is retained."""

        await self._close()


_DESCRIPTORS = {
    ArchiveTriageProvider.OPENAI_RESPONSES: ArchiveTriageProviderDescriptor(
        id=ArchiveTriageProvider.OPENAI_RESPONSES,
        label="OpenAI Responses",
        key_label="OpenAI API key",
        output_contract=ProviderOutputContract.STRICT_SCHEMA,
    ),
    ArchiveTriageProvider.GEMINI_OPENAI_COMPAT: ArchiveTriageProviderDescriptor(
        id=ArchiveTriageProvider.GEMINI_OPENAI_COMPAT,
        label="Google Gemini",
        key_label="Gemini API key",
        output_contract=ProviderOutputContract.JSON_VALIDATED,
    ),
    ArchiveTriageProvider.DEEPSEEK_CHAT: ArchiveTriageProviderDescriptor(
        id=ArchiveTriageProvider.DEEPSEEK_CHAT,
        label="DeepSeek Chat",
        key_label="DeepSeek API key",
        output_contract=ProviderOutputContract.JSON_VALIDATED,
    ),
}

ArchiveTriageProviderFactory = Callable[[ArchiveTriageProvider], ArchiveTriageProviderSession]


def archive_triage_provider_descriptors() -> tuple[ArchiveTriageProviderDescriptor, ...]:
    """Return the reviewed allowlist in a deterministic UI/API order."""

    return tuple(_DESCRIPTORS[provider] for provider in ArchiveTriageProvider)


def create_archive_triage_provider_session(
    provider: ArchiveTriageProvider,
    *,
    proxy_url: str,
) -> ArchiveTriageProviderSession:
    """Open a provider session through the composition-root-approved proxy.

    Hosts, routes, redirect behavior, and tool policy live in provider-package
    code. ``proxy_url`` is validated by the API settings composition root; it
    is never supplied by an API request or model. The route injects a one-time
    key only when calling the returned backend.
    """

    descriptor = _DESCRIPTORS[provider]
    if provider is ArchiveTriageProvider.OPENAI_RESPONSES:
        transport = HttpxResponsesTransport(proxy_url=proxy_url)
        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=OpenAIResponsesTriageClient(transport),
            _close=transport.aclose,
        )
    if provider is ArchiveTriageProvider.GEMINI_OPENAI_COMPAT:
        client = GeminiOpenAICompatTriageClient(proxy_url=proxy_url)
        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=client,
            _close=client.aclose,
        )
    if provider is ArchiveTriageProvider.DEEPSEEK_CHAT:
        client = DeepSeekChatTriageClient(proxy_url=proxy_url)
        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=client,
            _close=client.aclose,
        )
    # StrEnum/Pydantic validate this before the factory in product code. Keep
    # an explicit future-proof deny path if a caller bypasses that boundary.
    raise ValueError("archive_triage_provider_not_supported")


__all__ = [
    "ArchiveTriageProvider",
    "ArchiveTriageProviderDescriptor",
    "ArchiveTriageProviderFactory",
    "ArchiveTriageProviderSession",
    "ProviderOutputContract",
    "archive_triage_provider_descriptors",
    "create_archive_triage_provider_session",
]
