from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from ctfmesh_provider_base import TriageEvidence, TriageRequest
from ctfmesh_provider_gemini_openai_compat import (
    GEMINI_OPENAI_COMPAT_BASE_URL,
    GEMINI_OPENAI_COMPAT_PATH,
    GeminiOpenAICompatTriageClient,
)
from ctfmesh_provider_openai_compatible._chat import ChatCompletionsHTTPResponse


@dataclass
class FakeTransport:
    response: ChatCompletionsHTTPResponse
    calls: int = 0
    closed: bool = False

    async def post_chat_completions(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ChatCompletionsHTTPResponse:
        del api_key, payload, timeout_seconds
        self.calls += 1
        return self.response

    async def aclose(self) -> None:
        self.closed = True


def request() -> TriageRequest:
    return TriageRequest(
        model="operator-gemini-model",
        objective="Classify supplied evidence.",
        authorized_scope="Static evidence only.",
        evidence=(TriageEvidence(id="brief", kind="challenge", content="A CTF receipt."),),
    )


def response() -> ChatCompletionsHTTPResponse:
    return ChatCompletionsHTTPResponse(
        status_code=200,
        body={
            "id": "gemini_fixture",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": (
                            '{"category":"misc","summary":"A receipt exists.",'
                            '"facts":[],"hypotheses":[],"next_actions":['
                            '{"statement":"Inspect the receipt.","evidence_ids":["brief"]}]}'
                        )
                    },
                }
            ],
        },
    )


@pytest.mark.asyncio
async def test_gemini_wrapper_delegates_one_validated_request_and_closes_transport() -> None:
    transport = FakeTransport(response())
    client = GeminiOpenAICompatTriageClient(transport)

    completion = await client.triage(request(), api_key="AIzaGeminiFixture_123456789012345")
    await client.aclose()

    assert client.name == "gemini-openai-compat"
    assert completion.response_id == "gemini_fixture"
    assert transport.calls == 1
    assert transport.closed is True


def test_gemini_endpoint_is_a_reviewed_constant_not_a_constructor_argument() -> None:
    assert GEMINI_OPENAI_COMPAT_BASE_URL == "https://generativelanguage.googleapis.com"
    assert GEMINI_OPENAI_COMPAT_PATH == "/v1beta/openai/chat/completions"


def test_gemini_default_client_uses_only_the_reviewed_endpoint_and_explicit_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class SpyTransport:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        "ctfmesh_provider_gemini_openai_compat.triage.HttpxChatCompletionsTransport",
        SpyTransport,
    )
    GeminiOpenAICompatTriageClient(proxy_url="http://provider-proxy:3128")

    assert observed == {
        "base_url": GEMINI_OPENAI_COMPAT_BASE_URL,
        "path": GEMINI_OPENAI_COMPAT_PATH,
        "proxy_url": "http://provider-proxy:3128",
    }
