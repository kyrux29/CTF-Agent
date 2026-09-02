from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from ctfmesh_provider_base import TriageEvidence, TriageRequest
from ctfmesh_provider_deepseek_chat import (
    DEEPSEEK_CHAT_BASE_URL,
    DEEPSEEK_CHAT_PATH,
    DeepSeekChatTriageClient,
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
        model="operator-deepseek-model",
        objective="Classify supplied evidence.",
        authorized_scope="Static evidence only.",
        evidence=(TriageEvidence(id="brief", kind="challenge", content="A CTF receipt."),),
    )


def response() -> ChatCompletionsHTTPResponse:
    return ChatCompletionsHTTPResponse(
        status_code=200,
        body={
            "id": "deepseek_fixture",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": (
                            '{"category":"crypto","summary":"A receipt exists.",'
                            '"facts":[],"hypotheses":[],"next_actions":['
                            '{"statement":"Inspect the receipt.","evidence_ids":["brief"]}]}'
                        )
                    },
                }
            ],
        },
    )


@pytest.mark.asyncio
async def test_deepseek_wrapper_delegates_one_validated_request_and_closes_transport() -> None:
    transport = FakeTransport(response())
    client = DeepSeekChatTriageClient(transport)

    completion = await client.triage(request(), api_key="sk-deepseek-fixture-secret-123456")
    await client.aclose()

    assert client.name == "deepseek-chat"
    assert completion.response_id == "deepseek_fixture"
    assert transport.calls == 1
    assert transport.closed is True


def test_deepseek_endpoint_is_a_reviewed_constant_not_a_constructor_argument() -> None:
    assert DEEPSEEK_CHAT_BASE_URL == "https://api.deepseek.com"
    assert DEEPSEEK_CHAT_PATH == "/chat/completions"


def test_deepseek_default_client_uses_only_the_reviewed_endpoint_and_explicit_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class SpyTransport:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        "ctfmesh_provider_deepseek_chat.triage.HttpxChatCompletionsTransport",
        SpyTransport,
    )
    DeepSeekChatTriageClient(proxy_url="http://provider-proxy:3128")

    assert observed == {
        "base_url": DEEPSEEK_CHAT_BASE_URL,
        "path": DEEPSEEK_CHAT_PATH,
        "proxy_url": "http://provider-proxy:3128",
    }
