from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from ctfmesh_provider_base import (
    TriageEvidence,
    TriageHTTPError,
    TriageProtocolError,
    TriageRequest,
    TriageResponseTooLargeError,
    TriageTransportError,
)
from ctfmesh_provider_openai_compatible._chat import (
    ChatCompletionsHTTPResponse,
    ChatCompletionsTriageClient,
    HttpxChatCompletionsTransport,
)


@dataclass
class FakeTransport:
    responses: list[ChatCompletionsHTTPResponse | Exception]
    calls: list[dict[str, Any]] = field(default_factory=list)
    closed: bool = False

    async def post_chat_completions(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ChatCompletionsHTTPResponse:
        self.calls.append(
            {
                "api_key": api_key,
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        next_response = self.responses.pop(0)
        if isinstance(next_response, Exception):
            raise next_response
        return next_response

    async def aclose(self) -> None:
        self.closed = True


def request() -> TriageRequest:
    return TriageRequest(
        model="operator-model",
        objective="Classify the authorized case from supplied evidence only.",
        authorized_scope="Only static, redacted local evidence is authorized.",
        evidence=(
            TriageEvidence(
                id="brief",
                kind="challenge",
                content="A bounded CTF archive receipt was supplied.",
            ),
        ),
    )


def success_response(*, evidence_id: str = "brief") -> ChatCompletionsHTTPResponse:
    result = {
        "category": "forensics",
        "summary": "The supplied evidence describes a bounded artifact case.",
        "facts": [
            {
                "statement": "One receipt observation is available.",
                "confidence": 0.95,
                "evidence_ids": [evidence_id],
            }
        ],
        "hypotheses": [],
        "next_actions": [
            {
                "statement": "Inspect only the declared local artifact metadata.",
                "evidence_ids": [evidence_id],
            }
        ],
    }
    return ChatCompletionsHTTPResponse(
        status_code=200,
        body={
            "id": "chat_fixture",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": json.dumps(result)},
                }
            ],
        },
    )


@pytest.mark.asyncio
async def test_client_uses_one_toolless_json_mode_request_and_validates_evidence() -> None:
    transport = FakeTransport([success_response()])
    client = ChatCompletionsTriageClient(transport, provider_name="fixture-provider")
    api_key = "fixture-provider-secret"

    completion = await client.triage(request(), api_key=api_key, timeout_seconds=86_400)

    assert completion.response_id == "chat_fixture"
    assert completion.result.category == "forensics"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["api_key"] == api_key
    assert call["timeout_seconds"] == 86_400
    assert call["payload"]["response_format"] == {"type": "json_object"}
    assert call["payload"]["stream"] is False
    assert "tools" not in call["payload"]
    assert "tool_choice" not in call["payload"]
    assert api_key not in json.dumps(call["payload"])
    assert "output_schema" in json.loads(call["payload"]["messages"][1]["content"])

    with pytest.raises(ValueError, match="between 0 and 86400"):
        await client.triage(request(), api_key=api_key, timeout_seconds=86_401)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            {"id": "chat_length", "choices": [{"finish_reason": "length", "message": {}}]},
            "incomplete_response",
        ),
        (
            {
                "id": "chat_tool",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "{}", "tool_calls": [{"id": "not-allowed"}]},
                    }
                ],
            },
            "provider_tool_call_forbidden",
        ),
    ],
)
async def test_client_rejects_incomplete_or_provider_tool_output(
    body: dict[str, object], code: str
) -> None:
    transport = FakeTransport([ChatCompletionsHTTPResponse(status_code=200, body=body)])

    with pytest.raises(TriageProtocolError, match=code):
        await ChatCompletionsTriageClient(transport, provider_name="fixture").triage(
            request(), api_key="fixture-secret"
        )

    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_client_rejects_unknown_evidence_citations() -> None:
    transport = FakeTransport([success_response(evidence_id="not-supplied")])

    with pytest.raises(TriageProtocolError, match="triage_cites_unknown_evidence"):
        await ChatCompletionsTriageClient(transport, provider_name="fixture").triage(
            request(), api_key="fixture-secret"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "api_key",
    [
        "sk-deepseek-fixture-secret-123456",
        "AIzaGeminiFixtureSecret_1234567890123",
    ],
)
async def test_failures_redact_each_selected_provider_key(api_key: str) -> None:
    transport = FakeTransport([RuntimeError(f"upstream rejected Bearer {api_key}")])
    client = ChatCompletionsTriageClient(transport, provider_name="fixture")

    with pytest.raises(TriageTransportError) as raised:
        await client.triage(request(), api_key=api_key)

    diagnostic = f"{raised.value!r} {raised.value} {client!r}"
    assert api_key not in diagnostic
    assert "[REDACTED]" in diagnostic
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_http_error_is_redacted_and_not_retried() -> None:
    api_key = "sk-deepseek-http-secret-123456"
    transport = FakeTransport(
        [
            ChatCompletionsHTTPResponse(
                status_code=429,
                body={"error": {"message": f"Bearer {api_key} was rejected"}},
            )
        ]
    )

    with pytest.raises(TriageHTTPError) as raised:
        await ChatCompletionsTriageClient(transport, provider_name="fixture").triage(
            request(), api_key=api_key
        )

    assert api_key not in f"{raised.value!r} {raised.value}"
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_http_error_redacts_raw_flags_and_sensitive_json_fields() -> None:
    raw_flag = "ctf{unusual+/=characters!}"
    raw_answer = "a-provider-error-must-not-log-this-answer"
    transport = FakeTransport(
        [
            ChatCompletionsHTTPResponse(
                status_code=400,
                body={
                    "error": {"message": f"request context included {raw_flag}"},
                    "flag": raw_answer,
                },
            )
        ]
    )

    with pytest.raises(TriageHTTPError) as raised:
        await ChatCompletionsTriageClient(transport, provider_name="fixture").triage(
            request(), api_key="fixture-secret"
        )

    diagnostic = f"{raised.value!r} {raised.value}"
    assert raw_flag not in diagnostic
    assert raw_answer not in diagnostic
    assert "[REDACTED_FLAG]" in diagnostic
    assert "[REDACTED_SECRET]" in diagnostic


@pytest.mark.asyncio
async def test_httpx_transport_uses_bounded_body_and_exact_path() -> None:
    observed: dict[str, object] = {}

    async def handler(http_request: httpx.Request) -> httpx.Response:
        observed["method"] = http_request.method
        observed["url"] = str(http_request.url)
        observed["authorization"] = http_request.headers["Authorization"]
        observed["payload"] = json.loads(http_request.content)
        return httpx.Response(200, json={"id": "safe"})

    async with httpx.AsyncClient(
        base_url="https://provider.test",
        transport=httpx.MockTransport(handler),
    ) as http_client:
        transport = HttpxChatCompletionsTransport(
            base_url="https://provider.test",
            path="/chat/completions",
            client=http_client,
            max_response_bytes=1024,
        )
        response = await transport.post_chat_completions(
            api_key="fixture-key",
            payload={"model": "fixture"},
            timeout_seconds=3,
        )

    assert response.body == {"id": "safe"}
    assert observed == {
        "method": "POST",
        "url": "https://provider.test/chat/completions",
        "authorization": "Bearer fixture-key",
        "payload": {"model": "fixture"},
    }


@pytest.mark.asyncio
async def test_httpx_transport_rejects_a_response_over_the_real_byte_cap() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"0123456789")

    async with httpx.AsyncClient(
        base_url="https://provider.test",
        transport=httpx.MockTransport(handler),
    ) as http_client:
        transport = HttpxChatCompletionsTransport(
            base_url="https://provider.test",
            path="/chat/completions",
            client=http_client,
            max_response_bytes=8,
        )
        with pytest.raises(TriageResponseTooLargeError, match="response_too_large"):
            await transport.post_chat_completions(
                api_key="fixture-key",
                payload={"model": "fixture"},
                timeout_seconds=3,
            )


def test_httpx_transport_uses_only_an_explicit_proxy_and_disables_ambient_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class RecordingClient:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

    monkeypatch.setattr(
        "ctfmesh_provider_openai_compatible._chat.httpx.AsyncClient",
        RecordingClient,
    )
    HttpxChatCompletionsTransport(
        base_url="https://provider.test",
        path="/chat/completions",
        proxy_url="http://provider-proxy:3128",
    )

    assert observed["base_url"] == "https://provider.test"
    assert observed["follow_redirects"] is False
    assert observed["trust_env"] is False
    assert observed["proxy"] == "http://provider-proxy:3128"


@pytest.mark.asyncio
async def test_httpx_transport_rejects_ambiguous_custom_client_and_proxy() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="client and proxy_url"):
            HttpxChatCompletionsTransport(
                base_url="https://provider.test",
                path="/chat/completions",
                client=client,
                proxy_url="http://provider-proxy:3128",
            )
