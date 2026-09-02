from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from ctfmesh_provider_openai_responses import (
    HttpxResponsesTransport,
    MissingOpenAIAPIKeyError,
    OpenAIResponsesHTTPError,
    OpenAIResponsesProtocolError,
    OpenAIResponsesTimeoutError,
    OpenAIResponsesTransportError,
    OpenAIResponsesTriageClient,
    ResponsesHTTPResponse,
    TriageEvidence,
    TriageRequest,
    TriageResult,
)


@dataclass
class FakeResponsesTransport:
    responses: list[ResponsesHTTPResponse | Exception]
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def post_responses(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ResponsesHTTPResponse:
        self.calls.append(
            {
                "api_key": api_key,
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def triage_request() -> TriageRequest:
    return TriageRequest(
        model="gpt-test",
        objective="Classify the authorized challenge from its supplied evidence.",
        authorized_scope="Only the local CTF fixture is authorized.",
        evidence=(
            TriageEvidence(
                id="challenge-brief",
                kind="challenge",
                content="A service and an attachment are supplied.",
            ),
        ),
    )


def successful_response() -> ResponsesHTTPResponse:
    result = {
        "category": "reverse",
        "summary": "The attachment should be inspected before any exploitation attempt.",
        "facts": [
            {
                "statement": "An attachment is available.",
                "confidence": 0.99,
                "evidence_ids": ["challenge-brief"],
            }
        ],
        "hypotheses": [
            {
                "statement": "The attachment may contain the primary challenge logic.",
                "confidence": 0.7,
                "evidence_ids": ["challenge-brief"],
            }
        ],
        "next_actions": [
            {
                "statement": "Inspect the attachment metadata in the authorized workspace.",
                "evidence_ids": ["challenge-brief"],
            }
        ],
    }
    return ResponsesHTTPResponse(
        status_code=200,
        body={
            "id": "resp_test_123",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": json.dumps(result)}],
                }
            ],
        },
    )


@pytest.mark.parametrize(
    "category",
    [
        "web",
        "crypto",
        "pwn",
        "reverse",
        "forensics",
        "osint",
        "misc",
        "ai_ml",
        "mobile",
        "blockchain",
        "hardware",
        "stego",
        "programming",
    ],
)
def test_triage_result_accepts_every_declared_ctf_category(category: str) -> None:
    result = TriageResult.model_validate(
        {
            "category": category,
            "summary": "A bounded fixture was supplied.",
            "facts": [
                {
                    "statement": "One declared artifact is available.",
                    "confidence": 0.9,
                    "evidence_ids": ["challenge-brief"],
                }
            ],
            "hypotheses": [],
            "next_actions": [
                {
                    "statement": "Review the supplied evidence.",
                    "evidence_ids": ["challenge-brief"],
                }
            ],
        }
    )

    assert result.category == category


def test_next_actions_require_evidence_citations() -> None:
    with pytest.raises(ValueError, match="evidence_ids"):
        TriageResult.model_validate(
            {
                "category": "crypto",
                "summary": "A bounded fixture was supplied.",
                "facts": [],
                "hypotheses": [],
                "next_actions": [{"statement": "Inspect the fixture metadata."}],
            }
        )


@pytest.mark.asyncio
async def test_triage_posts_a_strict_toolless_structured_output_request() -> None:
    transport = FakeResponsesTransport([successful_response()])
    client = OpenAIResponsesTriageClient(transport)

    completion = await client.triage(
        triage_request(),
        api_key="sk-test-in-memory-123456789",
        timeout_seconds=86_400,
    )

    assert completion.response_id == "resp_test_123"
    assert completion.result.category == "reverse"
    assert completion.result.facts[0].evidence_ids == ("challenge-brief",)
    assert completion.result.hypotheses[0].evidence_ids == ("challenge-brief",)
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["timeout_seconds"] == 86_400
    assert call["payload"]["max_output_tokens"] == 900
    assert call["payload"]["store"] is False
    assert call["payload"]["tools"] == []
    assert call["payload"]["text"]["format"] == {
        "type": "json_schema",
        "name": "ctfmesh_triage",
        "strict": True,
        "schema": call["payload"]["text"]["format"]["schema"],
    }
    assert "api_key" not in json.dumps(call["payload"])

    with pytest.raises(ValueError, match="between 0 and 86400"):
        await client.triage(
            triage_request(),
            api_key="sk-test-in-memory-123456789",
            timeout_seconds=86_401,
        )


@pytest.mark.asyncio
async def test_triage_rejects_malformed_structured_output_without_echoing_it() -> None:
    transport = FakeResponsesTransport(
        [
            ResponsesHTTPResponse(
                status_code=200,
                body={
                    "id": "resp_malformed",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "not valid JSON"}],
                        }
                    ],
                },
            )
        ]
    )

    with pytest.raises(OpenAIResponsesProtocolError, match="malformed_structured_output") as raised:
        await OpenAIResponsesTriageClient(transport).triage(
            triage_request(),
            api_key="sk-test-in-memory-123456789",
        )

    assert "not valid JSON" not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            {
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
            },
            "incomplete_max_output_tokens",
        ),
        (
            {
                "status": "incomplete",
                "incomplete_details": {"reason": "content_filter"},
            },
            "incomplete_content_filter",
        ),
        (
            {"status": "failed", "error": {"message": "untrusted upstream detail"}},
            "incomplete_response",
        ),
    ],
)
async def test_triage_classifies_only_documented_incomplete_reasons(
    body: dict[str, object],
    code: str,
) -> None:
    """A useful retry hint must not expose a provider body or error message."""

    transport = FakeResponsesTransport([ResponsesHTTPResponse(status_code=200, body=body)])

    with pytest.raises(OpenAIResponsesProtocolError, match=code) as raised:
        await OpenAIResponsesTriageClient(transport).triage(
            triage_request(),
            api_key="sk-test-in-memory-123456789",
        )

    assert "untrusted upstream detail" not in str(raised.value)


@pytest.mark.asyncio
async def test_triage_requires_an_explicit_in_memory_api_key() -> None:
    transport = FakeResponsesTransport([successful_response()])

    with pytest.raises(MissingOpenAIAPIKeyError, match="missing_api_key"):
        await OpenAIResponsesTriageClient(transport).triage(triage_request(), api_key=" ")

    assert transport.calls == []


@pytest.mark.asyncio
async def test_http_error_and_diagnostics_redact_the_api_key() -> None:
    api_key = "sk-private-in-memory-123456789"
    raw_flag = "CTF{provider_error_must_not_leak}"
    transport = FakeResponsesTransport(
        [
            ResponsesHTTPResponse(
                status_code=429,
                body={"error": {"message": f"Bearer {api_key} was rejected {raw_flag}"}},
            )
        ]
    )
    client = OpenAIResponsesTriageClient(transport)

    with pytest.raises(OpenAIResponsesHTTPError) as raised:
        await client.triage(triage_request(), api_key=api_key)

    diagnostic = f"{raised.value!r} {raised.value} {client!r}"
    assert "status=429" in diagnostic
    assert api_key not in diagnostic
    assert raw_flag not in diagnostic
    assert "[REDACTED]" in diagnostic
    assert "[REDACTED_FLAG]" in diagnostic


@pytest.mark.asyncio
async def test_timeout_is_bounded_and_never_exposes_the_api_key() -> None:
    api_key = "sk-timeout-private-123456789"
    transport = FakeResponsesTransport([TimeoutError(f"Bearer {api_key}")])

    with pytest.raises(OpenAIResponsesTimeoutError) as raised:
        await OpenAIResponsesTriageClient(transport).triage(
            triage_request(),
            api_key=api_key,
            timeout_seconds=0.01,
        )

    assert api_key not in f"{raised.value!r} {raised.value}"


@pytest.mark.asyncio
async def test_transport_failure_redacts_the_api_key_from_diagnostics() -> None:
    api_key = "sk-transport-private-123456789"
    transport = FakeResponsesTransport([RuntimeError(f"upstream rejected Bearer {api_key}")])
    client = OpenAIResponsesTriageClient(transport)

    with pytest.raises(OpenAIResponsesTransportError) as raised:
        await client.triage(triage_request(), api_key=api_key)

    diagnostic = f"{raised.value!r} {raised.value} {client!r}"
    assert api_key not in diagnostic
    assert "[REDACTED]" in diagnostic


@pytest.mark.asyncio
async def test_httpx_transport_uses_the_responses_endpoint_and_in_memory_key() -> None:
    observed: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["path"] = request.url.path
        observed["authorization"] = request.headers["Authorization"]
        return httpx.Response(200, json={"id": "resp_httpx"})

    transport = HttpxResponsesTransport(transport=httpx.MockTransport(handler))
    try:
        response = await transport.post_responses(
            api_key="sk-transport-test-123456789",
            payload={"model": "gpt-test"},
            timeout_seconds=3,
        )
    finally:
        await transport.aclose()

    assert response.status_code == 200
    assert response.body == {"id": "resp_httpx"}
    assert observed == {
        "method": "POST",
        "path": "/v1/responses",
        "authorization": "Bearer sk-transport-test-123456789",
    }


@pytest.mark.asyncio
async def test_httpx_transport_keeps_a_redirect_from_leaving_the_openai_origin() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://example.invalid/steal"})

    transport = HttpxResponsesTransport(transport=httpx.MockTransport(handler))
    try:
        response = await transport.post_responses(
            api_key="sk-redirect-test-123456789",
            payload={"model": "gpt-test"},
            timeout_seconds=3,
        )
    finally:
        await transport.aclose()

    assert response.status_code == 302
    assert requests == ["https://api.openai.com/v1/responses"]


def test_httpx_transport_uses_only_an_explicit_proxy_and_disables_ambient_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class RecordingClient:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

    monkeypatch.setattr(
        "ctfmesh_provider_openai_responses.triage.httpx.AsyncClient",
        RecordingClient,
    )
    HttpxResponsesTransport(proxy_url="http://provider-proxy:3128")

    assert observed["base_url"] == "https://api.openai.com"
    assert observed["follow_redirects"] is False
    assert observed["trust_env"] is False
    assert observed["proxy"] == "http://provider-proxy:3128"


def test_httpx_transport_rejects_ambiguous_mock_transport_and_proxy() -> None:
    with pytest.raises(ValueError, match="transport and proxy_url"):
        HttpxResponsesTransport(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
            proxy_url="http://provider-proxy:3128",
        )
