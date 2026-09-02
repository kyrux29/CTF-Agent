"""P2 provider adapter contracts, without making a provider network call."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from ctfmesh_provider_openai_compatible._chat import ChatCompletionsHTTPResponse
from ctfmesh_solver_runtime import (
    OpenAICompatibleSolverBackend,
    SolverContext,
    SolverModelError,
    SolverProvider,
)
from pydantic import SecretStr


class _Transport:
    def __init__(self, response: ChatCompletionsHTTPResponse) -> None:
        self.response = response
        self.payload: Mapping[str, Any] | None = None
        self.api_key: str | None = None

    async def post_chat_completions(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ChatCompletionsHTTPResponse:
        assert timeout_seconds == 90.0
        self.api_key = api_key
        self.payload = payload
        return self.response

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_solver_backend_accepts_one_validated_json_action_without_exposing_its_key() -> None:
    """Provider text becomes an action only after local discriminated parsing."""

    api_key = "fixture-provider-key-123456"
    transport = _Transport(
        ChatCompletionsHTTPResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": '{"type":"fs.ls","path":"/challenge"}',
                        }
                    }
                ]
            },
        )
    )
    backend = OpenAICompatibleSolverBackend(
        provider=SolverProvider.DEEPSEEK_CHAT,
        model="deepseek-v4-pro",
        api_key=SecretStr(api_key),
        proxy_url="",
        transport=transport,
    )
    turn = await backend.next_turn(SolverContext("known file", "", ()))
    assert turn.action is not None
    assert turn.action.type == "fs.ls"
    assert transport.api_key == api_key
    assert transport.payload is not None
    assert transport.payload["response_format"] == {"type": "json_object"}
    assert transport.payload["thinking"] == {"type": "disabled"}
    assert transport.payload["temperature"] == 0.2
    assert api_key not in repr(backend)


@pytest.mark.asyncio
async def test_solver_backend_accepts_deepseek_thinking_metadata_without_exposing_it() -> None:
    """DeepSeek V4 reasoning is ignored while its final JSON action is validated."""

    private_reasoning = "private chain of thought that must not cross the adapter"
    transport = _Transport(
        ChatCompletionsHTTPResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "reasoning_content": private_reasoning,
                            "content": '{"type":"fs.ls","path":"/challenge"}',
                        }
                    }
                ]
            },
        )
    )
    backend = OpenAICompatibleSolverBackend(
        provider=SolverProvider.DEEPSEEK_CHAT,
        model="deepseek-v4-pro",
        api_key=SecretStr("fixture-provider-key-123456"),
        proxy_url="",
        transport=transport,
    )

    turn = await backend.next_turn(SolverContext("", "", ()))

    assert turn.action is not None and turn.action.type == "fs.ls"
    assert turn.thought == ""
    assert private_reasoning not in repr(turn)


@pytest.mark.asyncio
async def test_solver_backend_uses_validated_racer_temperature() -> None:
    """P6 can diversify same-model racers without letting evidence set sampling."""

    transport = _Transport(
        ChatCompletionsHTTPResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": '{"type":"fs.ls","path":"/challenge"}',
                        }
                    }
                ]
            },
        )
    )
    backend = OpenAICompatibleSolverBackend(
        provider=SolverProvider.OPENAI_CHAT,
        model="gpt-5.6-terra",
        api_key=SecretStr("fixture-provider-key-123456"),
        proxy_url="",
        temperature=0.8,
        transport=transport,
    )

    await backend.next_turn(SolverContext("", "", ()))
    assert transport.payload is not None
    assert transport.payload["temperature"] == 0.8
    with pytest.raises(ValueError, match="solver_model_temperature_invalid"):
        OpenAICompatibleSolverBackend(
            provider=SolverProvider.OPENAI_CHAT,
            model="gpt-5.6-terra",
            api_key=SecretStr("fixture-provider-key-123456"),
            proxy_url="",
            temperature=2.1,
            transport=transport,
        )


@pytest.mark.asyncio
async def test_solver_backend_rejects_provider_prose_or_tool_call_shape() -> None:
    """A provider completion cannot smuggle a tool-call result or untyped prose."""

    transport = _Transport(
        ChatCompletionsHTTPResponse(
            status_code=200,
            body={"choices": [{"message": {"role": "assistant", "content": "CTF{fake}"}}]},
        )
    )
    backend = OpenAICompatibleSolverBackend(
        provider=SolverProvider.GEMINI_OPENAI_COMPAT,
        model="gemini-3.7-flash",
        api_key=SecretStr("fixture-provider-key-123456"),
        proxy_url="",
        transport=transport,
    )
    with pytest.raises(SolverModelError, match="solver_model_action_invalid"):
        await backend.next_turn(SolverContext("", "", ()))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [
        (401, "solver_model_auth_rejected"),
        (402, "solver_model_payment_required"),
        (404, "solver_model_not_found"),
        (429, "solver_model_rate_limited"),
        (400, "solver_model_request_rejected"),
        (503, "solver_model_provider_unavailable"),
    ],
)
async def test_solver_backend_maps_only_provider_status_to_a_safe_error(
    status_code: int,
    expected_code: str,
) -> None:
    """Provider diagnostics stay unread while operators receive a recovery class."""

    transport = _Transport(
        ChatCompletionsHTTPResponse(
            status_code=status_code,
            body={"error": {"message": "diagnostic must remain private"}},
        )
    )
    backend = OpenAICompatibleSolverBackend(
        provider=SolverProvider.DEEPSEEK_CHAT,
        model="deepseek-v4-pro",
        api_key=SecretStr("fixture-provider-key-123456"),
        proxy_url="",
        transport=transport,
    )

    with pytest.raises(SolverModelError, match=f"^{expected_code}$"):
        await backend.next_turn(SolverContext("", "", ()))
