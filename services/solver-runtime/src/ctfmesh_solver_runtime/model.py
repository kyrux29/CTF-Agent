"""Sealed OpenAI-compatible model adapter for the Power ReAct loop.

The adapter owns only the short-lived provider call. It cannot create a
workspace, update run state, or turn text into a solve; those authorities stay
with sandboxd and flag-router respectively.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from ctfmesh_aci import SolverAction
from ctfmesh_provider_openai_compatible._chat import (
    AsyncChatCompletionsTransport,
    HttpxChatCompletionsTransport,
)
from pydantic import SecretStr, TypeAdapter, ValidationError

from .runner import ModelBackend, SolverContext, SolverTurn

_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_ACTION_ADAPTER = TypeAdapter(SolverAction)
_SYSTEM_PROMPT = (
    "You solve an authorized CTF only through the supplied action schema. "
    "Do not invent command output, a flag, or tool results. Return exactly one JSON action. "
    "Use flag.submit only when an observation contains the complete candidate and cite that "
    "observation artifact and SHA-256 exactly. Execute one action per turn."
)


class SolverProvider(StrEnum):
    """Reviewed provider endpoints; neither a model nor UI can add a URL."""

    OPENAI_CHAT = "openai-chat"
    GEMINI_OPENAI_COMPAT = "gemini-openai-compat"
    DEEPSEEK_CHAT = "deepseek-chat"


@dataclass(frozen=True, slots=True)
class _ProviderRoute:
    base_url: str
    path: str


_ROUTES = {
    SolverProvider.OPENAI_CHAT: _ProviderRoute("https://api.openai.com", "/v1/chat/completions"),
    SolverProvider.GEMINI_OPENAI_COMPAT: _ProviderRoute(
        "https://generativelanguage.googleapis.com", "/v1beta/openai/chat/completions"
    ),
    SolverProvider.DEEPSEEK_CHAT: _ProviderRoute("https://api.deepseek.com", "/chat/completions"),
}


class SolverModelError(RuntimeError):
    """Stable provider outcome that deliberately omits model/API-key details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OpenAICompatibleSolverBackend(ModelBackend):
    """Call one reviewed endpoint through the composition-owned provider proxy."""

    def __init__(
        self,
        *,
        provider: SolverProvider,
        model: str,
        api_key: SecretStr,
        proxy_url: str,
        timeout_seconds: float = 90.0,
        max_output_tokens: int = 1_024,
        temperature: float = 0.2,
        transport: AsyncChatCompletionsTransport | None = None,
    ) -> None:
        if _MODEL_NAME.fullmatch(model) is None:
            raise ValueError("solver_model_name_invalid")
        if not 1 <= len(api_key.get_secret_value()) <= 512:
            raise ValueError("solver_api_key_invalid")
        if not 1 <= timeout_seconds <= 86_400:
            raise ValueError("solver_model_timeout_invalid")
        if not 128 <= max_output_tokens <= 8_192:
            raise ValueError("solver_model_output_budget_invalid")
        if not 0 <= temperature <= 2:
            raise ValueError("solver_model_temperature_invalid")
        if transport is not None and proxy_url:
            raise ValueError("solver_model_transport_proxy_conflict")
        if transport is None and proxy_url != "http://provider-proxy:3128":
            raise ValueError("solver_model_proxy_invalid")
        route = _ROUTES[provider]
        self._provider = provider
        self._model = model
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_output_tokens = max_output_tokens
        self._temperature = temperature
        self._transport = transport or HttpxChatCompletionsTransport(
            base_url=route.base_url,
            path=route.path,
            proxy_url=proxy_url,
        )

    def __repr__(self) -> str:
        return (
            "OpenAICompatibleSolverBackend("
            f"provider={self._provider.value!r}, model={self._model!r})"
        )

    async def aclose(self) -> None:
        """Release the provider client; no credential is persisted by this call."""

        await self._transport.aclose()

    async def next_turn(self, context: SolverContext) -> SolverTurn:
        """Parse one JSON action; prose and malformed completions have no authority."""

        payload = {
            "model": self._model,
            "max_tokens": self._max_output_tokens,
            # P6 composes independent racers with different temperatures when
            # one provider key/model must power all three boxes. The value is
            # validated locally and is never supplied by challenge evidence.
            "temperature": self._temperature,
            "stream": False,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "initial_brief": context.initial_brief,
                            # P4 coordinator guidance is operational only.
                            # Tool observations remain the sole evidence for
                            # any later flag submission.
                            "coordinator_hint": context.coordinator_hint,
                            "observation_summary": context.observation_summary,
                            "recent_observations": [
                                {
                                    "sequence": item.sequence,
                                    "action_type": item.action_type,
                                    "stdout": item.stdout,
                                    "stderr": item.stderr,
                                    "exit_code": item.exit_code,
                                    "timed_out": item.timed_out,
                                    "output_truncated": item.output_truncated,
                                    "artifact_id": item.artifact_id,
                                    "sha256": item.sha256,
                                    # Session IDs originate solely from a
                                    # sandbox observation; sending them back
                                    # lets a later turn address the same GDB
                                    # or tube without inventing an endpoint.
                                    "interactive_id": item.interactive_id,
                                    "interactive_kind": item.interactive_kind,
                                }
                                for item in context.observations
                            ],
                            "action_schema": _ACTION_ADAPTER.json_schema(),
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
        }
        # DeepSeek V4 enables private thinking by default. A Power turn is a
        # typed action protocol, so keep the output budget for the JSON action
        # itself; private reasoning is never evidence or execution input.
        # Other reviewed providers do not receive this provider-specific key.
        if self._provider is SolverProvider.DEEPSEEK_CHAT:
            payload["thinking"] = {"type": "disabled"}
        try:
            async with asyncio.timeout(self._timeout_seconds):
                response = await self._transport.post_chat_completions(
                    api_key=self._api_key.get_secret_value(),
                    payload=payload,
                    timeout_seconds=self._timeout_seconds,
                )
        except TimeoutError:
            raise SolverModelError("solver_model_timeout") from None
        except Exception as exc:
            raise SolverModelError("solver_model_unavailable") from exc
        if not 200 <= response.status_code < 300:
            raise SolverModelError(_provider_status_code(response.status_code))
        try:
            action = _ACTION_ADAPTER.validate_json(_content_from_response(response.body))
        except (TypeError, ValidationError, ValueError) as exc:
            raise SolverModelError("solver_model_action_invalid") from exc
        return SolverTurn(action=action)


def _content_from_response(body: object | None) -> str:
    """Extract final content while discarding provider reasoning metadata.

    DeepSeek V4 emits ``reasoning_content`` by default in thinking mode. It is
    private model work rather than an observation, so the adapter accepts only
    its documented string/null shape and never returns or persists it.
    """

    if not isinstance(body, Mapping):
        raise ValueError("solver_model_response_invalid")
    choices = body.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], Mapping):
        raise ValueError("solver_model_response_invalid")
    message = choices[0].get("message")
    if not isinstance(message, Mapping) or set(message) - {
        "role",
        "content",
        "refusal",
        "reasoning_content",
    }:
        raise ValueError("solver_model_response_invalid")
    reasoning_content = message.get("reasoning_content")
    if reasoning_content is not None and not isinstance(reasoning_content, str):
        raise ValueError("solver_model_response_invalid")
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise ValueError("solver_model_response_invalid")
    return content


def _provider_status_code(status_code: int) -> str:
    """Map only an HTTP class to a stable recovery code; ignore response text."""

    if status_code in {401, 403}:
        return "solver_model_auth_rejected"
    if status_code == 402:
        return "solver_model_payment_required"
    if status_code == 404:
        return "solver_model_not_found"
    if status_code == 429:
        return "solver_model_rate_limited"
    if status_code in {400, 409, 422}:
        return "solver_model_request_rejected"
    if 500 <= status_code < 600:
        return "solver_model_provider_unavailable"
    return "solver_model_rejected"


__all__ = [
    "OpenAICompatibleSolverBackend",
    "SolverModelError",
    "SolverProvider",
]
