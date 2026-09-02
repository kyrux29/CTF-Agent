"""Bounded OpenAI-compatible chat-completions implementation.

Only provider wrappers construct this class with their reviewed endpoint
constants.  It intentionally accepts no browser-controlled URL, no provider
tool definitions, and no retry policy.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from ctfmesh_provider_base import (
    MissingTriageAPIKeyError,
    ProviderTriageError,
    TriageCompletion,
    TriageHTTPError,
    TriageProtocolError,
    TriageRequest,
    TriageResponseTooLargeError,
    TriageTimeoutError,
    TriageTransportError,
    parse_triage_result,
    triage_result_schema,
    validate_triage_completion,
)

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_DIAGNOSTIC_CHARS = 512
_BEARER_TOKEN = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_STYLE_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_GEMINI_STYLE_KEY = re.compile(r"\bAIza[A-Za-z0-9_-]{16,}\b")
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,63}\{[^}\r\n]{1,512}\}")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)
_JSON_SECRET_FIELD = re.compile(
    r'(?i)(["\']?(?:api[_-]?key|token|secret|password|cookie|authorization|flag|answer|proof)["\']?'
    r'\s*:\s*)(?:"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'|[^,\]\}\s]+)'
)

_TRIAGE_INSTRUCTIONS = (
    "You triage an authorized CTF challenge from supplied evidence only. "
    "Return exactly one JSON object matching the requested triage schema. "
    "Classify the challenge, distinguish observed facts from hypotheses, and "
    "recommend bounded next actions for the authorized scope. Do not invoke "
    "tools, make network requests, execute code, claim a flag, or claim a solve. "
    "Keep the JSON compact: at most four facts, three hypotheses, and four next "
    "actions; use one sentence per statement."
)


@dataclass(frozen=True, slots=True)
class ChatCompletionsHTTPResponse:
    """The only HTTP response shape exposed to the shared parser."""

    status_code: int
    body: object | None

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an HTTP status code")


class AsyncChatCompletionsTransport(Protocol):
    """Credential-injected transport boundary used by provider wrappers and tests."""

    async def post_chat_completions(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ChatCompletionsHTTPResponse: ...

    async def aclose(self) -> None: ...


class HttpxChatCompletionsTransport:
    """One endpoint-bound HTTPX transport with no ambient proxy trust.

    The ``base_url`` and ``path`` parameters are intentionally supplied only by
    wrapper code, never by an API request or a model.  Redirects and ambient
    proxy/environment configuration are disabled so a provider credential is
    not silently sent to a redirected or environment-selected host.
    """

    def __init__(
        self,
        *,
        base_url: str,
        path: str,
        proxy_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        if not base_url.startswith("https://") or not path.startswith("/"):
            raise ValueError("provider endpoint must use an absolute HTTPS base and absolute path")
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1
        ):
            raise ValueError("max_response_bytes must be a positive integer")
        if client is not None and proxy_url is not None:
            raise ValueError("client and proxy_url cannot be configured together")
        self._path = path
        self._max_response_bytes = max_response_bytes
        if client is not None:
            self._client = client
            self._owns_client = False
        elif proxy_url is None:
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                follow_redirects=False,
                trust_env=False,
            )
            self._owns_client = True
        else:
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                follow_redirects=False,
                trust_env=False,
                # This is an explicit, composition-root-supplied proxy rather
                # than ambient HTTP(S)_PROXY state. Provider wrappers never
                # accept a browser/model-controlled endpoint or proxy URL.
                proxy=proxy_url,
            )
            self._owns_client = True

    def __repr__(self) -> str:
        return "HttpxChatCompletionsTransport()"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def post_chat_completions(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ChatCompletionsHTTPResponse:
        async with self._client.stream(
            "POST",
            self._path,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=dict(payload),
            timeout=timeout_seconds,
        ) as response:
            body = await _read_bounded_body(response, max_bytes=self._max_response_bytes)
        return ChatCompletionsHTTPResponse(
            status_code=response.status_code,
            body=_decode_json_or_text(body),
        )


class ChatCompletionsTriageClient:
    """Parse one OpenAI-compatible JSON-mode completion as a CTF proposal."""

    def __init__(self, transport: AsyncChatCompletionsTransport, *, provider_name: str) -> None:
        self._transport = transport
        self.name = provider_name

    def __repr__(self) -> str:
        return f"ChatCompletionsTriageClient(provider={self.name!r})"

    @staticmethod
    def build_request(request: TriageRequest) -> dict[str, Any]:
        """Build a tool-free JSON-mode chat-completions request.

        ``response_format`` asks for JSON syntax only.  The local Pydantic
        parser remains authoritative for the complete schema and evidence
        citations because compatible providers do not share strict-output
        semantics across all models.
        """

        context = {
            "objective": request.objective,
            "authorized_scope": request.authorized_scope,
            "evidence": [item.model_dump(mode="json") for item in request.evidence],
            "output_schema": triage_result_schema(),
        }
        return {
            "model": request.model,
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
            "stream": False,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _TRIAGE_INSTRUCTIONS},
                {
                    "role": "user",
                    "content": json.dumps(context, separators=(",", ":"), ensure_ascii=False),
                },
            ],
        }

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        """Execute exactly one provider request without retaining its credential."""

        _require_api_key(api_key)
        _require_timeout(timeout_seconds)
        payload = self.build_request(request)
        try:
            async with asyncio.timeout(timeout_seconds):
                response = await self._transport.post_chat_completions(
                    api_key=api_key,
                    payload=payload,
                    timeout_seconds=timeout_seconds,
                )
        except TimeoutError:
            raise TriageTimeoutError() from None
        except ProviderTriageError:
            raise
        except Exception as exc:
            raise TriageTransportError(_redact_diagnostic(str(exc), api_key=api_key)) from None

        if not 200 <= response.status_code < 300:
            raise TriageHTTPError(
                status_code=response.status_code,
                diagnostic=_redact_diagnostic(_serialise_body(response.body), api_key=api_key),
            )
        completion = _parse_completion(response.body)
        try:
            validate_triage_completion(completion, request.evidence)
        except Exception as exc:
            # Do not let a provider return citations outside this invocation's
            # evidence list just because the JSON shape itself was valid.
            if isinstance(exc, ProviderTriageError):
                raise
            raise TriageProtocolError("triage_cites_unknown_evidence") from None
        return completion


async def _read_bounded_body(response: httpx.Response, *, max_bytes: int) -> bytes:
    declared_size = response.headers.get("content-length")
    if declared_size is not None and declared_size.isdecimal() and int(declared_size) > max_bytes:
        raise TriageResponseTooLargeError()
    received = 0
    chunks: list[bytes] = []
    async for chunk in response.aiter_bytes():
        received += len(chunk)
        if received > max_bytes:
            raise TriageResponseTooLargeError()
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_json_or_text(body: bytes) -> object:
    text = body.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _require_api_key(api_key: str) -> None:
    if not isinstance(api_key, str) or not api_key.strip():
        raise MissingTriageAPIKeyError()


def _require_timeout(timeout_seconds: float) -> None:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, float | int):
        raise ValueError("timeout_seconds must be a finite positive number")
    if (
        not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or timeout_seconds > 24 * 60 * 60
    ):
        raise ValueError("timeout_seconds must be between 0 and 86400 seconds")


def _serialise_body(body: object | None) -> str:
    if body is None:
        return "empty response body"
    try:
        return json.dumps(body, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(body)


def _redact_diagnostic(value: str, *, api_key: str) -> str:
    redacted = value.replace(api_key, "[REDACTED]")
    redacted = _BEARER_TOKEN.sub(r"\1[REDACTED]", redacted)
    redacted = _OPENAI_STYLE_KEY.sub("[REDACTED_API_KEY]", redacted)
    redacted = _GEMINI_STYLE_KEY.sub("[REDACTED_API_KEY]", redacted)
    redacted = _RAW_FLAG.sub("[REDACTED_FLAG]", redacted)
    redacted = _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", redacted)
    redacted = _JSON_SECRET_FIELD.sub(r"\1[REDACTED_SECRET]", redacted)
    return redacted[:_MAX_DIAGNOSTIC_CHARS]


def _parse_completion(body: object | None) -> TriageCompletion:
    if not isinstance(body, Mapping):
        raise TriageProtocolError("malformed_response")
    raw_id = body.get("id")
    if raw_id is not None and not isinstance(raw_id, str):
        raise TriageProtocolError("malformed_response")
    choices = body.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], Mapping):
        raise TriageProtocolError("missing_choice")
    choice = choices[0]
    finish_reason = choice.get("finish_reason")
    if finish_reason != "stop":
        raise TriageProtocolError("incomplete_response")
    message = choice.get("message")
    if not isinstance(message, Mapping):
        raise TriageProtocolError("missing_output_text")
    tool_calls = message.get("tool_calls")
    if tool_calls not in (None, []):
        raise TriageProtocolError("provider_tool_call_forbidden")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise TriageProtocolError("missing_output_text")
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError:
        raise TriageProtocolError("malformed_structured_output") from None
    result = parse_triage_result(decoded)
    try:
        return TriageCompletion(response_id=raw_id, result=result)
    except ValueError:
        raise TriageProtocolError("malformed_response") from None


__all__ = [
    "AsyncChatCompletionsTransport",
    "ChatCompletionsHTTPResponse",
    "ChatCompletionsTriageClient",
    "HttpxChatCompletionsTransport",
]
