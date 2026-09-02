"""Typed OpenAI Responses adapter for bounded, structured CTF triage.

This module is provider-specific by design. It does not discover credentials,
execute tools, or make authorization decisions. A caller supplies an API key at
the invocation boundary and an injected transport receives it in memory only.
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx
from ctfmesh_provider_base import (
    ProviderTriageError,
    TriageContractError,
    TriageResponseTooLargeError,
    validate_triage_completion,
)
from ctfmesh_provider_base import (
    TriageCategory as ProviderTriageCategory,
)
from ctfmesh_provider_base import (
    TriageCompletion as ProviderTriageCompletion,
)
from ctfmesh_provider_base import (
    TriageEvidence as ProviderTriageEvidence,
)
from ctfmesh_provider_base import (
    TriageFact as ProviderTriageFact,
)
from ctfmesh_provider_base import (
    TriageHypothesis as ProviderTriageHypothesis,
)
from ctfmesh_provider_base import (
    TriageNextAction as ProviderTriageNextAction,
)
from ctfmesh_provider_base import (
    TriageRequest as ProviderTriageRequest,
)
from ctfmesh_provider_base import (
    TriageResult as ProviderTriageResult,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_RESPONSES_PATH = "/v1/responses"
_OPENAI_RESPONSES_BASE_URL = "https://api.openai.com"
_MAX_DIAGNOSTIC_CHARS = 512
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_BEARER_TOKEN = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_GEMINI_KEY = re.compile(r"\bAIza[A-Za-z0-9_-]{16,}\b")
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)

_LegacyTriageCategory = Literal[
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
    "unknown",
]


class _LegacyTriageEvidence(BaseModel):
    """A bounded observation supplied to the triage model."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(min_length=1, max_length=160)
    kind: Literal["challenge", "artifact_excerpt", "tool_observation", "operator_note"]
    content: str = Field(min_length=1, max_length=16_000)


class _LegacyTriageRequest(BaseModel):
    """Inputs required to classify the next safe CTF workflow step."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    model: str = Field(min_length=1, max_length=160)
    max_output_tokens: int = Field(default=900, ge=128, le=4096)
    objective: str = Field(min_length=1, max_length=16_000)
    authorized_scope: str = Field(min_length=1, max_length=8_000)
    evidence: tuple[_LegacyTriageEvidence, ...] = Field(min_length=1, max_length=128)

    @field_validator("evidence", mode="before")
    @classmethod
    def freeze_evidence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class _LegacyTriageHypothesis(BaseModel):
    """A model hypothesis tied back to supplied evidence identifiers."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    statement: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def freeze_evidence_ids(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids cannot contain duplicates")
        return value


class _LegacyTriageFact(BaseModel):
    """A model-proposed observation that cites only supplied evidence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    statement: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def freeze_evidence_ids(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids cannot contain duplicates")
        return value


class _LegacyTriageNextAction(BaseModel):
    """An unexecuted next step that remains tied to supplied evidence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    statement: str = Field(min_length=1, max_length=2_000)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def freeze_evidence_ids(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_ids cannot contain duplicates")
        return value


class _LegacyTriageResult(BaseModel):
    """Strict structured model output used by later provider-neutral stages."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    category: _LegacyTriageCategory
    summary: str = Field(min_length=1, max_length=4_000)
    facts: tuple[_LegacyTriageFact, ...] = Field(max_length=64)
    hypotheses: tuple[_LegacyTriageHypothesis, ...] = Field(max_length=32)
    next_actions: tuple[_LegacyTriageNextAction, ...] = Field(min_length=1, max_length=16)

    @field_validator("facts", "hypotheses", "next_actions", mode="before")
    @classmethod
    def freeze_models(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class _LegacyTriageCompletion(BaseModel):
    """A validated triage result and the opaque provider response identifier."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    response_id: str | None = Field(default=None, min_length=1, max_length=160)
    result: _LegacyTriageResult


# The provider-neutral contracts own the public triage API.  These aliases are
# kept here so older imports from ``ctfmesh_provider_openai_responses`` remain
# source-compatible while all adapters, the archive service, and the
# orchestrator exchange exactly the same immutable Pydantic models.  The
# private legacy declarations above can be removed in a later compatibility
# release without changing this package's public import paths.
TriageCategory = ProviderTriageCategory
TriageEvidence = ProviderTriageEvidence
TriageFact = ProviderTriageFact
TriageHypothesis = ProviderTriageHypothesis
TriageNextAction = ProviderTriageNextAction
TriageRequest = ProviderTriageRequest
TriageResult = ProviderTriageResult
TriageCompletion = ProviderTriageCompletion


@dataclass(frozen=True, slots=True)
class ResponsesHTTPResponse:
    """The minimal, provider-neutral response shape returned by a transport."""

    status_code: int
    body: object | None

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an HTTP status code")


class AsyncResponsesTransport(Protocol):
    """Injection boundary for OpenAI Responses HTTP calls.

    ``api_key`` is intentionally a method argument rather than configuration so
    that a provider adapter cannot read or retain credentials itself.
    """

    async def post_responses(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ResponsesHTTPResponse: ...


class HttpxResponsesTransport:
    """HTTPX implementation of :class:`AsyncResponsesTransport`.

    The object never stores an API key. It only constructs the Authorization
    header while a single request is in flight.
    """

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        proxy_url: str | None = None,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1
        ):
            raise ValueError("max_response_bytes must be a positive integer")
        if transport is not None and proxy_url is not None:
            raise ValueError("transport and proxy_url cannot be configured together")
        # Build the client here so every production and test request keeps the
        # same reviewed origin, no redirects, and no ambient proxy settings.
        # Tests can inject only a low-level transport, never a different URL.
        if proxy_url is None:
            self._client = httpx.AsyncClient(
                base_url=_OPENAI_RESPONSES_BASE_URL,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            )
        else:
            self._client = httpx.AsyncClient(
                base_url=_OPENAI_RESPONSES_BASE_URL,
                follow_redirects=False,
                trust_env=False,
                # The API composition root supplies this exact internal CONNECT
                # proxy after validating it. Ambient proxy variables stay ignored.
                proxy=proxy_url,
            )
        self._max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return "HttpxResponsesTransport()"

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post_responses(
        self,
        *,
        api_key: str,
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ResponsesHTTPResponse:
        # Stream the response so an upstream provider cannot make the control
        # plane materialize an unbounded error page or model completion.
        async with self._client.stream(
            "POST",
            _RESPONSES_PATH,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=dict(payload),
            timeout=timeout_seconds,
        ) as response:
            body = await _read_bounded_body(response, max_bytes=self._max_response_bytes)
        return ResponsesHTTPResponse(
            status_code=response.status_code,
            body=_decode_json_or_text(body),
        )


async def _read_bounded_body(response: httpx.Response, *, max_bytes: int) -> bytes:
    """Read only the reviewed response budget, including chunked bodies."""

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
    """Keep provider parse failures as bounded, redaction-ready values."""

    text = body.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


class OpenAIResponsesError(ProviderTriageError):
    """Base error with a deliberately redacted diagnostic string."""

    def __init__(self, code: str, diagnostic: str) -> None:
        super().__init__(code, diagnostic)


class MissingOpenAIAPIKeyError(OpenAIResponsesError):
    def __init__(self) -> None:
        super().__init__("missing_api_key", "OpenAI API key is required")


class OpenAIResponsesTimeoutError(OpenAIResponsesError):
    def __init__(self) -> None:
        super().__init__("timeout", "OpenAI Responses request timed out")


class OpenAIResponsesTransportError(OpenAIResponsesError):
    def __init__(self, diagnostic: str) -> None:
        super().__init__("transport_error", diagnostic)


class OpenAIResponsesHTTPError(OpenAIResponsesError):
    def __init__(self, *, status_code: int, diagnostic: str) -> None:
        self.status_code = status_code
        super().__init__("http_error", f"status={status_code}; detail={diagnostic}")


class OpenAIResponsesProtocolError(OpenAIResponsesError):
    def __init__(self, code: str) -> None:
        super().__init__(code, "OpenAI Responses returned an invalid structured response")


_TRIAGE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "category": {
            "type": "string",
            "enum": [
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
                "unknown",
            ],
        },
        "summary": {"type": "string"},
        "facts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "statement": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["statement", "confidence", "evidence_ids"],
            },
        },
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "statement": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["statement", "confidence", "evidence_ids"],
            },
        },
        "next_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "statement": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["statement", "evidence_ids"],
            },
        },
    },
    "required": ["category", "summary", "facts", "hypotheses", "next_actions"],
}

_TRIAGE_INSTRUCTIONS = (
    "You triage an authorized CTF challenge from supplied evidence only. "
    "Classify the challenge, distinguish observed facts from hypotheses, and "
    "recommend bounded next actions for the authorized scope. Do not claim a "
    "flag or solve unless independently verified evidence has been supplied. "
    "Return compact JSON: at most four facts, three hypotheses, and four next "
    "actions; use one sentence per statement."
)


def build_triage_request(request: TriageRequest) -> dict[str, Any]:
    """Build the exact strict Structured Outputs request sent to OpenAI."""

    context = {
        "objective": request.objective,
        "authorized_scope": request.authorized_scope,
        "evidence": [evidence.model_dump(mode="json") for evidence in request.evidence],
    }
    return {
        "model": request.model,
        "max_output_tokens": request.max_output_tokens,
        "instructions": _TRIAGE_INSTRUCTIONS,
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": json.dumps(context, separators=(",", ":"), ensure_ascii=False),
                    }
                ],
            }
        ],
        "store": False,
        "tools": [],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "ctfmesh_triage",
                "strict": True,
                "schema": copy.deepcopy(_TRIAGE_OUTPUT_SCHEMA),
            }
        },
    }


class OpenAIResponsesTriageClient:
    """Triage client that keeps credential handling outside the adapter state."""

    name = "openai-responses"

    def __init__(self, transport: AsyncResponsesTransport) -> None:
        self._transport = transport

    def __repr__(self) -> str:
        return "OpenAIResponsesTriageClient()"

    @staticmethod
    def build_request(request: TriageRequest) -> dict[str, Any]:
        return build_triage_request(request)

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        """Request a strictly structured triage result.

        The API key is neither read from an environment variable nor stored on
        this client. It is passed directly to the injected transport for this
        call only.
        """

        _require_api_key(api_key)
        _require_timeout(timeout_seconds)
        payload = build_triage_request(request)
        try:
            async with asyncio.timeout(timeout_seconds):
                response = await self._transport.post_responses(
                    api_key=api_key,
                    payload=payload,
                    timeout_seconds=timeout_seconds,
                )
        except TimeoutError:
            raise OpenAIResponsesTimeoutError() from None
        except ProviderTriageError:
            raise
        except Exception as exc:
            diagnostic = _redact_diagnostic(str(exc), api_key=api_key)
            raise OpenAIResponsesTransportError(diagnostic) from None

        if not 200 <= response.status_code < 300:
            diagnostic = _redact_diagnostic(_serialise_body(response.body), api_key=api_key)
            raise OpenAIResponsesHTTPError(
                status_code=response.status_code,
                diagnostic=diagnostic,
            )

        completion = _parse_completion(response.body)
        try:
            validate_triage_completion(completion, request.evidence)
        except TriageContractError:
            raise OpenAIResponsesProtocolError("triage_cites_unknown_evidence") from None
        return completion


def _require_api_key(api_key: str) -> None:
    if not isinstance(api_key, str) or not api_key.strip():
        raise MissingOpenAIAPIKeyError()


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
    redacted = _OPENAI_KEY.sub("[REDACTED]", redacted)
    redacted = _GEMINI_KEY.sub("[REDACTED]", redacted)
    redacted = _RAW_FLAG.sub("[REDACTED_FLAG]", redacted)
    return _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", redacted)[:_MAX_DIAGNOSTIC_CHARS]


def _parse_completion(body: object | None) -> TriageCompletion:
    if not isinstance(body, Mapping):
        raise OpenAIResponsesProtocolError("malformed_response")
    if body.get("status") not in (None, "completed"):
        # Classify only a fixed, provider-documented reason. The raw response
        # and any upstream diagnostic remain untrusted and never reach events
        # or the UI.
        raise OpenAIResponsesProtocolError(_incomplete_response_code(body))

    output_text = _extract_output_text(body)
    try:
        parsed = json.loads(output_text)
    except (TypeError, json.JSONDecodeError):
        raise OpenAIResponsesProtocolError("malformed_structured_output") from None
    if not isinstance(parsed, dict):
        raise OpenAIResponsesProtocolError("malformed_structured_output")
    try:
        result = TriageResult.model_validate(parsed)
    except ValidationError:
        raise OpenAIResponsesProtocolError("triage_schema_violation") from None

    response_id = body.get("id")
    if response_id is not None and not isinstance(response_id, str):
        raise OpenAIResponsesProtocolError("malformed_response")
    return TriageCompletion(response_id=response_id, result=result)


def _incomplete_response_code(response: Mapping[str, object]) -> str:
    """Map documented incomplete reasons to a finite, secret-safe error code."""

    if response.get("status") != "incomplete":
        return "incomplete_response"
    details = response.get("incomplete_details")
    if not isinstance(details, Mapping):
        return "incomplete_response"
    reason = details.get("reason")
    if reason in {"max_output_tokens", "max_tokens"}:
        return "incomplete_max_output_tokens"
    if reason == "content_filter":
        return "incomplete_content_filter"
    return "incomplete_response"


def _extract_output_text(response: Mapping[str, object]) -> str:
    direct_output = response.get("output_text")
    if isinstance(direct_output, str):
        return direct_output

    output = response.get("output")
    if not isinstance(output, list):
        raise OpenAIResponsesProtocolError("missing_output_text")

    output_texts: list[str] = []
    for item in output:
        if not isinstance(item, Mapping) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, Mapping):
                continue
            if part.get("type") == "refusal":
                raise OpenAIResponsesProtocolError("model_refusal")
            text = part.get("text")
            if part.get("type") == "output_text" and isinstance(text, str):
                output_texts.append(text)
    if len(output_texts) != 1:
        raise OpenAIResponsesProtocolError("missing_output_text")
    return output_texts[0]
