"""Versioned contracts for the M3 gateway and its fixed source slot.

Pi Runner never imports these Python classes.  Its custom TypeBox schema is a
second, UX-oriented validator; this module is the authoritative process
boundary once the request reaches the control plane.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Protocol

from ctfmesh_domain import (
    ContractModel,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    ToolExecutionAuthority,
)
from ctfmesh_tools import (
    ArtifactInspectInput,
    ArtifactInspectOutput,
    FilesListInput,
    FilesListOutput,
    FilesReadOutput,
    FilesSearchInput,
    FilesSearchOutput,
    SourceManifestInput,
    SourceManifestOutput,
    SourceReadInput,
    TransformApplyInput,
    TransformApplyOutput,
)
from pydantic import BaseModel, Field, JsonValue, TypeAdapter, field_validator, model_validator


class ToolGatewayContractError(ValueError):
    """Stable input/output failure that is safe to present to a worker."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ToolCallBase(ContractModel):
    """Fields shared by all closed-world worker tool calls."""

    schema_version: Literal[1] = 1
    tool_call_id: Identifier
    # A Pi SDK tool-call ID is the only client-provided idempotency key for
    # M3. Requiring equality prevents a worker from choosing a key that
    # aliases another operation within the same sealed task.
    idempotency_key: Identifier

    @model_validator(mode="after")
    def _idempotency_is_call_bound(self) -> _ToolCallBase:
        if self.idempotency_key != self.tool_call_id:
            raise ValueError("tool_idempotency_key_must_match_tool_call_id")
        return self


class SourceListCall(_ToolCallBase):
    tool_name: Literal["source.list"] = "source.list"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: FilesListInput


class SourceReadCall(_ToolCallBase):
    tool_name: Literal["source.read"] = "source.read"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: SourceReadInput


class SourceSearchCall(_ToolCallBase):
    tool_name: Literal["source.search"] = "source.search"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: FilesSearchInput


class SourceManifestCall(_ToolCallBase):
    tool_name: Literal["source.manifest"] = "source.manifest"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: SourceManifestInput


class ArtifactInspectCall(_ToolCallBase):
    tool_name: Literal["artifacts.inspect"] = "artifacts.inspect"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: ArtifactInspectInput


class TransformApplyCall(_ToolCallBase):
    tool_name: Literal["transform.apply"] = "transform.apply"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: TransformApplyInput


_HTTP_HEADER_ALLOWLIST = frozenset(
    {
        "accept",
        "accept-language",
        "content-type",
        "if-match",
        "if-none-match",
        "referer",
        "user-agent",
        "x-csrf-token",
        "x-requested-with",
    }
)
_MAX_HTTP_BODY_BYTES = 64 * 1024
_MAX_HTTP_JSON_DEPTH = 12


def _json_depth(value: JsonValue, depth: int = 0) -> int:
    """Bound nested JSON before a slot passes it to an HTTP client.

    JSON objects sent to a target are data, not executable configuration. A
    depth limit keeps a malicious or accidental model request from consuming
    disproportionate validation or serialization resources while preserving
    ordinary CTF API payloads.
    """

    if depth > _MAX_HTTP_JSON_DEPTH:
        raise ValueError("http_request_json_too_deep")
    if isinstance(value, dict):
        return max((_json_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_json_depth(item, depth + 1) for item in value), default=depth)
    return depth


class HttpRequestCallInput(ContractModel):
    """A worker-selected alias and relative request, never an arbitrary URL.

    The alias is resolved against the operator-signed target manifest inside
    the fixed slot. Headers are deliberately limited to non-routing fields;
    cookie, authorization, host, proxy, forwarding, and connection handling
    remain owned by the constrained HTTP client.
    """

    target_alias: Identifier
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] = "GET"
    path: str = Field(default="/", min_length=1, max_length=4_096)
    query: dict[str, str] = Field(default_factory=dict, max_length=32)
    headers: dict[str, str] = Field(default_factory=dict, max_length=16)
    json_body: JsonValue | None = None
    content: str | None = Field(default=None, max_length=_MAX_HTTP_BODY_BYTES)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=15.0)
    max_response_bytes: int = Field(default=64 * 1024, ge=1, le=256 * 1024)

    @field_validator("path")
    @classmethod
    def _relative_path_only(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or any(character in value for character in "\r\n\t\x00\\?#")
        ):
            raise ValueError("http_request_path_invalid")
        return value

    @field_validator("query")
    @classmethod
    def _bounded_query(cls, values: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, value in values.items():
            if (
                not name
                or len(name) > 128
                or len(value) > 4_096
                or any(character in name or character in value for character in "\r\n\x00")
            ):
                raise ValueError("http_request_query_invalid")
            normalized[name] = value
        return dict(sorted(normalized.items()))

    @field_validator("headers")
    @classmethod
    def _allow_non_routing_headers(cls, values: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, value in values.items():
            safe_name = name.lower()
            if (
                safe_name not in _HTTP_HEADER_ALLOWLIST
                or safe_name in normalized
                or len(value) > 4_096
                or any(character in name or character in value for character in "\r\n\x00")
            ):
                raise ValueError("http_request_header_not_allowed")
            normalized[safe_name] = value
        return normalized

    @field_validator("content")
    @classmethod
    def _bounded_content(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > _MAX_HTTP_BODY_BYTES:
            raise ValueError("http_request_content_too_large")
        return value

    @model_validator(mode="after")
    def _body_is_exclusive_and_bounded(self) -> HttpRequestCallInput:
        if self.json_body is not None and self.content is not None:
            raise ValueError("http_request_body_is_ambiguous")
        if self.json_body is not None:
            try:
                _json_depth(self.json_body)
                encoded = json.dumps(
                    self.json_body,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ValueError("http_request_json_invalid") from exc
            if len(encoded) > _MAX_HTTP_BODY_BYTES:
                raise ValueError("http_request_json_too_large")
        return self


class HttpRequestCall(_ToolCallBase):
    tool_name: Literal["http.request"] = "http.request"
    tool_version: Literal["1.0.0"] = "1.0.0"
    arguments: HttpRequestCallInput


class HttpObservationOutput(ContractModel):
    """Safe HTTP evidence without exposing a target origin back to Pi.

    The content-addressed gateway artifact is the authoritative response
    record. ``body_text_*`` describes the displayed, redacted text and is
    repaired during normalization if a secret pattern is removed.
    """

    target_alias: Identifier
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    path: str = Field(min_length=1, max_length=4_096)
    status: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(max_length=64)
    body_text: str = Field(max_length=256 * 1024)
    body_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_text_size_bytes: int = Field(ge=0, le=256 * 1024)
    content_type: str | None = Field(default=None, max_length=4_096)
    elapsed_ms: int = Field(ge=0, le=60_000)
    cookie_count: int = Field(ge=0, le=1_024)
    truncated: bool

    @field_validator("headers")
    @classmethod
    def _response_headers_are_bounded(cls, values: dict[str, str]) -> dict[str, str]:
        if any(
            not name
            or len(name) > 256
            or len(value) > 4_096
            or any(character in name or character in value for character in "\r\n\x00")
            for name, value in values.items()
        ):
            raise ValueError("http_response_headers_invalid")
        return values

    @field_validator("body_text")
    @classmethod
    def _response_body_fits_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 256 * 1024:
            raise ValueError("http_response_body_too_large")
        return value

    @model_validator(mode="after")
    def _body_metadata_matches_display(self) -> HttpObservationOutput:
        body = self.body_text.encode("utf-8")
        if self.body_text_size_bytes != len(body):
            raise ValueError("http_response_body_size_mismatch")
        if self.body_text_sha256 != hashlib.sha256(body).hexdigest():
            raise ValueError("http_response_body_digest_mismatch")
        return self


type GatewayToolCall = Annotated[
    SourceListCall
    | SourceReadCall
    | SourceSearchCall
    | SourceManifestCall
    | ArtifactInspectCall
    | TransformApplyCall
    | HttpRequestCall,
    Field(discriminator="tool_name"),
]
_TOOL_CALL_ADAPTER = TypeAdapter(GatewayToolCall)


class GatewayToolRequest(ContractModel):
    """Authenticated-control request; it never contains a path to the host."""

    session_id: Identifier
    call: GatewayToolCall


class GatewayInvocationEnvelope(ContractModel):
    """API-to-gateway transport envelope for one authenticated Pi call.

    The worker ID and lease version are transport metadata only.  The gateway
    still loads and validates the durable job/session authority itself before
    dispatching a slot operation.
    """

    job_id: Identifier
    worker_id: Identifier
    lease_version: int = Field(ge=1, le=1_000_000)
    request: GatewayToolRequest


class SourceSlotInvocation(ContractModel):
    """Gateway-to-slot request without an operator filesystem location.

    The fixed slot has its source mount at a reviewed, configured path.  Its
    RPC contract therefore carries only server-derived authorization and the
    typed relative operation; no client can replace the mounted source root.
    """

    schema_version: Literal[1] = 1
    invocation_id: Identifier
    authority: ToolExecutionAuthority
    call: GatewayToolCall
    # Present only for a remote HTTP request in the UI exact-instance lane.
    # It is an opaque short-lived HMAC capability, never an API/provider key;
    # the source slot forwards it to the connector without parsing it.
    target_capability: str | None = Field(default=None, min_length=1, max_length=4096)


class SourceSlotResponse(ContractModel):
    """Transport envelope whose body is revalidated by the call-specific model."""

    schema_version: Literal[1] = 1
    invocation_id: Identifier
    tool_name: Identifier
    tool_version: Literal["1.0.0"] = "1.0.0"
    output: dict[str, JsonValue]


class ToolObservationArtifact(ContractModel):
    """The immutable result body Pi can cite in a later finding."""

    artifact_id: Identifier
    digest: Sha256Digest
    size_bytes: int = Field(ge=0)
    summary: NonEmptyText = Field(max_length=2_000)


class _AcceptedToolResultBase(ContractModel):
    schema_version: Literal[1] = 1
    accepted: Literal[True] = True
    invocation_id: Identifier
    tool_call_id: Identifier
    tool_version: Literal["1.0.0"] = "1.0.0"
    cached: bool
    artifact: ToolObservationArtifact


class SourceListResult(_AcceptedToolResultBase):
    tool_name: Literal["source.list"] = "source.list"
    result: FilesListOutput


class SourceReadResult(_AcceptedToolResultBase):
    tool_name: Literal["source.read"] = "source.read"
    result: FilesReadOutput


class SourceSearchResult(_AcceptedToolResultBase):
    tool_name: Literal["source.search"] = "source.search"
    result: FilesSearchOutput


class SourceManifestResult(_AcceptedToolResultBase):
    tool_name: Literal["source.manifest"] = "source.manifest"
    result: SourceManifestOutput


class ArtifactInspectResult(_AcceptedToolResultBase):
    tool_name: Literal["artifacts.inspect"] = "artifacts.inspect"
    result: ArtifactInspectOutput


class TransformApplyResult(_AcceptedToolResultBase):
    tool_name: Literal["transform.apply"] = "transform.apply"
    result: TransformApplyOutput


class HttpRequestResult(_AcceptedToolResultBase):
    tool_name: Literal["http.request"] = "http.request"
    result: HttpObservationOutput


type AcceptedGatewayToolResult = Annotated[
    SourceListResult
    | SourceReadResult
    | SourceSearchResult
    | SourceManifestResult
    | ArtifactInspectResult
    | TransformApplyResult
    | HttpRequestResult,
    Field(discriminator="tool_name"),
]
_ACCEPTED_RESULT_ADAPTER = TypeAdapter(AcceptedGatewayToolResult)


class RejectedToolResult(ContractModel):
    """A stable failure response that deliberately excludes exception detail."""

    schema_version: Literal[1] = 1
    accepted: Literal[False] = False
    tool_call_id: Identifier
    tool_name: Identifier
    code: Identifier
    invocation_id: Identifier | None = None
    cached: bool = False


type GatewayToolResponse = AcceptedGatewayToolResult | RejectedToolResult
_GATEWAY_RESPONSE_ADAPTER = TypeAdapter(GatewayToolResponse)


class ToolGatewayClient(Protocol):
    """Small API-facing boundary for local or remote gateway implementations.

    The control API deliberately depends on this interface rather than a
    source-slot implementation.  Production composition can therefore relay
    to a separately hardened gateway service, while integration tests inject
    the in-process implementation without granting Pi direct filesystem or
    database access.
    """

    async def invoke(
        self,
        request: GatewayToolRequest,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> GatewayToolResponse: ...


def parse_gateway_request(value: object) -> GatewayToolRequest:
    """Validate a raw request through the closed-world discriminated union."""

    try:
        return GatewayToolRequest.model_validate(value)
    except ValueError as exc:
        raise ToolGatewayContractError("tool_request_invalid") from exc


def parse_gateway_response(value: object) -> GatewayToolResponse:
    """Validate a gateway response before a relay returns it to Pi Runner."""

    try:
        return _GATEWAY_RESPONSE_ADAPTER.validate_python(value)
    except ValueError as exc:
        raise ToolGatewayContractError("tool_response_invalid") from exc


def parse_source_slot_invocation(value: object) -> SourceSlotInvocation:
    """Parse JSON transport data while retaining strict scalar contracts.

    Tuple-valued domain fields are intentionally immutable in Python but are
    represented as JSON arrays on the wire. ``model_validate_json`` preserves
    strict scalar checks while applying only that unavoidable JSON conversion.
    """

    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        return SourceSlotInvocation.model_validate_json(encoded)
    except (TypeError, ValueError) as exc:
        raise ToolGatewayContractError("source_slot_request_invalid") from exc


def canonical_input_digest(call: GatewayToolCall) -> str:
    """Digest exactly the typed operation, excluding retry transport metadata."""

    payload = {
        "schema_version": call.schema_version,
        "tool_name": call.tool_name,
        "tool_version": call.tool_version,
        "arguments": call.arguments.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def parse_accepted_result(value: object) -> AcceptedGatewayToolResult:
    """Rehydrate a cached artifact only through its declared output contract."""

    try:
        return _ACCEPTED_RESULT_ADAPTER.validate_python(value)
    except ValueError as exc:
        raise ToolGatewayContractError("tool_cached_result_invalid") from exc


def output_model_for(call: GatewayToolCall) -> type[BaseModel]:
    """Return the exact output model paired with one discriminated call type."""

    if isinstance(call, SourceListCall):
        return FilesListOutput
    if isinstance(call, SourceReadCall):
        return FilesReadOutput
    if isinstance(call, SourceSearchCall):
        return FilesSearchOutput
    if isinstance(call, SourceManifestCall):
        return SourceManifestOutput
    if isinstance(call, ArtifactInspectCall):
        return ArtifactInspectOutput
    if isinstance(call, TransformApplyCall):
        return TransformApplyOutput
    if isinstance(call, HttpRequestCall):
        return HttpObservationOutput
    raise ToolGatewayContractError("tool_request_unavailable")


def validate_output(call: GatewayToolCall, value: object) -> BaseModel:
    """Validate an untrusted slot result before gateway persistence.

    Pydantic's strict Python mode correctly rejects a list for a tuple field,
    but JSON has no tuple type. Re-encoding the declared JSON envelope through
    ``model_validate_json`` preserves strict scalar validation while accepting
    the canonical JSON representation returned by an out-of-process slot.
    """

    try:
        raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        return output_model_for(call).model_validate_json(encoded)
    except (TypeError, ValueError) as exc:
        raise ToolGatewayContractError("slot_output_invalid") from exc


def accepted_result(
    *,
    invocation_id: str,
    call: GatewayToolCall,
    artifact: ToolObservationArtifact,
    cached: bool,
    output: object,
) -> AcceptedGatewayToolResult:
    """Build the Pi-facing result while retaining the same discriminant as input."""

    payload = {
        "invocation_id": invocation_id,
        "tool_call_id": call.tool_call_id,
        "tool_name": call.tool_name,
        "tool_version": call.tool_version,
        "cached": cached,
        "artifact": artifact,
        "result": output,
    }
    try:
        return _ACCEPTED_RESULT_ADAPTER.validate_python(payload)
    except ValueError as exc:  # pragma: no cover - guarded by validate_output.
        raise ToolGatewayContractError("tool_result_invalid") from exc


__all__ = [
    "AcceptedGatewayToolResult",
    "ArtifactInspectCall",
    "ArtifactInspectResult",
    "HttpObservationOutput",
    "HttpRequestCall",
    "HttpRequestCallInput",
    "HttpRequestResult",
    "GatewayToolRequest",
    "GatewayInvocationEnvelope",
    "GatewayToolResponse",
    "RejectedToolResult",
    "SourceListCall",
    "SourceListResult",
    "SourceManifestCall",
    "SourceManifestResult",
    "SourceReadCall",
    "SourceReadResult",
    "SourceSearchCall",
    "SourceSearchResult",
    "SourceSlotInvocation",
    "SourceSlotResponse",
    "GatewayToolCall",
    "ToolGatewayContractError",
    "ToolGatewayClient",
    "ToolObservationArtifact",
    "TransformApplyCall",
    "TransformApplyResult",
    "accepted_result",
    "canonical_input_digest",
    "output_model_for",
    "parse_accepted_result",
    "parse_gateway_request",
    "parse_gateway_response",
    "parse_source_slot_invocation",
    "validate_output",
]
