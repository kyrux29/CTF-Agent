"""Narrow HTTP adapters for the fixed M3 control and source-slot boundaries.

These adapters do not expose a general HTTP client to a worker or model.  Each
one validates a preconfigured internal service URL, posts to exactly one path,
does not follow redirects or inherit proxy settings, and limits response bytes
before parsing a versioned Pydantic contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from .contracts import (
    GatewayInvocationEnvelope,
    GatewayToolCall,
    GatewayToolRequest,
    GatewayToolResponse,
    SourceSlotInvocation,
    SourceSlotResponse,
    ToolGatewayClient,
    ToolGatewayContractError,
    parse_gateway_response,
)
from .slots import SourceSlotClient, SourceSlotError, source_slot_binding

_MAX_CONTROL_RESPONSE_BYTES: Final = 512 * 1024
_TOOL_GATEWAY_HOSTS: Final = frozenset({"tool-gateway", "localhost", "127.0.0.1"})
# The two UI archive slots are separate services from the curated M3 slots,
# but retain the same fixed role names and never accept an operator URL.
_SOURCE_SLOT_HOSTS: Final = frozenset(
    {"sandbox-source-1", "sandbox-source-2", "ui-source-slot-1", "ui-source-slot-2"}
)


class ToolGatewayTransportError(RuntimeError):
    """Secret-free control/slot transport failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _internal_base_url(value: str, *, allowed_hosts: frozenset[str], code: str) -> str:
    """Accept only a static internal HTTP origin without a path or credentials."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ToolGatewayTransportError(code) from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.hostname.lower() not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65_535
    ):
        raise ToolGatewayTransportError(code)
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    return f"http://{rendered_host}{'' if port is None else f':{port}'}"


async def _post_json(
    *,
    base_url: str,
    path: str,
    token: str,
    payload: object,
    timeout_seconds: float,
    error_code: str,
    transport: httpx.AsyncBaseTransport | None,
) -> object:
    """POST one bounded JSON envelope without environment proxy inheritance."""

    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds),
            trust_env=False,
            transport=transport,
        ) as client:
            async with client.stream(
                "POST",
                path,
                headers={"x-ctfmesh-tool-gateway-token": token},
                json=payload,
            ) as response:
                if response.status_code != 200:
                    raise ToolGatewayTransportError(error_code)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_CONTROL_RESPONSE_BYTES:
                        raise ToolGatewayTransportError(error_code)
    except ToolGatewayTransportError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise ToolGatewayTransportError(error_code) from exc
    try:
        return json.loads(body)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolGatewayTransportError(error_code) from exc


def _source_slot_payload(invocation: SourceSlotInvocation) -> dict[str, object]:
    """Serialize a full invocation without inventing unset manifest defaults.

    Tool-call discriminator defaults (``tool_name``/version/schema) must stay
    on the wire. In contrast, an ``artifact_bundle`` manifest must *not* gain
    unset target fields such as ``allowed_endpoints`` during a JSON round trip.
    Serialize the parent fully, then replace only that nested declaration with
    its original declared-field shape.
    """

    payload = invocation.model_dump(mode="json", by_alias=True)
    authority = payload.get("authority")
    if not isinstance(authority, dict):  # pragma: no cover - Pydantic model invariant.
        raise ToolGatewayTransportError("source_slot_payload_invalid")
    authority["challenge_manifest"] = invocation.authority.challenge_manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_unset=True,
    )
    return payload


class HttpToolGatewayClient(ToolGatewayClient):
    """API relay adapter for the separately hardened gateway service."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not token or len(token) > 512:
            raise ValueError("tool_gateway_token_invalid")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("tool_gateway_timeout_invalid")
        self._base_url = _internal_base_url(
            base_url,
            allowed_hosts=_TOOL_GATEWAY_HOSTS,
            code="tool_gateway_url_invalid",
        )
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def invoke(
        self,
        request: GatewayToolRequest,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> GatewayToolResponse:
        envelope = GatewayInvocationEnvelope(
            job_id=job_id,
            worker_id=worker_id,
            lease_version=lease_version,
            request=request,
        )
        body = await _post_json(
            base_url=self._base_url,
            path="/internal/tool-invocations",
            token=self._token,
            payload=envelope.model_dump(mode="json"),
            timeout_seconds=self._timeout_seconds,
            error_code="tool_gateway_transport_failed",
            transport=self._transport,
        )
        try:
            response = parse_gateway_response(body)
        except ToolGatewayContractError as exc:
            raise ToolGatewayTransportError(exc.code) from exc
        if (
            response.tool_call_id != request.call.tool_call_id
            or response.tool_name != request.call.tool_name
        ):
            raise ToolGatewayTransportError("tool_gateway_response_mismatch")
        return response


class HttpSourceSlotClient(SourceSlotClient):
    """Gateway-only client for one static or backend-assigned source slot."""

    def __init__(
        self,
        *,
        slot_id: str,
        challenge_id: str | None,
        base_url: str,
        token: str,
        workspace_root: Path = Path("/challenge"),
        dynamic_assignment: bool = False,
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not slot_id or any(character.isspace() for character in slot_id):
            raise ValueError("source_slot_id_invalid")
        if dynamic_assignment and challenge_id is not None:
            raise ValueError("source_slot_dynamic_configuration_invalid")
        if not dynamic_assignment and (
            not challenge_id or any(character.isspace() for character in challenge_id)
        ):
            raise ValueError("source_slot_challenge_id_invalid")
        if not token or len(token) > 512:
            raise ValueError("source_slot_token_invalid")
        if not workspace_root.is_absolute():
            raise ValueError("source_slot_workspace_root_invalid")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("source_slot_timeout_invalid")
        self.slot_id = slot_id
        self._challenge_id = challenge_id
        self.dynamic_assignment = dynamic_assignment
        self._base_url = _internal_base_url(
            base_url,
            allowed_hosts=_SOURCE_SLOT_HOSTS,
            code="source_slot_url_invalid",
        )
        self._token = token
        self._workspace_root = workspace_root
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def supports(self, call: GatewayToolCall) -> bool:
        return call.tool_name in InProcessSourceSlotTools

    def workspace_root(self) -> Path:
        """Return fixed mount metadata, never a value supplied by Pi."""

        return self._workspace_root

    @property
    def challenge_id(self) -> str | None:
        """Expose the static binding when this is not a dynamic slot."""

        return self._challenge_id

    async def invoke(self, invocation: SourceSlotInvocation) -> SourceSlotResponse:
        if self.dynamic_assignment:
            binding = source_slot_binding(invocation.authority.challenge_manifest)
            if binding is None or binding.slot_id != self.slot_id:
                raise SourceSlotError("source_slot_challenge_mismatch")
        elif invocation.authority.challenge_id != self.challenge_id:
            raise SourceSlotError("source_slot_challenge_mismatch")
        try:
            body = await _post_json(
                base_url=self._base_url,
                path="/internal/slot-invocations",
                token=self._token,
                payload=_source_slot_payload(invocation),
                timeout_seconds=self._timeout_seconds,
                error_code="source_slot_transport_failed",
                transport=self._transport,
            )
        except ToolGatewayTransportError as exc:
            raise SourceSlotError(exc.code) from exc
        try:
            response = SourceSlotResponse.model_validate(body)
        except ValueError as exc:
            raise SourceSlotError("source_slot_response_invalid") from exc
        if response.invocation_id != invocation.invocation_id:
            raise SourceSlotError("source_slot_response_mismatch")
        return response


# Keep the remotely advertised catalog adjacent to the remote client rather
# than importing an in-process slot. This avoids accidentally granting the
# gateway a local source mount merely by importing a transport adapter.
InProcessSourceSlotTools: Final = frozenset(
    {
        "source.list",
        "source.read",
        "source.search",
        "source.manifest",
        "artifacts.inspect",
        "transform.apply",
        "http.request",
    }
)


__all__ = [
    "HttpSourceSlotClient",
    "HttpToolGatewayClient",
    "ToolGatewayTransportError",
]
