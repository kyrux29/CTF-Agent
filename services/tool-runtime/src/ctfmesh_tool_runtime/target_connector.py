"""The sole M6.a component permitted to open a public target socket.

Source slots attach only to their own internal bridge. They forward an opaque,
gateway-signed capability plus a typed HTTP request here. This service pins DNS
answers to public IP addresses before connection, disables redirects/proxies,
and consumes a capability before one outbound attempt. It has no database,
archive mount, model key, Docker socket, or browser-facing route.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hmac
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from time import monotonic
from typing import Any, Literal, Self, cast
from urllib.parse import urlsplit

import httpx
from ctfmesh_domain import normalize_exact_host
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .target_capability import TargetCapabilityError, TargetCapabilitySigner, request_digest

_MAX_REQUEST_BODY_BYTES = 1024 * 1024
_MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024
_MAX_CONNECTOR_JSON_BYTES = 6 * 1024 * 1024
_MAX_HEADER_BYTES = 64 * 1024
_MAX_HEADER_COUNT = 80
_MAX_DNS_RESULTS = 16
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")


class TargetConnectorError(RuntimeError):
    """Stable, secret-free connector failure returned to a source slot."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ConnectorHeader(BaseModel):
    """One bounded HTTP header from the source slot's typed runtime."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=8192)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if _HEADER_NAME.fullmatch(value) is None:
            raise ValueError("connector_header_invalid")
        return value

    @field_validator("value")
    @classmethod
    def valid_value(cls, value: str) -> str:
        if any(character in value for character in "\r\n\x00"):
            raise ValueError("connector_header_invalid")
        return value


class TargetConnectorRequest(BaseModel):
    """Private source-slot request; exact authority comes from capability."""

    model_config = ConfigDict(extra="forbid", strict=True)

    capability: str = Field(min_length=1, max_length=4096)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    url: str = Field(min_length=1, max_length=8192)
    headers: list[ConnectorHeader] = Field(default_factory=list, max_length=_MAX_HEADER_COUNT)
    body_base64: str = Field(max_length=2 * _MAX_REQUEST_BODY_BYTES)


class TargetConnectorSettings(BaseSettings):
    """Deployment-only connector configuration; it exposes no provider key."""

    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    target_capability_key: SecretStr
    target_connector_host: str = "0.0.0.0"  # noqa: S104 - internal bridge only.
    target_connector_port: int = Field(default=8083, ge=1, le=65_535)

    @field_validator("target_capability_key")
    @classmethod
    def capability_key_is_bounded(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not 32 <= len(raw) <= 512:
            raise ValueError("target_capability_key_invalid")
        return value

    @classmethod
    def from_environment(cls) -> Self:
        """Load the required capability key only at the process boundary."""

        # Pydantic performs required-environment validation at runtime. The
        # cast keeps the entry point typed without supplying a fake key as a
        # default or weakening that startup failure mode.
        constructor = cast(Callable[[], Self], cls)
        return constructor()

    def __repr_args__(self) -> Any:
        return (
            (key, value) for key, value in super().__repr_args__() if key != "target_capability_key"
        )


@dataclass(frozen=True, slots=True)
class _TargetResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool


class _NonceStore:
    """Bounded in-memory replay guard for signed request capabilities."""

    def __init__(self, *, max_entries: int = 4096) -> None:
        self._max_entries = max_entries
        self._entries: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def consume(self, nonce: str, *, expires_at: int, now: int) -> None:
        async with self._lock:
            expired = [key for key, expiry in self._entries.items() if expiry < now]
            for key in expired:
                self._entries.pop(key, None)
            if nonce in self._entries:
                raise TargetConnectorError("target_capability_replayed")
            if len(self._entries) >= self._max_entries:
                raise TargetConnectorError("target_capability_capacity_exhausted")
            self._entries[nonce] = expires_at


class TargetConnector:
    """Verify one capability and make exactly one public HTTP/1.1 attempt."""

    def __init__(self, signer: TargetCapabilitySigner) -> None:
        self._signer = signer
        self._nonces = _NonceStore()

    async def forward(self, request: TargetConnectorRequest) -> _TargetResponse:
        body = _decode_body(request.body_base64)
        try:
            capability = self._signer.verify(request.capability)
        except TargetCapabilityError as exc:
            raise TargetConnectorError(exc.code) from exc
        if (
            capability.method != request.method
            or not _constant_digest_match(capability.url_sha256, request_digest(request.url))
            or not _constant_digest_match(capability.body_sha256, request_digest(body))
        ):
            raise TargetConnectorError("target_capability_request_mismatch")
        await self._nonces.consume(
            capability.nonce,
            expires_at=capability.expires_at,
            now=int(time.time()),
        )
        # ``verify`` used wall time. Callers cannot influence the network
        # deadline, target host, origin, DNS answers, or redirect policy.
        return await _request_pinned(request, body)


class TargetConnectorTransport(httpx.AsyncBaseTransport):
    """Source-slot transport that can operate only inside a bound capability."""

    def __init__(self, base_url: str = "http://target-connector:8083") -> None:
        if base_url.rstrip("/") != "http://target-connector:8083":
            raise ValueError("target_connector_url_invalid")
        self._base_url = base_url.rstrip("/")
        self._capability: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "ctfmesh_target_capability",
            default=None,
        )

    def bind_capability(self, capability: str) -> contextvars.Token[str | None]:
        if not isinstance(capability, str) or not capability or len(capability) > 4096:
            raise TargetConnectorError("target_capability_unavailable")
        return self._capability.set(capability)

    def reset_capability(self, token: contextvars.Token[str | None]) -> None:
        self._capability.reset(token)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        capability = self._capability.get()
        if capability is None:
            raise httpx.ConnectError("target_capability_unavailable", request=request)
        body = await request.aread()
        if len(body) > _MAX_REQUEST_BODY_BYTES:
            raise httpx.RequestError("target_request_body_too_large", request=request)
        payload = {
            "capability": capability,
            "method": request.method,
            "url": str(request.url),
            "headers": [
                {"name": name, "value": value}
                for name, value in request.headers.multi_items()
                if name.lower() not in _HOP_BY_HOP_HEADERS
            ],
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(30.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post("/internal/target-requests", json=payload)
        except httpx.HTTPError as exc:
            raise httpx.ConnectError("target_connector_unavailable", request=request) from exc
        if response.status_code != 200:
            raise httpx.ConnectError("target_connector_rejected", request=request)
        try:
            payload = response.json()
            status = payload["status"]
            headers = payload["headers"]
            encoded = payload["body_base64"]
            truncated = payload["truncated"]
            if (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 599
                or not isinstance(headers, list)
                or not isinstance(encoded, str)
                or not isinstance(truncated, bool)
            ):
                raise ValueError
            raw_headers = [
                (item["name"], item["value"])
                for item in headers
                if isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("value"), str)
            ]
            if len(raw_headers) != len(headers):
                raise ValueError
            response_body = _decode_body(encoded, maximum=_MAX_RESPONSE_BODY_BYTES)
        except (KeyError, TypeError, ValueError) as exc:
            raise httpx.ConnectError("target_connector_response_invalid", request=request) from exc
        response_headers = httpx.Headers(raw_headers)
        if truncated:
            response_headers["x-ctfmesh-truncated"] = "true"
        return httpx.Response(
            status, headers=response_headers, content=response_body, request=request
        )

    async def aclose(self) -> None:
        # The transport creates no long-lived client or target connection.
        return None


def _decode_body(value: str, *, maximum: int = _MAX_REQUEST_BODY_BYTES) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum * 4) // 3) + 8:
        raise TargetConnectorError("target_connector_body_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise TargetConnectorError("target_connector_body_invalid") from exc
    if len(decoded) > maximum:
        raise TargetConnectorError("target_connector_body_invalid")
    return decoded


def _constant_digest_match(expected: str, observed: str) -> bool:
    return hmac.compare_digest(expected, observed)


async def _request_pinned(request: TargetConnectorRequest, body: bytes) -> _TargetResponse:
    try:
        parsed = urlsplit(request.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetConnectorError("target_connector_url_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise TargetConnectorError("target_connector_url_invalid")
    try:
        host = normalize_exact_host(parsed.hostname)
    except ValueError as exc:
        raise TargetConnectorError("target_connector_url_invalid") from exc
    addresses = await _resolve_public_addresses(host, port)
    return await _request_one_address(
        address=addresses[0],
        host=host,
        port=port,
        scheme=parsed.scheme,
        path=(parsed.path or "/") + (f"?{parsed.query}" if parsed.query else ""),
        method=request.method,
        headers=request.headers,
        body=body,
    )


async def _resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise TargetConnectorError("target_connector_dns_unavailable") from exc
    addresses: list[str] = []
    for _family, _socktype, _protocol, _canonical, address in records[:_MAX_DNS_RESULTS]:
        raw = address[0]
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise TargetConnectorError("target_connector_dns_invalid") from exc
        if not parsed.is_global:
            raise TargetConnectorError("target_connector_private_address_denied")
        normalized = parsed.compressed
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise TargetConnectorError("target_connector_dns_unavailable")
    return tuple(addresses)


async def _request_one_address(
    *,
    address: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    method: str,
    headers: list[ConnectorHeader],
    body: bytes,
) -> _TargetResponse:
    ssl_context = ssl.create_default_context() if scheme == "https" else None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port,
                ssl=ssl_context,
                server_hostname=host if ssl_context is not None else None,
                limit=_MAX_HEADER_BYTES + 1,
            ),
            timeout=10.0,
        )
        request_bytes = _render_request(
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            method=method,
            headers=headers,
            body=body,
        )
        writer.write(request_bytes)
        await asyncio.wait_for(writer.drain(), timeout=10.0)
        return await asyncio.wait_for(_read_response(reader, method=method), timeout=20.0)
    except TargetConnectorError:
        raise
    except (
        OSError,
        TimeoutError,
        UnicodeEncodeError,
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
    ) as exc:
        raise TargetConnectorError("target_connector_target_unavailable") from exc
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


def _render_request(
    *,
    host: str,
    port: int,
    scheme: str,
    path: str,
    method: str,
    headers: list[ConnectorHeader],
    body: bytes,
) -> bytes:
    host_header = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        host_header = f"{host_header}:{port}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}", "Accept-Encoding: identity"]
    for header in headers:
        if header.name.lower() in _HOP_BY_HOP_HEADERS or header.name.lower() == "accept-encoding":
            continue
        lines.append(f"{header.name}: {header.value}")
    lines.extend((f"Content-Length: {len(body)}", "Connection: close", "", ""))
    return "\r\n".join(lines).encode("iso-8859-1") + body


async def _read_response(reader: asyncio.StreamReader, *, method: str) -> _TargetResponse:
    try:
        raw_headers = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise TargetConnectorError("target_connector_response_invalid") from exc
    if len(raw_headers) > _MAX_HEADER_BYTES:
        raise TargetConnectorError("target_connector_response_invalid")
    try:
        lines = raw_headers[:-4].decode("iso-8859-1").split("\r\n")
        version, code, _reason = lines[0].split(" ", maxsplit=2)
        status = int(code)
    except (IndexError, ValueError, UnicodeDecodeError) as exc:
        raise TargetConnectorError("target_connector_response_invalid") from exc
    if version != "HTTP/1.1" or not 100 <= status <= 599:
        raise TargetConnectorError("target_connector_response_invalid")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            raise TargetConnectorError("target_connector_response_invalid")
        name, value = line.split(":", maxsplit=1)
        if _HEADER_NAME.fullmatch(name) is None or "\x00" in value:
            raise TargetConnectorError("target_connector_response_invalid")
        headers.append((name, value.lstrip(" \t")))
        if len(headers) > _MAX_HEADER_COUNT:
            raise TargetConnectorError("target_connector_response_invalid")
    if method == "HEAD" or status in {204, 304}:
        return _TargetResponse(status=status, headers=tuple(headers), body=b"", truncated=False)
    lower_headers = [(name.lower(), value) for name, value in headers]
    if any(
        name == "transfer-encoding" and "chunked" in value.lower() for name, value in lower_headers
    ):
        body, truncated = await _read_chunked_body(reader)
    else:
        lengths = [value for name, value in lower_headers if name == "content-length"]
        if len(lengths) > 1 and len(set(lengths)) != 1:
            raise TargetConnectorError("target_connector_response_invalid")
        if lengths:
            if not lengths[0].isdigit():
                raise TargetConnectorError("target_connector_response_invalid")
            length = int(lengths[0])
            if length > _MAX_RESPONSE_BODY_BYTES:
                body = await reader.readexactly(_MAX_RESPONSE_BODY_BYTES)
                truncated = True
            else:
                body = await reader.readexactly(length)
                truncated = False
        else:
            body = await reader.read(_MAX_RESPONSE_BODY_BYTES + 1)
            truncated = len(body) > _MAX_RESPONSE_BODY_BYTES
            body = body[:_MAX_RESPONSE_BODY_BYTES]
    return _TargetResponse(status=status, headers=tuple(headers), body=body, truncated=truncated)


async def _read_chunked_body(reader: asyncio.StreamReader) -> tuple[bytes, bool]:
    body = bytearray()
    while True:
        line = await reader.readline()
        if not line or len(line) > 1024:
            raise TargetConnectorError("target_connector_response_invalid")
        raw_size = line.rstrip(b"\r\n").split(b";", maxsplit=1)[0]
        try:
            size = int(raw_size, 16)
        except ValueError as exc:
            raise TargetConnectorError("target_connector_response_invalid") from exc
        if size < 0:
            raise TargetConnectorError("target_connector_response_invalid")
        if size == 0:
            await reader.readline()
            return bytes(body), False
        remaining = _MAX_RESPONSE_BODY_BYTES - len(body)
        if size > remaining:
            body.extend(await reader.readexactly(max(remaining, 0)))
            return bytes(body), True
        body.extend(await reader.readexactly(size))
        if await reader.readexactly(2) != b"\r\n":
            raise TargetConnectorError("target_connector_response_invalid")


def create_target_connector_app(settings: TargetConnectorSettings) -> FastAPI:
    """Create the internal capability-enforcing target connector ASGI app."""

    connector = TargetConnector(
        TargetCapabilitySigner(settings.target_capability_key.get_secret_value())
    )
    started_at = monotonic()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="CTFMesh Target Connector",
        version="0.1.0",
        description="Internal capability-enforcing target relay.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ctfmesh-target-connector",
            "uptime_seconds": round(monotonic() - started_at, 3),
        }

    @app.post("/internal/target-requests")
    async def forward_target_request(request: Request) -> dict[str, Any]:
        raw = bytearray()
        try:
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > _MAX_CONNECTOR_JSON_BYTES:
                    raise TargetConnectorError("target_connector_request_too_large")
            parsed = TargetConnectorRequest.model_validate_json(raw)
            response = await connector.forward(parsed)
        except (TargetConnectorError, ValidationError, ValueError):
            # No URL, header, source, capability, upstream response, or
            # exception diagnostic is reflected to a source-slot process.
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "target_connector_rejected",
                    "message": "Target connector rejected the request.",
                },
            ) from None
        return {
            "status": response.status,
            "headers": [{"name": name, "value": value} for name, value in response.headers],
            "body_base64": base64.b64encode(response.body).decode("ascii"),
            "truncated": response.truncated,
        }

    @app.exception_handler(ValidationError)
    async def validation_error(_request: Request, _exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "target_connector_request_invalid",
                    "message": "Target connector request validation failed.",
                }
            },
        )

    return app


__all__ = [
    "TargetCapabilitySigner",
    "TargetConnector",
    "TargetConnectorError",
    "TargetConnectorSettings",
    "TargetConnectorTransport",
    "TargetConnectorRequest",
    "create_target_connector_app",
]
