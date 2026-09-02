"""A bounded HTTP target tool with an injected transport and isolated sessions."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field, field_validator, model_validator

from ._compat import ToolRisk
from .contracts import ToolContractModel, ToolDeniedError, ToolInvocationContext, ToolSpec

_REDACTED_RESPONSE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authenticate",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
    }
)
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


class HttpRequestInput(ToolContractModel):
    session_id: str = Field(min_length=1, max_length=160)
    method: str = "GET"
    url: str = Field(min_length=1, max_length=8192)
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: Any | None = None
    content: str | None = Field(default=None, max_length=1024 * 1024)
    follow_redirects: Literal[False] = False
    timeout_seconds: float = Field(default=10, gt=0, le=30)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1, le=4 * 1024 * 1024)

    @field_validator("method")
    @classmethod
    def _method(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in _ALLOWED_METHODS:
            raise ValueError("HTTP method is not enabled")
        return normalized

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        _parse_target_url(value)
        return value

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if not name or any(character in name for character in "\r\n:\x00"):
                raise ValueError("invalid HTTP header name")
            if any(character in header_value for character in "\r\n\x00"):
                raise ValueError("invalid HTTP header value")
        return value

    @model_validator(mode="after")
    def _exclusive_body(self) -> HttpRequestInput:
        if self.json_body is not None and self.content is not None:
            raise ValueError("json_body and content are mutually exclusive")
        return self


class HttpResponseOutput(ToolContractModel):
    status: int = Field(ge=100, le=599)
    final_url: str
    headers: dict[str, str]
    body_text: str
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_size_bytes: int = Field(ge=0)
    content_type: str | None
    elapsed_ms: int = Field(ge=0)
    redirect_chain: tuple[str, ...] = ()
    cookie_delta: dict[str, int]
    truncated: bool


def _parse_target_url(url: str) -> tuple[str, str, int]:
    if any(character in url for character in "\r\n\t\x00\\"):
        raise ValueError("URL contains forbidden characters")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("URL must use absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are forbidden")
    if parsed.fragment:
        raise ValueError("URL fragments are forbidden")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    return parsed.scheme, parsed.hostname, port


def _assert_manifest_scope(url: str, context: ToolInvocationContext) -> None:
    scheme, host, port = _parse_target_url(url)
    try:
        endpoints = context.manifest.spec.target.allowed_endpoints
        allowed = any(
            endpoint.permits(protocol=scheme, host=host, port=port) for endpoint in endpoints
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ToolDeniedError("challenge manifest cannot authorize the requested URL") from exc
    if not allowed:
        raise ToolDeniedError("requested URL is outside the exact challenge scope")


def _redact_headers(headers: httpx.Headers) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in headers.multi_items():
        normalized = name.lower()
        safe_value = "<redacted>" if normalized in _REDACTED_RESPONSE_HEADERS else value
        if normalized in result:
            result[normalized] = f"{result[normalized]}, {safe_value}"
        else:
            result[normalized] = safe_value
    return result


class HttpRequestTool:
    """HTTP handler that cannot silently fall through to environment networking."""

    input_model: ClassVar[type[HttpRequestInput]] = HttpRequestInput
    output_model: ClassVar[type[HttpResponseOutput]] = HttpResponseOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="http.request",
        version="1.0.0",
        description="Send a bounded request to an exact manifest-authorized target.",
        risk=ToolRisk.TARGET_INTERACTION,
        idempotency="key_required",
        input_model=HttpRequestInput,
        output_model=HttpResponseOutput,
        required_capabilities=("target_http",),
        default_timeout_seconds=35,
        max_output_bytes=5 * 1024 * 1024,
    )

    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        if transport is None:
            raise ValueError("an explicitly scoped HTTP transport is required")
        self._transport = transport
        self._clients: dict[tuple[str, str], httpx.AsyncClient] = {}
        self._session_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._guard = asyncio.Lock()

    def requested_url(self, request: HttpRequestInput) -> str:
        return request.url

    def requested_path(
        self,
        request: HttpRequestInput,
        context: ToolInvocationContext,
    ) -> None:
        return None

    async def invoke(
        self,
        request: HttpRequestInput,
        context: ToolInvocationContext,
    ) -> HttpResponseOutput:
        _assert_manifest_scope(request.url, context)
        key = (context.run_id, request.session_id)
        client, lock = await self._session(key)
        headers = {"accept-encoding": "identity", **request.headers}
        before_cookie_count = len(client.cookies)
        started = time.monotonic()
        async with lock:
            async with client.stream(
                request.method,
                request.url,
                headers=headers,
                json=request.json_body,
                content=request.content,
                follow_redirects=False,
                timeout=httpx.Timeout(request.timeout_seconds),
            ) as response:
                body = bytearray()
                truncated = False
                async for chunk in response.aiter_raw():
                    remaining = request.max_response_bytes - len(body)
                    if remaining <= 0:
                        truncated = True
                        break
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                response_headers = _redact_headers(response.headers)
                status = response.status_code
                final_url = str(response.url)
                content_type = response.headers.get("content-type")
        elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
        payload = bytes(body)
        encoding = "utf-8"
        if content_type and "charset=" in content_type.lower():
            encoding = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip()
        try:
            body_text = payload.decode(encoding, errors="replace")
        except LookupError:
            body_text = payload.decode("utf-8", errors="replace")
        return HttpResponseOutput(
            status=status,
            final_url=final_url,
            headers=response_headers,
            body_text=body_text,
            body_sha256=hashlib.sha256(payload).hexdigest(),
            body_size_bytes=len(payload),
            content_type=content_type,
            elapsed_ms=elapsed_ms,
            redirect_chain=(),
            cookie_delta={"before": before_cookie_count, "after": len(client.cookies)},
            truncated=truncated,
        )

    async def close_session(self, run_id: str, session_id: str) -> None:
        key = (run_id, session_id)
        async with self._guard:
            client = self._clients.pop(key, None)
            self._session_locks.pop(key, None)
        if client is not None:
            await client.aclose()

    async def aclose(self) -> None:
        async with self._guard:
            clients = tuple(self._clients.values())
            self._clients.clear()
            self._session_locks.clear()
        for client in clients:
            await client.aclose()

    async def _session(
        self,
        key: tuple[str, str],
    ) -> tuple[httpx.AsyncClient, asyncio.Lock]:
        async with self._guard:
            client = self._clients.get(key)
            if client is None:
                client = httpx.AsyncClient(
                    transport=self._transport,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=httpx.Timeout(30.0),
                )
                self._clients[key] = client
                self._session_locks[key] = asyncio.Lock()
            return client, self._session_locks[key]


__all__ = ["HttpRequestInput", "HttpRequestTool", "HttpResponseOutput"]
