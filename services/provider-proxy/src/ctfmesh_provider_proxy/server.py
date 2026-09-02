"""A small exact-host CONNECT proxy for model-provider egress.

It accepts only ``CONNECT dns-name:443 HTTP/1.1`` and only for an
operator-reviewed hostname.  The Pi runner sits on an internal network with
this proxy, while this process is the sole service joined to a non-internal
provider network.  It never logs request headers, tunnel bytes, or credentials.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import sys
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass

_DEFAULT_PROVIDER_HOSTS = "api.openai.com,generativelanguage.googleapis.com,api.deepseek.com"
_DEFAULT_BIND_HOST = "0.0.0.0"  # noqa: S104 - private Compose networks expose no host port.
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_RELAY_CHUNK_BYTES = 64 * 1024

type AsyncConnector = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


class ProviderProxyConfigurationError(ValueError):
    """A safe startup or client-input failure with no credential detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_provider_host(raw: str) -> str:
    """Accept only a plain DNS name, never an IP literal or wildcard."""

    host = raw.strip().lower()
    if not host or len(host) > 253 or host.endswith(".") or "." not in host:
        raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ProviderProxyConfigurationError("provider_proxy_host_ip_forbidden")
    labels = host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
    return host


def parse_provider_hosts(raw: str) -> frozenset[str]:
    """Parse an explicit, deduplicated allowlist from deployment config."""

    hosts = frozenset(_canonical_provider_host(item) for item in raw.split(",") if item.strip())
    if not hosts:
        raise ProviderProxyConfigurationError("provider_proxy_hosts_required")
    if len(hosts) > 32:
        raise ProviderProxyConfigurationError("provider_proxy_hosts_too_many")
    return hosts


def _bounded_int(
    raw: str | None,
    *,
    default: int,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    """Read one non-secret integer setting with a finite resource bound."""

    value = str(default) if raw is None or not raw.strip() else raw.strip()
    if not value.isascii() or not value.isdecimal():
        raise ProviderProxyConfigurationError(code)
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ProviderProxyConfigurationError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class ProviderProxySettings:
    """Closed configuration for the only provider-facing network service."""

    allowed_hosts: frozenset[str]
    bind_host: str = _DEFAULT_BIND_HOST
    bind_port: int = 3128
    handshake_timeout_seconds: int = 5
    connect_timeout_seconds: int = 10
    idle_timeout_seconds: int = 60
    max_header_bytes: int = 8 * 1024
    max_connections: int = 8

    def __post_init__(self) -> None:
        """Keep direct construction as strict as environment construction."""

        if not self.allowed_hosts or len(self.allowed_hosts) > 32:
            raise ProviderProxyConfigurationError("provider_proxy_hosts_required")
        canonical_hosts = frozenset(_canonical_provider_host(host) for host in self.allowed_hosts)
        if canonical_hosts != self.allowed_hosts:
            raise ProviderProxyConfigurationError("provider_proxy_host_not_canonical")
        if self.bind_host not in {_DEFAULT_BIND_HOST, "127.0.0.1"}:
            raise ProviderProxyConfigurationError("provider_proxy_bind_host_invalid")
        for value, minimum, maximum, code in (
            (self.bind_port, 1024, 65535, "provider_proxy_bind_port_invalid"),
            (self.handshake_timeout_seconds, 1, 30, "provider_proxy_handshake_timeout_invalid"),
            (self.connect_timeout_seconds, 1, 30, "provider_proxy_connect_timeout_invalid"),
            # Unlimited UI waits retain a 24-hour API watchdog. Keep a small
            # bounded relay margin so the adapter, not the opaque tunnel, owns
            # the public timeout classification.
            (self.idle_timeout_seconds, 1, 90_000, "provider_proxy_idle_timeout_invalid"),
            (self.max_header_bytes, 1024, 64 * 1024, "provider_proxy_header_limit_invalid"),
            (self.max_connections, 1, 32, "provider_proxy_connection_limit_invalid"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ProviderProxyConfigurationError(code)

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> ProviderProxySettings:
        """Load deployment configuration without reading any provider key."""

        values = os.environ if environment is None else environment
        bind_host = values.get("CTFMESH_PROVIDER_PROXY_BIND_HOST", _DEFAULT_BIND_HOST).strip()
        if bind_host not in {_DEFAULT_BIND_HOST, "127.0.0.1"}:
            raise ProviderProxyConfigurationError("provider_proxy_bind_host_invalid")
        return cls(
            allowed_hosts=parse_provider_hosts(
                values.get("CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS", _DEFAULT_PROVIDER_HOSTS)
            ),
            bind_host=bind_host,
            bind_port=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_BIND_PORT"),
                default=3128,
                minimum=1024,
                maximum=65535,
                code="provider_proxy_bind_port_invalid",
            ),
            handshake_timeout_seconds=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_HANDSHAKE_TIMEOUT_SECONDS"),
                default=5,
                minimum=1,
                maximum=30,
                code="provider_proxy_handshake_timeout_invalid",
            ),
            connect_timeout_seconds=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_CONNECT_TIMEOUT_SECONDS"),
                default=10,
                minimum=1,
                maximum=30,
                code="provider_proxy_connect_timeout_invalid",
            ),
            idle_timeout_seconds=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_IDLE_TIMEOUT_SECONDS"),
                default=60,
                minimum=1,
                maximum=90_000,
                code="provider_proxy_idle_timeout_invalid",
            ),
            max_header_bytes=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_MAX_HEADER_BYTES"),
                default=8 * 1024,
                minimum=1024,
                maximum=64 * 1024,
                code="provider_proxy_header_limit_invalid",
            ),
            max_connections=_bounded_int(
                values.get("CTFMESH_PROVIDER_PROXY_MAX_CONNECTIONS"),
                default=8,
                minimum=1,
                maximum=32,
                code="provider_proxy_connection_limit_invalid",
            ),
        )


def parse_connect_authority(raw: str) -> str:
    """Parse exactly one DNS hostname with the fixed HTTPS provider port."""

    if not raw or len(raw) > 260 or raw.strip() != raw or raw.count(":") != 1:
        raise ProviderProxyConfigurationError("provider_proxy_connect_authority_invalid")
    host, separator, port = raw.rpartition(":")
    if separator != ":" or port != "443":
        raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
    return _canonical_provider_host(host)


def parse_connect_request(raw: bytes) -> str:
    """Validate a bounded proxy preface without retaining sensitive headers."""

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProviderProxyConfigurationError("provider_proxy_request_invalid") from exc
    if not text.endswith("\r\n\r\n"):
        raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
    lines = text[:-4].split("\r\n")
    if not lines:
        raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
    request_line = lines[0].split(" ")
    if len(request_line) != 3 or request_line[0] != "CONNECT" or request_line[2] != "HTTP/1.1":
        raise ProviderProxyConfigurationError("provider_proxy_method_forbidden")
    for header in lines[1:]:
        if not header or ":" not in header:
            raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
        name, value = header.split(":", 1)
        if not name or any(character in name or character in value for character in "\r\n\x00"):
            raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
        # A CONNECT request should not carry credentials. Provider credentials
        # are encrypted inside the later TLS tunnel and are never parsed here.
        if name.lower() == "proxy-authorization":
            raise ProviderProxyConfigurationError("provider_proxy_auth_forbidden")
    return parse_connect_authority(request_line[1])


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Close a transport without leaking a peer-specific socket exception."""

    if writer is None:
        return
    writer.close()
    with suppress(ConnectionError, OSError):
        await writer.wait_closed()


class AllowlistConnectProxy:
    """Serve bounded CONNECT tunnels to the deployment's reviewed hosts."""

    def __init__(
        self,
        settings: ProviderProxySettings,
        *,
        connector: AsyncConnector = asyncio.open_connection,
    ) -> None:
        self._settings = settings
        self._connector = connector
        self._connections = asyncio.BoundedSemaphore(settings.max_connections)

    async def handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one client with fail-closed protocol and resource limits."""

        acquired = False
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            try:
                await asyncio.wait_for(self._connections.acquire(), timeout=0.05)
                acquired = True
            except TimeoutError:
                await self._respond(client_writer, "503 Service Unavailable")
                return
            try:
                raw_request = await asyncio.wait_for(
                    client_reader.readuntil(b"\r\n\r\n"),
                    timeout=self._settings.handshake_timeout_seconds,
                )
                if len(raw_request) > self._settings.max_header_bytes:
                    raise ProviderProxyConfigurationError("provider_proxy_request_too_large")
                host = parse_connect_request(raw_request)
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                ProviderProxyConfigurationError,
                TimeoutError,
            ):
                await self._respond(client_writer, "400 Bad Request")
                return
            if host not in self._settings.allowed_hosts:
                await self._respond(client_writer, "403 Forbidden")
                return
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    self._connector(host, 443),
                    timeout=self._settings.connect_timeout_seconds,
                )
            except (ConnectionError, OSError, TimeoutError):
                await self._respond(client_writer, "502 Bad Gateway")
                return
            await self._respond(client_writer, "200 Connection Established")
            await asyncio.gather(
                self._relay(client_reader, upstream_writer),
                self._relay(upstream_reader, client_writer),
            )
        finally:
            await _close_writer(upstream_writer)
            await _close_writer(client_writer)
            if acquired:
                self._connections.release()

    async def _respond(self, writer: asyncio.StreamWriter, status: str) -> None:
        """Return a generic proxy status without reflecting host or headers."""

        writer.write(
            (f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").encode("ascii")
        )
        with suppress(ConnectionError, OSError, TimeoutError):
            await asyncio.wait_for(writer.drain(), timeout=self._settings.handshake_timeout_seconds)

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Copy opaque TLS bytes with idle back-pressure and no inspection."""

        while True:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(_MAX_RELAY_CHUNK_BYTES),
                    timeout=self._settings.idle_timeout_seconds,
                )
            except (ConnectionError, OSError, TimeoutError):
                return
            if not chunk:
                if writer.can_write_eof():
                    with suppress(ConnectionError, OSError):
                        writer.write_eof()
                        await writer.drain()
                return
            writer.write(chunk)
            try:
                await asyncio.wait_for(writer.drain(), timeout=self._settings.idle_timeout_seconds)
            except (ConnectionError, OSError, TimeoutError):
                return


async def start_proxy(
    settings: ProviderProxySettings,
    *,
    connector: AsyncConnector = asyncio.open_connection,
) -> asyncio.AbstractServer:
    """Bind the restricted proxy with a reader limit just above its header cap."""

    proxy = AllowlistConnectProxy(settings, connector=connector)
    return await asyncio.start_server(
        proxy.handle_connection,
        host=settings.bind_host,
        port=settings.bind_port,
        limit=settings.max_header_bytes + 4,
    )


async def _serve() -> None:
    """Run until container shutdown; no request metadata is emitted to stdout."""

    settings = ProviderProxySettings.from_environment()
    server = await start_proxy(settings)
    async with server:
        await server.serve_forever()


def main() -> None:
    """Container entry point with a safe configuration-only startup failure."""

    try:
        asyncio.run(_serve())
    except ProviderProxyConfigurationError as exc:
        sys.stderr.write(f"[ctfmesh-provider-proxy] {exc.code}\n")
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        return


if __name__ == "__main__":  # pragma: no cover - exercised by Compose.
    main()
