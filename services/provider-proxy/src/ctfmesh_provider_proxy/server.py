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
_FORWARDABLE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
# Dropped rather than forwarded: they describe this hop, not the upstream one.
_HOP_BY_HOP_HEADERS = frozenset(
    {"proxy-connection", "connection", "keep-alive", "te", "trailer", "upgrade"}
)

type AsyncConnector = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


class ProviderProxyConfigurationError(ValueError):
    """A safe startup or client-input failure with no credential detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_provider_host(raw: str, *, allow_ip: bool = False) -> str:
    """Accept a plain DNS name, and an IP literal only where declared.

    A bare name in the allowlist is resolved by this proxy, so an IP literal
    there would let a short entry name an address nobody reviewed. An operator
    who writes a full ``scheme://host:port`` entry has named the address on
    purpose, which is the only way a model server on the local network can be
    reached at all.
    """

    host = raw.strip().lower()
    if not host or len(host) > 253 or host.endswith("."):
        raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if allow_ip:
            return host
        raise ProviderProxyConfigurationError("provider_proxy_host_ip_forbidden")
    if "." not in host:
        # A single label is a container or search-domain name, which would
        # resolve differently here than the operator expects.
        raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
    labels = host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
    return host


@dataclass(frozen=True, slots=True)
class ProviderEndpoint:
    """One upstream this deployment's operator reviewed and named."""

    host: str
    port: int
    #: ``False`` only for an endpoint the operator wrote as ``http://``. A
    #: plaintext hop carries the model key in the clear, so it is never
    #: inferred - it has to be asked for, and it exists so a model server on
    #: the operator's own machine can be reached without a certificate.
    tls: bool = True


def _parse_provider_endpoint(raw: str) -> ProviderEndpoint:
    """Parse one allowlist entry in its bare, ported, or full-URL form."""

    item = raw.strip()
    scheme, separator, remainder = item.partition("://")
    if separator:
        scheme = scheme.lower()
        if scheme not in {"http", "https"}:
            raise ProviderProxyConfigurationError("provider_proxy_scheme_forbidden")
        authority = remainder.rstrip("/")
        if "/" in authority:
            raise ProviderProxyConfigurationError("provider_proxy_host_invalid")
        tls = scheme == "https"
        explicit = True
    else:
        authority = item
        tls = True
        explicit = False
    host, port_separator, port_text = authority.rpartition(":")
    if not port_separator:
        host, port = authority, 443
    else:
        if not port_text.isascii() or not port_text.isdecimal():
            raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
        port = int(port_text)
        if not 1 <= port <= 65_535:
            raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
        explicit = True
    return ProviderEndpoint(
        host=_canonical_provider_host(host, allow_ip=explicit),
        port=port,
        tls=tls,
    )


def parse_provider_hosts(raw: str) -> frozenset[ProviderEndpoint]:
    """Parse an explicit, deduplicated allowlist from deployment config.

    Three forms, in rising order of how much the operator is asking for:
    ``api.openai.com`` tunnels to port 443, ``gateway.example.com:8443``
    tunnels to another TLS port, and ``http://192.168.1.50:11434`` forwards in
    the clear to a model server the operator runs themselves.
    """

    endpoints = frozenset(_parse_provider_endpoint(item) for item in raw.split(",") if item.strip())
    if not endpoints:
        raise ProviderProxyConfigurationError("provider_proxy_hosts_required")
    if len(endpoints) > 32:
        raise ProviderProxyConfigurationError("provider_proxy_hosts_too_many")
    return endpoints


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

    allowed_hosts: frozenset[ProviderEndpoint]
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
        for endpoint in self.allowed_hosts:
            # Direct construction is held to the environment's rules: a name
            # must already be canonical, and an address literal is accepted
            # only where a port says the operator named it deliberately.
            canonical = _canonical_provider_host(
                endpoint.host, allow_ip=endpoint.port != 443 or not endpoint.tls
            )
            if canonical != endpoint.host:
                raise ProviderProxyConfigurationError("provider_proxy_host_not_canonical")
            if not 1 <= endpoint.port <= 65_535:
                raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
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


def parse_connect_authority(raw: str) -> ProviderEndpoint:
    """Parse exactly one tunnel target from a CONNECT request line."""

    if not raw or len(raw) > 260 or raw.strip() != raw or raw.count(":") != 1:
        raise ProviderProxyConfigurationError("provider_proxy_connect_authority_invalid")
    host, separator, port_text = raw.rpartition(":")
    if separator != ":" or not port_text.isascii() or not port_text.isdecimal():
        raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
    # The allowlist decides which targets exist; a CONNECT line only names one.
    # Address literals are matched against entries the operator wrote in full,
    # so naming one here can never reach an endpoint they did not review.
    return ProviderEndpoint(host=_canonical_provider_host(host, allow_ip=True), port=port)


@dataclass(frozen=True, slots=True)
class ForwardRequest:
    """One plaintext request this proxy will relay to a declared endpoint."""

    endpoint: ProviderEndpoint
    #: The request rewritten to origin form, as the upstream server expects it.
    preface: bytes


def _forward_target(raw_uri: str) -> tuple[ProviderEndpoint, str]:
    """Split an absolute-form request URI into its endpoint and path."""

    scheme, separator, remainder = raw_uri.partition("://")
    if not separator or scheme.lower() != "http":
        raise ProviderProxyConfigurationError("provider_proxy_method_forbidden")
    authority, slash, path = remainder.partition("/")
    host, port_separator, port_text = authority.rpartition(":")
    if not port_separator:
        host, port = authority, 80
    else:
        if not port_text.isascii() or not port_text.isdecimal():
            raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
        port = int(port_text)
        if not 1 <= port <= 65_535:
            raise ProviderProxyConfigurationError("provider_proxy_connect_port_forbidden")
    endpoint = ProviderEndpoint(
        host=_canonical_provider_host(host, allow_ip=True), port=port, tls=False
    )
    return endpoint, f"/{path}" if slash else "/"


def parse_proxy_request(raw: bytes) -> ProviderEndpoint | ForwardRequest:
    """Validate a bounded proxy preface without retaining sensitive headers.

    A CONNECT names a tunnel and this proxy never sees inside it. An
    absolute-form request is the only shape a plaintext model server can be
    reached in, and it is rewritten to origin form here; the allowlist still
    decides whether that endpoint exists at all.
    """

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
    if len(request_line) != 3 or request_line[2] != "HTTP/1.1":
        raise ProviderProxyConfigurationError("provider_proxy_method_forbidden")
    method, target, _version = request_line
    if method not in _FORWARDABLE_METHODS and method != "CONNECT":
        raise ProviderProxyConfigurationError("provider_proxy_method_forbidden")
    headers: list[str] = []
    for header in lines[1:]:
        if not header or ":" not in header:
            raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
        name, value = header.split(":", 1)
        if not name or any(character in name or character in value for character in "\r\n\x00"):
            raise ProviderProxyConfigurationError("provider_proxy_request_invalid")
        lowered = name.lower()
        # A proxy credential is never this proxy's business: a tunnelled key is
        # encrypted beyond it, and a forwarded key belongs to the upstream.
        if lowered == "proxy-authorization":
            raise ProviderProxyConfigurationError("provider_proxy_auth_forbidden")
        if lowered in _HOP_BY_HOP_HEADERS:
            continue
        headers.append(header)
    if method == "CONNECT":
        return parse_connect_authority(target)
    endpoint, path = _forward_target(target)
    # One request per connection. Reusing it would leave later requests in
    # absolute form with no second rewrite, and this hop is not on the path
    # that needs to be fast.
    preface = "\r\n".join([f"{method} {path} HTTP/1.1", *headers, "Connection: close"])
    return ForwardRequest(endpoint=endpoint, preface=f"{preface}\r\n\r\n".encode())


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
                parsed = parse_proxy_request(raw_request)
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                ProviderProxyConfigurationError,
                TimeoutError,
            ):
                await self._respond(client_writer, "400 Bad Request")
                return
            forward = parsed if isinstance(parsed, ForwardRequest) else None
            endpoint = parsed.endpoint if isinstance(parsed, ForwardRequest) else parsed
            if endpoint not in self._settings.allowed_hosts:
                await self._respond(client_writer, "403 Forbidden")
                return
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    self._connector(endpoint.host, endpoint.port),
                    timeout=self._settings.connect_timeout_seconds,
                )
            except (ConnectionError, OSError, TimeoutError):
                await self._respond(client_writer, "502 Bad Gateway")
                return
            if forward is None:
                await self._respond(client_writer, "200 Connection Established")
            else:
                # No proxy response of its own: the upstream's reply is the
                # client's reply, relayed byte for byte like a tunnel.
                upstream_writer.write(forward.preface)
                await upstream_writer.drain()
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
