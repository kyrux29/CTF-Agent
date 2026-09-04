"""Deterministic tests for M3's provider-only CONNECT egress boundary."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import pytest
from ctfmesh_provider_proxy.server import (
    AllowlistConnectProxy,
    ForwardRequest,
    ProviderEndpoint,
    ProviderProxyConfigurationError,
    ProviderProxySettings,
    parse_connect_authority,
    parse_provider_hosts,
    parse_proxy_request,
)


def test_provider_proxy_parses_the_endpoints_an_operator_declared() -> None:
    # A bare name still means "tunnel to 443", which is every hosted provider.
    assert parse_provider_hosts("api.openai.com, API.ANTHROPIC.COM") == {
        ProviderEndpoint("api.openai.com", 443),
        ProviderEndpoint("api.anthropic.com", 443),
    }
    # A port reaches a gateway that does not listen on 443, and the full URL
    # form is the only way to name a model server the operator runs locally.
    assert parse_provider_hosts("gateway.example.test:8443, http://192.168.1.50:11434") == {
        ProviderEndpoint("gateway.example.test", 8443),
        ProviderEndpoint("192.168.1.50", 11434, tls=False),
    }

    for invalid in (
        "",
        "*.openai.com",
        # A bare address is still refused: this proxy resolves short entries,
        # so an address there would name a host nobody reviewed.
        "127.0.0.1",
        "api.openai.com.",
        "ftp://api.openai.com",
        "http://192.168.1.50:11434/v1",
        "gateway.example.test:0",
        "gateway.example.test:99999",
    ):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_provider_hosts(invalid)

    # The CONNECT line only names a target; the allowlist decides whether it
    # exists. Port and address checks moved there rather than being dropped,
    # which the network test below proves.
    assert parse_connect_authority("API.OPENAI.COM:443") == ProviderEndpoint("api.openai.com", 443)
    for invalid in ("api.openai.com:443@evil.test", "api.openai.com:443:443", "api.openai.com"):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_connect_authority(invalid)

    # A plaintext request is rewritten to origin form; hop headers describe
    # this hop and do not travel, and one request per connection avoids a
    # second request going out still in absolute form.
    forwarded = parse_proxy_request(
        b"POST http://192.168.1.50:11434/v1/chat HTTP/1.1\r\n"
        b"Host: 192.168.1.50:11434\r\nProxy-Connection: keep-alive\r\n\r\n"
    )
    assert isinstance(forwarded, ForwardRequest)
    assert forwarded.endpoint == ProviderEndpoint("192.168.1.50", 11434, tls=False)
    assert forwarded.preface.startswith(b"POST /v1/chat HTTP/1.1\r\n")
    assert b"Proxy-Connection" not in forwarded.preface
    assert forwarded.preface.endswith(b"Connection: close\r\n\r\n")

    for request in (
        b"CONNECT api.openai.com:443 HTTP/1.0\r\n\r\n",
        # A proxy credential is never this hop's business.
        b"CONNECT api.openai.com:443 HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n",
        # https:// absolute form would mean terminating TLS here.
        b"GET https://api.openai.com/ HTTP/1.1\r\n\r\n",
        b"TRACE http://192.168.1.50:11434/ HTTP/1.1\r\n\r\n",
    ):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_proxy_request(request)


def test_provider_proxy_configuration_rejects_unbounded_deployment_settings() -> None:
    settings = ProviderProxySettings.from_environment(
        {
            "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
            "CTFMESH_PROVIDER_PROXY_MAX_CONNECTIONS": "2",
        }
    )
    assert settings.allowed_hosts == {ProviderEndpoint("api.openai.com", 443)}
    assert settings.max_connections == 2

    slow_provider_settings = ProviderProxySettings.from_environment(
        {
            "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
            "CTFMESH_PROVIDER_PROXY_IDLE_TIMEOUT_SECONDS": "86520",
        }
    )
    assert slow_provider_settings.idle_timeout_seconds == 86_520

    with pytest.raises(ProviderProxyConfigurationError, match="provider_proxy_bind_host_invalid"):
        ProviderProxySettings.from_environment(
            {
                "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
                "CTFMESH_PROVIDER_PROXY_BIND_HOST": "::",
            }
        )
    with pytest.raises(
        ProviderProxyConfigurationError,
        match="provider_proxy_connection_limit_invalid",
    ):
        ProviderProxySettings.from_environment(
            {
                "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
                "CTFMESH_PROVIDER_PROXY_MAX_CONNECTIONS": "1000",
            }
        )
    with pytest.raises(ProviderProxyConfigurationError, match="provider_proxy_host_invalid"):
        ProviderProxySettings(allowed_hosts=frozenset({ProviderEndpoint("*.openai.com", 443)}))
    with pytest.raises(
        ProviderProxyConfigurationError,
        match="provider_proxy_idle_timeout_invalid",
    ):
        ProviderProxySettings.from_environment(
            {
                "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
                "CTFMESH_PROVIDER_PROXY_IDLE_TIMEOUT_SECONDS": "90001",
            }
        )


@pytest.mark.asyncio
async def test_provider_proxy_relays_only_an_allowed_opaque_tunnel() -> None:
    """The network exercise proves a denied host never reaches the connector."""

    received: list[bytes] = []

    async def echo_upstream(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while data := await reader.read(1024):
                received.append(data)
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    upstream = await asyncio.start_server(echo_upstream, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    connector_calls: list[tuple[str, int]] = []

    async def connector(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connector_calls.append((host, port))
        return await asyncio.open_connection("127.0.0.1", upstream_port)

    settings = ProviderProxySettings(
        allowed_hosts=frozenset({ProviderEndpoint("api.openai.com", 443)}),
        bind_host="127.0.0.1",
        bind_port=3128,
        handshake_timeout_seconds=2,
        connect_timeout_seconds=2,
        idle_timeout_seconds=2,
        max_header_bytes=8 * 1024,
        max_connections=2,
    )
    proxy = AllowlistConnectProxy(settings, connector=connector)
    listener = await asyncio.start_server(
        proxy.handle_connection,
        "127.0.0.1",
        0,
        limit=settings.max_header_bytes + 4,
    )
    proxy_port = listener.sockets[0].getsockname()[1]

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        await writer.drain()
        assert b"200 Connection Established" in await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=2
        )
        writer.write(b"opaque tls payload")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(18), timeout=2) == b"opaque tls payload"
        writer.close()
        await writer.wait_closed()

        denied_reader, denied_writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        denied_writer.write(b"CONNECT target.example.test:443 HTTP/1.1\r\n\r\n")
        await denied_writer.drain()
        assert b"403 Forbidden" in await asyncio.wait_for(
            denied_reader.readuntil(b"\r\n\r\n"), timeout=2
        )
        denied_writer.close()
        await denied_writer.wait_closed()
    finally:
        listener.close()
        upstream.close()
        await listener.wait_closed()
        await upstream.wait_closed()

    assert connector_calls == [("api.openai.com", 443)]
    assert received == [b"opaque tls payload"]


@pytest.mark.asyncio
async def test_provider_proxy_forwards_plaintext_only_where_it_was_declared() -> None:
    """A local model server is reachable, and nothing else becomes reachable.

    Ollama, vLLM and llama.cpp speak plain HTTP on a port of their choosing, so
    a tunnel to 443 cannot reach them at all. The forward path exists for that,
    and the allowlist is still what decides an endpoint exists: a port the
    operator did not declare is refused even on a host they did.
    """

    seen: list[bytes] = []

    async def upstream_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            seen.append(request)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    upstream = await asyncio.start_server(upstream_handler, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    connector_calls: list[tuple[str, int]] = []

    async def connector(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connector_calls.append((host, port))
        return await asyncio.open_connection("127.0.0.1", upstream_port)

    settings = ProviderProxySettings(
        allowed_hosts=frozenset({ProviderEndpoint("192.168.1.50", 11434, tls=False)}),
        bind_host="127.0.0.1",
        handshake_timeout_seconds=2,
        connect_timeout_seconds=2,
        idle_timeout_seconds=2,
        max_connections=2,
    )
    proxy = AllowlistConnectProxy(settings, connector=connector)
    listener = await asyncio.start_server(
        proxy.handle_connection, "127.0.0.1", 0, limit=settings.max_header_bytes + 4
    )
    proxy_port = listener.sockets[0].getsockname()[1]

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            b"POST http://192.168.1.50:11434/v1/chat/completions HTTP/1.1\r\n"
            b"Host: 192.168.1.50:11434\r\nContent-Length: 4\r\n\r\nbody"
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
        assert b"200 OK" in response
        assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"ok"
        writer.close()
        await writer.wait_closed()

        # Same host, a port the operator never declared.
        denied_reader, denied_writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        denied_writer.write(b"POST http://192.168.1.50:9999/v1/chat HTTP/1.1\r\nHost: x\r\n\r\n")
        await denied_writer.drain()
        assert b"403 Forbidden" in await asyncio.wait_for(
            denied_reader.readuntil(b"\r\n\r\n"), timeout=2
        )
        denied_writer.close()
        await denied_writer.wait_closed()

        # A tunnel to that endpoint is refused too: it was declared plaintext,
        # and a CONNECT to it is a different endpoint than the one reviewed.
        tunnel_reader, tunnel_writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        tunnel_writer.write(b"CONNECT 192.168.1.50:11434 HTTP/1.1\r\n\r\n")
        await tunnel_writer.drain()
        assert b"403 Forbidden" in await asyncio.wait_for(
            tunnel_reader.readuntil(b"\r\n\r\n"), timeout=2
        )
        tunnel_writer.close()
        await tunnel_writer.wait_closed()
    finally:
        listener.close()
        upstream.close()
        await listener.wait_closed()
        await upstream.wait_closed()

    assert connector_calls == [("192.168.1.50", 11434)]
    assert seen[0].startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
