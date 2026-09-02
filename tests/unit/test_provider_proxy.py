"""Deterministic tests for M3's provider-only CONNECT egress boundary."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import pytest
from ctfmesh_provider_proxy.server import (
    AllowlistConnectProxy,
    ProviderProxyConfigurationError,
    ProviderProxySettings,
    parse_connect_authority,
    parse_connect_request,
    parse_provider_hosts,
)


def test_provider_proxy_parses_only_exact_dns_hosts_and_https_connects() -> None:
    assert parse_provider_hosts("api.openai.com, API.DEEPSEEK.COM") == {
        "api.openai.com",
        "api.deepseek.com",
    }
    assert parse_connect_authority("API.OPENAI.COM:443") == "api.openai.com"
    assert (
        parse_connect_request(
            b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n"
        )
        == "api.openai.com"
    )

    for invalid in (
        "",
        "*.openai.com",
        "127.0.0.1",
        "[::1]",
        "api.openai.com.",
    ):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_provider_hosts(invalid)
    for invalid in (
        "api.openai.com:80",
        "api.openai.com:443@evil.test",
        "127.0.0.1:443",
        "api.openai.com:443:443",
    ):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_connect_authority(invalid)
    for request in (
        b"GET http://api.openai.com/ HTTP/1.1\r\n\r\n",
        b"CONNECT api.openai.com:443 HTTP/1.0\r\n\r\n",
        b"CONNECT api.openai.com:443 HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n",
    ):
        with pytest.raises(ProviderProxyConfigurationError):
            parse_connect_request(request)


def test_provider_proxy_configuration_rejects_unbounded_deployment_settings() -> None:
    settings = ProviderProxySettings.from_environment(
        {
            "CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS": "api.openai.com",
            "CTFMESH_PROVIDER_PROXY_MAX_CONNECTIONS": "2",
        }
    )
    assert settings.allowed_hosts == {"api.openai.com"}
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
        ProviderProxySettings(allowed_hosts=frozenset({"*.openai.com"}))
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
        allowed_hosts=frozenset({"api.openai.com"}),
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
