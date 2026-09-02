"""Safe error translation coverage for the Power sandboxd client."""

from __future__ import annotations

from typing import Any

import pytest
from ctfmesh_solver_runtime import HttpSandboxdClient, SandboxdClientError


class _Response:
    status_code = 503

    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


class _Client:
    """Minimal async HTTP seam; it records neither credentials nor payloads."""

    def __init__(self, response: _Response) -> None:
        self._response = response

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *arguments: object) -> None:
        del arguments

    async def request(self, *arguments: Any, **kwargs: Any) -> _Response:
        del arguments, kwargs
        return self._response


@pytest.mark.asyncio
async def test_sandboxd_client_exposes_only_reviewed_recovery_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A service error remains actionable without reflecting its diagnostics."""

    response = _Response({"detail": {"code": "archive_intake_unavailable", "path": "/secret"}})
    fake_client = _Client(response)
    monkeypatch.setattr(
        "ctfmesh_solver_runtime.sandboxd.httpx.AsyncClient",
        lambda **_kwargs: fake_client,
    )
    client = HttpSandboxdClient(base_url="http://sandboxd", token="private-capability")

    with pytest.raises(SandboxdClientError, match="^sandboxd_archive_intake_unavailable$"):
        await client.create(run_id="run-test", archive_digest="a" * 64)


@pytest.mark.asyncio
async def test_sandboxd_client_does_not_reflect_an_unreviewed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected server fields never become a browser-visible error code."""

    response = _Response({"detail": {"code": "docker_denied", "diagnostic": "sensitive"}})
    fake_client = _Client(response)
    monkeypatch.setattr(
        "ctfmesh_solver_runtime.sandboxd.httpx.AsyncClient",
        lambda **_kwargs: fake_client,
    )
    client = HttpSandboxdClient(base_url="http://sandboxd", token="private-capability")

    with pytest.raises(SandboxdClientError, match="^sandboxd_request_rejected$"):
        await client.create(run_id="run-test", archive_digest="a" * 64)
