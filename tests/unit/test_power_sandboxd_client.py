"""Safe error translation coverage for the Power sandboxd client."""

from __future__ import annotations

from typing import Any

import pytest
from ctfmesh_solver_runtime import HttpSandboxdClient, SandboxdClientError


class _Response:
    def __init__(self, payload: object, *, status_code: int = 503) -> None:
        self._payload = payload
        self.status_code = status_code

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


@pytest.mark.asyncio
async def test_sandboxd_client_keeps_both_exec_stream_artifact_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normal exec receipts retain stderr provenance for candidate review."""

    response = _Response(
        {
            "exit_code": 0,
            "timed_out": False,
            "output_truncated": False,
            "stdout": "normal output",
            "stderr": "diagnostic output",
            "stdout_artifact": {
                "id": f"sha256:{'a' * 64}",
                "sha256": "a" * 64,
                "size_bytes": 13,
            },
            "stderr_artifact": {
                "id": f"sha256:{'b' * 64}",
                "sha256": "b" * 64,
                "size_bytes": 17,
            },
        },
        status_code=200,
    )
    fake_client = _Client(response)
    monkeypatch.setattr(
        "ctfmesh_solver_runtime.sandboxd.httpx.AsyncClient",
        lambda **_kwargs: fake_client,
    )
    client = HttpSandboxdClient(base_url="http://sandboxd", token="private-capability")

    observation = await client.exec(
        "ws_123",
        command=("printf", "ok"),
        timeout_seconds=10,
        working_directory="/challenge",
    )

    assert observation.stdout_artifact_id == f"sha256:{'a' * 64}"
    assert observation.stderr_artifact_id == f"sha256:{'b' * 64}"
    assert observation.stderr_sha256 == "b" * 64
    assert observation.stderr_artifact_size_bytes == 17
