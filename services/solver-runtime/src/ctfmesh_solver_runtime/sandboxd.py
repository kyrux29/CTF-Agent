"""Typed HTTP client for P1's private sandboxd RPC."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx

from .runner import SandboxObservation

_PUBLIC_SANDBOXD_ERROR_CODES = frozenset(
    {
        "archive_intake_unavailable",
        "archive_workspace_unavailable",
        "archive_workspace_too_large",
        "workspace_image_unavailable",
        "workspace_create_failed",
        "workspace_copy_failed",
        "workspace_artifact_store_failed",
    }
)


class SandboxdClientError(RuntimeError):
    """Stable client error that does not expose response bodies or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HttpSandboxdClient:
    """Solver-facing façade with no Docker, filesystem or provider authority."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        tube_targets: tuple[tuple[str, int], ...] = (),
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        # The browser/API can nominate only a normalized host:port pair. This
        # client serializes it once at workspace creation; every later tube
        # call is still re-checked by sandboxd against that immutable list.
        if len(tube_targets) > 16 or any(
            not isinstance(host, str)
            or not host
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65_535
            for host, port in tube_targets
        ):
            raise ValueError("sandboxd_tube_targets_invalid")
        self._tube_targets = tube_targets

    async def create(self, *, run_id: str, archive_digest: str) -> str:
        payload = await self._request(
            "POST",
            "/v1/workspaces",
            {
                "run_id": run_id,
                "archive_digest": archive_digest,
                "tube_targets": [{"host": host, "port": port} for host, port in self._tube_targets],
            },
            expected=201,
        )
        workspace_id = payload.get("workspace_id")
        if not isinstance(workspace_id, str):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return workspace_id

    async def exec(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
    ) -> SandboxObservation:
        payload = await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/exec",
            {
                "command": list(command),
                "timeout_seconds": timeout_seconds,
                "working_directory": working_directory,
            },
            expected=200,
        )
        stdout = payload.get("stdout")
        stderr = payload.get("stderr")
        stdout_artifact = payload.get("stdout_artifact")
        stderr_artifact = payload.get("stderr_artifact")
        if (
            not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or not isinstance(stdout_artifact, dict)
            or not isinstance(stdout_artifact.get("id"), str)
            or not isinstance(stdout_artifact.get("sha256"), str)
            or not isinstance(stdout_artifact.get("size_bytes"), int)
            or not isinstance(stderr_artifact, dict)
            or not isinstance(stderr_artifact.get("id"), str)
            or not isinstance(stderr_artifact.get("sha256"), str)
            or not isinstance(stderr_artifact.get("size_bytes"), int)
            or not isinstance(payload.get("timed_out"), bool)
            or not isinstance(payload.get("output_truncated"), bool)
        ):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        exit_code = payload.get("exit_code")
        if exit_code is not None and not isinstance(exit_code, int):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return SandboxObservation(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=payload["timed_out"],
            output_truncated=payload["output_truncated"],
            stdout_artifact_id=stdout_artifact["id"],
            stdout_sha256=stdout_artifact["sha256"],
            stdout_artifact_size_bytes=stdout_artifact["size_bytes"],
            stderr_artifact_id=stderr_artifact["id"],
            stderr_sha256=stderr_artifact["sha256"],
            stderr_artifact_size_bytes=stderr_artifact["size_bytes"],
        )

    async def destroy(self, workspace_id: str) -> None:
        await self._request("DELETE", f"/v1/workspaces/{workspace_id}", None, expected=200)

    async def pty_start(
        self,
        workspace_id: str,
        *,
        command: tuple[str, ...],
        timeout_seconds: int,
        working_directory: str,
        kind: str,
    ) -> SandboxObservation:
        """Create a live terminal, then read its real initial prompt/banner."""

        started = await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/pty",
            {
                "command": list(command),
                "timeout_seconds": timeout_seconds,
                "working_directory": working_directory,
            },
            expected=201,
        )
        pty_id = started.get("pty_id")
        if not isinstance(pty_id, str):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return await self.pty_send_read(
            workspace_id,
            pty_id=pty_id,
            data="",
            max_bytes=16 * 1024,
            wait_ms=1_000,
            kind=kind,
        )

    async def pty_send_read(
        self,
        workspace_id: str,
        *,
        pty_id: str,
        data: str,
        max_bytes: int,
        wait_ms: int,
        kind: str,
    ) -> SandboxObservation:
        """Keep input out of any shell and return a CAS-backed terminal observation."""

        if data:
            await self._request(
                "POST",
                f"/v1/workspaces/{workspace_id}/pty/{pty_id}/send",
                {"data": data},
                expected=200,
            )
        payload = await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/pty/{pty_id}/read",
            {"max_bytes": max_bytes, "wait_ms": wait_ms},
            expected=200,
        )
        data_value = payload.get("data")
        artifact = payload.get("observation_artifact")
        if not isinstance(data_value, str) or not isinstance(artifact, dict):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        observation = self._observation(
            stdout=data_value,
            stderr="",
            artifact=artifact,
            timed_out=False,
            output_truncated=False,
        )
        return replace(observation, interactive_id=pty_id, interactive_kind=kind)

    async def pty_send(self, workspace_id: str, *, pty_id: str, data: str) -> None:
        """Write to a known PTY without conflating it with a later read."""

        await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/pty/{pty_id}/send",
            {"data": data},
            expected=200,
        )

    async def pty_close(self, workspace_id: str, *, pty_id: str) -> None:
        await self._request(
            "DELETE", f"/v1/workspaces/{workspace_id}/pty/{pty_id}", None, expected=200
        )

    async def tube_connect(
        self,
        workspace_id: str,
        *,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> SandboxObservation:
        payload = await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/tubes",
            {"host": host, "port": port, "timeout_seconds": timeout_seconds},
            expected=201,
        )
        tube_id = payload.get("tube_id")
        artifact = payload.get("observation_artifact")
        if not isinstance(tube_id, str) or not isinstance(artifact, dict):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        observation = self._observation(
            stdout=f"connected {host}:{port}\n",
            stderr="",
            artifact=artifact,
            timed_out=False,
            output_truncated=False,
        )
        return replace(observation, interactive_id=tube_id, interactive_kind="tube")

    async def tube_send(
        self,
        workspace_id: str,
        *,
        tube_id: str,
        data_base64: str,
    ) -> None:
        await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/tubes/{tube_id}/send",
            {"data_base64": data_base64},
            expected=200,
        )

    async def tube_recv_until(
        self,
        workspace_id: str,
        *,
        tube_id: str,
        delimiter_base64: str,
        max_bytes: int,
        timeout_seconds: int,
    ) -> SandboxObservation:
        payload = await self._request(
            "POST",
            f"/v1/workspaces/{workspace_id}/tubes/{tube_id}/recv-until",
            {
                "delimiter_base64": delimiter_base64,
                "max_bytes": max_bytes,
                "timeout_seconds": timeout_seconds,
            },
            expected=200,
        )
        data_value = payload.get("data")
        artifact = payload.get("observation_artifact")
        if not isinstance(data_value, str) or not isinstance(artifact, dict):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return self._observation(
            stdout=data_value,
            stderr="",
            artifact=artifact,
            timed_out=payload.get("timed_out") is True,
            output_truncated=payload.get("output_truncated") is True,
            interactive_id=tube_id,
            interactive_kind="tube",
        )

    async def tube_close(self, workspace_id: str, *, tube_id: str) -> None:
        await self._request(
            "DELETE", f"/v1/workspaces/{workspace_id}/tubes/{tube_id}", None, expected=200
        )

    @staticmethod
    def _observation(
        *,
        stdout: str,
        stderr: str,
        artifact: object,
        timed_out: bool,
        output_truncated: bool,
        interactive_id: str | None = None,
        interactive_kind: str | None = None,
    ) -> SandboxObservation:
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("id"), str)
            or not isinstance(artifact.get("sha256"), str)
            or not isinstance(artifact.get("size_bytes"), int)
        ):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return SandboxObservation(
            stdout=stdout,
            stderr=stderr,
            exit_code=None,
            timed_out=timed_out,
            output_truncated=output_truncated,
            stdout_artifact_id=artifact["id"],
            stdout_sha256=artifact["sha256"],
            stdout_artifact_size_bytes=artifact["size_bytes"],
            interactive_id=interactive_id,
            interactive_kind=interactive_kind,
        )

    async def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        *,
        expected: int,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(125.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.request(
                    method,
                    path,
                    headers={"X-CTFMesh-Sandboxd-Token": self._token},
                    json=body,
                )
        except httpx.HTTPError as exc:
            raise SandboxdClientError("sandboxd_unavailable") from exc
        if response.status_code != expected:
            # sandboxd publishes only reviewed, implementation-free codes.
            # Preserve an allowlisted one so the operator can recover from a
            # local runtime setup issue without exposing a Docker diagnostic,
            # source path, target response, or credential.
            safe_code = _safe_sandboxd_error_code(response)
            if safe_code is not None:
                raise SandboxdClientError(f"sandboxd_{safe_code}")
            raise SandboxdClientError("sandboxd_request_rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SandboxdClientError("sandboxd_protocol_invalid") from exc
        if not isinstance(payload, dict):
            raise SandboxdClientError("sandboxd_protocol_invalid")
        return payload


def _safe_sandboxd_error_code(response: httpx.Response) -> str | None:
    """Return only a reviewed service code from an otherwise opaque response."""

    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    if not isinstance(detail, dict):
        return None
    code = detail.get("code")
    return code if isinstance(code, str) and code in _PUBLIC_SANDBOXD_ERROR_CODES else None


__all__ = ["HttpSandboxdClient", "SandboxdClientError"]
