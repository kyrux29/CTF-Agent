"""Explicit fail-closed runner for hosts without an approved OCI runtime."""

from __future__ import annotations

from collections.abc import AsyncIterator

from .contracts import (
    SandboxCapabilityReport,
    SandboxEvent,
    SandboxExecRequest,
    SandboxHandle,
    SandboxHealth,
    SandboxResult,
    SandboxSpec,
)


class SandboxUnavailableError(RuntimeError):
    pass


class UnavailableSandboxRunner:
    """Never executes on the host and never reports a degraded profile as secure."""

    def __init__(self, detail: str = "no approved rootless OCI runtime is configured") -> None:
        self._detail = detail

    async def capability_report(self) -> SandboxCapabilityReport:
        return SandboxCapabilityReport(
            available=False,
            secure_for_untrusted_code=False,
            runtime=None,
            missing_requirements=("rootless_oci", "enforced_egress"),
            degraded=False,
            detail=self._detail,
        )

    async def create(self, spec: SandboxSpec, *, run_id: str) -> SandboxHandle:
        raise self._unavailable()

    async def start(self, handle: SandboxHandle) -> None:
        raise self._unavailable()

    async def exec(
        self,
        handle: SandboxHandle,
        request: SandboxExecRequest,
    ) -> SandboxResult:
        raise self._unavailable()

    async def stream(self, handle: SandboxHandle) -> AsyncIterator[SandboxEvent]:
        raise self._unavailable()
        yield  # pragma: no cover - makes this an async iterator without executing.

    async def cancel(self, handle: SandboxHandle) -> None:
        raise self._unavailable()

    async def destroy(self, handle: SandboxHandle) -> None:
        raise self._unavailable()

    async def health(self) -> SandboxHealth:
        return SandboxHealth(healthy=False, detail=self._detail)

    def _unavailable(self) -> SandboxUnavailableError:
        return SandboxUnavailableError(self._detail)


__all__ = ["SandboxUnavailableError", "UnavailableSandboxRunner"]
