"""Versioned sandbox contracts without an insecure host-execution fallback."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class SandboxContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        validate_default=True,
    )


def _absolute_container_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("container path must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("container path must be absolute and normalized")
    return str(path)


def _normalize_host(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or any(character in candidate for character in "*?/@#"):
        raise ValueError("network endpoint must use one exact host")
    try:
        return ipaddress.ip_address(candidate.strip("[]")).compressed
    except ValueError:
        labels = candidate.split(".")
        if len(candidate) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("network endpoint host is invalid") from None
        return candidate


class SandboxImageRef(SandboxContractModel):
    reference: str = Field(min_length=1, max_length=512)

    @field_validator("reference")
    @classmethod
    def _digest_pinned(cls, value: str) -> str:
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", value):
            raise ValueError("sandbox images must be pinned by a SHA-256 digest")
        return value


class WorkspaceMount(SandboxContractModel):
    source_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
    mount_path: str
    read_only: bool = True

    _mount_path = field_validator("mount_path")(_absolute_container_path)


class NetworkEndpoint(SandboxContractModel):
    host: str
    ports: tuple[int, ...] = Field(min_length=1)

    _host = field_validator("host")(_normalize_host)

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(port, bool) or not 1 <= port <= 65_535 for port in value):
            raise ValueError("network ports must be in 1..65535")
        if len(value) != len(set(value)):
            raise ValueError("network endpoint ports cannot contain duplicates")
        return value


class NetworkPolicy(SandboxContractModel):
    mode: Literal["none", "allowlist"] = "none"
    endpoints: tuple[NetworkEndpoint, ...] = ()

    @model_validator(mode="after")
    def _mode_matches_endpoints(self) -> NetworkPolicy:
        if self.mode == "none" and self.endpoints:
            raise ValueError("network mode none cannot contain endpoints")
        if self.mode == "allowlist" and not self.endpoints:
            raise ValueError("allowlist mode requires exact endpoints")
        return self


class ResourceLimits(SandboxContractModel):
    cpu_millis: int = Field(gt=0, le=64_000)
    memory_mb: int = Field(gt=0, le=262_144)
    pids: int = Field(gt=0, le=4096)
    wall_time_seconds: int = Field(gt=0, le=3600)
    output_bytes: int = Field(gt=0, le=64 * 1024 * 1024)


class SecurityProfile(SandboxContractModel):
    rootless: Literal[True] = True
    no_new_privileges: Literal[True] = True
    drop_capabilities: tuple[str, ...] = ("ALL",)
    read_only_rootfs: Literal[True] = True
    non_root_user: Literal[True] = True
    allow_privileged: Literal[False] = False
    allow_host_network: Literal[False] = False
    allow_host_pid: Literal[False] = False
    allow_host_ipc: Literal[False] = False
    allow_host_devices: Literal[False] = False
    allow_container_runtime_socket: Literal[False] = False
    runtime_class: str | None = Field(default=None, max_length=128)

    @field_validator("drop_capabilities")
    @classmethod
    def _all_capabilities_dropped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != ("ALL",):
            raise ValueError("the security profile must drop ALL capabilities")
        return value


class SandboxSpec(SandboxContractModel):
    schema_version: Literal[1] = 1
    image: SandboxImageRef
    command: tuple[str, ...] = Field(min_length=1, max_length=128)
    workspace: WorkspaceMount
    writable_paths: tuple[str, ...] = ("/workspace/out", "/tmp")  # noqa: S108
    network: NetworkPolicy
    resources: ResourceLimits
    security: SecurityProfile = Field(default_factory=SecurityProfile)

    @field_validator("command")
    @classmethod
    def _command_elements(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not element or "\x00" in element for element in value):
            raise ValueError("command elements cannot be empty or contain NUL")
        return value

    @field_validator("writable_paths")
    @classmethod
    def _writable_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_absolute_container_path(path) for path in value)
        if len(normalized) != len(set(normalized)):
            raise ValueError("writable_paths cannot contain duplicates")
        allowed = {"/workspace/out", "/tmp"}  # noqa: S108
        if not set(normalized).issubset(allowed):
            raise ValueError("writable paths are limited to /workspace/out and /tmp")
        return normalized


class SandboxHandle(SandboxContractModel):
    id: str = Field(pattern=r"^sandbox:[A-Za-z0-9_.:-]+$")
    run_id: str = Field(min_length=1, max_length=160)


class SandboxExecRequest(SandboxContractModel):
    command: tuple[str, ...] = Field(min_length=1, max_length=128)
    timeout_seconds: int = Field(gt=0, le=3600)


class SandboxEventKind(StrEnum):
    CREATED = "created"
    STARTED = "started"
    STDOUT = "stdout"
    STDERR = "stderr"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    DESTROYED = "destroyed"


class SandboxEvent(SandboxContractModel):
    handle_id: str
    sequence: int = Field(ge=1)
    kind: SandboxEventKind
    data: str | None = Field(default=None, max_length=64 * 1024)


class SandboxResult(SandboxContractModel):
    handle_id: str
    exit_code: int | None
    stdout: str = Field(max_length=64 * 1024 * 1024)
    stderr: str = Field(max_length=64 * 1024 * 1024)
    timed_out: bool = False
    output_truncated: bool = False


class SandboxHealth(SandboxContractModel):
    healthy: bool
    detail: str = Field(min_length=1, max_length=4096)


class SandboxCapabilityReport(SandboxContractModel):
    available: bool
    secure_for_untrusted_code: bool
    runtime: str | None = None
    capabilities: tuple[str, ...] = ()
    missing_requirements: tuple[str, ...] = ()
    degraded: bool = False
    detail: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def _fail_closed_claims(self) -> SandboxCapabilityReport:
        if self.secure_for_untrusted_code and (not self.available or self.degraded):
            raise ValueError("an unavailable/degraded runtime cannot be marked secure")
        if not self.available and not self.missing_requirements:
            raise ValueError("an unavailable runtime must state missing requirements")
        return self


class SandboxRunner(Protocol):
    async def capability_report(self) -> SandboxCapabilityReport: ...

    async def create(self, spec: SandboxSpec, *, run_id: str) -> SandboxHandle: ...

    async def start(self, handle: SandboxHandle) -> None: ...

    async def exec(
        self,
        handle: SandboxHandle,
        request: SandboxExecRequest,
    ) -> SandboxResult: ...

    def stream(self, handle: SandboxHandle) -> AsyncIterator[SandboxEvent]: ...

    async def cancel(self, handle: SandboxHandle) -> None: ...

    async def destroy(self, handle: SandboxHandle) -> None: ...

    async def health(self) -> SandboxHealth: ...


__all__ = [
    "NetworkEndpoint",
    "NetworkPolicy",
    "ResourceLimits",
    "SandboxCapabilityReport",
    "SandboxContractModel",
    "SandboxEvent",
    "SandboxEventKind",
    "SandboxExecRequest",
    "SandboxHandle",
    "SandboxHealth",
    "SandboxImageRef",
    "SandboxResult",
    "SandboxRunner",
    "SandboxSpec",
    "SecurityProfile",
    "WorkspaceMount",
]
