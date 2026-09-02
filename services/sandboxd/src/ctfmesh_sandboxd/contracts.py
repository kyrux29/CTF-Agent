"""Strict, versioned contracts for the private Power workspace RPC."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_WORKSPACE_ID_PATTERN = r"^ws_[0-9a-f]{32}$"
_PTY_ID_PATTERN = r"^pty_[0-9a-f]{32}$"
_TUBE_ID_PATTERN = r"^tube_[0-9a-f]{32}$"
_WORKING_DIRECTORIES = frozenset({"/challenge", "/work"})
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class WorkspaceContract(BaseModel):
    """Reject coercion and unexpected fields at the process boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)


def _json_array_to_tuple(value: object) -> object:
    """Convert only JSON arrays to tuples while keeping strict item validation."""

    return tuple(value) if isinstance(value, list) else value


class WorkspaceCreateRequest(WorkspaceContract):
    """Create one disposable workspace from a previously validated intake."""

    run_id: str = Field(pattern=_RUN_ID_PATTERN, min_length=1, max_length=160)
    archive_digest: str = Field(pattern=_SHA256_PATTERN, min_length=64, max_length=64)
    tube_targets: tuple[TubeTarget, ...] = ()

    _tube_targets_json = field_validator("tube_targets", mode="before")(_json_array_to_tuple)

    @field_validator("tube_targets")
    @classmethod
    def distinct_tube_targets(cls, value: tuple[TubeTarget, ...]) -> tuple[TubeTarget, ...]:
        if len(value) > 16:
            raise ValueError("tube_targets may contain at most 16 endpoints")
        if len({(target.host, target.port) for target in value}) != len(value):
            raise ValueError("tube_targets must not contain duplicate endpoints")
        return value


class WorkspaceState(StrEnum):
    ACTIVE = "active"
    DESTROYED = "destroyed"


class WorkspaceReceipt(WorkspaceContract):
    """Non-sensitive workspace identity returned only on the control bridge."""

    workspace_id: str = Field(pattern=_WORKSPACE_ID_PATTERN, min_length=35, max_length=35)
    run_id: str = Field(pattern=_RUN_ID_PATTERN, min_length=1, max_length=160)
    archive_digest: str = Field(pattern=_SHA256_PATTERN, min_length=64, max_length=64)
    state: WorkspaceState = WorkspaceState.ACTIVE


def _validate_argv(value: tuple[str, ...]) -> tuple[str, ...]:
    if not value or len(value) > 128:
        raise ValueError("command must contain 1..128 argv elements")
    if any(not item or "\x00" in item or len(item) > 4096 for item in value):
        raise ValueError("command argv elements must be non-empty, bounded, and NUL-free")
    return value


def _validate_working_directory(value: str) -> str:
    if value not in _WORKING_DIRECTORIES:
        raise ValueError("working_directory must be exactly /challenge or /work")
    return value


def _validate_host(value: str) -> str:
    """Accept one canonical IP or DNS name, never a URL or wildcard."""

    normalized = value.lower().rstrip(".")
    if not normalized or "/" in normalized or "://" in normalized or "*" in normalized:
        raise ValueError("host must be an exact IP address or DNS name")
    try:
        ipaddress.ip_address(normalized)
    except ValueError as exc:
        if not _HOSTNAME_PATTERN.fullmatch(normalized):
            raise ValueError("host must be an exact IP address or DNS name") from exc
    return normalized


class TubeTarget(WorkspaceContract):
    """One exact TCP endpoint declared by the trusted run-scoping layer."""

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)

    _host = field_validator("host")(_validate_host)


class WorkspaceExecRequest(WorkspaceContract):
    """One argv-only command; no environment, mount, network or shell host input."""

    command: tuple[str, ...]
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    working_directory: str = "/work"

    _command_json = field_validator("command", mode="before")(_json_array_to_tuple)
    _command = field_validator("command")(_validate_argv)
    _working_directory = field_validator("working_directory")(_validate_working_directory)


class ArtifactReceipt(WorkspaceContract):
    """A small pointer to an immutable observation in the local artifact CAS."""

    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)
    sha256: str = Field(pattern=_SHA256_PATTERN, min_length=64, max_length=64)
    size_bytes: int = Field(ge=0, le=64 * 1024)


class WorkspaceExecReceipt(WorkspaceContract):
    """Bounded decoded output plus immutable raw byte references."""

    workspace_id: str = Field(pattern=_WORKSPACE_ID_PATTERN, min_length=35, max_length=35)
    exit_code: int | None
    timed_out: bool
    output_truncated: bool
    stdout: str = Field(max_length=64 * 1024)
    stderr: str = Field(max_length=64 * 1024)
    stdout_artifact: ArtifactReceipt
    stderr_artifact: ArtifactReceipt


class WorkspacePtyStartRequest(WorkspaceContract):
    """Start one bounded interactive command in an existing workspace."""

    command: tuple[str, ...]
    timeout_seconds: int = Field(default=120, ge=1, le=120)
    working_directory: str = "/work"

    _command_json = field_validator("command", mode="before")(_json_array_to_tuple)
    _command = field_validator("command")(_validate_argv)
    _working_directory = field_validator("working_directory")(_validate_working_directory)


class PtyReceipt(WorkspaceContract):
    pty_id: str = Field(pattern=_PTY_ID_PATTERN, min_length=36, max_length=36)
    workspace_id: str = Field(pattern=_WORKSPACE_ID_PATTERN, min_length=35, max_length=35)
    state: Literal["open", "closed"]


class PtySendRequest(WorkspaceContract):
    data: str = Field(min_length=1, max_length=64 * 1024)


class PtyReadRequest(WorkspaceContract):
    max_bytes: int = Field(default=16 * 1024, ge=1, le=64 * 1024)
    wait_ms: int = Field(default=250, ge=1, le=2_000)


class PtyReadReceipt(WorkspaceContract):
    pty_id: str = Field(pattern=_PTY_ID_PATTERN, min_length=36, max_length=36)
    data: str = Field(max_length=64 * 1024)
    closed: bool
    observation_artifact: ArtifactReceipt


class TubeReceipt(WorkspaceContract):
    """A live scoped TCP session owned by exactly one workspace."""

    tube_id: str = Field(pattern=_TUBE_ID_PATTERN, min_length=37, max_length=37)
    workspace_id: str = Field(pattern=_WORKSPACE_ID_PATTERN, min_length=35, max_length=35)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    state: Literal["open", "closed"]
    observation_artifact: ArtifactReceipt | None = None


class TubeConnectRequest(TubeTarget):
    """Request a connection; service policy compares it to the run allowlist."""

    timeout_seconds: int = Field(default=10, ge=1, le=30)


def _validate_base64(value: str) -> str:
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("value must be valid base64") from exc
    return value


class TubeSendRequest(WorkspaceContract):
    """Binary-safe TCP payload. It is never persisted as an event payload."""

    data_base64: str = Field(min_length=1, max_length=88 * 1024)

    _data_base64 = field_validator("data_base64")(_validate_base64)


class TubeRecvUntilRequest(WorkspaceContract):
    """Read bounded bytes until a binary delimiter, close, or timeout."""

    delimiter_base64: str = Field(min_length=1, max_length=4 * 1024)
    max_bytes: int = Field(default=16 * 1024, ge=1, le=64 * 1024)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    _delimiter_base64 = field_validator("delimiter_base64")(_validate_base64)


class TubeRecvReceipt(WorkspaceContract):
    tube_id: str = Field(pattern=_TUBE_ID_PATTERN, min_length=37, max_length=37)
    data: str = Field(max_length=64 * 1024)
    matched_delimiter: bool
    closed: bool
    timed_out: bool
    output_truncated: bool
    observation_artifact: ArtifactReceipt


class WorkspaceDestroyReceipt(WorkspaceContract):
    workspace_id: str = Field(pattern=_WORKSPACE_ID_PATTERN, min_length=35, max_length=35)
    state: WorkspaceState = WorkspaceState.DESTROYED
    already_destroyed: bool


__all__ = [
    "ArtifactReceipt",
    "PtyReadReceipt",
    "PtyReadRequest",
    "PtyReceipt",
    "PtySendRequest",
    "TubeConnectRequest",
    "TubeReceipt",
    "TubeRecvReceipt",
    "TubeRecvUntilRequest",
    "TubeSendRequest",
    "TubeTarget",
    "WorkspaceCreateRequest",
    "WorkspaceDestroyReceipt",
    "WorkspaceExecReceipt",
    "WorkspaceExecRequest",
    "WorkspacePtyStartRequest",
    "WorkspaceReceipt",
    "WorkspaceState",
]
