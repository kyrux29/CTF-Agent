"""Small action surface for a single Power ReAct turn.

These models accept data from a model backend.  They intentionally exclude
environment variables, arbitrary workspace IDs, Docker resources, network
destinations and persistence controls; those stay at trusted service seams.
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

_WORKSPACE_PATHS = ("/challenge", "/work")


class AciContract(BaseModel):
    """Reject coercion and unknown action fields from a model response."""

    model_config = ConfigDict(extra="forbid", strict=True)


def _argv_from_json(value: object) -> object:
    """JSON has lists only; normalize just that outer representation."""

    return tuple(value) if isinstance(value, list) else value


def _validate_argv(value: tuple[str, ...]) -> tuple[str, ...]:
    if not 1 <= len(value) <= 128:
        raise ValueError("command must contain 1..128 argv elements")
    if any(not item or "\x00" in item or len(item) > 4096 for item in value):
        raise ValueError("command argv elements must be non-empty, bounded, and NUL-free")
    return value


def _workspace_path(value: str) -> str:
    """Resolve only a normalized path inside the two workspace-owned roots."""

    if (
        not value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or ".." in value.split("/")
        or len(value) > 4096
    ):
        raise ValueError("workspace path is invalid")
    if value != "/challenge" and value != "/work" and not value.startswith(_WORKSPACE_PATHS):
        raise ValueError("workspace path is outside /challenge and /work")
    return value.rstrip("/") or "/"


class ShellExecAction(AciContract):
    type: Literal["shell.exec"] = "shell.exec"
    command: tuple[str, ...]
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    working_directory: Literal["/challenge", "/work"] = "/work"

    _command_json = field_validator("command", mode="before")(_argv_from_json)
    _command = field_validator("command")(_validate_argv)


class PtyStartAction(AciContract):
    """Start a generic live REPL such as `python -q` or `sage -q`."""

    type: Literal["shell.pty_start"] = "shell.pty_start"
    command: tuple[str, ...]
    timeout_seconds: int = Field(default=120, ge=1, le=120)
    working_directory: Literal["/challenge", "/work"] = "/work"

    _command_json = field_validator("command", mode="before")(_argv_from_json)
    _command = field_validator("command")(_validate_argv)


class PtySendAction(AciContract):
    type: Literal["shell.pty_send"] = "shell.pty_send"
    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)
    data: str = Field(min_length=1, max_length=64 * 1024)


class PtyReadAction(AciContract):
    type: Literal["shell.pty_read"] = "shell.pty_read"
    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)
    max_bytes: int = Field(default=16 * 1024, ge=1, le=64 * 1024)
    wait_ms: int = Field(default=500, ge=1, le=2_000)


class PtyCloseAction(AciContract):
    type: Literal["shell.pty_close"] = "shell.pty_close"
    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)


def _challenge_path(value: str) -> str:
    normalized = _workspace_path(value)
    if normalized != "/challenge" and not normalized.startswith("/challenge/"):
        raise ValueError("gdb target must be inside /challenge")
    return normalized


class GdbStartAction(AciContract):
    """Launch GDB without user init files against one challenge-local target."""

    type: Literal["gdb.start"] = "gdb.start"
    path: str
    timeout_seconds: int = Field(default=120, ge=1, le=120)

    _path = field_validator("path")(_challenge_path)


class GdbCmdAction(AciContract):
    type: Literal["gdb.cmd"] = "gdb.cmd"
    gdb_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)
    command: str = Field(min_length=1, max_length=8 * 1024)


class GdbCloseAction(AciContract):
    type: Literal["gdb.close"] = "gdb.close"
    gdb_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)


def _tube_host(value: str) -> str:
    normalized = value.lower().rstrip(".")
    if not normalized or "/" in normalized or "://" in normalized or "*" in normalized:
        raise ValueError("tube host must be an exact host or IP")
    return normalized


def _base64(value: str) -> str:
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("value must be valid base64") from exc
    return value


class TubeConnectAction(AciContract):
    """Open a TCP connection; sandboxd enforces this exact scoped endpoint."""

    type: Literal["tube.connect"] = "tube.connect"
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    _host = field_validator("host")(_tube_host)


class TubeSendAction(AciContract):
    type: Literal["tube.send"] = "tube.send"
    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)
    data_base64: str = Field(min_length=1, max_length=88 * 1024)

    _data = field_validator("data_base64")(_base64)


class TubeRecvUntilAction(AciContract):
    type: Literal["tube.recv_until"] = "tube.recv_until"
    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)
    delimiter_base64: str = Field(min_length=1, max_length=4 * 1024)
    max_bytes: int = Field(default=16 * 1024, ge=1, le=64 * 1024)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    _delimiter = field_validator("delimiter_base64")(_base64)


class TubeCloseAction(AciContract):
    type: Literal["tube.close"] = "tube.close"
    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)


class FsListAction(AciContract):
    type: Literal["fs.ls"] = "fs.ls"
    path: str = "/challenge"

    _path = field_validator("path")(_workspace_path)


class FsReadAction(AciContract):
    type: Literal["fs.read"] = "fs.read"
    path: str
    max_bytes: int = Field(default=16 * 1024, ge=1, le=64 * 1024)

    _path = field_validator("path")(_workspace_path)


class FsWriteAction(AciContract):
    type: Literal["fs.write"] = "fs.write"
    path: str
    content: str = Field(min_length=0, max_length=64 * 1024)

    _path = field_validator("path")(_workspace_path)


class FlagSubmitAction(AciContract):
    """A candidate remains secret and must name an already observed artifact."""

    type: Literal["flag.submit"] = "flag.submit"
    candidate: SecretStr = Field(min_length=1, max_length=1024)
    observation_artifact_id: Annotated[
        str, Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)
    ]
    observation_sha256: Annotated[
        str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)
    ]


SolverAction = Annotated[
    ShellExecAction
    | PtyStartAction
    | PtySendAction
    | PtyReadAction
    | PtyCloseAction
    | GdbStartAction
    | GdbCmdAction
    | GdbCloseAction
    | TubeConnectAction
    | TubeSendAction
    | TubeRecvUntilAction
    | TubeCloseAction
    | FsListAction
    | FsReadAction
    | FsWriteAction
    | FlagSubmitAction,
    Field(discriminator="type"),
]

__all__ = [
    "AciContract",
    "FlagSubmitAction",
    "FsListAction",
    "FsReadAction",
    "FsWriteAction",
    "GdbCloseAction",
    "GdbCmdAction",
    "GdbStartAction",
    "PtyCloseAction",
    "PtyReadAction",
    "PtySendAction",
    "PtyStartAction",
    "ShellExecAction",
    "SolverAction",
    "TubeCloseAction",
    "TubeConnectAction",
    "TubeRecvUntilAction",
    "TubeSendAction",
]
