"""Provider-neutral worker contracts and deterministic test backend."""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _now() -> datetime:
    return datetime.now(UTC)


class WorkerTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(min_length=1, max_length=160)
    run_id: str = Field(min_length=1, max_length=160)
    branch_id: str | None = None
    role: str = Field(min_length=1, max_length=160)
    objective: str = Field(min_length=1, max_length=16_384)
    context: dict[str, Any] = Field(default_factory=dict)
    allowed_tools: tuple[str, ...] = ()
    workspace: Path
    budget: dict[str, int | float]
    expected_output_schema: dict[str, Any]

    @field_validator("allowed_tools", mode="before")
    @classmethod
    def freeze_allowed_tools(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("workspace", mode="before")
    @classmethod
    def parse_workspace(cls, value: Any) -> Any:
        return Path(value) if isinstance(value, str) else value

    @field_validator("workspace")
    @classmethod
    def workspace_must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("workspace must be absolute")
        return value

    @field_validator("budget")
    @classmethod
    def budget_must_be_finite_and_bounded(
        cls, value: dict[str, int | float]
    ) -> dict[str, int | float]:
        if not value:
            raise ValueError("budget cannot be empty")
        for name, amount in value.items():
            if not name.strip() or isinstance(amount, bool):
                raise ValueError("budget entries must be named numeric limits")
            if not math.isfinite(float(amount)) or amount < 0:
                raise ValueError("budget entries must be finite and non-negative")
        return value

    @field_validator("expected_output_schema")
    @classmethod
    def output_schema_must_describe_an_object(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("type") != "object":
            raise ValueError("expected_output_schema must describe an object")
        return value


class WorkerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    sandbox: Literal["read-only", "workspace-write"] = "workspace-write"
    approval: Literal["on-request", "never"] = "on-request"
    timeout_seconds: float = Field(default=120, gt=0, le=3600)
    max_output_bytes: int = Field(default=2_000_000, gt=0, le=10_000_000)


class WorkerCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    streaming: bool
    resume: bool
    structured_output: bool
    native_tools_disabled: bool


class WorkerHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    available: bool
    reason: str | None = None


class WorkerEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    type: Literal[
        "worker.started",
        "worker.message.delta",
        "worker.message.completed",
        "worker.plan.updated",
        "worker.tool.requested",
        "worker.command.observed",
        "worker.file.changed",
        "worker.usage.updated",
        "worker.completed",
        "worker.failed",
        "worker.cancelled",
    ]
    worker_session_id: str
    sequence: int = Field(ge=1)
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=_now)

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(UTC)


class WorkerBackend(Protocol):
    name: str

    async def capabilities(self) -> WorkerCapabilities: ...

    def start(self, task: WorkerTask, *, policy: WorkerPolicy) -> AsyncIterator[WorkerEvent]: ...

    async def cancel(self, session_id: str) -> None: ...

    async def health(self) -> WorkerHealth: ...


class FakeWorkerBackend:
    """Deterministic CI worker. It never executes a subprocess or network call."""

    name = "fake-deterministic"

    def __init__(
        self,
        scripted_payloads: Sequence[dict[str, Any]],
        *,
        fail_after: int | None = None,
    ) -> None:
        self._payloads = list(scripted_payloads)
        self._fail_after = fail_after
        self._cancelled: set[str] = set()

    async def capabilities(self) -> WorkerCapabilities:
        return WorkerCapabilities(
            streaming=True,
            resume=False,
            structured_output=True,
            native_tools_disabled=True,
        )

    async def health(self) -> WorkerHealth:
        return WorkerHealth(available=True)

    async def cancel(self, session_id: str) -> None:
        self._cancelled.add(session_id)

    async def start(self, task: WorkerTask, *, policy: WorkerPolicy) -> AsyncIterator[WorkerEvent]:
        del policy
        session_id = f"fake_{uuid4().hex}"
        yield WorkerEvent(
            type="worker.started",
            worker_session_id=session_id,
            sequence=1,
            payload={"task_id": task.id, "role": task.role},
        )
        for index, payload in enumerate(self._payloads, start=2):
            await asyncio.sleep(0)
            if session_id in self._cancelled:
                yield WorkerEvent(
                    type="worker.cancelled",
                    worker_session_id=session_id,
                    sequence=index,
                    payload={"reason": "cancelled"},
                )
                return
            if self._fail_after is not None and index - 2 >= self._fail_after:
                yield WorkerEvent(
                    type="worker.failed",
                    worker_session_id=session_id,
                    sequence=index,
                    payload={"error": "scripted_failure"},
                )
                return
            yield WorkerEvent(
                type="worker.message.completed",
                worker_session_id=session_id,
                sequence=index,
                payload=payload,
            )
        yield WorkerEvent(
            type="worker.completed",
            worker_session_id=session_id,
            sequence=len(self._payloads) + 2,
            payload={"task_id": task.id},
        )


_SECRET_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "api_key",
    "raw_flag",
)
_SENSITIVE_TEXT = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}"),
)


def _redact_string(value: str) -> str:
    for pattern in _SENSITIVE_TEXT:
        value = pattern.sub("[REDACTED]", value)
    return value


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(marker in key.lower() for marker in _SECRET_MARKERS)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value
