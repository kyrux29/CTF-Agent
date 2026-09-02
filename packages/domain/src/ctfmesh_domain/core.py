"""Core run and actor value objects."""

from enum import StrEnum
from typing import Any

from pydantic import field_validator

from .base import ContractModel, Identifier


class RunMode(StrEnum):
    COACH = "coach"
    ASSISTED = "assisted"
    AUTOPILOT_LAB = "autopilot_lab"
    CONTEST = "contest"


class RunStatus(StrEnum):
    CREATED = "created"
    PREPARING = "preparing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SOLVED = "solved"


class ActorKind(StrEnum):
    HUMAN = "human"
    WORKER = "worker"
    SYSTEM = "system"
    TOOL = "tool"
    VERIFIER = "verifier"


class ActorRef(ContractModel):
    kind: ActorKind
    id: Identifier

    @field_validator("kind", mode="before")
    @classmethod
    def _parse_kind(cls, value: Any) -> Any:
        return ActorKind(value) if isinstance(value, str) else value
