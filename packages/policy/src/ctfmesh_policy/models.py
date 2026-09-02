"""Typed policy request and decision contracts."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Any

from ctfmesh_domain import ActorRef, ContractModel, FrozenSequence, Identifier, RunMode
from pydantic import Field, JsonValue, StringConstraints, field_validator, model_validator

ToolName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$",
    ),
]


class ToolRisk(StrEnum):
    READ_ONLY = "read_only"
    WORKSPACE_WRITE = "workspace_write"
    TARGET_INTERACTION = "target_interaction"
    HIGH_IMPACT = "high_impact"


class ApprovalState(StrEnum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ReasonCode(StrEnum):
    MANIFEST_SCOPE_MATCH = "manifest_scope_match"
    READ_ONLY_ALLOWED = "read_only_allowed"
    WORKSPACE_ALLOWED = "workspace_allowed"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DENIED = "approval_denied"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    MODE_MISMATCH = "mode_mismatch"
    BUDGET_EXHAUSTED = "budget_exhausted"
    BUDGET_INVALID = "budget_invalid"
    SCOPE_REQUIRED = "scope_required"
    SCOPE_NOT_ALLOWED = "scope_not_allowed"
    RISK_SCOPE_MISMATCH = "risk_scope_mismatch"
    WORKSPACE_SCOPE_REQUIRED = "workspace_scope_required"
    WORKSPACE_SCOPE_DENIED = "workspace_scope_denied"


class BudgetRemaining(ContractModel):
    tool_calls: int = Field(ge=0)
    http_requests: int = Field(ge=0)
    cost_usd: float = Field(ge=0)

    @model_validator(mode="after")
    def _finite_cost(self) -> BudgetRemaining:
        if not math.isfinite(self.cost_usd):
            raise ValueError("cost_usd must be finite")
        return self


class PolicyRequest(ContractModel):
    run_id: Identifier
    mode: RunMode
    actor: ActorRef
    tool: ToolName
    risk: ToolRisk
    allowed_tools: FrozenSequence[ToolName]
    budget_remaining: BudgetRemaining
    approval_state: ApprovalState = ApprovalState.NOT_REQUESTED
    requested_url: str | None = None
    requested_cost_usd: float = Field(default=0, ge=0)
    workspace_root: str | None = None
    requested_path: str | None = None

    @field_validator("mode", mode="before")
    @classmethod
    def _parse_mode(cls, value: Any) -> Any:
        return RunMode(value) if isinstance(value, str) else value

    @field_validator("risk", mode="before")
    @classmethod
    def _parse_risk(cls, value: Any) -> Any:
        return ToolRisk(value) if isinstance(value, str) else value

    @field_validator("approval_state", mode="before")
    @classmethod
    def _parse_approval(cls, value: Any) -> Any:
        return ApprovalState(value) if isinstance(value, str) else value

    @field_validator("allowed_tools")
    @classmethod
    def _unique_allowed_tools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_tools cannot contain duplicates")
        return values

    @model_validator(mode="after")
    def _validate_requested_cost(self) -> PolicyRequest:
        if not math.isfinite(self.requested_cost_usd):
            raise ValueError("requested_cost_usd must be finite")
        if self.requested_path is not None and self.workspace_root is None:
            raise ValueError("requested_path requires workspace_root")
        return self


class PolicyResult(ContractModel):
    decision: Decision
    reason_code: ReasonCode
    constraints: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("decision", mode="before")
    @classmethod
    def _parse_decision(cls, value: Any) -> Any:
        return Decision(value) if isinstance(value, str) else value

    @field_validator("reason_code", mode="before")
    @classmethod
    def _parse_reason(cls, value: Any) -> Any:
        return ReasonCode(value) if isinstance(value, str) else value
