"""Versioned contracts for typed tool invocation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, ClassVar, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ._compat import (
    ActorRef,
    ApprovalState,
    ArtifactRef,
    BudgetRemaining,
    ChallengeManifest,
    RunMode,
    ToolRisk,
)


class ToolContractModel(BaseModel):
    """Strict base for data crossing the tool boundary."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        validate_default=True,
        arbitrary_types_allowed=True,
    )


class ToolSpec(ToolContractModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    description: str = Field(min_length=1, max_length=4096)
    risk: ToolRisk
    idempotency: Literal["safe", "key_required", "not_idempotent"]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    required_capabilities: tuple[str, ...] = ()
    default_timeout_seconds: float = Field(gt=0, le=300)
    max_output_bytes: int = Field(gt=0, le=16 * 1024 * 1024)

    @field_validator("required_capabilities")
    @classmethod
    def _unique_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required_capabilities cannot contain duplicates")
        return value

    @classmethod
    def from_models(
        cls,
        *,
        name: str,
        version: str,
        description: str,
        risk: ToolRisk,
        idempotency: Literal["safe", "key_required", "not_idempotent"],
        input_model: type[BaseModel],
        output_model: type[BaseModel],
        required_capabilities: tuple[str, ...] = (),
        default_timeout_seconds: float = 10,
        max_output_bytes: int = 1024 * 1024,
    ) -> ToolSpec:
        return cls(
            name=name,
            version=version,
            description=description,
            risk=risk,
            idempotency=idempotency,
            input_schema=input_model.model_json_schema(),
            output_schema=output_model.model_json_schema(),
            required_capabilities=required_capabilities,
            default_timeout_seconds=default_timeout_seconds,
            max_output_bytes=max_output_bytes,
        )


class ToolRequest(ToolContractModel):
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    version: str = Field(default="1.0.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    arguments: dict[str, Any]
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)
    invocation_id: str | None = Field(default=None, min_length=1, max_length=160)


class ToolPolicyAudit(ToolContractModel):
    """The policy decision recorded before a tool handler is entered."""

    invocation_id: str
    tool: str
    version: str
    decision: Literal["allow", "deny"]
    reason: str


class ToolInvocationContext(ToolContractModel):
    run_id: str = Field(min_length=1, max_length=160)
    actor: ActorRef
    mode: RunMode
    manifest: ChallengeManifest
    allowed_tools: tuple[str, ...]
    budget_remaining: BudgetRemaining
    approval_state: ApprovalState = ApprovalState.NOT_REQUESTED
    workspace_root: str | None = None
    branch_id: str | None = None
    task_id: str | None = None
    capabilities: frozenset[str] = frozenset()
    policy_audit_hook: Callable[[ToolPolicyAudit], Awaitable[None] | None] | None = Field(
        default=None,
        exclude=True,
    )

    @field_validator("allowed_tools")
    @classmethod
    def _unique_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_tools cannot contain duplicates")
        return value


class ToolResult(ToolContractModel):
    invocation_id: str
    tool: str
    version: str
    output: dict[str, Any] | None = None
    output_artifact: ArtifactRef | None = None
    policy_reason: str
    elapsed_ms: int = Field(ge=0)
    cached: bool = False


class ToolHandler(Protocol):
    """Structural protocol for a runtime handler.

    Concrete handlers expose their Pydantic input/output types as class
    attributes; runtime validation narrows dynamic payloads at invocation.
    ``Any`` here avoids falsely treating a concrete input model as incompatible
    with a generic protocol's contravariant method parameter.
    """

    spec: ClassVar[ToolSpec]
    input_model: ClassVar[type[Any]]
    output_model: ClassVar[type[Any]]

    async def invoke(
        self,
        request: Any,
        context: ToolInvocationContext,
    ) -> Any: ...

    def requested_url(self, request: Any) -> str | None: ...

    def requested_path(
        self,
        request: Any,
        context: ToolInvocationContext,
    ) -> str | None: ...


class ToolRuntimeError(RuntimeError):
    """Base class for stable, non-secret tool runtime failures."""


class UnknownToolError(ToolRuntimeError):
    pass


class DuplicateToolError(ToolRuntimeError):
    pass


class ToolInputError(ToolRuntimeError):
    pass


class ToolOutputError(ToolRuntimeError):
    pass


class ToolDeniedError(ToolRuntimeError):
    pass


class ToolTimeoutError(ToolRuntimeError):
    pass


__all__ = [
    "DuplicateToolError",
    "ToolContractModel",
    "ToolDeniedError",
    "ToolHandler",
    "ToolInputError",
    "ToolInvocationContext",
    "ToolOutputError",
    "ToolPolicyAudit",
    "ToolRequest",
    "ToolResult",
    "ToolRisk",
    "ToolRuntimeError",
    "ToolSpec",
    "ToolTimeoutError",
    "UnknownToolError",
]
