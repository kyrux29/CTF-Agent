"""Policy-first typed tool registry and runtime."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
import uuid
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from ._compat import ActorKind, ActorRef, Decision, PolicyDecisionPointLike, PolicyRequest
from .artifacts import LocalArtifactStore
from .contracts import (
    DuplicateToolError,
    ToolDeniedError,
    ToolHandler,
    ToolInputError,
    ToolInvocationContext,
    ToolOutputError,
    ToolPolicyAudit,
    ToolRequest,
    ToolResult,
    ToolTimeoutError,
    UnknownToolError,
)


class ToolRegistry:
    def __init__(self) -> None:
        self._handlers: dict[tuple[str, str], ToolHandler] = {}

    def register(self, handler: ToolHandler) -> None:
        key = (handler.spec.name, handler.spec.version)
        if key in self._handlers:
            raise DuplicateToolError(f"duplicate tool registration: {key[0]}@{key[1]}")
        if handler.spec.input_schema != handler.input_model.model_json_schema():
            raise ValueError("tool input schema does not match its declared input model")
        if handler.spec.output_schema != handler.output_model.model_json_schema():
            raise ValueError("tool output schema does not match its declared output model")
        self._handlers[key] = handler

    def get(self, name: str, version: str) -> ToolHandler:
        try:
            return self._handlers[(name, version)]
        except KeyError as exc:
            raise UnknownToolError(f"unknown tool version: {name}@{version}") from exc

    def list_specs(self) -> tuple[Any, ...]:
        return tuple(
            self._handlers[key].spec
            for key in sorted(self._handlers, key=lambda item: (item[0], item[1]))
        )


class ToolRuntime:
    """The only supported execution path for registered tool handlers."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyDecisionPointLike,
        *,
        artifact_store: LocalArtifactStore | None = None,
        max_concurrency: int = 8,
        max_input_bytes: int = 1024 * 1024,
        max_json_depth: int = 20,
        max_string_bytes: int = 256 * 1024,
    ) -> None:
        if min(max_concurrency, max_input_bytes, max_json_depth, max_string_bytes) <= 0:
            raise ValueError("runtime limits must be positive")
        self._registry = registry
        self._policy = policy
        self._artifact_store = artifact_store
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_input_bytes = max_input_bytes
        self._max_json_depth = max_json_depth
        self._max_string_bytes = max_string_bytes
        self._idempotency_cache: dict[tuple[str, str, str, str], ToolResult] = {}
        self._idempotency_locks: dict[tuple[str, str, str, str], asyncio.Lock] = {}
        self._cache_guard = asyncio.Lock()

    async def invoke(
        self,
        request: ToolRequest,
        context: ToolInvocationContext,
    ) -> ToolResult:
        handler = self._registry.get(request.tool, request.version)
        if request.tool not in context.allowed_tools:
            raise ToolDeniedError("tool is not in the task allowlist")
        missing = set(handler.spec.required_capabilities) - context.capabilities
        if missing:
            raise ToolDeniedError("required tool capabilities are unavailable")
        if handler.spec.idempotency == "key_required" and request.idempotency_key is None:
            raise ToolInputError("this tool requires an idempotency key")

        self._validate_json(request.arguments)
        try:
            typed_input = handler.input_model.model_validate(request.arguments)
        except ValidationError as exc:
            raise ToolInputError("tool input failed schema validation") from exc

        cache_key: tuple[str, str, str, str] | None = None
        if request.idempotency_key is not None and handler.spec.idempotency != "not_idempotent":
            cache_key = (
                context.run_id,
                request.tool,
                request.version,
                request.idempotency_key,
            )
            lock = await self._lock_for(cache_key)
            async with lock:
                cached = self._idempotency_cache.get(cache_key)
                if cached is not None:
                    return cached.model_copy(update={"cached": True})
                result = await self._invoke_once(handler, typed_input, request, context)
                self._idempotency_cache[cache_key] = result
                return result
        return await self._invoke_once(handler, typed_input, request, context)

    async def _invoke_once(
        self,
        handler: ToolHandler,
        typed_input: BaseModel,
        request: ToolRequest,
        context: ToolInvocationContext,
    ) -> ToolResult:
        # Most tools can report their requested URL from input alone. A fixed
        # slot may instead resolve a worker alias through the sealed manifest,
        # so it can expose an optional context-aware resolver without putting
        # a raw URL field back into the worker contract.
        requested_url = self._optional_handler_value(
            handler,
            "requested_url_with_context",
            typed_input,
            context,
        )
        if requested_url is None:
            requested_url = self._optional_handler_value(handler, "requested_url", typed_input)
        requested_path = self._optional_handler_value(
            handler,
            "requested_path",
            typed_input,
            context,
        )
        policy_request = PolicyRequest(
            run_id=context.run_id,
            mode=context.mode,
            actor=context.actor,
            tool=request.tool,
            risk=handler.spec.risk,
            allowed_tools=context.allowed_tools,
            budget_remaining=context.budget_remaining,
            approval_state=context.approval_state,
            requested_url=requested_url,
            requested_cost_usd=0,
            workspace_root=context.workspace_root,
            requested_path=requested_path,
        )
        policy_result = self._policy.decide(policy_request, context.manifest)
        if inspect.isawaitable(policy_result):
            policy_result = await policy_result
        decision = getattr(policy_result.decision, "value", policy_result.decision)
        reason = str(getattr(policy_result.reason_code, "value", policy_result.reason_code))
        invocation_id = request.invocation_id or f"tool:{uuid.uuid4()}"
        await self._record_policy_decision(
            context,
            ToolPolicyAudit(
                invocation_id=invocation_id,
                tool=request.tool,
                version=request.version,
                decision="allow" if decision == Decision.ALLOW.value else "deny",
                reason=reason,
            ),
        )
        if decision != Decision.ALLOW.value:
            raise ToolDeniedError(f"policy denied tool invocation: {reason}")

        started = time.monotonic()
        try:
            async with self._semaphore:
                raw_output = await asyncio.wait_for(
                    handler.invoke(typed_input, context),
                    timeout=handler.spec.default_timeout_seconds,
                )
        except TimeoutError as exc:
            raise ToolTimeoutError("tool invocation exceeded its timeout") from exc

        try:
            typed_output = handler.output_model.model_validate(raw_output)
        except ValidationError as exc:
            raise ToolOutputError("tool output failed schema validation") from exc
        output = typed_output.model_dump(mode="json")
        encoded = json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
        elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
        if len(encoded) <= handler.spec.max_output_bytes:
            return ToolResult(
                invocation_id=invocation_id,
                tool=request.tool,
                version=request.version,
                output=output,
                policy_reason=reason,
                elapsed_ms=elapsed_ms,
            )
        if self._artifact_store is None:
            raise ToolOutputError("tool output exceeds its byte limit")
        artifact = await self._artifact_store.put_bytes(
            encoded,
            run_id=context.run_id,
            mime_type="application/json",
            producer=ActorRef(kind=ActorKind.TOOL, id=request.tool),
            branch_id=context.branch_id,
            task_id=context.task_id,
            tool_invocation_id=invocation_id,
        )
        return ToolResult(
            invocation_id=invocation_id,
            tool=request.tool,
            version=request.version,
            output_artifact=artifact,
            policy_reason=reason,
            elapsed_ms=elapsed_ms,
        )

    @staticmethod
    async def _record_policy_decision(
        context: ToolInvocationContext,
        audit: ToolPolicyAudit,
    ) -> None:
        """Persist authorization before handler execution when a caller supplies a ledger hook."""

        hook = context.policy_audit_hook
        if hook is None:
            return
        result = hook(audit)
        if inspect.isawaitable(result):
            await result

    async def _lock_for(self, key: tuple[str, str, str, str]) -> asyncio.Lock:
        async with self._cache_guard:
            return self._idempotency_locks.setdefault(key, asyncio.Lock())

    @staticmethod
    def _optional_handler_value(
        handler: ToolHandler,
        name: str,
        *arguments: Any,
    ) -> Any:
        callback = getattr(handler, name, None)
        return callback(*arguments) if callback is not None else None

    def _validate_json(self, value: Any) -> None:
        try:
            encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ToolInputError("tool input must contain JSON values only") from exc
        if len(encoded) > self._max_input_bytes:
            raise ToolInputError("tool input exceeds its byte limit")

        def visit(item: Any, depth: int) -> None:
            if depth > self._max_json_depth:
                raise ToolInputError("tool input exceeds its nesting limit")
            if isinstance(item, str) and len(item.encode("utf-8")) > self._max_string_bytes:
                raise ToolInputError("tool input contains an oversized string")
            if isinstance(item, Mapping):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise ToolInputError("tool input object keys must be strings")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    visit(child, depth + 1)

        visit(value, 0)


__all__ = ["ToolRegistry", "ToolRuntime"]
