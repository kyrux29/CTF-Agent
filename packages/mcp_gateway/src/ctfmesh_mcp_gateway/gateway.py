"""A deliberately small, read-only MCP facade for CTFMesh tools.

The facade is not a second policy engine.  It translates two bounded MCP calls
to :class:`ctfmesh_tools.ToolRequest` instances and delegates every decision
and handler invocation to the supplied :class:`ctfmesh_tools.ToolRuntime`.
It intentionally exposes neither code execution nor network tools.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Mapping
from typing import Final

from ctfmesh_tools import (
    ToolDeniedError,
    ToolInputError,
    ToolInvocationContext,
    ToolOutputError,
    ToolRequest,
    ToolRuntime,
    ToolRuntimeError,
    ToolTimeoutError,
    UnknownToolError,
)
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

_SERVER_INSTRUCTIONS: Final = (
    "CTFMesh local read-only artifact gateway. It exposes only bounded workspace listing "
    "and static artifact inspection through the configured CTFMesh ToolRuntime. It has no "
    "network, code-execution, secret-management, or policy-decision capability."
)
_READ_ONLY_ANNOTATIONS: Final = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

_FLAG_TEXT = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER_TEXT = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY_TEXT = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_KEY_VALUE_TEXT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|token|secret|password)\s*[:=]\s*[^\s,;]+"
)
_FLAG_BYTES = re.compile(rb"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_BEARER_BYTES = re.compile(rb"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY_BYTES = re.compile(rb"\bsk-[A-Za-z0-9_-]{8,}\b")
_KEY_VALUE_BYTES = re.compile(
    rb"(?i)\b(api[_-]?key|authorization|token|secret|password)\s*[:=]\s*[^\s,;]+"
)


class _StrictMCPArguments(BaseModel):
    """Strict, JSON-only values accepted at the MCP boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class _FilesListArguments(_StrictMCPArguments):
    path: str = "."
    recursive: bool = False
    max_entries: int = Field(default=500, ge=1, le=10_000)


class _ArtifactsInspectArguments(_StrictMCPArguments):
    path: str
    max_file_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_header_bytes: int = Field(default=64, ge=1, le=4096)
    max_strings: int = Field(default=64, ge=1, le=512)
    max_string_bytes: int = Field(default=256, ge=4, le=4096)


class _ReadOnlyMCPGateway:
    """Translate MCP calls without inspecting policy or invoking handlers directly."""

    def __init__(self, runtime: ToolRuntime, context: ToolInvocationContext) -> None:
        self._runtime = runtime
        self._context = context
        self._calls_used = 0
        self._budget_lock = asyncio.Lock()
        self._deadline = time.monotonic() + context.manifest.spec.limits.wall_time_seconds

    async def files_list(
        self,
        *,
        path: object = ".",
        recursive: object = False,
        max_entries: object = 500,
    ) -> CallToolResult:
        return await self._dispatch(
            mcp_tool="files_list",
            runtime_tool="files.list",
            argument_model=_FilesListArguments,
            raw_arguments={
                "path": path,
                "recursive": recursive,
                "max_entries": max_entries,
            },
        )

    async def artifacts_inspect(
        self,
        *,
        path: object,
        max_file_bytes: object = 16 * 1024 * 1024,
        max_header_bytes: object = 64,
        max_strings: object = 64,
        max_string_bytes: object = 256,
    ) -> CallToolResult:
        return await self._dispatch(
            mcp_tool="artifacts_inspect",
            runtime_tool="artifacts.inspect",
            argument_model=_ArtifactsInspectArguments,
            raw_arguments={
                "path": path,
                "max_file_bytes": max_file_bytes,
                "max_header_bytes": max_header_bytes,
                "max_strings": max_strings,
                "max_string_bytes": max_string_bytes,
            },
        )

    async def _dispatch(
        self,
        *,
        mcp_tool: str,
        runtime_tool: str,
        argument_model: type[_StrictMCPArguments],
        raw_arguments: dict[str, object],
    ) -> CallToolResult:
        try:
            arguments = argument_model.model_validate(raw_arguments).model_dump(mode="json")
            request = ToolRequest(tool=runtime_tool, arguments=arguments)
        except ValidationError:
            return _failure("invalid_request")

        if self._remaining_wall_time() <= 0:
            return _failure("wall_time_exhausted")
        context = await self._reserve_context()
        if context is None:
            if self._remaining_wall_time() <= 0:
                return _failure("wall_time_exhausted")
            return _failure("tool_budget_exhausted")
        timeout_seconds = self._remaining_wall_time()
        if timeout_seconds <= 0:
            return _failure("wall_time_exhausted")

        try:
            result = await asyncio.wait_for(
                self._runtime.invoke(request, context),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            return _failure("wall_time_exhausted")
        except ToolDeniedError:
            return _failure("tool_denied")
        except ToolInputError:
            return _failure("invalid_request")
        except UnknownToolError:
            return _failure("tool_unavailable")
        except ToolTimeoutError:
            return _failure("tool_timeout")
        except (ToolOutputError, ToolRuntimeError):
            return _failure("tool_failure")
        except Exception:
            # Tool handlers and policy implementations are untrusted to this
            # transport boundary. Do not reflect their messages to MCP clients.
            return _failure("tool_failure")

        if result.output is None:
            # The gateway intentionally does not reveal internal artifact locators.
            return _failure("output_unavailable")
        return _success(mcp_tool, _redact_json(result.output))

    async def _reserve_context(self) -> ToolInvocationContext | None:
        """Reserve one bounded runtime call before a client can invoke a tool.

        ``ToolRuntime`` consumes an immutable context, so a long-lived MCP
        connection must derive a fresh shrinking budget per valid request.
        Counting a policy-denied invocation is intentional: it prevents an
        MCP client from probing scope indefinitely without consuming its
        manifest-declared tool-call budget.
        """

        async with self._budget_lock:
            if self._remaining_wall_time() <= 0:
                return None
            remaining = self._context.budget_remaining.tool_calls - self._calls_used
            if remaining < 1:
                return None
            self._calls_used += 1
            budget = self._context.budget_remaining.model_copy(update={"tool_calls": remaining})
            return self._context.model_copy(update={"budget_remaining": budget})

    def _remaining_wall_time(self) -> float:
        return self._deadline - time.monotonic()


def create_readonly_mcp_server(
    runtime: ToolRuntime,
    context: ToolInvocationContext,
    *,
    name: str = "CTFMesh Read-Only Gateway",
) -> FastMCP:
    """Create a local MCP server backed only by a supplied tool runtime.

    The caller owns runtime and context construction.  In particular, policy,
    manifest scope, workspace scope, capability checks, timeouts, and all tool
    execution remain inside ``ToolRuntime``.  This factory does not read
    environment variables or configure an HTTP transport; callers may run the
    returned FastMCP instance over a local transport they control.
    """

    gateway = _ReadOnlyMCPGateway(runtime, context)
    server = FastMCP(name=name, instructions=_SERVER_INSTRUCTIONS)

    @server.tool(
        name="files_list",
        description=(
            "List bounded entries below the run workspace through the CTFMesh read-only "
            "tool runtime. No network or code execution is available."
        ),
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def files_list(
        path: object = ".",
        recursive: object = False,
        max_entries: object = 500,
    ) -> CallToolResult:
        return await gateway.files_list(
            path=path,
            recursive=recursive,
            max_entries=max_entries,
        )

    @server.tool(
        name="artifacts_inspect",
        description=(
            "Inspect bounded static metadata and redacted strings from one workspace artifact "
            "through the CTFMesh read-only tool runtime. It never executes or unpacks files."
        ),
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def artifacts_inspect(
        path: object,
        max_file_bytes: object = 16 * 1024 * 1024,
        max_header_bytes: object = 64,
        max_strings: object = 64,
        max_string_bytes: object = 256,
    ) -> CallToolResult:
        return await gateway.artifacts_inspect(
            path=path,
            max_file_bytes=max_file_bytes,
            max_header_bytes=max_header_bytes,
            max_strings=max_strings,
            max_string_bytes=max_string_bytes,
        )

    return server


def _success(mcp_tool: str, result: object) -> CallToolResult:
    payload: dict[str, object] = {"ok": True, "tool": mcp_tool, "result": result}
    return CallToolResult(
        content=[TextContent(type="text", text=_safe_json(payload))],
        structuredContent=payload,
        isError=False,
    )


def _failure(code: str) -> CallToolResult:
    messages = {
        "invalid_request": "The request did not match the read-only tool contract.",
        "tool_denied": "The CTFMesh runtime denied this request.",
        "tool_unavailable": "The requested read-only tool is unavailable.",
        "tool_timeout": "The CTFMesh runtime timed out before a safe result was produced.",
        "tool_budget_exhausted": "The manifest-declared read-only tool-call budget is exhausted.",
        "wall_time_exhausted": "The manifest-declared MCP wall-time budget is exhausted.",
        "tool_failure": "The CTFMesh runtime could not safely return a result.",
        "output_unavailable": (
            "The runtime returned an internal artifact reference, which is unavailable here."
        ),
    }
    payload: dict[str, object] = {
        "ok": False,
        "error": {"code": code, "message": messages[code]},
    }
    return CallToolResult(
        content=[TextContent(type="text", text=_safe_json(payload))],
        structuredContent=payload,
        isError=True,
    )


def _safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _redact_json(value: object, *, key: str | None = None) -> object:
    if isinstance(value, str):
        if key is not None and key.endswith("_hex"):
            return _redact_hex(value)
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_json(item, key=str(item_key)) for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_json(item) for item in value]
    return value


def _redact_text(value: str) -> str:
    value = _FLAG_TEXT.sub("[REDACTED_FLAG]", value)
    value = _BEARER_TEXT.sub(r"\1[REDACTED]", value)
    value = _OPENAI_KEY_TEXT.sub("[REDACTED_API_KEY]", value)
    return _KEY_VALUE_TEXT.sub(r"\1=[REDACTED]", value)


def _redact_hex(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return "[REDACTED]"
    raw = _FLAG_BYTES.sub(b"[REDACTED_FLAG]", raw)
    raw = _BEARER_BYTES.sub(rb"\1[REDACTED]", raw)
    raw = _OPENAI_KEY_BYTES.sub(b"[REDACTED_API_KEY]", raw)
    raw = _KEY_VALUE_BYTES.sub(rb"\1=[REDACTED]", raw)
    return raw.hex()


__all__ = ["create_readonly_mcp_server"]
