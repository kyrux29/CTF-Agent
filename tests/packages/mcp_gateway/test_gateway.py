from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, RunMode
from ctfmesh_mcp_gateway import create_readonly_mcp_server
from ctfmesh_policy import (
    ApprovalState,
    BudgetRemaining,
    Decision,
    PolicyDecisionPoint,
    PolicyResult,
    ReasonCode,
)
from ctfmesh_tools import (
    ArtifactInspectTool,
    FilesListTool,
    ToolInvocationContext,
    ToolRegistry,
    ToolRuntime,
)
from mcp.shared.memory import create_connected_server_and_client_session


def _manifest(*, wall_time_seconds: int = 60) -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "mcp-readonly-lab", "category": "forensics"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "sample.bin", "role": "attachment"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:\-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": False,
                        "allow_from_target_filesystem": False,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": wall_time_seconds,
                    "max_worker_turns": 2,
                    "max_tool_calls": 4,
                    "max_http_requests": 1,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1,
                    "max_artifact_bytes": 1024 * 1024,
                },
                "providers": {"preferred": "fake-deterministic"},
                "memory": {
                    "namespace": "mcp-readonly",
                    "cutoff": "2026-07-26T00:00:00Z",
                    "internet_search": False,
                },
            },
        }
    )


def _context(
    workspace: Path,
    *,
    tool_calls: int = 4,
    wall_time_seconds: int = 60,
) -> ToolInvocationContext:
    return ToolInvocationContext(
        run_id="run_mcp_readonly",
        actor=ActorRef(kind=ActorKind.WORKER, id="mcp-client"),
        mode=RunMode.ASSISTED,
        manifest=_manifest(wall_time_seconds=wall_time_seconds),
        allowed_tools=("files.list", "artifacts.inspect"),
        budget_remaining=BudgetRemaining(tool_calls=tool_calls, http_requests=1, cost_usd=1),
        approval_state=ApprovalState.NOT_REQUESTED,
        workspace_root=str(workspace),
        capabilities=frozenset({"artifact.inspection"}),
    )


def _runtime(
    *,
    artifact_tool: ArtifactInspectTool | None = None,
    files_tool: FilesListTool | None = None,
    policy: Any | None = None,
) -> ToolRuntime:
    registry = ToolRegistry()
    registry.register(files_tool or FilesListTool())
    registry.register(artifact_tool or ArtifactInspectTool())
    return ToolRuntime(registry, policy or PolicyDecisionPoint())


@pytest.mark.asyncio
async def test_mcp_lists_and_calls_only_the_readonly_tools(tmp_path: Path) -> None:
    raw_flag = "CTF{must_not_escape_over_mcp}"
    raw_key = "sk-artifact-input-123456789"
    raw_secret = "=".join(("api_key", "artifact-key-value"))
    payload = f"{raw_flag} Bearer artifact-token {raw_key} {raw_secret}".encode("ascii")
    (tmp_path / "sample.bin").write_bytes(payload)
    server = create_readonly_mcp_server(_runtime(), _context(tmp_path))

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        listed = await session.list_tools()
        assert {tool.name for tool in listed.tools} == {"files_list", "artifacts_inspect"}

        listed_files = await session.call_tool("files_list", {"path": "."})
        assert listed_files.isError is False
        assert listed_files.structuredContent == {
            "ok": True,
            "tool": "files_list",
            "result": {
                "entries": [{"path": "sample.bin", "kind": "file", "size_bytes": len(payload)}],
                "truncated": False,
            },
        }

        inspected = await session.call_tool("artifacts_inspect", {"path": "sample.bin"})
        assert inspected.isError is False
        inspected_text = json.dumps(inspected.structuredContent)
        assert raw_flag not in inspected_text
        assert raw_key not in inspected_text
        assert "artifact-token" not in inspected_text
        assert raw_secret not in inspected_text
        assert "[REDACTED_FLAG]" in inspected_text


class _CountingArtifactInspectTool(ArtifactInspectTool):
    def __init__(self) -> None:
        self.invocations = 0

    async def invoke(self, request: Any, context: ToolInvocationContext) -> Any:
        self.invocations += 1
        return await super().invoke(request, context)


class _DenyingPolicy:
    def __init__(self) -> None:
        self.calls = 0

    def decide(self, request: object, manifest: object) -> PolicyResult:
        del request, manifest
        self.calls += 1
        return PolicyResult(
            decision=Decision.DENY,
            reason_code=ReasonCode.TOOL_NOT_ALLOWED,
        )


@pytest.mark.asyncio
async def test_denied_mcp_request_cannot_bypass_tool_runtime(tmp_path: Path) -> None:
    (tmp_path / "sample.bin").write_bytes(b"safe fixture")
    artifact_tool = _CountingArtifactInspectTool()
    policy = _DenyingPolicy()
    server = create_readonly_mcp_server(
        _runtime(artifact_tool=artifact_tool, policy=policy),
        _context(tmp_path),
    )

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        response = await session.call_tool("artifacts_inspect", {"path": "sample.bin"})

    assert response.isError is True
    assert response.structuredContent == {
        "ok": False,
        "error": {
            "code": "tool_denied",
            "message": "The CTFMesh runtime denied this request.",
        },
    }
    assert policy.calls == 1
    assert artifact_tool.invocations == 0


@pytest.mark.asyncio
async def test_mcp_connection_enforces_manifest_tool_call_budget(tmp_path: Path) -> None:
    (tmp_path / "sample.bin").write_bytes(b"safe fixture")
    artifact_tool = _CountingArtifactInspectTool()
    server = create_readonly_mcp_server(
        _runtime(artifact_tool=artifact_tool),
        _context(tmp_path, tool_calls=1),
    )

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        first = await session.call_tool("files_list", {"path": "."})
        second = await session.call_tool("artifacts_inspect", {"path": "sample.bin"})

    assert first.isError is False
    assert second.isError is True
    assert second.structuredContent == {
        "ok": False,
        "error": {
            "code": "tool_budget_exhausted",
            "message": "The manifest-declared read-only tool-call budget is exhausted.",
        },
    }
    assert artifact_tool.invocations == 0


class _SlowFilesListTool(FilesListTool):
    def __init__(self) -> None:
        self.cancelled = False

    async def invoke(self, request: Any, context: ToolInvocationContext) -> Any:
        del request, context
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("wall-time deadline did not cancel the tool")


@pytest.mark.asyncio
async def test_mcp_wall_time_budget_cancels_a_running_tool(tmp_path: Path) -> None:
    (tmp_path / "sample.bin").write_bytes(b"safe fixture")
    slow_tool = _SlowFilesListTool()
    server = create_readonly_mcp_server(
        _runtime(files_tool=slow_tool),
        _context(tmp_path, wall_time_seconds=1),
    )

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        response = await session.call_tool("files_list", {"path": "."})

    assert response.isError is True
    assert response.structuredContent == {
        "ok": False,
        "error": {
            "code": "wall_time_exhausted",
            "message": "The manifest-declared MCP wall-time budget is exhausted.",
        },
    }
    assert slow_tool.cancelled is True
