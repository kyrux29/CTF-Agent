from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, RunMode
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_tools import (
    ArtifactInspectTool,
    ToolDeniedError,
    ToolInvocationContext,
    ToolRegistry,
    ToolRequest,
    ToolRuntime,
    WorkspaceFileError,
    WorkspacePathError,
)


def _manifest() -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "artifact-inspect-lab", "category": "web"},
            "spec": {
                "mode": "assisted",
                "target": {
                    "type": "docker_compose",
                    "compose_file": "docker-compose.yml",
                    "service": "lab",
                    "healthcheck": {"url": "http://lab:8080/health", "expected_status": 200},
                    "allowed_endpoints": [{"host": "lab", "ports": [8080], "protocols": ["http"]}],
                },
                "artifacts": [{"path": "input.bin", "role": "attachment"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:\-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": False,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": 60,
                    "max_worker_turns": 4,
                    "max_tool_calls": 10,
                    "max_http_requests": 1,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1,
                    "max_artifact_bytes": 1024 * 1024,
                },
                "providers": {"preferred": "fake-deterministic"},
                "memory": {
                    "namespace": "artifact-inspect",
                    "cutoff": "2026-07-26T00:00:00Z",
                    "internet_search": False,
                },
            },
        }
    )


def _context(
    workspace: Path,
    *,
    capabilities: frozenset[str] = frozenset({"artifact.inspection"}),
) -> ToolInvocationContext:
    return ToolInvocationContext(
        run_id="run_artifact_inspect",
        actor=ActorRef(kind=ActorKind.WORKER, id="triage-worker"),
        mode=RunMode.ASSISTED,
        manifest=_manifest(),
        allowed_tools=("artifacts.inspect",),
        budget_remaining=BudgetRemaining(tool_calls=10, http_requests=1, cost_usd=1),
        approval_state=ApprovalState.NOT_REQUESTED,
        workspace_root=str(workspace),
        capabilities=capabilities,
    )


@pytest.mark.asyncio
async def test_artifact_inspect_fingerprints_binary_and_redacts_raw_flag(tmp_path: Path) -> None:
    payload = (
        b"\x7fELF"
        + bytes(range(32))
        + b" useful-string CTF{must_not_escape} Bearer secret-value "
        + b"sk-private-123456789 Cookie:session-value tail"
    )
    (tmp_path / "sample.bin").write_bytes(payload)
    registry = ToolRegistry()
    registry.register(ArtifactInspectTool())
    runtime = ToolRuntime(registry, PolicyDecisionPoint())

    result = await runtime.invoke(
        ToolRequest(tool="artifacts.inspect", arguments={"path": "sample.bin"}),
        _context(tmp_path),
    )

    assert result.output is not None
    assert result.output["media_hint"] == "application/x-elf"
    assert result.output["classification"] == "binary"
    assert result.output["sha256"]
    assert "CTF{must_not_escape}" not in str(result.output)
    assert "secret-value" not in str(result.output)
    assert "sk-private-123456789" not in str(result.output)
    assert "session-value" not in str(result.output)
    assert b"CTF{".hex() not in result.output["header_hex"]
    assert "[REDACTED_FLAG]" in str(result.output)


@pytest.mark.asyncio
async def test_artifact_inspect_rejects_symlink_and_missing_capability(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"data")
    link = tmp_path / "link.bin"
    os.symlink(target, link)
    tool = ArtifactInspectTool()

    with pytest.raises(WorkspacePathError, match="symlink"):
        await tool.invoke(
            tool.input_model.model_validate({"path": "link.bin"}),
            _context(tmp_path),
        )

    registry = ToolRegistry()
    registry.register(tool)
    runtime = ToolRuntime(registry, PolicyDecisionPoint())
    with pytest.raises(ToolDeniedError, match="required tool capabilities"):
        await runtime.invoke(
            ToolRequest(tool="artifacts.inspect", arguments={"path": "target.bin"}),
            _context(tmp_path, capabilities=frozenset()),
        )


@pytest.mark.asyncio
async def test_artifact_inspect_rejects_oversized_input_before_reading(tmp_path: Path) -> None:
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * 65)
    tool = ArtifactInspectTool()

    with pytest.raises(WorkspaceFileError, match="configured byte limit"):
        await tool.invoke(
            tool.input_model.model_validate({"path": "large.bin", "max_file_bytes": 64}),
            _context(tmp_path),
        )


@pytest.mark.asyncio
async def test_runtime_records_policy_before_entering_the_tool_handler(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("offline artifact", encoding="utf-8")
    call_order: list[str] = []

    class ObservedArtifactInspectTool(ArtifactInspectTool):
        async def invoke(self, request: Any, context: ToolInvocationContext) -> Any:
            call_order.append("handler")
            return await super().invoke(request, context)

    async def record_policy(_: object) -> None:
        call_order.append("policy")

    registry = ToolRegistry()
    registry.register(ObservedArtifactInspectTool())
    runtime = ToolRuntime(registry, PolicyDecisionPoint())
    context = _context(tmp_path).model_copy(update={"policy_audit_hook": record_policy})

    await runtime.invoke(
        ToolRequest(tool="artifacts.inspect", arguments={"path": "sample.txt"}),
        context,
    )

    assert call_order == ["policy", "handler"]
