"""Contract tests for the production-named, read-only source tool catalog."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, RunMode
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_tools import (
    SourceListTool,
    SourceManifestTool,
    SourceReadTool,
    SourceSearchTool,
    ToolDeniedError,
    ToolInvocationContext,
    ToolRegistry,
    ToolRequest,
    ToolRuntime,
)


def _manifest() -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "source-tools-lab", "category": "web"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "src/app.py", "role": "source"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:-]+\}"],
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
                "providers": {"preferred": "fixture"},
                "memory": {
                    "namespace": "source-tools",
                    "cutoff": "2026-08-29T00:00:00Z",
                    "internet_search": False,
                },
            },
        }
    )


def _context(workspace: Path) -> ToolInvocationContext:
    return ToolInvocationContext(
        run_id="run_source_tools",
        actor=ActorRef(kind=ActorKind.WORKER, id="source-auditor"),
        mode=RunMode.ASSISTED,
        manifest=_manifest(),
        allowed_tools=("source.list", "source.read", "source.search", "source.manifest"),
        budget_remaining=BudgetRemaining(tool_calls=10, http_requests=0, cost_usd=1),
        approval_state=ApprovalState.NOT_REQUESTED,
        workspace_root=str(workspace),
        capabilities=frozenset({"source.read"}),
    )


def _runtime() -> ToolRuntime:
    registry = ToolRegistry()
    registry.register(SourceListTool())
    registry.register(SourceReadTool())
    registry.register(SourceSearchTool())
    registry.register(SourceManifestTool())
    return ToolRuntime(registry, PolicyDecisionPoint())


@pytest.mark.asyncio
async def test_source_catalog_reads_only_bounded_workspace_content(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text(
        "@app.get('/health')\ndef health(): return 'ok'\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    runtime = _runtime()
    context = _context(tmp_path)
    listed = await runtime.invoke(ToolRequest(tool="source.list", arguments={}), context)
    read = await runtime.invoke(
        ToolRequest(tool="source.read", arguments={"path": "src/app.py"}), context
    )
    searched = await runtime.invoke(
        ToolRequest(tool="source.search", arguments={"query": "health"}), context
    )
    inventory = await runtime.invoke(ToolRequest(tool="source.manifest", arguments={}), context)

    assert listed.output is not None
    assert [entry["path"] for entry in listed.output["entries"]] == ["pyproject.toml", "src"]
    assert read.output is not None
    assert read.output["text"].startswith("@app.get")
    assert searched.output is not None
    assert searched.output["matches"][0]["path"] == "src/app.py"
    assert inventory.output is not None
    assert inventory.output["manifest_paths"] == ["pyproject.toml"]
    assert inventory.output["framework_hints"] == ["python-app"]
    assert inventory.output["route_path_hints"] == []
    assert len(inventory.output["inventory_sha256"]) == 64


@pytest.mark.asyncio
async def test_source_reader_enforces_32_kib_and_denies_symlink_escape(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("x" * (33 * 1024), encoding="utf-8")
    outside = tmp_path.parent / "outside-source.txt"
    outside.write_text("not visible", encoding="utf-8")
    os.symlink(outside, tmp_path / "escape.txt")

    runtime = _runtime()
    context = _context(tmp_path)
    result = await runtime.invoke(
        ToolRequest(tool="source.read", arguments={"path": "large.txt"}), context
    )
    assert result.output is not None
    assert len(result.output["text"].encode("utf-8")) == 32 * 1024
    assert result.output["truncated"] is True

    # Policy canonicalization rejects the link before the file handler reads
    # it, so a worker cannot distinguish or follow an outside-root target.
    with pytest.raises(ToolDeniedError, match="workspace_scope_denied"):
        await runtime.invoke(
            ToolRequest(tool="source.read", arguments={"path": "escape.txt"}), context
        )
