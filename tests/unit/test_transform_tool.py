"""Tests for M3's pure, allowlisted transform catalog."""

from __future__ import annotations

import hashlib

import pytest
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, RunMode
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_tools import (
    ToolDeniedError,
    ToolInputError,
    ToolInvocationContext,
    ToolRegistry,
    ToolRequest,
    ToolRuntime,
    TransformApplyTool,
)


def _manifest() -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "transform-tools-lab", "category": "misc"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "bundle/input.txt", "role": "attachment"}],
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
                    "namespace": "transform-tools",
                    "cutoff": "2026-08-29T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": ["transform.apply"],
            },
        }
    )


def _context(
    *,
    capabilities: frozenset[str] = frozenset({"transform.apply"}),
) -> ToolInvocationContext:
    return ToolInvocationContext(
        run_id="run_transform_tools",
        actor=ActorRef(kind=ActorKind.WORKER, id="source-auditor"),
        mode=RunMode.ASSISTED,
        manifest=_manifest(),
        allowed_tools=("transform.apply",),
        budget_remaining=BudgetRemaining(tool_calls=10, http_requests=0, cost_usd=1),
        approval_state=ApprovalState.NOT_REQUESTED,
        capabilities=capabilities,
    )


def _runtime() -> ToolRuntime:
    registry = ToolRegistry()
    registry.register(TransformApplyTool())
    return ToolRuntime(registry, PolicyDecisionPoint())


@pytest.mark.asyncio
async def test_transform_apply_is_pure_bounded_and_self_describing() -> None:
    result = await _runtime().invoke(
        ToolRequest(
            tool="transform.apply",
            arguments={"transform": "base64.decode_utf8", "input_text": "Y3RmbWVzaA=="},
        ),
        _context(),
    )

    assert result.output is not None
    assert result.output["transform"] == "base64.decode_utf8"
    assert result.output["output_text"] == "ctfmesh"
    assert result.output["output_size_bytes"] == len(b"ctfmesh")
    assert result.output["output_sha256"] == hashlib.sha256(b"ctfmesh").hexdigest()
    assert result.output["truncated"] is False


@pytest.mark.asyncio
async def test_transform_apply_denies_invalid_or_oversized_work_without_execution() -> None:
    runtime = _runtime()
    context = _context()

    with pytest.raises(ToolInputError, match="transform_input_invalid"):
        await runtime.invoke(
            ToolRequest(
                tool="transform.apply",
                arguments={"transform": "base64.decode_utf8", "input_text": "not base64!"},
            ),
            context,
        )
    with pytest.raises(ToolInputError, match="transform_output_too_large"):
        await runtime.invoke(
            ToolRequest(
                tool="transform.apply",
                arguments={
                    "transform": "base64.encode_utf8",
                    "input_text": "x" * 16,
                    "max_output_bytes": 2,
                },
            ),
            context,
        )
    with pytest.raises(ToolDeniedError, match="required tool capabilities"):
        await runtime.invoke(
            ToolRequest(
                tool="transform.apply",
                arguments={"transform": "rot13", "input_text": "safe"},
            ),
            _context(capabilities=frozenset()),
        )
