"""Tests for M3's alias-bound HTTP wrapper inside a fixed slot."""

from __future__ import annotations

import hashlib

import httpx
import pytest
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest, RunMode
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_tool_runtime.http_slot import FixedHttpRequestTool
from ctfmesh_tools import (
    ToolDeniedError,
    ToolInputError,
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
            "metadata": {"name": "fixed-http-slot", "category": "web"},
            "spec": {
                "mode": "assisted",
                "target": {
                    "type": "docker_compose",
                    "compose_file": "lab/docker-compose.yml",
                    "service": "lab-target",
                    "healthcheck": {
                        "url": "http://lab-target:8080/health",
                        "expected_status": 200,
                    },
                    "allowed_endpoints": [
                        {"host": "lab-target", "ports": [8080], "protocols": ["http"]}
                    ],
                    "target_aliases": {"lab": "http://lab-target:8080"},
                },
                "artifacts": [{"path": "source/app.py", "role": "source"}],
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
                    "max_http_requests": 4,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1,
                    "max_artifact_bytes": 1024 * 1024,
                },
                "providers": {"preferred": "fixture"},
                "memory": {
                    "namespace": "fixed-http-slot",
                    "cutoff": "2026-08-29T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": ["http.request"],
            },
        }
    )


def _context() -> ToolInvocationContext:
    return ToolInvocationContext(
        run_id="run-fixed-http-slot",
        actor=ActorRef(kind=ActorKind.TOOL, id="source-slot-1"),
        mode=RunMode.ASSISTED,
        manifest=_manifest(),
        allowed_tools=("http.request",),
        budget_remaining=BudgetRemaining(tool_calls=1, http_requests=1, cost_usd=0),
        approval_state=ApprovalState.NOT_REQUESTED,
        branch_id="branch-fixed-http-slot",
        capabilities=frozenset({"target_http"}),
    )


@pytest.mark.asyncio
async def test_fixed_http_slot_builds_only_an_alias_bound_relative_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/plain", "set-cookie": "session=secret"},
            stream=httpx.ByteStream(b"ok"),
        )

    tool = FixedHttpRequestTool(httpx.MockTransport(handler))
    registry = ToolRegistry()
    registry.register(tool)
    runtime = ToolRuntime(registry, PolicyDecisionPoint())
    result = await runtime.invoke(
        ToolRequest(
            tool="http.request",
            idempotency_key="http-fixed-slot-1",
            arguments={
                "target_alias": "lab",
                "path": "/health",
                "query": {"z": "two words", "a": "1"},
                "headers": {"accept": "text/plain"},
            },
        ),
        _context(),
    )
    await tool.aclose()

    assert len(seen) == 1
    assert seen[0].url == httpx.URL("http://lab-target:8080/health?a=1&z=two+words")
    assert seen[0].headers["accept"] == "text/plain"
    assert result.output is not None
    assert result.output["target_alias"] == "lab"
    assert result.output["path"] == "/health"
    assert result.output["body_text"] == "ok"
    assert "final_url" not in result.output
    assert result.output["body_text_sha256"] == hashlib.sha256(b"ok").hexdigest()
    assert result.output["headers"]["set-cookie"] == "<redacted>"


@pytest.mark.asyncio
async def test_fixed_http_slot_rejects_unreviewed_alias_path_and_routing_header() -> None:
    tool = FixedHttpRequestTool(httpx.MockTransport(lambda _request: httpx.Response(200)))
    registry = ToolRegistry()
    registry.register(tool)
    runtime = ToolRuntime(registry, PolicyDecisionPoint())
    context = _context()

    with pytest.raises(ToolDeniedError, match="http_target_alias_unavailable"):
        await runtime.invoke(
            ToolRequest(
                tool="http.request",
                idempotency_key="http-fixed-slot-alias",
                arguments={"target_alias": "other", "path": "/health"},
            ),
            context,
        )
    with pytest.raises(ToolInputError, match="tool input failed schema validation"):
        await runtime.invoke(
            ToolRequest(
                tool="http.request",
                idempotency_key="http-fixed-slot-path",
                arguments={"target_alias": "lab", "path": "//evil.test/path"},
            ),
            context,
        )
    too_deep_json: object = 1
    for _ in range(13):
        too_deep_json = {"nested": too_deep_json}
    with pytest.raises(ToolInputError, match="tool input failed schema validation"):
        await runtime.invoke(
            ToolRequest(
                tool="http.request",
                idempotency_key="http-fixed-slot-header",
                arguments={
                    "target_alias": "lab",
                    "path": "/health",
                    "headers": {"host": "evil.test"},
                },
            ),
            context,
        )
    with pytest.raises(ToolInputError, match="tool input failed schema validation"):
        await runtime.invoke(
            ToolRequest(
                tool="http.request",
                idempotency_key="http-fixed-slot-url",
                arguments={
                    "target_alias": "lab",
                    "path": "/health",
                    "url": "https://outside.example.test/",
                },
            ),
            context,
        )
    with pytest.raises(ToolInputError, match="tool input failed schema validation"):
        await runtime.invoke(
            ToolRequest(
                tool="http.request",
                idempotency_key="http-fixed-slot-depth",
                arguments={
                    "target_alias": "lab",
                    "path": "/health",
                    "json_body": too_deep_json,
                },
            ),
            context,
        )
    await tool.aclose()
