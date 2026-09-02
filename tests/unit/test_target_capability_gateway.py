"""Gateway-to-slot capability binding tests for the M6.a remote lane."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from ctfmesh_db import Repository
from ctfmesh_domain import AgentRole, ChallengeManifest, ContextManifest, ToolExecutionAuthority
from ctfmesh_tool_runtime.contracts import (
    GatewayToolCall,
    HttpRequestCall,
    HttpRequestCallInput,
    SourceSlotInvocation,
    SourceSlotResponse,
)
from ctfmesh_tool_runtime.dispatch import ToolGateway
from ctfmesh_tool_runtime.slots import SourceSlotClient
from ctfmesh_tool_runtime.target_capability import TargetCapabilitySigner, request_digest

_KEY = "gateway-capability-test-key-material-00001"


def _authority() -> ToolExecutionAuthority:
    """Create a fresh archive-backed, exact-origin HTTP authority."""

    now = datetime.now(UTC)
    manifest = ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "gateway-capability", "category": "web"},
            "spec": {
                "mode": "assisted",
                "target": {
                    "type": "remote",
                    "healthcheck": {
                        "url": "https://challenge.example/health",
                        "expected_status": 200,
                    },
                    "allowed_endpoints": [
                        {"host": "challenge.example", "ports": [443], "protocols": ["https"]}
                    ],
                    "target_aliases": {"target": "https://challenge.example"},
                },
                "artifacts": [{"path": "src/app.py", "role": "source"}],
                "source": {"intake_id": "intake_" + "b" * 32, "slot_id": "source-slot-1"},
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
                    "wall_time_seconds": 300,
                    "max_worker_turns": 4,
                    "max_tool_calls": 8,
                    "max_http_requests": 4,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1.0,
                    "max_artifact_bytes": 1_000_000,
                },
                "providers": {"preferred": "openai", "fallbacks": []},
                "memory": {
                    "namespace": "gateway-capability",
                    "cutoff": "2026-08-31T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": ["http.request"],
            },
        }
    )
    context = ContextManifest.issue(
        id="ctx-gateway-capability",
        run_id="run-gateway-capability",
        task_id="task-gateway-capability",
        challenge_digest="a" * 64,
        role="http_tester",
        objective="Observe the one declared target alias.",
        allowed_tool_ids=("http.request", "finding.submit"),
        budget_slice={"tool_calls": 1, "input_tokens": 100, "output_tokens": 100},
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    return ToolExecutionAuthority(
        run_id="run-gateway-capability",
        challenge_id="challenge-gateway-capability",
        agent_job_id="job-gateway-capability",
        session_id="session-gateway-capability",
        task_id="task-gateway-capability",
        branch_id="branch-gateway-capability",
        role=AgentRole.HTTP_TESTER,
        context_manifest=context,
        challenge_manifest=manifest,
        lease_expires_at=now + timedelta(seconds=30),
    )


@dataclass
class _CapturingDynamicSlot:
    """Slot double that exposes the opaque capability only to this test."""

    slot_id: str = "source-slot-1"
    challenge_id: str | None = None
    dynamic_assignment: bool = True
    invocations: list[SourceSlotInvocation] = field(default_factory=list)

    def supports(self, call: GatewayToolCall) -> bool:
        return call.tool_name == "http.request"

    def workspace_root(self) -> Path:
        return Path("/slot/challenge")

    async def invoke(self, invocation: SourceSlotInvocation) -> SourceSlotResponse:
        self.invocations.append(invocation)
        body = "{}"
        return SourceSlotResponse(
            invocation_id=invocation.invocation_id,
            tool_name="http.request",
            output={
                "target_alias": "target",
                "method": "POST",
                "path": "/api/score",
                "status": 200,
                "headers": {},
                "body_text": body,
                "body_text_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "body_text_size_bytes": len(body),
                "content_type": "application/json",
                "elapsed_ms": 1,
                "cookie_count": 0,
                "truncated": False,
            },
        )


class _CompletingRepository:
    """Only the completion projection used after a successful slot call."""

    async def complete_tool_invocation(
        self, invocation_id: str, **values: object
    ) -> SimpleNamespace:
        summary = values.get("result_summary")
        assert isinstance(summary, str)
        return SimpleNamespace(id=invocation_id, result_summary=summary)


@pytest.mark.asyncio
async def test_gateway_binds_dynamic_http_to_an_exact_one_use_capability(tmp_path: Path) -> None:
    """The gateway, rather than a source slot, selects request authority."""

    signer = TargetCapabilitySigner(_KEY)
    slot = _CapturingDynamicSlot()
    gateway = ToolGateway(
        repository=cast(Repository, _CompletingRepository()),
        artifact_root=tmp_path,
        source_slots=(cast(SourceSlotClient, slot),),
        target_capability_signer=signer,
    )
    authority = _authority()
    call = HttpRequestCall(
        tool_call_id="call-gateway-capability",
        idempotency_key="call-gateway-capability",
        arguments=HttpRequestCallInput(
            target_alias="target",
            method="POST",
            path="/api/score",
            json_body={"probe": "one"},
        ),
    )

    result = await gateway._dispatch_reserved(
        authority, call, "invocation-gateway-capability", slot
    )

    assert result.accepted is True
    assert len(slot.invocations) == 1
    capability = slot.invocations[0].target_capability
    assert capability is not None
    claims = signer.verify(capability)
    assert claims.invocation_id == "invocation-gateway-capability"
    assert claims.run_id == authority.run_id
    assert claims.challenge_id == authority.challenge_id
    assert claims.method == "POST"
    assert claims.url_sha256 == request_digest("https://challenge.example/api/score")
    assert claims.body_sha256 == request_digest(b'{"probe":"one"}')
