"""Contract tests for the M3 fixed-service HTTP adapters."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from ctfmesh_domain import (
    AgentRole,
    ChallengeManifest,
    ContextManifest,
    ToolExecutionAuthority,
)
from ctfmesh_tool_runtime.contracts import (
    GatewayToolRequest,
    HttpRequestCall,
    HttpRequestCallInput,
    SourceManifestCall,
    SourceSlotInvocation,
)
from ctfmesh_tool_runtime.remote import (
    HttpSourceSlotClient,
    HttpToolGatewayClient,
    ToolGatewayTransportError,
)
from ctfmesh_tool_runtime.settings import SourceSlotSettings
from ctfmesh_tool_runtime.slot_app import create_source_slot_app
from ctfmesh_tool_runtime.slots import SourceSlotError
from ctfmesh_tools import SourceManifestInput
from pydantic import SecretStr


def _manifest() -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "gateway-remote-contract", "category": "web"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "bundle/source.zip", "role": "source"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": True,
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
                "providers": {"preferred": "fixture", "fallbacks": []},
                "memory": {
                    "namespace": "gateway-remote-contract",
                    "cutoff": "2026-08-29T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": [
                    "source.list",
                    "source.search",
                    "source.read",
                    "source.manifest",
                    "artifacts.inspect",
                    "transform.apply",
                ],
            },
        }
    )


def _authority(*, challenge_id: str = "challenge-slot-1") -> ToolExecutionAuthority:
    created_at = datetime(2026, 8, 29, tzinfo=UTC)
    context = ContextManifest.issue(
        id="ctx-source-slot-1",
        run_id="run-source-slot-1",
        task_id="task-source-slot-1",
        challenge_digest="a" * 64,
        role="source_auditor",
        objective="Read only a sealed source mount.",
        allowed_tool_ids=(
            "source.list",
            "source.search",
            "source.read",
            "source.manifest",
            "artifacts.inspect",
            "transform.apply",
            "finding.submit",
        ),
        budget_slice={"tool_calls": 2, "input_tokens": 100, "output_tokens": 100},
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=10),
    )
    return ToolExecutionAuthority(
        run_id="run-source-slot-1",
        challenge_id=challenge_id,
        agent_job_id="job-source-slot-1",
        session_id="session-source-slot-1",
        task_id="task-source-slot-1",
        branch_id="branch-source-slot-1",
        role=AgentRole.SOURCE_AUDITOR,
        context_manifest=context,
        challenge_manifest=_manifest(),
        lease_expires_at=created_at + timedelta(minutes=1),
    )


def _http_manifest() -> ChallengeManifest:
    payload = _manifest().model_dump(mode="json", by_alias=True, exclude_unset=True)
    payload["spec"]["target"] = {
        "type": "docker_compose",
        "compose_file": "lab/docker-compose.yml",
        "service": "lab-target",
        "healthcheck": {"url": "http://lab-target:8080/health", "expected_status": 200},
        "allowed_endpoints": [{"host": "lab-target", "ports": [8080], "protocols": ["http"]}],
        "target_aliases": {"lab": "http://lab-target:8080"},
    }
    payload["spec"]["tool_profile"] = ["http.request"]
    return ChallengeManifest.model_validate(payload)


def _http_authority() -> ToolExecutionAuthority:
    created_at = datetime(2026, 8, 29, tzinfo=UTC)
    context = ContextManifest.issue(
        id="ctx-http-slot-1",
        run_id="run-http-slot-1",
        task_id="task-http-slot-1",
        challenge_digest="b" * 64,
        role="http_tester",
        objective="Observe one exact target alias through the fixed slot.",
        allowed_tool_ids=("http.request", "finding.submit"),
        budget_slice={"tool_calls": 2, "input_tokens": 100, "output_tokens": 100},
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=10),
    )
    return ToolExecutionAuthority(
        run_id="run-http-slot-1",
        challenge_id="challenge-slot-1",
        agent_job_id="job-http-slot-1",
        session_id="session-http-slot-1",
        task_id="task-http-slot-1",
        branch_id="branch-http-slot-1",
        role=AgentRole.HTTP_TESTER,
        context_manifest=context,
        challenge_manifest=_http_manifest(),
        lease_expires_at=created_at + timedelta(minutes=1),
    )


def _call() -> SourceManifestCall:
    return SourceManifestCall(
        tool_call_id="call-source-manifest",
        idempotency_key="call-source-manifest",
        arguments=SourceManifestInput(),
    )


def _http_call() -> HttpRequestCall:
    return HttpRequestCall(
        tool_call_id="call-http-slot",
        idempotency_key="call-http-slot",
        arguments=HttpRequestCallInput(target_alias="lab", path="/health"),
    )


@pytest.mark.asyncio
async def test_http_gateway_client_posts_only_the_static_internal_route() -> None:
    """The API relay cannot turn source tool input into an arbitrary URL."""

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        assert body["job_id"] == "job-source-slot-1"
        assert body["request"]["call"]["tool_name"] == "source.manifest"
        return httpx.Response(
            200,
            json={
                "schema_version": 1,
                "accepted": False,
                "tool_call_id": "call-source-manifest",
                "tool_name": "source.manifest",
                "code": "tool_authority_denied",
                "invocation_id": None,
                "cached": False,
            },
        )

    client = HttpToolGatewayClient(
        base_url="http://tool-gateway:8081",
        token="gateway-relay-token-1234",
        transport=httpx.MockTransport(handler),
    )
    response = await client.invoke(
        GatewayToolRequest(session_id="session-source-slot-1", call=_call()),
        job_id="job-source-slot-1",
        worker_id="pi-runner-1",
        lease_version=1,
    )

    assert response.accepted is False
    assert response.code == "tool_authority_denied"
    assert len(seen) == 1
    assert seen[0].url == httpx.URL("http://tool-gateway:8081/internal/tool-invocations")
    assert seen[0].headers["x-ctfmesh-tool-gateway-token"] == "gateway-relay-token-1234"


def test_http_gateway_client_rejects_external_or_path_config() -> None:
    """The deployment setting is a fixed control origin, never a proxy URL."""

    with pytest.raises(ToolGatewayTransportError, match="tool_gateway_url_invalid"):
        HttpToolGatewayClient(
            base_url="https://example.test/internal/tool-invocations",
            token="gateway-relay-token-1234",
        )


@pytest.mark.asyncio
async def test_source_slot_http_service_checks_gateway_auth_and_challenge_binding(
    tmp_path: Path,
) -> None:
    """A fixed slot reads only its configured mount for its configured challenge."""

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'safe'\n", encoding="utf-8")
    token = "source-slot-token-1234"
    app = create_source_slot_app(
        SourceSlotSettings(
            source_slot_id="source-slot-1",
            source_slot_challenge_id="challenge-slot-1",
            source_slot_root=tmp_path,
            source_slot_token=SecretStr(token),
        )
    )
    client = HttpSourceSlotClient(
        slot_id="source-slot-1",
        challenge_id="challenge-slot-1",
        base_url="http://sandbox-source-1:8082",
        token=token,
        transport=httpx.ASGITransport(app=app),
    )
    invocation = SourceSlotInvocation(
        invocation_id="tool-source-slot-1",
        authority=_authority(),
        call=_call(),
    )

    response = await client.invoke(invocation)

    assert response.tool_name == "source.manifest"
    assert response.output["manifest_paths"] == ["pyproject.toml"]
    assert response.output["file_count"] == 1
    with pytest.raises(SourceSlotError, match="source_slot_challenge_mismatch"):
        await client.invoke(
            SourceSlotInvocation(
                invocation_id="tool-source-slot-2",
                authority=_authority(challenge_id="challenge-other"),
                call=_call(),
            )
        )


@pytest.mark.asyncio
async def test_source_slot_http_rpc_materializes_only_the_manifest_alias(tmp_path: Path) -> None:
    """Gateway-to-slot RPC keeps absolute target origins out of the request body."""

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'safe'\n", encoding="utf-8")
    token = "source-slot-token-1234"
    seen: list[httpx.Request] = []

    def target_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            204,
            headers={"content-type": "text/plain"},
            stream=httpx.ByteStream(b""),
        )

    app = create_source_slot_app(
        SourceSlotSettings(
            source_slot_id="source-slot-1",
            source_slot_challenge_id="challenge-slot-1",
            source_slot_root=tmp_path,
            source_slot_token=SecretStr(token),
        ),
        http_transport=httpx.MockTransport(target_handler),
    )
    client = HttpSourceSlotClient(
        slot_id="source-slot-1",
        challenge_id="challenge-slot-1",
        base_url="http://sandbox-source-1:8082",
        token=token,
        transport=httpx.ASGITransport(app=app),
    )

    response = await client.invoke(
        SourceSlotInvocation(
            invocation_id="tool-http-slot-1",
            authority=_http_authority(),
            call=_http_call(),
        )
    )

    assert response.tool_name == "http.request"
    assert response.output["target_alias"] == "lab"
    assert response.output["status"] == 204
    assert len(seen) == 1
    assert seen[0].url == httpx.URL("http://lab-target:8080/health")
