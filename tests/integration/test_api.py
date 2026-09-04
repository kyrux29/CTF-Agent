from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from asgi_lifespan import LifespanManager
from ctfmesh_api import create_app
from ctfmesh_api.app import (
    _DEFAULT_EXACT_INSTANCE_FLAG_PATTERN,
    _exact_flag_pattern,
    parse_content_length,
    run_activity_event,
)
from ctfmesh_api.archive_intake import ArchiveIntakeError
from ctfmesh_api.provider_registry import (
    ArchiveTriageProvider,
    ArchiveTriageProviderSession,
    archive_triage_provider_descriptors,
)
from ctfmesh_api.settings import Settings
from ctfmesh_orchestrator import FakeRunHarness
from ctfmesh_provider_base import (
    ProviderTriageError,
    TriageCompletion,
    TriageNextAction,
    TriageRequest,
    TriageResult,
)
from ctfmesh_tool_runtime.contracts import GatewayToolRequest, RejectedToolResult
from pydantic import SecretStr


def valid_manifest_data() -> dict[str, object]:
    return {
        "apiVersion": "ctfmesh.io/v1alpha1",
        "kind": "Challenge",
        "metadata": {
            "name": "operator-contract-case",
            "category": "web",
            "tags": ["contract-test", "source-available"],
        },
        "spec": {
            "mode": "assisted",
            "target": {
                "type": "docker_compose",
                "compose_file": "challenge/docker-compose.yml",
                "service": "app",
                "healthcheck": {
                    "url": "http://challenge:8080/health",
                    "expected_status": 200,
                },
                "allowed_endpoints": [
                    {"host": "challenge", "ports": [8080], "protocols": ["http"]}
                ],
            },
            "artifacts": [{"path": "dist/source.zip", "role": "source"}],
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
                "wall_time_seconds": 3600,
                "max_worker_turns": 120,
                "max_tool_calls": 500,
                "max_http_requests": 1500,
                "max_parallel_requests": 10,
                "max_cost_usd": 20.0,
                "max_artifact_bytes": 1_073_741_824,
            },
            "providers": {
                "preferred": "codex",
                "fallbacks": ["claude-code", "openai-responses"],
            },
            "memory": {
                "namespace": "personal-techniques",
                "cutoff": "2026-07-18T00:00:00Z",
                "internet_search": False,
            },
        },
    }


@pytest.fixture
async def client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[httpx.AsyncClient]:
    # Developer-owned .env files configure the live Compose stack. Boundary
    # tests must be hermetic and must not inherit those service capabilities.
    monkeypatch.chdir(tmp_path)
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            yield api


def test_settings_hide_database_credentials_and_reject_wildcard_cors() -> None:
    password = "database-password-must-stay-secret"
    settings = Settings(
        database_url=SecretStr(f"postgresql+asyncpg://ctfmesh:{password}@postgres:5432/ctfmesh")
    )
    assert password not in repr(settings)
    assert password not in settings.model_dump_json()
    with pytest.raises(ValueError, match="explicit non-empty allowlist"):
        Settings(cors_origins=["*"])
    with pytest.raises(ValueError, match="cannot contain credentials"):
        Settings(cors_origins=["https://user:password@example.test"])
    with pytest.raises(ValueError, match="valid port"):
        Settings(cors_origins=["https://example.test:99999"])
    assert Settings(provider_proxy_url="http://provider-proxy:3128").provider_proxy_url == (
        "http://provider-proxy:3128"
    )
    with pytest.raises(ValueError, match="reviewed internal proxy origin"):
        Settings(provider_proxy_url="http://operator-controlled-proxy.test:3128")


def test_archive_content_length_rejects_an_unbounded_decimal_header() -> None:
    assert parse_content_length("0") == 0
    with pytest.raises(ArchiveIntakeError, match="archive_upload_too_large"):
        parse_content_length("9" * 128)


async def import_challenge(client: httpx.AsyncClient) -> dict[str, object]:
    response = await client.post("/v1/challenges", json={"manifest": valid_manifest_data()})
    assert response.status_code == 201, response.text
    return response.json()


class RecordingArchiveTriageBackend:
    """Injected provider fake proving API dispatch stays one-shot and key-local."""

    name = "recording-provider"

    def __init__(self, *, fail: bool = False, failure_code: str = "transport_error") -> None:
        self.fail = fail
        self.failure_code = failure_code
        self.requests: list[TriageRequest] = []
        self.keys: list[str] = []
        self.timeouts: list[float] = []

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        self.requests.append(request)
        self.keys.append(api_key)
        self.timeouts.append(timeout_seconds)
        if self.fail:
            raise ProviderTriageError(self.failure_code, f"provider echoed {api_key}")
        return TriageCompletion(
            response_id="provider_response_test",
            result=TriageResult(
                category="forensics",
                summary="Only metadata-only static evidence was reviewed.",
                facts=(),
                hypotheses=(),
                next_actions=(
                    TriageNextAction(
                        statement="Review the local receipt before any authorized follow-up.",
                        evidence_ids=(request.evidence[0].id,),
                    ),
                ),
            ),
        )


class RecordingToolGateway:
    """In-process boundary fake used to test the API relay contract only."""

    def __init__(self) -> None:
        self.calls: list[tuple[GatewayToolRequest, str, str, int]] = []

    async def invoke(
        self,
        request: GatewayToolRequest,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> RejectedToolResult:
        self.calls.append((request, job_id, worker_id, lease_version))
        # A real gateway makes this determination from database rows. The
        # fake returns a stable denial to prove the API cannot change a tool
        # result into a direct filesystem/target response.
        return RejectedToolResult(
            tool_call_id=request.call.tool_call_id,
            tool_name=request.call.tool_name,
            code="tool_authority_denied",
        )


class RecordingPiCredentialLeases:
    """In-memory fake proving a browser key has one private destination."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.grants: list[dict[str, object]] = []

    async def grant(
        self,
        *,
        run_id: str,
        provider: str,
        model: str,
        api_key: str,
        ttl_seconds: int,
    ) -> str:
        if self.fail:
            from ctfmesh_api.app import PiCredentialLeaseError

            raise PiCredentialLeaseError("pi_credential_lease_rejected")
        self.grants.append(
            {
                "run_id": run_id,
                "provider": provider,
                "model": model,
                "api_key": api_key,
                "ttl_seconds": ttl_seconds,
            }
        )
        return "2026-08-31T12:00:00Z"


def zip_payload(entries: dict[str, bytes], *, symlink_name: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, payload in entries.items():
            archive.writestr(path, payload)
        if symlink_name is not None:
            link = zipfile.ZipInfo(symlink_name)
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"ignored")
    return buffer.getvalue()


def tar_payload(entries: dict[str, bytes], *, symlink_name: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, payload in entries.items():
            member = tarfile.TarInfo(path)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        if symlink_name is not None:
            link = tarfile.TarInfo(symlink_name)
            link.type = tarfile.SYMTYPE
            link.linkname = "outside"
            archive.addfile(link)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_health_and_readiness(client: httpx.AsyncClient) -> None:
    health = await client.get("/v1/health")
    ready = await client.get("/v1/ready")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_runtime_capabilities_fail_closed_without_exposing_configuration(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/v1/runtime/capabilities")
    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "ctfmesh.runtime-capabilities/v1",
        "archive_intake": {"status": "ready"},
        "provider_triage": {"status": "unavailable"},
        "exact_instance": {
            "status": "unavailable",
            "missing": [
                "source_slots",
                "tool_gateway",
                "credential_lease",
                "independent_verifier",
            ],
        },
        "power": {
            "status": "unavailable",
            "missing": ["power_profile", "sandboxd", "flag_router", "pi_credential_lease"],
        },
    }


@pytest.mark.asyncio
async def test_removed_demo_routes_are_not_exposed(client: httpx.AsyncClient) -> None:
    for path in ("/v1/demo/run", "/v1/demo/council", "/v1/demo/triage/openai"):
        response = await client.post(path, json={})
        assert response.status_code == 404, path


@pytest.mark.asyncio
async def test_validation_errors_do_not_echo_secret_input(client: httpx.AsyncClient) -> None:
    secret = "sk-this-must-never-be-echoed"
    response = await client.post(
        "/v1/runs",
        json={
            "challenge_id": "challenge_missing",
            "budget": {
                "wall_time_seconds": 300,
                "max_tool_calls": -1,
                "max_http_requests": 20,
                "max_cost_usd": 1,
                "api_key": secret,
            },
        },
    )
    assert response.status_code == 422
    assert secret not in response.text
    assert response.json()["detail"]["code"] == "request_validation_failed"


@pytest.mark.asyncio
async def test_internal_tool_request_relay_is_typed_and_runner_authenticated(
    tmp_path: Path,
) -> None:
    """Pi-facing API code relays a closed source call without a slot address."""

    runner_token = "m3-tool-relay-token-1234"
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"),
        artifact_root=tmp_path / "artifacts",
        internal_runner_token=SecretStr(runner_token),
    )
    gateway = RecordingToolGateway()
    app = create_app(settings, tool_gateway_factory=lambda _repository, _root: gateway)
    payload = {
        "runner_id": "pi-tool-test",
        "lease_version": 7,
        "session_id": "session-tool-test",
        "call": {
            "schema_version": 1,
            "tool_call_id": "call-source-manifest",
            "idempotency_key": "call-source-manifest",
            "tool_name": "source.manifest",
            "tool_version": "1.0.0",
            "arguments": {},
        },
    }
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            unauthorized = await api.post(
                "/internal/agent-jobs/job-tool-test/tool-requests",
                json=payload,
            )
            assert unauthorized.status_code == 401
            response = await api.post(
                "/internal/agent-jobs/job-tool-test/tool-requests",
                json=payload,
                headers={"x-ctfmesh-runner-token": runner_token},
            )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "schema_version": 1,
        "accepted": False,
        "tool_call_id": "call-source-manifest",
        "tool_name": "source.manifest",
        "code": "tool_authority_denied",
        "invocation_id": None,
        "cached": False,
    }
    assert len(gateway.calls) == 1
    request, job_id, worker_id, lease_version = gateway.calls[0]
    assert request.session_id == "session-tool-test"
    assert request.call.tool_name == "source.manifest"
    assert request.call.arguments.model_dump(mode="json") == {}
    assert (job_id, worker_id, lease_version) == ("job-tool-test", "pi-tool-test", 7)


@pytest.mark.asyncio
async def test_internal_tool_request_rejects_unknown_or_unconfigured_capabilities(
    tmp_path: Path,
) -> None:
    """No M3 route accepts an arbitrary tool name or leaks rejected input."""

    runner_token = "m3-tool-unavailable-token-1234"
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}"),
        artifact_root=tmp_path / "artifacts",
        internal_runner_token=SecretStr(runner_token),
    )
    app = create_app(settings)
    secret = "sk-tool-request-must-not-appear"
    malformed = {
        "runner_id": "pi-tool-test",
        "lease_version": 1,
        "session_id": "session-tool-test",
        "call": {
            "schema_version": 1,
            "tool_call_id": "call-unknown-tool",
            "idempotency_key": "call-unknown-tool",
            "tool_name": "http.request",
            "tool_version": "1.0.0",
            "arguments": {"url": f"https://example.test/?token={secret}"},
        },
    }
    source_request = {
        **malformed,
        "call": {
            "schema_version": 1,
            "tool_call_id": "call-source-manifest",
            "idempotency_key": "call-source-manifest",
            "tool_name": "source.manifest",
            "tool_version": "1.0.0",
            "arguments": {},
        },
    }
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            rejected = await api.post(
                "/internal/agent-jobs/job-tool-test/tool-requests",
                json=malformed,
                headers={"x-ctfmesh-runner-token": runner_token},
            )
            unavailable = await api.post(
                "/internal/agent-jobs/job-tool-test/tool-requests",
                json=source_request,
                headers={"x-ctfmesh-runner-token": runner_token},
            )

    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "request_validation_failed"
    assert secret not in rejected.text
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["code"] == "tool_gateway_unavailable"


@pytest.mark.asyncio
async def test_manifest_error_details_are_sanitized(client: httpx.AsyncClient) -> None:
    secret = "sk-invalid-manifest-secret"
    manifest = cast(dict[str, Any], valid_manifest_data())
    manifest["api_key"] = secret
    response = await client.post("/v1/challenges", json={"manifest": manifest})
    assert response.status_code == 422
    assert secret not in response.text


@pytest.mark.asyncio
async def test_artifact_bundle_manifest_can_be_validated_then_imported(
    client: httpx.AsyncClient,
) -> None:
    """Validation output remains a safe, importable canonical declaration."""

    manifest = cast(dict[str, Any], valid_manifest_data())
    manifest["metadata"] = {
        "name": "offline-artifact-bundle",
        "category": "forensics",
        "tags": ["offline"],
    }
    manifest["spec"]["target"] = {"type": "artifact_bundle"}
    manifest["spec"]["artifacts"] = [{"path": "inputs/evidence.pcapng", "role": "pcap"}]
    validated = await client.post("/v1/challenges/validate", json={"manifest": manifest})
    assert validated.status_code == 200, validated.text
    assert validated.json()["valid"] is True

    imported = await client.post(
        "/v1/challenges",
        json={"manifest": validated.json()["manifest"]},
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["manifest"]["spec"]["target"] == {"type": "artifact_bundle"}


@pytest.mark.asyncio
async def test_challenge_run_and_event_contract(client: httpx.AsyncClient) -> None:
    challenge = await import_challenge(client)
    response = await client.post(
        "/v1/runs",
        json={"challenge_id": challenge["id"], "mode": "assisted"},
    )
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "preparing"
    events = await client.get(f"/v1/runs/{run['id']}/events")
    assert events.status_code == 200
    assert [event["sequence"] for event in events.json()["items"]] == [1, 2, 3]
    assert [event["type"] for event in events.json()["items"]] == [
        "run.created",
        "run.state.changed",
        "agent.job.queued",
    ]


@pytest.mark.asyncio
async def test_m1_fake_vertical_slice_survives_api_restart(tmp_path: Path) -> None:
    """The explicit fixture proves durable state without exposing a demo route."""

    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'm1-restart.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            challenge = await import_challenge(api)
            body = {"challenge_id": challenge["id"], "mode": "assisted"}
            first_headers = {
                "Idempotency-Key": "m1-restart-safe-run",
                "X-Correlation-ID": "m1-first-request",
            }
            retry_headers = {
                "Idempotency-Key": "m1-restart-safe-run",
                "X-Correlation-ID": "m1-retry-request",
            }
            first_response = await api.post("/v1/runs", json=body, headers=first_headers)
            duplicate_response = await api.post("/v1/runs", json=body, headers=retry_headers)
            conflict_response = await api.post(
                "/v1/runs",
                json={**body, "provider": "different-provider"},
                headers=retry_headers,
            )
            assert first_response.status_code == 201, first_response.text
            assert duplicate_response.status_code == 201, duplicate_response.text
            assert conflict_response.status_code == 409, conflict_response.text
            assert conflict_response.json()["detail"]["code"] == "idempotency_conflict"
            run = first_response.json()
            assert duplicate_response.json()["id"] == run["id"]

        harness = FakeRunHarness(app.state.run_engine)
        assert await harness.drain() == ("preflight", "fake_harness", "fake_verify")
        solved = await app.state.repository.get_run(run["id"])
        assert solved is not None
        assert solved["status"] == "solved"

    restarted_app = create_app(settings)
    async with LifespanManager(restarted_app):
        transport = httpx.ASGITransport(app=restarted_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            console = await api.get(f"/v1/runs/{run['id']}/console")
            events = await api.get(f"/v1/runs/{run['id']}/events")
            verifications = await api.get(f"/v1/runs/{run['id']}/verifications")

    assert console.status_code == 200, console.text
    assert console.json()["run"]["status"] == "solved"
    assert events.status_code == 200, events.text
    assert events.json()["items"][-1]["type"] == "agent.job.completed"
    assert any(item["type"] == "verification.completed" for item in events.json()["items"])
    assert verifications.status_code == 200, verifications.text
    assert verifications.json()["items"][0]["verification_proof_ref"]


@pytest.mark.asyncio
async def test_m2_pi_runner_protocol_is_token_gated_target_free_and_safe_to_steer(
    tmp_path: Path,
) -> None:
    """Exercise the durable M2 bridge without a model, key, or target service.

    The test intentionally calls the deterministic preflight worker directly;
    production API handlers only enqueue it. Everything after that crosses the
    same token-gated HTTP boundary the isolated Pi Runner uses in Compose.
    """

    runner_token = "m2-internal-runner-token-123456"
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'm2-bridge.db'}"),
        artifact_root=tmp_path / "artifacts",
        internal_runner_token=SecretStr(runner_token),
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            denied = await api.post(
                "/internal/agent-jobs/claim",
                json={"runner_id": "m2-runner", "lease_seconds": 30},
            )
            assert denied.status_code == 401
            assert runner_token not in denied.text

            challenge = await import_challenge(api)
            created = await api.post(
                "/v1/runs",
                json={"challenge_id": challenge["id"], "mode": "assisted"},
                headers={"Idempotency-Key": "m2-bridge-run"},
            )
            assert created.status_code == 201, created.text
            run = created.json()
            # This is the trusted, deterministic producer that queues M2's
            # start_session job. It is not a model and performs no target I/O.
            assert await app.state.run_engine.process_next_preflight(worker_id="m2-preflight")

            headers = {"X-CTFMESH-Runner-Token": runner_token}
            claimed = await api.post(
                "/internal/agent-jobs/claim",
                json={"runner_id": "m2-runner", "lease_seconds": 30},
                headers=headers,
            )
            assert claimed.status_code == 200, claimed.text
            start_job = claimed.json()["job"]
            assert start_job["kind"] == "start_session"

            start_work = await api.post(
                f"/internal/agent-jobs/{start_job['id']}/work",
                json={"runner_id": "m2-runner", "lease_version": start_job["lease_version"]},
                headers=headers,
            )
            assert start_work.status_code == 200, start_work.text
            # The sealed worker envelope cannot leak challenge paths, target
            # endpoint data, provider credentials, or a raw candidate flag.
            serialized_work = start_work.text
            assert "allowed_endpoints" not in serialized_work
            assert "compose_file" not in serialized_work
            assert "api_key" not in serialized_work
            assert "CTF{" not in serialized_work

            reservation_payload = {
                "runner_id": "m2-runner",
                "lease_version": start_job["lease_version"],
            }
            reserved = await api.post(
                f"/internal/agent-jobs/{start_job['id']}/session-reservation",
                json=reservation_payload,
                headers=headers,
            )
            duplicate_reserved = await api.post(
                f"/internal/agent-jobs/{start_job['id']}/session-reservation",
                json=reservation_payload,
                headers=headers,
            )
            assert reserved.status_code == duplicate_reserved.status_code == 200
            session_id = reserved.json()["session"]["id"]
            assert duplicate_reserved.json()["session"]["id"] == session_id

            activated = await api.post(
                f"/internal/agent-jobs/{start_job['id']}/session-activation",
                json={**reservation_payload, "session_id": session_id},
                headers=headers,
            )
            assert activated.status_code == 200, activated.text
            sessions = await api.get(f"/v1/runs/{run['id']}/agent-sessions")
            assert sessions.status_code == 200
            assert [item["id"] for item in sessions.json()["items"]] == [session_id]

            turn_claim = await api.post(
                "/internal/agent-jobs/claim",
                json={"runner_id": "m2-runner", "lease_seconds": 30},
                headers=headers,
            )
            turn_job = turn_claim.json()["job"]
            assert turn_job["kind"] == "run_turn"
            turn_lease = {
                "runner_id": "m2-runner",
                "lease_version": turn_job["lease_version"],
            }
            turn_work = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/work",
                json=turn_lease,
                headers=headers,
            )
            assert turn_work.status_code == 200, turn_work.text
            assert turn_work.json()["session"]["state"] == "running"

            # Capture patterns are not part of the master's coordination state.
            # Even an authenticated runner lease cannot bypass the builder-only
            # `capture.get` tool by calling its narrow control route directly.
            capture_as_master = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/flag-capture-patterns",
                json={**turn_lease, "session_id": session_id},
                headers=headers,
            )
            assert capture_as_master.status_code == 409
            assert capture_as_master.json()["detail"]["code"] == "flag_capture_role_not_allowed"
            assert "CTF{" not in capture_as_master.text

            # The master can request one worker only through the kernel. It
            # supplies neither task/session IDs nor a context document, and a
            # retry of the same tool call returns the same durable child.
            evidence_id = turn_work.json()["context_manifest"]["evidence_refs"][0]["observation_id"]
            delegation_body = {
                **turn_lease,
                "delegation": {
                    "tool_call_id": "call-m2-delegate",
                    "role": "source_auditor",
                    "objective": "Review one sealed source-evidence hypothesis.",
                    "evidence_ids": [evidence_id],
                },
            }
            delegated = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/task-delegations",
                json=delegation_body,
                headers=headers,
            )
            delegated_retry = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/task-delegations",
                json=delegation_body,
                headers=headers,
            )
            assert delegated.status_code == delegated_retry.status_code == 200, (
                delegated.text,
                delegated_retry.text,
            )
            assert delegated.json()["task"]["id"] == delegated_retry.json()["task"]["id"]
            assert delegated.json()["task"]["role"] == "source_auditor"
            assert delegated.json()["session_job"]["kind"] == "start_session"
            nested_master = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/task-delegations",
                json={
                    **turn_lease,
                    "delegation": {**delegation_body["delegation"], "role": "master"},
                },
                headers=headers,
            )
            assert nested_master.status_code == 422

            # Steering during a running turn persists only a digest; it does
            # not create a runnable Pi steer job until turn completion.
            steer = await api.post(
                f"/v1/runs/{run['id']}/steer",
                json={"message": "Re-check only the sealed evidence after this turn."},
            )
            assert steer.status_code == 202, steer.text
            assert "Re-check" not in steer.text
            assert not any(
                item["kind"] == "steer" and item["state"] in {"queued", "leased"}
                for item in await app.state.repository.list_agent_jobs(run["id"])
            )

            raw_flag = "CTF{must_not_reach_event_log}"
            bridged_event = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/events",
                json={
                    **turn_lease,
                    "events": [
                        {
                            "sequence": 1,
                            "type": "agent.turn.started",
                            "session_id": session_id,
                            "occurred_at": "2026-08-29T00:00:00Z",
                            "preview": raw_flag,
                        }
                    ],
                },
                headers=headers,
            )
            assert bridged_event.status_code == 200, bridged_event.text
            assert raw_flag not in bridged_event.text

            completed_turn = await api.post(
                f"/internal/agent-jobs/{turn_job['id']}/turn-completion",
                json={**turn_lease, "result_ref": "agent:inconclusive"},
                headers=headers,
            )
            assert completed_turn.status_code == 200, completed_turn.text
            assert any(
                item["kind"] == "steer" and item["state"] == "queued"
                for item in await app.state.repository.list_agent_jobs(run["id"])
            )

            # The delegated worker's start job is ahead of the safe-boundary
            # steer in FIFO order. Complete only its session bootstrap, then
            # verify that a restarted runner can fetch the parent session's
            # sealed context with the steer work; it never needs a source path
            # or an unsealed operator payload to reopen the transcript.
            child_start_claim = await api.post(
                "/internal/agent-jobs/claim",
                json={"runner_id": "m2-runner", "lease_seconds": 30},
                headers=headers,
            )
            child_start_job = child_start_claim.json()["job"]
            assert child_start_job["kind"] == "start_session"
            child_lease = {
                "runner_id": "m2-runner",
                "lease_version": child_start_job["lease_version"],
            }
            child_reservation = await api.post(
                f"/internal/agent-jobs/{child_start_job['id']}/session-reservation",
                json=child_lease,
                headers=headers,
            )
            assert child_reservation.status_code == 200, child_reservation.text
            child_activation = await api.post(
                f"/internal/agent-jobs/{child_start_job['id']}/session-activation",
                json={**child_lease, "session_id": child_reservation.json()["session"]["id"]},
                headers=headers,
            )
            assert child_activation.status_code == 200, child_activation.text

            steer_claim = await api.post(
                "/internal/agent-jobs/claim",
                json={"runner_id": "m2-runner", "lease_seconds": 30},
                headers=headers,
            )
            steer_job = steer_claim.json()["job"]
            assert steer_job["kind"] == "steer"
            steer_lease = {
                "runner_id": "m2-runner",
                "lease_version": steer_job["lease_version"],
            }
            steer_work = await api.post(
                f"/internal/agent-jobs/{steer_job['id']}/work",
                json=steer_lease,
                headers=headers,
            )
            assert steer_work.status_code == 200, steer_work.text
            assert steer_work.json()["session"]["id"] == session_id
            assert steer_work.json()["context_manifest"]["role"] == "master"
            assert "allowed_endpoints" not in steer_work.text
            applied_steer = await api.post(
                f"/internal/agent-jobs/{steer_job['id']}/steer-completion",
                json=steer_lease,
                headers=headers,
            )
            assert applied_steer.status_code == 200, applied_steer.text

            denied_steer = await api.post(
                f"/v1/runs/{run['id']}/steer",
                json={"message": raw_flag},
            )
            assert denied_steer.status_code == 409
            assert raw_flag not in denied_steer.text
            persisted_events = await api.get(f"/v1/runs/{run['id']}/events")
            assert raw_flag not in persisted_events.text
            assert "[REDACTED_FLAG]" in persisted_events.text
            persisted_run = await api.get(f"/v1/runs/{run['id']}")
            assert persisted_run.json()["status"] == "running"


@pytest.mark.asyncio
async def test_hint_catalog_requires_retry_key_and_never_echoes_rejected_note(
    client: httpx.AsyncClient,
) -> None:
    """Hint API failures must not turn an operator note into a public trace."""

    templates = await client.get("/v1/hint-templates")
    assert templates.status_code == 200, templates.text
    assert [item["id"] for item in templates.json()["items"]] == [
        "web.path_traversal.suspect.v1",
        "web.authz_boundary.suspect.v1",
        "web.sqli_basic.suspect.v1",
    ]

    payload = {"template_id": "web.path_traversal.suspect.v1", "note": "operator prose"}
    no_retry_key = await client.post("/v1/runs/run-missing/hints", json=payload)
    assert no_retry_key.status_code == 422
    assert no_retry_key.json()["detail"]["code"] == "idempotency_key_required"

    raw_flag = "CTF{hint_card_note_must_not_echo}"
    rejected_note = await client.post(
        "/v1/runs/run-missing/hints",
        json={**payload, "note": raw_flag},
        headers={"Idempotency-Key": "m4-rejected-secret-note"},
    )
    assert rejected_note.status_code == 422
    assert rejected_note.json()["detail"]["code"] == "hint_card_invalid"
    assert raw_flag not in rejected_note.text


@pytest.mark.asyncio
async def test_imported_challenges_are_listed_newest_first(client: httpx.AsyncClient) -> None:
    first = await import_challenge(client)
    second_manifest = valid_manifest_data()
    second_manifest["metadata"] = {
        "name": "forensics-pcap-lab",
        "category": "forensics",
        "tags": ["pcap"],
    }
    response = await client.post("/v1/challenges", json={"manifest": second_manifest})
    assert response.status_code == 201, response.text
    second = response.json()

    listed = await client.get("/v1/challenges?limit=2")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["items"]] == [second["id"], first["id"]]

    invalid = await client.get("/v1/challenges?limit=0")
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_archive_history_is_small_newest_first_and_does_not_follow_links(
    client: httpx.AsyncClient,
    tmp_path: Path,
) -> None:
    hidden_value = "CTF{history_name_must_stay_redacted}"
    first = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"first.txt": b"first receipt"}),
        headers={"Content-Type": "application/zip", "X-Archive-Name": "older.zip"},
    )
    second = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"second.bin": b"\x7fELF\x02\x01"}),
        headers={
            "Content-Type": "application/zip",
            "X-Archive-Name": f"newer-{hidden_value}.zip",
        },
    )
    assert first.status_code == second.status_code == 201

    # A locally planted symlink with a valid-looking ID must never extend the
    # service-owned receipt root into an arbitrary report reader.
    outside = tmp_path / "outside-history"
    outside.mkdir()
    link_secret = "sk-history-link-must-not-be-read"
    (outside / "report.json").write_text(link_secret, encoding="utf-8")
    rogue = tmp_path / "artifacts" / "archive-intakes" / f"intake_{'f' * 32}"
    rogue.symlink_to(outside, target_is_directory=True)

    listed = await client.get("/v1/archive-intakes?limit=50")
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert [item["intake_id"] for item in items] == [
        second.json()["intake_id"],
        first.json()["intake_id"],
    ]
    assert set(items[0]) == {
        "intake_id",
        "created_at",
        "name",
        "format",
        "file_count",
        "expanded_size_bytes",
        "category",
        "ai_status",
    }
    assert items[0]["name"] == "newer-[REDACTED_FLAG].zip"
    assert items[0]["category"] == "reverse"
    assert "inventory" not in items[0]
    assert hidden_value not in listed.text
    assert link_secret not in listed.text

    limited = await client.get("/v1/archive-intakes?limit=1")
    assert limited.status_code == 200
    assert [item["intake_id"] for item in limited.json()["items"]] == [second.json()["intake_id"]]
    invalid = await client.get("/v1/archive-intakes?limit=0")
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_archive_remove_is_explicit_permanent_and_idempotently_absent(
    client: httpx.AsyncClient,
    tmp_path: Path,
) -> None:
    uploaded = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"notes.txt": b"operator-owned archive"}),
        headers={"Content-Type": "application/zip", "X-Archive-Name": "remove-me.zip"},
    )
    assert uploaded.status_code == 201, uploaded.text
    intake_id = uploaded.json()["intake_id"]
    intake_root = tmp_path / "artifacts" / "archive-intakes" / intake_id

    denied = await client.delete(f"/v1/archive-intakes/{intake_id}")
    assert denied.status_code == 422
    assert denied.json()["detail"]["code"] == "archive_remove_confirmation_required"
    assert intake_root.is_dir()

    removed = await client.delete(
        f"/v1/archive-intakes/{intake_id}",
        headers={"X-Confirm-Remove": intake_id},
    )
    assert removed.status_code == 200, removed.text
    assert removed.json() == {"removed": True, "intake_id": intake_id}
    assert not intake_root.exists()
    assert (await client.get(f"/v1/archive-intakes/{intake_id}")).status_code == 404

    repeated = await client.delete(
        f"/v1/archive-intakes/{intake_id}",
        headers={"X-Confirm-Remove": intake_id},
    )
    assert repeated.status_code == 404


@pytest.mark.asyncio
async def test_archive_intake_extracts_offline_evidence_without_persisting_raw_candidates(
    client: httpx.AsyncClient,
    tmp_path: Path,
) -> None:
    candidate = "CTF{archive_intake_candidate}"
    payload = zip_payload(
        {
            "notes/brief.txt": f"operator note: {candidate}".encode(),
            "data.bin": b"\x7fELF\x02\x01",
        }
    )
    response = await client.post(
        "/v1/archive-intakes",
        content=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Archive-Name": f"submission-{candidate}.zip",
        },
    )
    assert response.status_code == 201, response.text
    intake = response.json()
    assert intake["archive"]["format"] == "zip"
    assert intake["inventory"]["file_count"] == 2
    assert intake["analysis"]["static"]["candidate_flags"]["count"] == 1
    # A flag-shaped string is supplied input, so neither the upload response
    # nor its durable public report may disclose or validate it as a solve.
    assert candidate not in response.text

    report_path = tmp_path / "artifacts" / "archive-intakes" / intake["intake_id"] / "report.json"
    assert candidate not in report_path.read_text(encoding="utf-8")
    assert (
        json.loads(report_path.read_text(encoding="utf-8"))["inventory"]["files"][0]["id"]
        == "file-001"
    )

    denied_reveal = await client.post(
        f"/v1/archive-intakes/{intake['intake_id']}/candidate-flags/reveal",
        json={"confirm": False},
    )
    assert denied_reveal.status_code == 422
    # This deny path prevents a background/client bug from turning a normal
    # receipt fetch into raw candidate disclosure.
    assert denied_reveal.json()["detail"]["code"] == "candidate_reveal_confirmation_required"
    assert candidate not in denied_reveal.text

    reveal = await client.post(
        f"/v1/archive-intakes/{intake['intake_id']}/candidate-flags/reveal",
        json={"confirm": True},
    )
    assert reveal.status_code == 200, reveal.text
    assert reveal.json()["classification"] == "unverified_input_candidate"
    assert reveal.json()["candidate_flags"] == [candidate]
    assert candidate not in report_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_archive_intake_rejects_zip_traversal_and_link_entries(
    client: httpx.AsyncClient,
    tmp_path: Path,
) -> None:
    # Every variant below would either escape the service workspace or make a
    # later server-side file access ambiguous; reject before publishing receipt.
    traversal = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"../outside.txt": b"blocked"}),
        headers={"Content-Type": "application/octet-stream", "X-Archive-Name": "traversal.zip"},
    )
    assert traversal.status_code == 422
    assert traversal.json()["detail"]["code"] == "archive_entry_path_denied"
    assert not (tmp_path / "outside.txt").exists()

    windows_path = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"C:outside.txt": b"blocked"}),
        headers={"Content-Type": "application/octet-stream", "X-Archive-Name": "windows.zip"},
    )
    assert windows_path.status_code == 422
    assert windows_path.json()["detail"]["code"] == "archive_entry_path_denied"

    link = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"regular.txt": b"safe"}, symlink_name="link"),
        headers={"Content-Type": "application/octet-stream", "X-Archive-Name": "link.zip"},
    )
    assert link.status_code == 422
    assert link.json()["detail"]["code"] == "archive_link_entry_denied"

    conflict = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"a": b"regular", "a/child.txt": b"blocked"}),
        headers={"Content-Type": "application/octet-stream", "X-Archive-Name": "conflict.zip"},
    )
    assert conflict.status_code == 422
    assert conflict.json()["detail"]["code"] == "archive_path_prefix_conflict"

    staging = tmp_path / "artifacts" / "archive-intakes" / ".staging"
    # Failed intakes are not resumable artifacts and must not accumulate.
    assert list(staging.iterdir()) == []


@pytest.mark.asyncio
async def test_archive_intake_accepts_standard_targz_and_rejects_tar_links(
    client: httpx.AsyncClient,
) -> None:
    # TAR support is intentionally limited to regular files, matching the ZIP
    # boundary and preventing a link from redirecting later analysis reads.
    accepted = await client.post(
        "/v1/archive-intakes",
        content=tar_payload({"bundle/readme.txt": b"offline artifact"}),
        headers={"Content-Type": "application/gzip", "X-Archive-Name": "bundle.tar.gz"},
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["archive"]["format"] == "tar"
    assert accepted.json()["inventory"]["files"][0]["path"] == "bundle/readme.txt"

    link = await client.post(
        "/v1/archive-intakes",
        content=tar_payload({"regular.txt": b"safe"}, symlink_name="link"),
        headers={"Content-Type": "application/gzip", "X-Archive-Name": "link.tar.gz"},
    )
    assert link.status_code == 422
    assert link.json()["detail"]["code"] == "archive_link_entry_denied"


@pytest.mark.asyncio
async def test_ui_exact_instance_launch_materializes_source_and_leases_key_without_persistence(
    tmp_path: Path,
) -> None:
    """The browser flow creates one scoped run; API key has no durable copy."""

    slot_one = tmp_path / "source-slot-1"
    slot_two = tmp_path / "source-slot-2"
    slot_one.mkdir()
    slot_two.mkdir()
    key = "sk-ui-exact-instance-must-never-persist"
    leases = RecordingPiCredentialLeases()
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'ui-exact.db'}"),
        artifact_root=tmp_path / "artifacts",
        source_slot_1_root=slot_one,
        source_slot_2_root=slot_two,
    )
    app = create_app(
        settings,
        tool_gateway_factory=lambda _repository, _root: RecordingToolGateway(),
        pi_credential_lease_factory=lambda _settings: leases,  # type: ignore[return-value]
    )
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"app/main.py": b"print('safe source')\n"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "challenge.zip"},
            )
            assert uploaded.status_code == 201, uploaded.text
            intake_id = uploaded.json()["intake_id"]
            request_body = {
                "target": {
                    "entry_url": "https://ctf.example.org/",
                    "flag_format": "HTB{...}",
                },
                "execution": {
                    "provider": "gemini",
                    "model": "gemini-3.7-flash",
                    "api_key": key,
                    "provider_egress_acknowledged": True,
                    "target_access_acknowledged": True,
                },
                "budget": {
                    "wall_time_seconds": 543,
                    "max_tool_calls": 73,
                    "max_http_requests": 41,
                    "max_cost_usd": 1.5,
                },
            }
            headers = {"Idempotency-Key": "ui-exact-instance-launch"}
            launched = await api.post(
                f"/v1/archive-intakes/{intake_id}/runs",
                json=request_body,
                headers=headers,
            )
            retry = await api.post(
                f"/v1/archive-intakes/{intake_id}/runs",
                json=request_body,
                headers=headers,
            )

            assert launched.status_code == retry.status_code == 202, launched.text
            launch = launched.json()
            assert retry.json()["run_id"] == launch["run_id"]
            assert launch["status"] == "preparing"
            assert launch["scope"] == {
                "entry_origin": "https://ctf.example.org:443",
                "source_slot": "source-slot-1",
            }
            assert launch["progress"]["console_url"].endswith(f"/{launch['run_id']}/console")
            assert launch["credential_lease_expires_at"] == "2026-08-31T12:00:00Z"
            assert launched.headers["cache-control"] == "no-store"
            assert len(leases.grants) == 1
            assert leases.grants[0] == {
                "run_id": launch["run_id"],
                "provider": "google",
                "model": "gemini-3.7-flash",
                "api_key": key,
                "ttl_seconds": 543,
            }

            challenge = await api.get(f"/v1/challenges/{launch['challenge_id']}")
            events = await api.get(f"/v1/runs/{launch['run_id']}/events")
            assert challenge.status_code == events.status_code == 200
            manifest = challenge.json()["manifest"]
            assert manifest["spec"]["source"] == {
                "intake_id": intake_id,
                "slot_id": "source-slot-1",
            }
            assert manifest["spec"]["target"]["target_aliases"] == {
                "target": "https://ctf.example.org:443"
            }
            assert manifest["spec"]["flag"]["patterns"] == [
                _exact_flag_pattern("HTB{...}"),
                _DEFAULT_EXACT_INSTANCE_FLAG_PATTERN,
            ]
            assert manifest["spec"]["limits"] == {
                "wall_time_seconds": 543,
                "max_worker_turns": 120,
                "max_tool_calls": 73,
                "max_http_requests": 41,
                "max_parallel_requests": 4,
                "max_cost_usd": 1.5,
                "max_artifact_bytes": 1_073_741_824,
            }
            retained = await api.delete(
                f"/v1/archive-intakes/{intake_id}",
                headers={"X-Confirm-Remove": intake_id},
            )
            assert retained.status_code == 409
            assert retained.json()["detail"]["code"] == "archive_intake_in_use"
            assert (await api.get(f"/v1/archive-intakes/{intake_id}")).status_code == 200
            # A run can be removed now, but never casually. The route exists
            # and still refuses here twice over: this request names no run, and
            # the run is live, so its rows are leased by a runner.
            unconfirmed = await api.delete(f"/v1/runs/{launch['run_id']}")
            assert unconfirmed.status_code == 422
            assert unconfirmed.json()["detail"]["code"] == "run_remove_confirmation_required"
            live = await api.delete(
                f"/v1/runs/{launch['run_id']}",
                headers={"X-Confirm-Remove": launch["run_id"]},
            )
            assert live.status_code == 409
            assert live.json()["detail"]["code"] == "run_not_settled"
            assert (await api.get(f"/v1/archive-intakes/{intake_id}")).status_code == 200
            assert (await api.get(f"/v1/runs/{launch['run_id']}")).status_code == 200
            assert key not in launched.text
            assert key not in retry.text
            assert key not in events.text

    assert (slot_one / "challenge" / "app" / "main.py").read_bytes() == b"print('safe source')\n"
    assert json.loads((slot_one / "assignment.json").read_text(encoding="utf-8")) == {
        "challenge_id": launch["challenge_id"],
        "intake_id": intake_id,
        "schema_version": 1,
        "slot_id": "source-slot-1",
    }
    durable_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (tmp_path / "artifacts").rglob("*")
        if path.is_file()
    )
    assert key not in durable_text


@pytest.mark.asyncio
async def test_ui_exact_instance_launch_rejects_private_target_and_never_leases_key(
    tmp_path: Path,
) -> None:
    """A loopback target cannot turn the new UI route into an SSRF primitive."""

    slot = tmp_path / "source-slot-1"
    slot.mkdir()
    key = "sk-private-target-must-not-leak"
    leases = RecordingPiCredentialLeases()
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'private-target.db'}"),
        artifact_root=tmp_path / "artifacts",
        source_slot_1_root=slot,
    )
    app = create_app(
        settings,
        tool_gateway_factory=lambda _repository, _root: RecordingToolGateway(),
        pi_credential_lease_factory=lambda _settings: leases,  # type: ignore[return-value]
    )
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"app.py": b"safe"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "challenge.zip"},
            )
            intake_id = uploaded.json()["intake_id"]
            rejected = await api.post(
                f"/v1/archive-intakes/{intake_id}/runs",
                json={
                    "target": {"entry_url": "http://127.0.0.1:8080"},
                    "execution": {
                        "provider": "openai",
                        "model": "gpt-5.6-sol",
                        "api_key": key,
                        "provider_egress_acknowledged": True,
                        "target_access_acknowledged": True,
                    },
                },
                headers={"Idempotency-Key": "ui-private-target"},
            )

    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "ui_instance_target_not_public"
    assert key not in rejected.text
    assert leases.grants == []
    assert not (slot / "challenge").exists()


@pytest.mark.asyncio
async def test_ui_exact_instance_rejects_budget_above_hard_ceiling_without_leasing_key(
    tmp_path: Path,
) -> None:
    """Custom controls cannot turn the browser into arbitrary resource control."""

    slot = tmp_path / "source-slot-1"
    slot.mkdir()
    key = "sk-unreviewed-budget-must-not-leak"
    leases = RecordingPiCredentialLeases()
    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'budget-profile.db'}"),
        artifact_root=tmp_path / "artifacts",
        source_slot_1_root=slot,
    )
    app = create_app(
        settings,
        tool_gateway_factory=lambda _repository, _root: RecordingToolGateway(),
        pi_credential_lease_factory=lambda _settings: leases,  # type: ignore[return-value]
    )
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"app.py": b"safe"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "challenge.zip"},
            )
            assert uploaded.status_code == 201, uploaded.text
            rejected = await api.post(
                f"/v1/archive-intakes/{uploaded.json()['intake_id']}/runs",
                json={
                    "target": {"entry_url": "https://ctf.example.org/"},
                    "execution": {
                        "provider": "openai",
                        "model": "gpt-5.6-sol",
                        "api_key": key,
                        "provider_egress_acknowledged": True,
                        "target_access_acknowledged": True,
                    },
                    "budget": {
                        "wall_time_seconds": 901,
                        "max_tool_calls": 121,
                        "max_http_requests": 81,
                        "max_cost_usd": 3.1,
                    },
                },
                headers={"Idempotency-Key": "ui-unreviewed-budget"},
            )

    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "ui_exact_instance_budget_not_allowed"
    assert key not in rejected.text
    assert leases.grants == []
    assert not (slot / "challenge").exists()


@pytest.mark.asyncio
async def test_archive_triage_request_never_echoes_api_key(client: httpx.AsyncClient) -> None:
    secret = "sk-archive-intake-key-must-not-echo"
    response = await client.post(
        "/v1/archive-intakes/intake_0123456789abcdef0123456789abcdef/triage",
        json={
            "provider": "openai-responses",
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": True,
        },
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "archive_intake_not_found"
    assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_fails_closed_without_the_reviewed_provider_proxy(
    client: httpx.AsyncClient,
) -> None:
    """Host-local API tests must not silently fall back to direct Internet egress."""

    uploaded = await client.post(
        "/v1/archive-intakes",
        content=zip_payload({"notes.txt": b"offline CTF evidence"}),
        headers={"Content-Type": "application/zip", "X-Archive-Name": "case.zip"},
    )
    assert uploaded.status_code == 201, uploaded.text
    secret = "sk-no-direct-provider-egress-123456"
    response = await client.post(
        f"/v1/archive-intakes/{uploaded.json()['intake_id']}/triage",
        json={
            "provider": "openai-responses",
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": True,
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "archive_triage_provider_egress_unavailable"
    assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_rejects_unknown_provider_before_provider_factory(
    client: httpx.AsyncClient,
) -> None:
    secret = "sk-unknown-provider-must-not-leak"
    response = await client.post(
        "/v1/archive-intakes/intake_0123456789abcdef0123456789abcdef/triage",
        json={
            "provider": "operator-controlled-url",
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": True,
        },
    )
    assert response.status_code == 422
    assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_dispatches_one_selected_provider_without_persisting_key(
    tmp_path: Path,
) -> None:
    backend = RecordingArchiveTriageBackend()
    closed: list[bool] = []

    def provider_factory(provider: ArchiveTriageProvider) -> ArchiveTriageProviderSession:
        descriptor = next(
            item for item in archive_triage_provider_descriptors() if item.id is provider
        )

        async def close() -> None:
            closed.append(True)

        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=backend,
            _close=close,
        )

    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'provider-api.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings, archive_provider_factory=provider_factory)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"notes.txt": b"offline CTF evidence"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "case.zip"},
            )
            assert uploaded.status_code == 201, uploaded.text
            intake_id = uploaded.json()["intake_id"]
            secret = "sk-selected-provider-key-must-not-persist"
            triaged = await api.post(
                f"/v1/archive-intakes/{intake_id}/triage",
                json={
                    "provider": "deepseek-chat",
                    "model": "operator-deepseek-model",
                    "api_key": secret,
                    "provider_egress_acknowledged": True,
                    "max_output_tokens": 2500,
                    "timeout_seconds": 86_400,
                },
            )
            second_secret = "sk-second-triage-must-not-leave"
            repeated = await api.post(
                f"/v1/archive-intakes/{intake_id}/triage",
                json={
                    "provider": "deepseek-chat",
                    "model": "operator-deepseek-model",
                    "api_key": second_secret,
                    "provider_egress_acknowledged": True,
                },
            )

    assert triaged.status_code == 200, triaged.text
    assert repeated.status_code == 422, repeated.text
    assert repeated.json()["detail"]["code"] == "archive_triage_already_requested"
    assert second_secret not in repeated.text
    result = triaged.json()
    assert result["analysis"]["ai"]["provider"] == "deepseek-chat"
    assert result["analysis"]["ai"]["output_contract"] == "json_validated"
    assert result["boundary"]["target_network"] == "not authorized (0 requests)"
    assert result["boundary"]["provider_egress"] == "1 metadata-only evidence request"
    assert result["analysis"]["ai"]["execution"] == "none"
    assert result["analysis"]["ai"]["verification"] == "not_attempted"
    assert len(backend.requests) == 1
    # Archive triage accepts an operator-tuned value, but only inside the
    # server-owned hard interval tested by the deny path below.
    assert backend.requests[0].max_output_tokens == 2_500
    assert backend.keys == [secret]
    assert backend.timeouts == [86_400.0]
    assert closed == [True, True]
    report = (tmp_path / "artifacts" / "archive-intakes" / intake_id / "report.json").read_text(
        encoding="utf-8"
    )
    assert secret not in report


@pytest.mark.asyncio
async def test_archive_triage_stream_reports_only_code_owned_progress_and_result(
    tmp_path: Path,
) -> None:
    backend = RecordingArchiveTriageBackend()
    closed: list[bool] = []

    def provider_factory(provider: ArchiveTriageProvider) -> ArchiveTriageProviderSession:
        descriptor = next(
            item for item in archive_triage_provider_descriptors() if item.id is provider
        )

        async def close() -> None:
            closed.append(True)

        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=backend,
            _close=close,
        )

    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'provider-stream.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings, archive_provider_factory=provider_factory)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"notes.txt": b"offline CTF evidence"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "case.zip"},
            )
            intake_id = uploaded.json()["intake_id"]
            secret = "sk-stream-key-must-not-appear"
            streamed = await api.post(
                f"/v1/archive-intakes/{intake_id}/triage/stream",
                json={
                    "provider": "openai-responses",
                    "model": "operator-model",
                    "api_key": secret,
                    "provider_egress_acknowledged": True,
                    "timeout_seconds": 120,
                },
            )

    assert streamed.status_code == 200, streamed.text
    assert streamed.headers["content-type"].startswith("application/x-ndjson")
    assert streamed.headers["cache-control"] == "no-cache, no-store"
    assert streamed.headers["x-accel-buffering"] == "no"
    assert secret not in streamed.text
    events = [json.loads(line) for line in streamed.text.splitlines()]
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert [event["stage"] for event in events[:-1]] == [
        "request_accepted",
        "receipt_loaded",
        "evidence_prepared",
        "provider_request_started",
        "provider_response_received",
        "result_validated",
        "result_saved",
    ]
    assert all(event["kind"] == "progress" for event in events[:-1])
    assert events[-1]["kind"] == "result"
    assert events[-1]["intake"]["analysis"]["ai"]["status"] == "completed"
    assert all(event["schema_version"] == "ctfmesh.archive-triage-stream/v1" for event in events)
    assert backend.keys == [secret]
    assert backend.timeouts == [120.0]
    assert closed == [True]


@pytest.mark.asyncio
async def test_archive_triage_stream_failure_is_terminal_and_never_reflects_key(
    tmp_path: Path,
) -> None:
    backend = RecordingArchiveTriageBackend(fail=True, failure_code="transport_error")
    closed: list[bool] = []

    def provider_factory(provider: ArchiveTriageProvider) -> ArchiveTriageProviderSession:
        descriptor = next(
            item for item in archive_triage_provider_descriptors() if item.id is provider
        )

        async def close() -> None:
            closed.append(True)

        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=backend,
            _close=close,
        )

    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'provider-stream-fail.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings, archive_provider_factory=provider_factory)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"notes.txt": b"offline CTF evidence"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "case.zip"},
            )
            intake_id = uploaded.json()["intake_id"]
            secret = "sk-stream-failure-must-not-appear"
            streamed = await api.post(
                f"/v1/archive-intakes/{intake_id}/triage/stream",
                json={
                    "provider": "openai-responses",
                    "model": "operator-model",
                    "api_key": secret,
                    "provider_egress_acknowledged": True,
                },
            )

    assert streamed.status_code == 200, streamed.text
    assert secret not in streamed.text
    events = [json.loads(line) for line in streamed.text.splitlines()]
    assert [event["stage"] for event in events[:-1]] == [
        "request_accepted",
        "receipt_loaded",
        "evidence_prepared",
        "provider_request_started",
    ]
    assert events[-1] == {
        "schema_version": "ctfmesh.archive-triage-stream/v1",
        "kind": "error",
        "sequence": 5,
        "code": "archive_triage_provider_failed",
        "message": "The provider did not return a usable triage result.",
        "provider_code": "transport_error",
    }
    assert closed == [True]


@pytest.mark.asyncio
async def test_archive_triage_provider_failure_never_reflects_key(tmp_path: Path) -> None:
    secret = "sk-provider-error-must-not-leak"
    backend = RecordingArchiveTriageBackend(fail=True, failure_code=secret)

    def provider_factory(provider: ArchiveTriageProvider) -> ArchiveTriageProviderSession:
        descriptor = next(
            item for item in archive_triage_provider_descriptors() if item.id is provider
        )

        async def close() -> None:
            return None

        return ArchiveTriageProviderSession(
            descriptor=descriptor,
            backend=backend,
            _close=close,
        )

    settings = Settings(
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path / 'provider-failure.db'}"),
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings, archive_provider_factory=provider_factory)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
            uploaded = await api.post(
                "/v1/archive-intakes",
                content=zip_payload({"notes.txt": b"offline CTF evidence"}),
                headers={"Content-Type": "application/zip", "X-Archive-Name": "case.zip"},
            )
            intake_id = uploaded.json()["intake_id"]
            response = await api.post(
                f"/v1/archive-intakes/{intake_id}/triage",
                json={
                    "provider": "gemini-openai-compat",
                    "model": "operator-gemini-model",
                    "api_key": secret,
                    "provider_egress_acknowledged": True,
                },
            )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "archive_triage_provider_failed"
    assert response.json()["detail"]["details"] == {"provider_code": "provider_failure"}
    assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_requires_explicit_provider_acknowledgement_and_small_key(
    client: httpx.AsyncClient,
) -> None:
    secret = "sk-omitted-provider-must-not-leak"
    path = "/v1/archive-intakes/intake_0123456789abcdef0123456789abcdef/triage"
    missing_provider = await client.post(
        path,
        json={
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": True,
        },
    )
    assert missing_provider.status_code == 422
    assert secret not in missing_provider.text

    rejected_acknowledgement = await client.post(
        path,
        json={
            "provider": "openai-responses",
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": False,
        },
    )
    assert rejected_acknowledgement.status_code == 422
    assert secret not in rejected_acknowledgement.text

    oversized_key = "k" * 8193
    rejected_key = await client.post(
        path,
        json={
            "provider": "openai-responses",
            "model": "operator-model",
            "api_key": oversized_key,
            "provider_egress_acknowledged": True,
        },
    )
    assert rejected_key.status_code == 422
    assert oversized_key not in rejected_key.text

    oversized_bodies = []
    for request_path in (path, f"{path}/stream"):
        oversized_bodies.append(
            await client.post(
                request_path,
                content=b"x" * (16 * 1024 + 1),
                headers={"Content-Type": "application/json"},
            )
        )
    for oversized_body in oversized_bodies:
        assert oversized_body.status_code == 413
        assert oversized_body.json()["detail"]["code"] == "archive_triage_request_too_large"


@pytest.mark.asyncio
async def test_archive_triage_rejects_unreviewed_output_budget_without_reflecting_key(
    client: httpx.AsyncClient,
) -> None:
    secret = "sk-unreviewed-triage-budget-must-not-leak"
    response = await client.post(
        "/v1/archive-intakes/intake_0123456789abcdef0123456789abcdef/triage",
        json={
            "provider": "openai-responses",
            "model": "operator-model",
            "api_key": secret,
            "provider_egress_acknowledged": True,
            "max_output_tokens": 4096,
        },
    )

    assert response.status_code == 422
    assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_rejects_unbounded_timeout_without_reflecting_key(
    client: httpx.AsyncClient,
) -> None:
    secret = "sk-unbounded-triage-timeout-must-not-leak"
    path = "/v1/archive-intakes/intake_0123456789abcdef0123456789abcdef/triage"

    for invalid_timeout in (0, -1, 86_401, True, "86400"):
        response = await client.post(
            path,
            json={
                "provider": "openai-responses",
                "model": "operator-model",
                "api_key": secret,
                "provider_egress_acknowledged": True,
                "timeout_seconds": invalid_timeout,
            },
        )

        assert response.status_code == 422
        assert secret not in response.text


@pytest.mark.asyncio
async def test_archive_triage_provider_catalog_is_fixed_and_non_secret(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/v1/archive-triage/providers")
    assert response.status_code == 200
    assert response.json()["items"] == [
        {
            "id": "openai-responses",
            "label": "OpenAI Responses",
            "key_label": "OpenAI API key",
            "output_contract": "strict_schema",
        },
        {
            "id": "gemini-openai-compat",
            "label": "Google Gemini",
            "key_label": "Gemini API key",
            "output_contract": "json_validated",
        },
        {
            "id": "deepseek-chat",
            "label": "DeepSeek Chat",
            "key_label": "DeepSeek API key",
            "output_contract": "json_validated",
        },
    ]


@pytest.mark.asyncio
async def test_skill_catalog_exposes_only_checked_in_local_metadata(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/v1/skill-catalog?category=web")
    assert response.status_code == 200
    catalog = response.json()
    assert [skill["id"] for skill in catalog["skills"]] == ["web.triage"]
    assert catalog["skills"][0]["source_refs"][0]["role"] == "reference_only"
    assert catalog["mcp_profiles"] == [
        {
            "id": "web.readonly-artifacts",
            "category": "web",
            "description": (
                "Category-aware web reference profile for CTFMesh's bounded local read-only "
                "artifact MCP facade. Upstream catalog references remain metadata only."
            ),
            "transport": "local_stdio",
            "server_id": "ctfmesh.local.readonly",
            "mcp_tool_names": ["artifacts_inspect", "files_list"],
            "runtime_tool_ids": ["artifacts.inspect", "files.list"],
            "source_refs": catalog["skills"][0]["source_refs"],
            "allows_external_connection": False,
            "allows_network": False,
            "allows_code_execution": False,
        }
    ]

    denied = await client.get("/v1/skill-catalog?category=not-a-category")
    assert denied.status_code == 422
    assert denied.json()["detail"]["code"] == "skill_category_invalid"


@pytest.mark.asyncio
async def test_run_mode_and_budget_must_stay_within_manifest(client: httpx.AsyncClient) -> None:
    challenge = await import_challenge(client)
    wrong_mode = await client.post(
        "/v1/runs",
        json={"challenge_id": challenge["id"], "mode": "contest"},
    )
    assert wrong_mode.status_code == 422
    assert wrong_mode.json()["detail"]["code"] == "run_mode_must_match_manifest"

    too_large = await client.post(
        "/v1/runs",
        json={
            "challenge_id": challenge["id"],
            "mode": "assisted",
            "budget": {
                "wall_time_seconds": 300,
                "max_tool_calls": 30,
                "max_http_requests": 2000,
                "max_cost_usd": 1,
            },
        },
    )
    assert too_large.status_code == 422
    assert too_large.json()["detail"]["code"].startswith("budget_exceeds_manifest")


@pytest.mark.asyncio
async def test_missing_run_subresources_and_stream_return_404(client: httpx.AsyncClient) -> None:
    for path in (
        "/v1/runs/missing/artifacts",
        "/v1/runs/missing/verifications",
        "/v1/runs/missing/events/stream",
        "/v1/runs/missing/activity/stream",
    ):
        response = await client.get(path)
        assert response.status_code == 404, path
        assert response.json()["detail"]["code"] == "run_not_found"


def test_run_activity_projection_drops_event_payloads_and_unknown_types() -> None:
    """The browser progress rail must never become an event-payload reader."""

    assert run_activity_event(
        {
            "sequence": 7,
            "type": "tool.completed",
            "payload": {"raw_flag": "CTF{must_not_render}", "api_key": "sk-not-rendered"},
        }
    ) == {
        "schema_version": "ctfmesh.run-activity-stream/v1",
        "sequence": 7,
        "stage": "tool",
        "summary": "Scoped tool result recorded.",
    }
    assert run_activity_event({"sequence": 8, "type": "future.unknown", "payload": {}}) == {
        "schema_version": "ctfmesh.run-activity-stream/v1",
        "sequence": 8,
        "stage": "activity",
        "summary": "Run activity updated.",
    }
    assert run_activity_event({"sequence": False, "type": "tool.completed"}) is None


@pytest.mark.asyncio
async def test_invalid_pagination_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/runs?limit=-1")
    assert response.status_code == 422
    response = await client.get("/v1/runs/missing/events?after=-1")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_missing_run_transition_is_404_not_conflict(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/runs/missing/pause")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "run_not_found"


@pytest.mark.asyncio
async def test_invalid_correlation_id_is_replaced(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/health", headers={"X-Correlation-ID": "invalid value"})
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"].startswith("req_")
    assert response.headers["X-Correlation-ID"] != "invalid value"
