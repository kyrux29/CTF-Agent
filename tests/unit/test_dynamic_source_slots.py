"""Focused security tests for M6.a's backend-assigned source slots."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from ctfmesh_db import Repository
from ctfmesh_domain import AgentRole, ChallengeManifest, ContextManifest, ToolExecutionAuthority
from ctfmesh_tool_runtime.contracts import SourceManifestCall, SourceSlotInvocation
from ctfmesh_tool_runtime.dispatch import ToolGateway
from ctfmesh_tool_runtime.gateway_app import configured_source_slots
from ctfmesh_tool_runtime.settings import SourceSlotSettings, ToolGatewaySettings
from ctfmesh_tool_runtime.slots import InProcessSourceSlot, SourceSlotError
from ctfmesh_tools import SourceManifestInput
from pydantic import SecretStr

_INTAKE_ID = "intake_" + "a" * 32


def _manifest(*, source_slot_id: str | None = "source-slot-2") -> ChallengeManifest:
    """Create an assisted remote manifest with an optional M6.a source binding."""

    spec: dict[str, object] = {
        "mode": "assisted",
        "target": {
            "type": "remote",
            "healthcheck": {"url": "https://challenge.example/health", "expected_status": 200},
            "allowed_endpoints": [
                {"host": "challenge.example", "ports": [443], "protocols": ["https"]}
            ],
            "target_aliases": {"target": "https://challenge.example"},
        },
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
            "namespace": "dynamic-source-slot",
            "cutoff": "2026-08-31T00:00:00Z",
            "internet_search": False,
        },
        "tool_profile": ["source.manifest"],
    }
    if source_slot_id is not None:
        spec["source"] = {"intake_id": _INTAKE_ID, "slot_id": source_slot_id}
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "dynamic-source-slot", "category": "web"},
            "spec": spec,
        }
    )


def _authority(
    *,
    challenge_id: str = "challenge-dynamic-source",
    source_slot_id: str | None = "source-slot-2",
) -> ToolExecutionAuthority:
    """Issue a normal tool authority; source binding stays in the manifest."""

    created_at = datetime(2026, 8, 31, tzinfo=UTC)
    context = ContextManifest.issue(
        id="ctx-dynamic-source-slot",
        run_id="run-dynamic-source-slot",
        task_id="task-dynamic-source-slot",
        challenge_digest="a" * 64,
        role="source_auditor",
        objective="Inspect a backend-assigned read-only archive mount.",
        allowed_tool_ids=("source.manifest", "finding.submit"),
        budget_slice={"tool_calls": 2, "input_tokens": 100, "output_tokens": 100},
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=10),
    )
    return ToolExecutionAuthority(
        run_id="run-dynamic-source-slot",
        challenge_id=challenge_id,
        agent_job_id="job-dynamic-source-slot",
        session_id="session-dynamic-source-slot",
        task_id="task-dynamic-source-slot",
        branch_id="branch-dynamic-source-slot",
        role=AgentRole.SOURCE_AUDITOR,
        context_manifest=context,
        challenge_manifest=_manifest(source_slot_id=source_slot_id),
        lease_expires_at=created_at + timedelta(minutes=1),
    )


def _call() -> SourceManifestCall:
    return SourceManifestCall(
        tool_call_id="call-dynamic-source-manifest",
        idempotency_key="call-dynamic-source-manifest",
        arguments=SourceManifestInput(),
    )


def _write_assignment(
    path: Path,
    *,
    challenge_id: str = "challenge-dynamic-source",
    intake_id: str = _INTAKE_ID,
    slot_id: str = "source-slot-2",
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "slot_id": slot_id,
                "challenge_id": challenge_id,
                "intake_id": intake_id,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


@pytest.mark.asyncio
async def test_dynamic_slot_uses_external_assignment_and_reloads_it_per_invocation(
    tmp_path: Path,
) -> None:
    """A stale or retargeted slot mapping cannot expose the mounted archive."""

    slot_root = tmp_path / "slot"
    source_root = slot_root / "challenge"
    source_root.mkdir(parents=True)
    (source_root / "pyproject.toml").write_text("[project]\nname = 'safe'\n", encoding="utf-8")
    assignment_path = slot_root / "assignment.json"
    _write_assignment(assignment_path)
    slot = InProcessSourceSlot(
        slot_id="source-slot-2",
        challenge_id=None,
        source_root=source_root,
        assignment_path=assignment_path,
    )

    first = await slot.invoke(
        SourceSlotInvocation(
            invocation_id="invocation-dynamic-source-one",
            authority=_authority(),
            call=_call(),
        )
    )

    assert first.output["manifest_paths"] == ["pyproject.toml"]
    _write_assignment(assignment_path, challenge_id="challenge-reassigned")
    with pytest.raises(SourceSlotError, match="source_slot_assignment_mismatch"):
        await slot.invoke(
            SourceSlotInvocation(
                invocation_id="invocation-dynamic-source-two",
                authority=_authority(),
                call=_call(),
            )
        )


@pytest.mark.asyncio
async def test_dynamic_slot_rejects_an_assignment_path_inside_or_linked_from_archive(
    tmp_path: Path,
) -> None:
    """The upload cannot create or replace the metadata that authorizes it."""

    slot_root = tmp_path / "slot"
    source_root = slot_root / "challenge"
    source_root.mkdir(parents=True)
    (source_root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source_slot_assignment_path_inside_source_root"):
        InProcessSourceSlot(
            slot_id="source-slot-2",
            challenge_id=None,
            source_root=source_root,
            assignment_path=source_root / "assignment.json",
        )

    external_assignment = slot_root / "assignment.json"
    assignment_target = slot_root / "assignment-target.json"
    slot = InProcessSourceSlot(
        slot_id="source-slot-2",
        challenge_id=None,
        source_root=source_root,
        assignment_path=external_assignment,
    )
    _write_assignment(assignment_target)
    os.symlink(assignment_target, external_assignment)
    with pytest.raises(SourceSlotError, match="source_slot_assignment_unavailable"):
        await slot.invoke(
            SourceSlotInvocation(
                invocation_id="invocation-dynamic-source-symlink",
                authority=_authority(),
                call=_call(),
            )
        )


def test_dynamic_source_slot_settings_require_an_external_assignment_path(tmp_path: Path) -> None:
    """Deployment cannot accidentally turn a dynamic slot into a broad mount."""

    source_root = tmp_path / "slot" / "challenge"
    with pytest.raises(ValueError, match="source_slot_assignment_path_required"):
        SourceSlotSettings(
            source_slot_id="source-slot-2",
            source_slot_challenge_id=None,
            source_slot_root=source_root,
            source_slot_dynamic_assignment=True,
            source_slot_token=SecretStr("source-slot-token-1234"),
        )
    with pytest.raises(ValueError, match="source_slot_assignment_path_inside_source_root"):
        SourceSlotSettings(
            source_slot_id="source-slot-2",
            source_slot_challenge_id=None,
            source_slot_root=source_root,
            source_slot_dynamic_assignment=True,
            source_slot_assignment_path=source_root / "assignment.json",
            target_connector_url="http://target-connector:8083",
            source_slot_token=SecretStr("source-slot-token-1234"),
        )


def test_gateway_settings_build_a_dynamic_client_without_static_challenge_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gateway only gets a fixed slot service, never an archive location."""

    # Keep this constructor independent from the operator's live .env.
    monkeypatch.chdir(tmp_path)
    settings = ToolGatewaySettings(
        database_url=SecretStr("sqlite+aiosqlite:////tmp/ctfmesh-dynamic-slot.db"),
        artifact_root=tmp_path / "artifacts",
        tool_gateway_token=SecretStr("tool-gateway-token-1234"),
        source_slot_token=SecretStr("source-slot-token-1234"),
        source_slot_1_url="http://sandbox-source-1:8082",
        source_slot_1_dynamic_assignment=True,
        source_slot_2_challenge_id="challenge-curated-static",
        source_slot_2_url="http://sandbox-source-2:8082",
    )

    dynamic_slot, static_slot = configured_source_slots(settings)

    assert dynamic_slot.slot_id == "source-slot-1"
    assert dynamic_slot.challenge_id is None
    assert getattr(dynamic_slot, "dynamic_assignment", False) is True
    assert dynamic_slot.workspace_root() == Path("/slot/challenge")
    assert static_slot.slot_id == "source-slot-2"
    assert static_slot.challenge_id == "challenge-curated-static"
    assert getattr(static_slot, "dynamic_assignment", False) is False


def test_gateway_settings_treats_compose_empty_dynamic_slot_ids_as_unconfigured(
    tmp_path: Path,
) -> None:
    """`${NAME:-}` must not turn a dynamic M6 slot into an invalid empty ID."""

    settings = ToolGatewaySettings(
        database_url=SecretStr("sqlite+aiosqlite:////tmp/ctfmesh-dynamic-empty.db"),
        artifact_root=tmp_path / "artifacts",
        tool_gateway_token=SecretStr("tool-gateway-token-1234"),
        source_slot_token=SecretStr("source-slot-token-1234"),
        target_capability_key=SecretStr("target-capability-key-fixture-material-1234"),
        source_slot_1_challenge_id="",
        source_slot_1_url="http://ui-source-slot-1:8082",
        source_slot_1_dynamic_assignment=True,
        source_slot_2_challenge_id="",
        source_slot_2_url="http://ui-source-slot-2:8082",
        source_slot_2_dynamic_assignment=True,
    )

    first, second = configured_source_slots(settings)
    assert first.challenge_id is second.challenge_id is None


@dataclass(frozen=True)
class _SelectOnlySlot:
    """Minimal slot double: selection must not require a source mount or I/O."""

    slot_id: str
    challenge_id: str | None
    dynamic_assignment: bool

    def supports(self, _call: object) -> bool:
        return True

    def workspace_root(self) -> Path:
        return Path("/challenge")


def test_gateway_selects_declared_dynamic_slot_without_affecting_static_fallback(
    tmp_path: Path,
) -> None:
    """An archive-bound manifest never falls through to a static M3 source mount."""

    static_slot = _SelectOnlySlot(
        slot_id="source-slot-1",
        challenge_id="challenge-dynamic-source",
        dynamic_assignment=False,
    )
    dynamic_slot = _SelectOnlySlot(
        slot_id="source-slot-2",
        challenge_id=None,
        dynamic_assignment=True,
    )
    gateway = ToolGateway(
        repository=cast(Repository, object()),
        artifact_root=tmp_path,
        source_slots=(static_slot, dynamic_slot),  # type: ignore[arg-type]
    )

    assert gateway._select_source_slot(_authority(), _call()) is dynamic_slot
    assert (
        gateway._select_source_slot(
            _authority(source_slot_id=None),
            _call(),
        )
        is static_slot
    )
