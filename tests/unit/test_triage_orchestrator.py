from __future__ import annotations

import json
from pathlib import Path

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_domain import ChallengeManifest
from ctfmesh_orchestrator import (
    TriageConfigurationError,
    TriageOrchestrator,
    TriageProposalError,
    build_console_snapshot,
)
from ctfmesh_orchestrator.console import _power_trace_details
from ctfmesh_provider_openai_responses import (
    TriageCompletion,
    TriageFact,
    TriageHypothesis,
    TriageNextAction,
    TriageRequest,
    TriageResult,
)
from ctfmesh_tools import LocalArtifactStore


class FakeTriageBackend:
    name = "fake-triage"

    def __init__(self, completion: TriageCompletion) -> None:
        self.completion = completion
        self.requests: list[TriageRequest] = []

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        del timeout_seconds
        assert api_key
        self.requests.append(request)
        return self.completion


def test_power_failure_projection_is_allowlisted_and_drops_raw_provider_text() -> None:
    assert _power_trace_details(
        "power.pi.session.failed",
        {"reason": "power_pi_provider_authentication_failed"},
    ) == [
        {
            "label": "Failure",
            "content": {
                "value": "Provider rejected the saved API key.",
                "classification": "public",
            },
        }
    ]
    assert (
        _power_trace_details(
            "power.pi.session.failed",
            {"reason": "raw upstream body with key-like material"},
        )
        == []
    )


def _manifest(*, tools: list[str] | None = None) -> ChallengeManifest:
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "crypto-artifact-triage", "category": "crypto"},
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "inputs/challenge.txt", "role": "ciphertext"}],
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
                    "wall_time_seconds": 60,
                    "max_worker_turns": 1,
                    "max_tool_calls": 4,
                    "max_http_requests": 1,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 2,
                    "max_artifact_bytes": 1024 * 1024,
                },
                "providers": {"preferred": "openai-responses"},
                "memory": {
                    "namespace": "local-triage",
                    "cutoff": "2026-07-26T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": tools or ["artifacts.inspect", "files.list"],
                "skill_profile": ["common.artifact-triage", "crypto.triage"],
            },
        }
    )


def _completion(*, category: str = "crypto") -> TriageCompletion:
    return TriageCompletion(
        response_id="resp_safe_fixture",
        result=TriageResult(
            category=category,  # type: ignore[arg-type]
            summary="The supplied text is an encoded ciphertext-like artifact.",
            facts=(
                TriageFact(
                    statement="A declared ciphertext artifact is available for static inspection.",
                    confidence=0.97,
                    evidence_ids=("artifact-01",),
                ),
            ),
            hypotheses=(
                TriageHypothesis(
                    statement=(
                        "The encoding and cryptographic parameters should be identified first."
                    ),
                    confidence=0.71,
                    evidence_ids=("challenge-context", "artifact-01"),
                ),
            ),
            next_actions=(
                TriageNextAction(
                    statement="Review the bounded fingerprint before selecting a decoder.",
                    evidence_ids=("challenge-context", "artifact-01"),
                ),
            ),
        ),
    )


async def _repository(root: Path) -> tuple[Database, Repository]:
    database = Database(f"sqlite+aiosqlite:///{(root / 'ctfmesh.db').resolve()}")
    await database.create_schema()
    return database, Repository(database)


@pytest.mark.asyncio
async def test_triage_persists_only_redacted_proposals_and_never_executes_them(
    tmp_path: Path,
) -> None:
    challenge_root = tmp_path / "challenge"
    input_path = challenge_root / "inputs" / "challenge.txt"
    input_path.parent.mkdir(parents=True)
    raw_flag = "CTF{input_artifacts_are_not_evidence}"
    api_like_value = "sk-input-not-a-provider-key-123456789"
    input_path.write_text(
        f"encoded message {raw_flag} Bearer input-secret {api_like_value} Cookie:session-value",
        encoding="utf-8",
    )
    database, repository = await _repository(tmp_path)
    backend = FakeTriageBackend(_completion())
    artifact_root = tmp_path / "runtime"
    orchestrator = TriageOrchestrator(repository=repository, artifact_root=artifact_root)
    try:
        result = await orchestrator.run(
            manifest=_manifest(),
            challenge_root=challenge_root,
            backend=backend,
            api_key="sk-live-key-never-persisted-123456789",
            model="operator-selected-model",
        )

        assert result.status == "completed"
        assert result.category == "crypto"
        assert result.model == "operator-selected-model"
        assert result.selected_skills == ("common.artifact-triage", "crypto.triage")
        assert len(backend.requests) == 1
        request_text = json.dumps(backend.requests[0].model_dump(mode="json"))
        assert raw_flag not in request_text
        assert api_like_value not in request_text
        assert "input-secret" not in request_text
        assert "session-value" not in request_text
        assert "[REDACTED_FLAG]" in request_text

        run = await repository.get_run(result.run_id)
        assert run is not None
        assert run["status"] == "completed"
        assert await repository.list_verifications(result.run_id) == []
        blackboard = await repository.blackboard(result.run_id)
        assert [fact["status"] for fact in blackboard["facts"]] == ["proposed"]
        assert [hypothesis["status"] for hypothesis in blackboard["hypotheses"]] == ["open"]
        assert blackboard["experiments"] == []

        snapshot = await build_console_snapshot(repository, result.run_id)
        assert snapshot["run"]["category"] == "crypto"
        assert snapshot["run"]["current_stage"] == "triage"
        assert snapshot["run"]["target_scope"] == "artifact://declared-bundle"
        assert snapshot["run"]["scope_kind"] == "artifact_bundle"
        assert snapshot["run"]["execution_mode"] == "read_only_triage"
        assert snapshot["run"]["provider_label"] == "openai-responses · read-only triage"
        assert snapshot["run"]["triage"] == {
            "read_only": True,
            "actions_executed": 0,
            "verification_attempted": False,
            "selected_skill_ids": ["common.artifact-triage", "crypto.triage"],
        }
        assert [fact["state"] for fact in snapshot["facts"]] == ["proposed"]
        assert [hypothesis["status"] for hypothesis in snapshot["hypotheses"]] == ["open"]
        assert snapshot["verification"]["status"] == "pending"
        assert snapshot["verification"]["summary"] == (
            "No verification was attempted in this read-only triage stage."
        )
        assert all(item["label"] != "HTTP" for item in snapshot["budgets"])

        events = await repository.list_events(result.run_id, limit=100)
        event_text = json.dumps(events)
        assert "sk-live-key-never-persisted-123456789" not in event_text
        assert raw_flag not in event_text
        proposal_event = next(
            event for event in events if event["type"] == "triage.proposal.received"
        )
        assert proposal_event["payload"]["actions_executed"] == 0

        store = LocalArtifactStore(artifact_root / "object-store")
        for artifact in await repository.list_artifacts(result.run_id):
            content = (await store.get_bytes(artifact["sha256"])).decode("utf-8")
            assert raw_flag not in content
            assert api_like_value not in content
        assert not (artifact_root / "workspaces" / result.run_id).exists()

        export_root = tmp_path / "triage-report"
        await orchestrator.export(result, export_root)
        assert {path.name for path in export_root.iterdir()} == {
            "README.md",
            "blackboard.json",
            "proposal.json",
            "trace.jsonl",
            "triage-report.json",
        }
        exported = "".join(path.read_text(encoding="utf-8") for path in export_root.iterdir())
        assert raw_flag not in exported
        assert api_like_value not in exported
        assert "did not execute any suggested action" in (export_root / "README.md").read_text(
            encoding="utf-8"
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_console_counts_power_command_receipts_but_not_queue_placeholders(
    tmp_path: Path,
) -> None:
    """Power's compact command ledger contributes to the visible tool count."""

    database, repository = await _repository(tmp_path)
    try:
        manifest = _manifest()
        challenge = await repository.create_challenge(
            manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
            name="power-console-counts",
        )
        run = await repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="power-swarm",
            budget={
                "wall_time_seconds": 60,
                "max_tool_calls": 4,
                "max_http_requests": 1,
                "max_cost_usd": 1.0,
            },
        )
        actor = {"kind": "system", "id": "power-controller"}
        await repository.append_event(
            run["id"],
            "power.command.observed",
            {"state": "queued", "action_type": None},
            actor=actor,
            idempotency_key="power-console-queued",
        )
        await repository.append_event(
            run["id"],
            "power.command.observed",
            {
                "state": "running",
                "racer_id": "racer-a",
                "label": "A",
                "turn_count": 1,
                "action_type": "fs.ls",
                "action_summary": "Mapping workspace files.",
                "observation_received": True,
                "observation_count": 1,
            },
            actor=actor,
            idempotency_key="power-console-action-1",
        )
        await repository.append_event(
            run["id"],
            "power.command.observed",
            {
                # Old snapshots could repeat this receipt while a sibling
                # progressed. The console must still report one action.
                "state": "running",
                "racer_id": "racer-a",
                "turn_count": 1,
                "action_type": "fs.ls",
            },
            actor=actor,
            idempotency_key="power-console-action-2",
        )
        await repository.append_event(
            run["id"],
            "power.command.observed",
            {
                "state": "running",
                "racer_id": "racer-a",
                "turn_count": 2,
                "action_type": "fs.read",
            },
            actor=actor,
            idempotency_key="power-console-action-3",
        )
        await repository.append_event(
            run["id"],
            "power.budget.progress",
            {
                "max_cost_microusd": 1_000_000,
                "reserved_cost_microusd": 500_000,
                "remaining_cost_microusd": 500_000,
                "reservation_count": 5,
                "exhausted_reason": None,
            },
            actor=actor,
            idempotency_key="power-console-budget",
        )
        await repository.append_event(
            run["id"],
            "power.candidate.review.confirmed",
            {
                "summary": "Racer B candidate confirmed for independent verification.",
                "label": "B",
                "session_id": "power-session-b",
            },
            actor=actor,
            idempotency_key="power-console-candidate-confirmed",
        )

        snapshot = await build_console_snapshot(repository, run["id"])
        tool_budget = next(item for item in snapshot["budgets"] if item["id"] == "tool_calls")
        cost_budget = next(item for item in snapshot["budgets"] if item["id"] == "cost")
        power_action = next(item for item in snapshot["events"] if item["tool_name"] == "fs.ls")
        candidate_confirmation = next(
            item
            for item in snapshot["events"]
            if item["title"] == "Power candidate review confirmed"
        )
        assert tool_budget["used"] == 2
        assert cost_budget == {
            "id": "cost",
            "label": "Reserved cost",
            "used": 0.5,
            "limit": 1.0,
            "unit": "USD",
        }
        assert power_action["tool_name"] == "fs.ls"
        assert power_action["details"] == [
            {"label": "Racer", "content": {"value": "A", "classification": "public"}},
            {"label": "State", "content": {"value": "running", "classification": "public"}},
            {"label": "Turn", "content": {"value": "1", "classification": "public"}},
            {"label": "Action", "content": {"value": "fs.ls", "classification": "public"}},
            {
                "label": "Activity",
                "content": {"value": "Mapping workspace files.", "classification": "public"},
            },
            {
                "label": "Evidence",
                "content": {
                    "value": "Captured immutable observation.",
                    "classification": "public",
                },
            },
            {"label": "Evidence count", "content": {"value": "1", "classification": "public"}},
        ]
        assert candidate_confirmation["details"] == [
            {"label": "Racer", "content": {"value": "B", "classification": "public"}},
        ]
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_console_projects_observed_pi_usage_without_a_transcript(tmp_path: Path) -> None:
    """Pi usage is useful to an operator but remains counter-only telemetry."""

    database, repository = await _repository(tmp_path)
    try:
        manifest = _manifest()
        challenge = await repository.create_challenge(
            manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
            name="power-console-pi-usage",
        )
        run = await repository.create_run(
            challenge["id"],
            mode="assisted",
            provider="power-swarm",
            budget={
                "wall_time_seconds": 60,
                "max_tool_calls": 4,
                "max_http_requests": 1,
                "max_cost_usd": 1.0,
            },
        )
        await repository.append_event(
            run["id"],
            "power.pi.usage",
            {
                "summary": "Racer A: Pi usage settled.",
                "label": "A",
                "input_tokens": 120,
                "output_tokens": 30,
                "cache_read_tokens": 10,
                "cache_write_tokens": 0,
                "cost_usd": 0.03125,
                "compacted": 1,
                "budget_accepted": True,
            },
            actor={"kind": "service", "id": "pi-runner"},
            idempotency_key="power-console-pi-usage",
        )

        snapshot = await build_console_snapshot(repository, run["id"])
        cost_budget = next(item for item in snapshot["budgets"] if item["id"] == "cost")
        usage_event = next(item for item in snapshot["events"] if item["title"] == "Power pi usage")
        assert cost_budget == {
            "id": "cost",
            "label": "Observed cost",
            "used": 0.03125,
            "limit": 1.0,
            "unit": "USD",
        }
        assert usage_event["details"] == [
            {"label": "Racer", "content": {"value": "A", "classification": "public"}},
            {"label": "Input", "content": {"value": "120", "classification": "public"}},
            {"label": "Output", "content": {"value": "30", "classification": "public"}},
            {
                "label": "Context",
                "content": {"value": "Compacted 1 time(s)", "classification": "public"},
            },
        ]
        assert "fixture" not in json.dumps(usage_event)
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_triage_rejects_category_drift_and_marks_the_run_failed(tmp_path: Path) -> None:
    challenge_root = tmp_path / "challenge"
    input_path = challenge_root / "inputs" / "challenge.txt"
    input_path.parent.mkdir(parents=True)
    input_path.write_text("ciphertext: 48656c6c6f", encoding="utf-8")
    database, repository = await _repository(tmp_path)
    backend = FakeTriageBackend(_completion(category="web"))
    try:
        with pytest.raises(TriageProposalError, match="triage_category_conflicts_with_manifest"):
            await TriageOrchestrator(repository=repository, artifact_root=tmp_path / "runtime").run(
                manifest=_manifest(),
                challenge_root=challenge_root,
                backend=backend,
                api_key="sk-live-key-never-persisted-123456789",
                model="operator-selected-model",
            )
        runs = await repository.list_runs()
        assert len(runs) == 1
        assert runs[0]["status"] == "failed"
        assert (await repository.blackboard(runs[0]["id"]))["experiments"] == []
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_triage_rejects_citations_to_evidence_excluded_from_model_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge_root = tmp_path / "challenge"
    input_path = challenge_root / "inputs" / "challenge.txt"
    input_path.parent.mkdir(parents=True)
    input_path.write_text("ciphertext: 48656c6c6f", encoding="utf-8")
    database, repository = await _repository(tmp_path)
    backend = FakeTriageBackend(_completion())
    orchestrator = TriageOrchestrator(repository=repository, artifact_root=tmp_path / "runtime")
    monkeypatch.setattr(
        TriageOrchestrator,
        "_bound_evidence",
        staticmethod(
            lambda evidence: tuple(item for item in evidence if item.id == "challenge-context")
        ),
    )
    try:
        with pytest.raises(TriageProposalError, match="fact_cites_unsupplied_evidence"):
            await orchestrator.run(
                manifest=_manifest(),
                challenge_root=challenge_root,
                backend=backend,
                api_key="sk-live-key-never-persisted-123456789",
                model="operator-selected-model",
            )
        assert len(backend.requests) == 1
        assert {item.id for item in backend.requests[0].evidence} == {"challenge-context"}
        runs = await repository.list_runs()
        assert len(runs) == 1
        assert runs[0]["status"] == "failed"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_triage_requires_manifest_profiles_before_calling_a_model(tmp_path: Path) -> None:
    challenge_root = tmp_path / "challenge"
    (challenge_root / "inputs").mkdir(parents=True)
    (challenge_root / "inputs" / "challenge.txt").write_text("safe", encoding="utf-8")
    database, repository = await _repository(tmp_path)
    backend = FakeTriageBackend(_completion())
    try:
        with pytest.raises(TriageConfigurationError, match="triage_tools_not_declared"):
            await TriageOrchestrator(repository=repository, artifact_root=tmp_path / "runtime").run(
                manifest=_manifest(tools=["files.list"]),
                challenge_root=challenge_root,
                backend=backend,
                api_key="sk-live-key-never-persisted-123456789",
                model="operator-selected-model",
            )
        assert backend.requests == []
        assert await repository.list_runs() == []
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_triage_rejects_network_target_before_calling_a_model(tmp_path: Path) -> None:
    challenge_root = tmp_path / "challenge"
    (challenge_root / "inputs").mkdir(parents=True)
    (challenge_root / "inputs" / "challenge.txt").write_text("safe", encoding="utf-8")
    manifest_data = _manifest().model_dump(mode="json", by_alias=True)
    manifest_data["spec"]["target"] = {
        "type": "remote",
        "healthcheck": {"url": "http://lab.test:8080/health", "expected_status": 200},
        "allowed_endpoints": [{"host": "lab.test", "ports": [8080], "protocols": ["http"]}],
    }
    manifest = ChallengeManifest.model_validate(manifest_data)
    database, repository = await _repository(tmp_path)
    backend = FakeTriageBackend(_completion())
    try:
        with pytest.raises(TriageConfigurationError, match="triage_target_must_be_artifact_bundle"):
            await TriageOrchestrator(repository=repository, artifact_root=tmp_path / "runtime").run(
                manifest=manifest,
                challenge_root=challenge_root,
                backend=backend,
                api_key="sk-live-key-never-persisted-123456789",
                model="operator-selected-model",
            )
        assert backend.requests == []
        assert await repository.list_runs() == []
    finally:
        await database.close()
