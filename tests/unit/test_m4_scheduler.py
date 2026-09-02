"""M4 scheduler, Hint Card, and falsifier regression coverage.

These tests drive the same durable repository paths used by Pi Runner.  They
do not use a model, target, shell, or network service: M4 scheduling decisions
must be explainable from reviewed templates and sealed preflight evidence.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from ctfmesh_db import Database, Repository
from ctfmesh_domain import (
    AgentRole,
    BranchScoreFactors,
    ChallengeManifest,
    FindingSubmission,
    HintCard,
    HintDirective,
    TaskDelegationRequest,
    ToolInvocationRequest,
    ToolInvocationState,
    agent_role_tool_ids,
)
from ctfmesh_orchestrator import (
    RunEngine,
    branch_score,
    hint_template,
    hint_templates,
    prompt_skill_pack_ids,
    rank_branches,
    role_prompt_contracts,
    task_template_for_hint,
)
from ctfmesh_orchestrator.scheduler import ScheduledBranch


def _manifest() -> ChallengeManifest:
    """Return an offline fixture; M4 never needs an unbounded target for policy tests."""

    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {"name": "m4-scheduler-contract", "category": "web"},
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
                    "wall_time_seconds": 600,
                    "max_worker_turns": 20,
                    "max_tool_calls": 20,
                    "max_http_requests": 10,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1.0,
                    "max_artifact_bytes": 1_000_000,
                },
                "providers": {"preferred": "fixture", "fallbacks": []},
                "memory": {
                    "namespace": "m4-scheduler-contract",
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


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'm4-scheduler.db'}")
    await database.create_schema()
    try:
        yield Repository(database)
    finally:
        await database.close()


async def _running_run(repository: Repository, tmp_path: Path) -> dict[str, Any]:
    """Create one run and let the deterministic preflight seal its evidence."""

    manifest = _manifest()
    challenge = await repository.create_challenge(
        manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
        name="m4-scheduler-contract",
    )
    engine = RunEngine(repository=repository, artifact_root=tmp_path / "artifacts")
    run = await engine.start(
        challenge_id=challenge["id"],
        mode="assisted",
        provider="fixture",
        budget={
            "wall_time_seconds": 300,
            "max_tool_calls": 8,
            "max_http_requests": 4,
            "max_cost_usd": 0.5,
        },
        idempotency_key="m4-run-start",
    )
    assert await engine.process_next_preflight(worker_id="m4-preflight") is not None
    assert run["status"] == "preparing"
    return run


def _mapping(value: object) -> Mapping[str, Any]:
    assert isinstance(value, Mapping)
    return value


def _identifier(value: object) -> str:
    assert isinstance(value, str)
    return value


def _lease_version(job: Mapping[str, Any]) -> int:
    value = job.get("lease_version")
    assert isinstance(value, int)
    return value


async def _activate_next_session(
    repository: Repository,
    *,
    runner_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Claim and activate the next durable Pi start job without creating Pi itself."""

    start_job = await repository.claim_agent_job(
        worker_id=runner_id,
        lease_seconds=60,
        kinds=("start_session",),
    )
    assert start_job is not None
    start = _mapping(start_job)
    reservation = await repository.reserve_pi_session(
        _identifier(start["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(start),
    )
    session = _mapping(_mapping(reservation)["session"])
    activated = await repository.activate_pi_session(
        _identifier(start["id"]),
        session_id=_identifier(session["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(start),
    )
    assert _mapping(activated)["state"] == "ready"
    return start, session


async def _lease_next_turn(
    repository: Repository,
    *,
    runner_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Open one queued turn so a test uses the same lease gates as Pi Runner."""

    job = await repository.claim_agent_job(
        worker_id=runner_id,
        lease_seconds=60,
        kinds=("run_turn",),
    )
    assert job is not None
    turn = _mapping(job)
    work = _mapping(
        await repository.get_pi_agent_job_work(
            _identifier(turn["id"]),
            worker_id=runner_id,
            lease_version=_lease_version(turn),
        )
    )
    return turn, work


def _first_evidence_id(work: Mapping[str, Any]) -> str:
    context = _mapping(work["context_manifest"])
    evidence_refs = context.get("evidence_refs")
    assert isinstance(evidence_refs, list) and evidence_refs
    return _identifier(_mapping(evidence_refs[0])["observation_id"])


async def _attach_hint(
    repository: Repository,
    *,
    run_id: str,
    directive: HintDirective,
    priority: int = 4,
    note: str = "",
    suffix: str,
) -> dict[str, Any]:
    """Attach a checked-in template; arbitrary technique creation is impossible."""

    template = hint_template("web.path_traversal.suspect.v1")
    assert template is not None
    now = datetime.now(UTC)
    card = HintCard(
        id=f"hint-m4-{suffix}",
        run_id=run_id,
        template_id=template.id,
        template_version=template.version,
        technique_id=template.technique_id,
        category=template.category,
        directive=directive,
        target_ref="run:all",
        priority=priority,
        note=note,
        actor_id="m4-operator",
        created_at=now,
        updated_at=now,
    )
    return await repository.create_hint_card(
        card,
        template=template,
        idempotency_key=f"m4-hint-{suffix}",
    )


def test_reviewed_scheduler_policy_is_scored_and_pinned() -> None:
    """The scheduler remains a tiny deterministic policy, not an agent framework."""

    templates = hint_templates()
    assert [template.id for template in templates] == [
        "web.path_traversal.suspect.v1",
        "web.authz_boundary.suspect.v1",
        "web.sqli_basic.suspect.v1",
    ]
    path_template = templates[0]
    probe_template = templates[-1]
    probe = task_template_for_hint(
        probe_template,
        role=AgentRole.HTTP_TESTER,
        directive=HintDirective.REQUIRE_PROBE,
    )
    assert probe.requires_control is True
    assert "parameterized-query evidence" in probe.objective
    with pytest.raises(ValueError, match="avoid_hint_has_no_task_template"):
        task_template_for_hint(
            path_template,
            role=AgentRole.SOURCE_AUDITOR,
            directive=HintDirective.AVOID,
        )

    strong = BranchScoreFactors(
        evidence_strength=1.0,
        novelty=1.0,
        hint_priority=1.0,
        expected_value=1.0,
        normalized_cost=0.0,
        repetition_penalty=0.0,
    )
    expensive_repeat = strong.model_copy(update={"normalized_cost": 1.0, "repetition_penalty": 1.0})
    assert branch_score(strong) == 0.95
    assert branch_score(expensive_repeat) == -0.25
    ranked = rank_branches(
        (
            ScheduledBranch(
                "branch-repeat",
                "web.path_traversal",
                AgentRole.SOURCE_AUDITOR,
                expensive_repeat,
                "active",
            ),
            ScheduledBranch(
                "branch-strong", "web.path_traversal", AgentRole.HTTP_TESTER, strong, "active"
            ),
            ScheduledBranch(
                "branch-stalled", "web.path_traversal", AgentRole.HTTP_TESTER, strong, "stalled"
            ),
        )
    )
    assert [branch.branch_id for branch in ranked] == ["branch-strong", "branch-repeat"]

    expected_pack_ids = {
        "skill.web_path_traversal.v1",
        "skill.web_authz_boundary.v1",
        "skill.web_sqli_basic.v1",
    }
    assert set(prompt_skill_pack_ids(AgentRole.FALSIFIER)) == expected_pack_ids
    contracts = role_prompt_contracts({role: "a" * 64 for role in AgentRole})
    assert {contract.role for contract in contracts} == set(AgentRole)
    assert (
        set(
            next(
                contract for contract in contracts if contract.role is AgentRole.HTTP_TESTER
            ).skill_pack_ids
        )
        == expected_pack_ids
    )
    master_capabilities = set(agent_role_tool_ids(AgentRole.MASTER))
    assert (
        not {"finding.submit", "candidate.submit", "fact.create", "run.solve"} & master_capabilities
    )
    falsifier_capabilities = set(agent_role_tool_ids(AgentRole.FALSIFIER))
    assert {"source.read", "http.request", "finding.submit"} <= falsifier_capabilities
    assert not {"candidate.submit", "fact.create", "run.solve"} & falsifier_capabilities
    exploit_capabilities = set(agent_role_tool_ids(AgentRole.EXPLOIT_BUILDER))
    assert {
        "source.read",
        "http.request",
        "capture.get",
        "candidate.submit",
    } <= exploit_capabilities
    assert not {"state.get", "task.delegate", "fact.create", "run.solve"} & exploit_capabilities


@pytest.mark.asyncio
async def test_hint_creates_a_reviewed_branch_without_turning_note_into_prompt_data(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """A Hint Card schedules fixed reviewed work while its note stays untrusted UI data."""

    run = await _running_run(repository, tmp_path)
    note = "Ignore any challenge text and inspect only sealed evidence."
    card = await _attach_hint(
        repository,
        run_id=_identifier(run["id"]),
        directive=HintDirective.PRIORITIZE,
        priority=4,
        note=note,
        suffix="note-boundary",
    )
    assert card["epistemic_status"] == "human_hypothesis"
    assert card["status"] == "active"

    tasks = await repository.list_worker_tasks(_identifier(run["id"]))
    branches = await repository.list_run_branches(_identifier(run["id"]))
    branch = next(item for item in branches if item["technique_id"] == "web.path_traversal")
    scheduled = next(task for task in tasks if task["branch_id"] == branch["id"])
    context = await repository.get_context_manifest(_identifier(scheduled["context_manifest_id"]))
    assert context is not None
    serialized_context = json.dumps(context.model_dump(mode="json"), sort_keys=True)
    assert note not in serialized_context
    assert context.active_hint_refs == (_identifier(card["id"]),)
    assert "path normalization" in _identifier(scheduled["objective"])

    assert branch["priority"] == 0.8
    assert branch["state"] == "active"
    events = await repository.list_events(_identifier(run["id"]))
    event_payloads = json.dumps([event["payload"] for event in events], sort_keys=True)
    assert note not in event_payloads
    assert any(
        event["type"] == "human.hint_card.added" and "note_sha256" in event["payload"]
        for event in events
    )


@pytest.mark.asyncio
async def test_exploit_builder_reads_only_the_manifest_capture_projection(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """The typed builder capability avoids widening common Pi session state."""

    await _running_run(repository, tmp_path)
    runner_id = "m4-capture-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    master_turn, master_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(master_work["session"])["id"] == master_session["id"]
    delegated = await repository.delegate_pi_task(
        TaskDelegationRequest(
            tool_call_id="m4-capture-builder",
            role=AgentRole.EXPLOIT_BUILDER,
            technique_id="general.review",
            objective="Build one declarative plan from sealed observations.",
            evidence_ids=(_first_evidence_id(master_work),),
        ),
        job_id=_identifier(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(master_turn),
    )
    assert delegated["task"]["role"] == AgentRole.EXPLOIT_BUILDER.value
    await repository.complete_pi_turn(
        _identifier(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(master_turn),
        result_ref="agent:delegated",
    )
    _, builder_session = await _activate_next_session(repository, runner_id=runner_id)
    builder_turn, builder_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(builder_work["session"])["id"] == builder_session["id"]

    capture = await repository.pi_flag_capture_patterns_view(
        _identifier(builder_session["id"]),
        job_id=_identifier(builder_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(builder_turn),
    )

    assert capture == {"flag_capture_patterns": (r"CTF\{[A-Za-z0-9_:-]+\}",)}


@pytest.mark.asyncio
async def test_avoid_blocks_new_tasks_and_a_leased_worker_tool_with_audit(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """An avoid card takes effect both before task creation and before dispatch."""

    run = await _running_run(repository, tmp_path)
    run_id = _identifier(run["id"])
    await _attach_hint(
        repository,
        run_id=run_id,
        directive=HintDirective.EXPLORE,
        suffix="avoid-base",
    )
    runner_id = "m4-avoid-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    _, source_session = await _activate_next_session(repository, runner_id=runner_id)
    master_turn, master_work = await _lease_next_turn(repository, runner_id=runner_id)
    source_turn, source_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(master_work["session"])["id"] == master_session["id"]
    assert _mapping(source_work["session"])["id"] == source_session["id"]

    # Creating the avoid after source turn activation proves that the tool
    # gateway has an independent deny path for already-leased work.
    await _attach_hint(
        repository,
        run_id=run_id,
        directive=HintDirective.AVOID,
        suffix="avoid-gate",
    )
    denied = await repository.reserve_pi_tool_invocation(
        ToolInvocationRequest(
            tool_call_id="m4-avoid-source-search",
            tool_name="source.search",
            tool_version="1.0.0",
            idempotency_key="m4-avoid-source-search",
            input_digest="a" * 64,
        ),
        job_id=_identifier(source_turn["id"]),
        session_id=_identifier(source_session["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(source_turn),
        policy_decision="allow",
        policy_reason="reviewed_source_read_only",
    )
    assert denied.state is ToolInvocationState.DENIED
    assert denied.policy_reason == "hint_avoid_blocks_tool"

    evidence_id = _first_evidence_id(master_work)
    with pytest.raises(ValueError, match="hint_avoid_blocks_task"):
        await repository.delegate_pi_task(
            TaskDelegationRequest(
                tool_call_id="m4-avoid-delegate",
                role=AgentRole.HTTP_TESTER,
                technique_id="web.path_traversal",
                objective="Run one bounded control request.",
                evidence_ids=(evidence_id,),
            ),
            job_id=_identifier(master_turn["id"]),
            worker_id=runner_id,
            lease_version=_lease_version(master_turn),
        )
    events = await repository.list_events(run_id)
    assert any(
        event["type"] == "tool.policy_denied"
        and event["payload"]["reason"] == "hint_avoid_blocks_tool"
        for event in events
    )


@pytest.mark.asyncio
async def test_conflicting_worker_findings_queue_one_independent_falsifier(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """Opposite evidence-backed findings wake a bounded falsifier, not a council swarm."""

    run = await _running_run(repository, tmp_path)
    run_id = _identifier(run["id"])
    await _attach_hint(
        repository,
        run_id=run_id,
        directive=HintDirective.PRIORITIZE,
        suffix="conflict",
    )
    runner_id = "m4-conflict-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    master_turn, master_work = await _lease_next_turn(repository, runner_id=runner_id)
    evidence_id = _first_evidence_id(master_work)
    delegated = await repository.delegate_pi_task(
        TaskDelegationRequest(
            tool_call_id="m4-http-control",
            role=AgentRole.HTTP_TESTER,
            technique_id="web.path_traversal",
            objective="Compare one bounded control response.",
            evidence_ids=(evidence_id,),
        ),
        job_id=_identifier(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(master_turn),
    )
    assert delegated["task"]["role"] == AgentRole.HTTP_TESTER.value
    await repository.complete_pi_turn(
        _identifier(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(master_turn),
        result_ref="agent:delegated",
    )

    # The hint's source task was committed before the master delegation.
    _, source_session = await _activate_next_session(repository, runner_id=runner_id)
    source_turn, source_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(source_work["session"])["id"] == source_session["id"]
    source_finding = await repository.submit_pi_finding(
        FindingSubmission(
            session_id=_identifier(source_session["id"]),
            tool_call_id="m4-source-support",
            statement="The sealed source observation supports the bounded path hypothesis.",
            evidence_ids=(_first_evidence_id(source_work),),
            confidence=0.6,
            disposition="supports",
        ),
        job_id=_identifier(source_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(source_turn),
    )
    await repository.complete_pi_turn(
        _identifier(source_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(source_turn),
        result_ref=f"finding:{source_finding['finding_id']}",
    )

    _, http_session = await _activate_next_session(repository, runner_id=runner_id)
    http_turn, http_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(http_work["session"])["id"] == http_session["id"]
    await repository.submit_pi_finding(
        FindingSubmission(
            session_id=_identifier(http_session["id"]),
            tool_call_id="m4-http-contradiction",
            statement="The bounded control observation contradicts the path hypothesis.",
            evidence_ids=(_first_evidence_id(http_work),),
            confidence=0.95,
            disposition="contradicts",
        ),
        job_id=_identifier(http_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(http_turn),
    )

    tasks = await repository.list_worker_tasks(run_id)
    assert [task["role"] for task in tasks].count(AgentRole.FALSIFIER.value) == 1
    events = await repository.list_events(run_id)
    queued = next(event for event in events if event["type"] == "scheduler.falsifier.queued")
    assert queued["payload"]["trigger"] == "conflicting_findings"
    # The parent master remains control-only; it was never granted evidence,
    # fact, candidate, verifier, or solved-state mutation authority.
    assert master_session["role"] == AgentRole.MASTER.value


@pytest.mark.asyncio
async def test_duplicate_worker_attempt_fingerprint_is_denied_after_the_first_task_finishes(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """A new model tool-call ID cannot rerun the same reviewed worker attempt."""

    run = await _running_run(repository, tmp_path)
    run_id = _identifier(run["id"])
    await _attach_hint(
        repository,
        run_id=run_id,
        directive=HintDirective.PRIORITIZE,
        suffix="dedupe",
    )
    runner_id = "m4-dedupe-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    _, initial_source_session = await _activate_next_session(repository, runner_id=runner_id)
    master_turn, master_work = await _lease_next_turn(repository, runner_id=runner_id)
    source_turn, source_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(master_work["session"])["id"] == master_session["id"]
    assert _mapping(source_work["session"])["id"] == initial_source_session["id"]
    await repository.complete_pi_turn(
        _identifier(source_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(source_turn),
        result_ref="agent:inconclusive",
    )

    evidence_id = _first_evidence_id(master_work)
    first_request = TaskDelegationRequest(
        tool_call_id="m4-dedupe-first",
        role=AgentRole.SOURCE_AUDITOR,
        technique_id="web.path_traversal",
        objective="Inspect one sealed source-evidence hypothesis.",
        evidence_ids=(evidence_id,),
    )
    await repository.delegate_pi_task(
        first_request,
        job_id=_identifier(master_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(master_turn),
    )
    _, duplicate_source_session = await _activate_next_session(repository, runner_id=runner_id)
    duplicate_source_turn, duplicate_source_work = await _lease_next_turn(
        repository,
        runner_id=runner_id,
    )
    assert _mapping(duplicate_source_work["session"])["id"] == duplicate_source_session["id"]
    await repository.complete_pi_turn(
        _identifier(duplicate_source_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(duplicate_source_turn),
        result_ref="agent:inconclusive",
    )

    # A changed Pi tool-call ID creates a new request identity, but every
    # reviewed input to the canonical M4 fingerprint is identical.
    with pytest.raises(ValueError, match="attempt_fingerprint_exists"):
        await repository.delegate_pi_task(
            first_request.model_copy(update={"tool_call_id": "m4-dedupe-second"}),
            job_id=_identifier(master_turn["id"]),
            worker_id=runner_id,
            lease_version=_lease_version(master_turn),
        )


@pytest.mark.asyncio
async def test_two_empty_master_turns_stall_then_use_reviewed_fallback(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """Schema/prose stalls select one ranked reviewed branch instead of model prose."""

    run = await _running_run(repository, tmp_path)
    run_id = _identifier(run["id"])
    await _attach_hint(
        repository,
        run_id=run_id,
        directive=HintDirective.PRIORITIZE,
        priority=5,
        suffix="fallback",
    )
    runner_id = "m4-fallback-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    first_turn, first_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(first_work["session"])["id"] == master_session["id"]
    await repository.complete_pi_turn(
        _identifier(first_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(first_turn),
        result_ref="agent:inconclusive",
    )
    retry_turn, retry_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(retry_work["session"])["id"] == master_session["id"]
    await repository.complete_pi_turn(
        _identifier(retry_turn["id"]),
        worker_id=runner_id,
        lease_version=_lease_version(retry_turn),
        result_ref="agent:inconclusive",
    )

    branches = await repository.list_run_branches(run_id)
    master_branch = next(
        branch for branch in branches if branch["id"] == first_work["task"]["branch_id"]
    )
    assert master_branch["state"] == "stalled"
    tasks = await repository.list_worker_tasks(run_id)
    fallback = next(task for task in tasks if task["role"] == AgentRole.HTTP_TESTER.value)
    fallback_branch = next(branch for branch in branches if branch["id"] == fallback["branch_id"])
    assert fallback_branch["technique_id"] == "web.path_traversal"
    assert fallback["state"] == "queued"
    events = await repository.list_events(run_id)
    assert any(event["type"] == "scheduler.fallback.queued" for event in events)


@pytest.mark.asyncio
async def test_pause_resume_and_cancel_keep_audit_but_block_new_pi_work(
    repository: Repository,
    tmp_path: Path,
) -> None:
    """Lifecycle controls stop new work and queue aborts without deleting evidence."""

    run = await _running_run(repository, tmp_path)
    run_id = _identifier(run["id"])
    paused = await repository.transition_run(
        run_id,
        "paused",
        actor={"kind": "human", "id": "m4-operator"},
        reason="m4_pause_check",
        idempotency_key="m4-pause",
    )
    assert paused["status"] == "paused"
    assert (
        await repository.claim_agent_job(
            worker_id="m4-pause-runner",
            lease_seconds=30,
            kinds=("start_session",),
        )
        is None
    )
    resumed = await repository.transition_run(
        run_id,
        "running",
        actor={"kind": "human", "id": "m4-operator"},
        reason="m4_resume_check",
        idempotency_key="m4-resume",
    )
    assert resumed["status"] == "running"

    runner_id = "m4-cancel-runner"
    _, master_session = await _activate_next_session(repository, runner_id=runner_id)
    master_turn, master_work = await _lease_next_turn(repository, runner_id=runner_id)
    assert _mapping(master_work["session"])["id"] == master_session["id"]
    abort_jobs = await repository.request_pi_abort(
        run_id,
        idempotency_key="m4-cancel",
        requested_by="m4-operator",
    )
    assert len(abort_jobs) == 1
    cancelled = await repository.get_run(run_id)
    assert cancelled is not None
    assert cancelled["status"] == "cancelled"
    assert (
        await repository.claim_agent_job(
            worker_id=runner_id,
            lease_seconds=30,
            kinds=("run_turn",),
        )
        is None
    )
    # The current leased turn cannot be completed into new scheduler work
    # after cancellation; the remaining abort job is the only Pi action.
    with pytest.raises(ValueError, match="pi_turn_session_lease_lost"):
        await repository.complete_pi_turn(
            _identifier(master_turn["id"]),
            worker_id=runner_id,
            lease_version=_lease_version(master_turn),
            result_ref="agent:inconclusive",
        )
    events = await repository.list_events(run_id)
    assert any(event["type"] == "run.state.changed" for event in events)
    assert any(event["type"] == "agent.abort.requested" for event in events)
