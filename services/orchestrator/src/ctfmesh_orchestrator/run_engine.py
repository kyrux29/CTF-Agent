"""Durable, deterministic v0.1 run kernel and test-only fake vertical slice.

The engine owns state transitions and consumes typed database jobs. It does not
call a model, execute challenge code, invoke a CTF tool, or reach a target. The
fake harness below is deliberately opt-in for tests and proves only the ledger
and verifier flow before Pi or real tools are introduced in later milestones.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ctfmesh_db import Repository
from ctfmesh_domain import (
    ActorKind,
    ActorRef,
    AgentRole,
    ChallengeManifest,
    CleanReplay,
    ContextBudgetSlice,
    ContextEvidenceRef,
    ContextManifest,
    PreflightObservation,
    RuntimeArtifact,
    RuntimeTask,
    VerificationProof,
    agent_role_tool_ids,
)
from ctfmesh_tools import LocalArtifactStore

from .preflight import (
    DeterministicPreflight,
    PreflightError,
    PreflightPayload,
    canonical_preflight_bytes,
)


class RunEngineError(RuntimeError):
    """Stable, secret-free failure surfaced by the deterministic kernel."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RunEngine:
    """Own the M1 state/job flow without granting a model execution authority."""

    def __init__(
        self,
        *,
        repository: Repository,
        artifact_root: Path,
        preflight: DeterministicPreflight | None = None,
        source_roots: Mapping[str, Path] | None = None,
        preflight_timeout_seconds: float = 15.0,
    ) -> None:
        if (
            isinstance(preflight_timeout_seconds, bool)
            or not isinstance(preflight_timeout_seconds, int | float)
            or not 1 <= float(preflight_timeout_seconds) <= 60
        ):
            raise ValueError("invalid_preflight_timeout_seconds")
        self.repository = repository
        self.preflight = preflight or DeterministicPreflight()
        # The mapping is injected only by a trusted composition root or test;
        # no API request can supply an arbitrary host path to preflight.
        self._source_roots = {
            challenge_id: root.resolve() for challenge_id, root in (source_roots or {}).items()
        }
        self._artifact_root = artifact_root.resolve()
        self._preflight_timeout_seconds = float(preflight_timeout_seconds)
        self._artifacts = LocalArtifactStore(self._artifact_root / "runtime-kernel")

    async def start(
        self,
        *,
        challenge_id: str,
        mode: str,
        provider: str,
        budget: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create the run and durable preflight job in one database transaction."""

        return await self.repository.create_preparing_run(
            challenge_id,
            mode=mode,
            provider=provider,
            budget=budget,
            idempotency_key=idempotency_key,
        )

    async def process_next_preflight(
        self,
        *,
        worker_id: str = "preflight-worker",
        lease_seconds: int = 30,
    ) -> dict[str, Any] | None:
        """Claim and finish one preflight job; normal API requests never call this."""

        job = await self.repository.claim_agent_job(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            kinds=("preflight",),
        )
        if job is None:
            return None
        try:
            return await self.process_claimed_preflight(job, worker_id=worker_id)
        except RunEngineError as exc:
            # The error codes exposed by this module are identifier-shaped and
            # carry no source path, exception message, secret, or raw flag.
            await self.repository.fail_agent_job(
                self._required_string(job, "id"),
                worker_id=worker_id,
                lease_version=self._required_positive_int(job, "lease_version"),
                reason=exc.code,
            )
            raise

    async def process_claimed_preflight(
        self,
        job: Mapping[str, Any],
        *,
        worker_id: str,
        enqueue_pi_session: bool = True,
    ) -> dict[str, Any]:
        """Materialize only deterministic observations for one leased preflight job."""

        job_id = self._required_string(job, "id")
        run_id = self._required_string(job, "run_id")
        if job.get("kind") != "preflight":
            raise RunEngineError("unexpected_agent_job_kind")
        lease_version = self._required_positive_int(job, "lease_version")
        if job.get("lease_owner") != worker_id:
            raise RunEngineError("agent_job_lease_owner_mismatch")
        run = await self.repository.get_run(run_id)
        if run is None:
            raise RunEngineError("run_not_found")
        challenge = await self.repository.get_challenge(self._required_string(run, "challenge_id"))
        if challenge is None:
            raise RunEngineError("challenge_not_found")
        try:
            manifest = ChallengeManifest.model_validate(challenge["manifest"])
        except (TypeError, ValueError) as exc:
            raise RunEngineError("stored_challenge_manifest_invalid") from exc

        source_root = self._source_roots.get(challenge["id"])
        if source_root is None:
            source_root = self._bound_archive_source_root(manifest)
        try:
            payloads = await asyncio.wait_for(
                asyncio.to_thread(
                    self.preflight.inspect,
                    challenge_digest=self._required_string(challenge, "digest"),
                    manifest=manifest,
                    source_root=source_root,
                ),
                timeout=self._preflight_timeout_seconds,
            )
        except PreflightError as exc:
            raise RunEngineError(exc.code) from exc
        except TimeoutError as exc:
            raise RunEngineError("preflight_timeout") from exc
        now = datetime.now(UTC)
        artifacts, observations = await self._persist_observation_artifacts(
            run_id=run_id,
            payloads=payloads,
            created_at=now,
        )
        task_id = self._new_id("task")
        context_id = self._new_id("ctx")
        branch_id = self._new_id("branch")
        evidence_refs = tuple(
            ContextEvidenceRef(
                observation_id=observation.id,
                artifact_id=observation.artifact_id,
                digest=observation.digest,
            )
            for observation in observations
        )
        # The production M2 flow starts with a capability-limited master. It
        # may create one worker task only through the kernel's typed
        # `task.delegate` boundary. The M1 fake harness deliberately retains a
        # source-auditor task so its historical deterministic fixture remains
        # independent of Pi scheduling.
        initial_role = AgentRole.MASTER if enqueue_pi_session else AgentRole.SOURCE_AUDITOR
        context_objective = (
            "Choose one evidence-backed worker task through the reviewed control tools."
            if initial_role is AgentRole.MASTER
            else "Review only the sealed deterministic preflight observations."
        )
        context = ContextManifest.issue(
            id=context_id,
            run_id=run_id,
            task_id=task_id,
            challenge_digest=challenge["digest"],
            role=initial_role.value,
            objective=context_objective,
            # M2 gives the master only control tools and workers only a
            # finding boundary. Source/HTTP capability stays absent until the
            # typed M3 tool gateway.
            allowed_tool_ids=agent_role_tool_ids(initial_role),
            evidence_refs=evidence_refs,
            hypothesis_refs=(),
            active_hint_refs=(),
            attempt_fingerprints=(),
            budget_slice=ContextBudgetSlice(
                tool_calls=min(8, manifest.spec.limits.max_tool_calls),
                input_tokens=12_000,
                output_tokens=1_800,
            ),
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        task = RuntimeTask(
            id=task_id,
            run_id=run_id,
            branch_id=branch_id,
            role=initial_role.value,
            objective=context_objective,
            required_evidence=tuple(observation.id for observation in observations),
            context_manifest_id=context.id,
            lease_version=0,
            deadline_at=now + timedelta(seconds=min(manifest.spec.limits.wall_time_seconds, 900)),
        )
        return await self.repository.complete_preflight_job(
            job_id,
            worker_id=worker_id,
            lease_version=lease_version,
            branch_family="deterministic-preflight",
            artifacts=artifacts,
            observations=observations,
            context_manifest=context,
            task=task,
            enqueue_pi_session=enqueue_pi_session,
        )

    def _bound_archive_source_root(self, manifest: ChallengeManifest) -> Path | None:
        """Resolve only a manifest-validated intake receipt under artifacts.

        M6.a never accepts a filesystem location from an operator request.
        The optional source binding has already passed the domain's exact
        ``intake_<hex>`` contract, so this composition-time derivation cannot
        escape the service-owned archive-intake root.
        """

        source = manifest.spec.source
        if source is None:
            return None
        return self._artifact_root / "archive-intakes" / source.intake_id / "workspace"

    async def _persist_observation_artifacts(
        self,
        *,
        run_id: str,
        payloads: tuple[PreflightPayload, ...],
        created_at: datetime,
    ) -> tuple[tuple[RuntimeArtifact, ...], tuple[PreflightObservation, ...]]:
        artifacts: list[RuntimeArtifact] = []
        observations: list[PreflightObservation] = []
        producer = ActorRef(kind=ActorKind.SYSTEM, id="preflight-worker")
        for payload in payloads:
            body = canonical_preflight_bytes(payload)
            reference = await self._artifacts.put_bytes(
                body,
                run_id=run_id,
                mime_type="application/json",
                producer=producer,
                classification="internal",
            )
            artifact_id = self._new_id("artifact")
            observation_id = self._new_id("obs")
            artifacts.append(
                RuntimeArtifact(
                    id=artifact_id,
                    run_id=run_id,
                    sha256=reference.sha256,
                    name=f"preflight/{payload.kind.value}.json",
                    media_type="application/json",
                    size_bytes=reference.size_bytes,
                    classification="internal",
                    producer="preflight-worker",
                    locator=f"sha256:{reference.sha256}",
                    created_at=created_at,
                )
            )
            observations.append(
                PreflightObservation(
                    id=observation_id,
                    run_id=run_id,
                    kind=payload.kind,
                    artifact_id=artifact_id,
                    digest=reference.sha256,
                    summary=payload.summary,
                    created_at=created_at,
                )
            )
        return tuple(artifacts), tuple(observations)

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid4().hex}"

    @staticmethod
    def _required_string(value: Mapping[str, Any], key: str) -> str:
        selected = value.get(key)
        if not isinstance(selected, str) or not selected:
            raise RunEngineError(f"invalid_{key}")
        return selected

    @staticmethod
    def _required_positive_int(value: Mapping[str, Any], key: str) -> int:
        selected = value.get(key)
        if isinstance(selected, bool) or not isinstance(selected, int) or selected < 1:
            raise RunEngineError(f"invalid_{key}")
        return selected


class FakeRunHarness:
    """Explicit test/dev-only consumer proving M1's durable vertical slice.

    It is never registered by ``create_app``. The fixture cannot inspect a
    challenge, invoke tools, call a provider, or produce a raw flag; it merely
    drives already-sealed state through the independent verifier proof path.
    """

    lifecycle = "test-dev-only"

    def __init__(self, engine: RunEngine) -> None:
        self.engine = engine
        self.repository = engine.repository

    async def drain(
        self,
        *,
        worker_id: str = "fake-harness",
        max_jobs: int = 16,
    ) -> tuple[str, ...]:
        """Process a finite fixture queue, returning only completed job kinds."""

        if isinstance(max_jobs, bool) or not 1 <= max_jobs <= 64:
            raise ValueError("invalid_fake_harness_max_jobs")
        completed: list[str] = []
        for _ in range(max_jobs):
            job = await self.repository.claim_agent_job(
                worker_id=worker_id,
                lease_seconds=30,
                kinds=("preflight", "fake_harness", "fake_verify"),
            )
            if job is None:
                return tuple(completed)
            kind = str(job["kind"])
            if kind == "preflight":
                result = await self.engine.process_claimed_preflight(
                    job,
                    worker_id=worker_id,
                    # A fake vertical-slice test must not manufacture a real
                    # Pi job that no test consumer owns.
                    enqueue_pi_session=False,
                )
                context = result["context_manifest"]
                await self.repository.enqueue_agent_job(
                    result["run"]["id"],
                    kind="fake_harness",
                    payload_ref=f"context:{context['id']}",
                    payload_digest=str(context["digest"]),
                    idempotency_key="fake-harness:v1",
                    actor={"kind": "service", "id": worker_id},
                )
            elif kind == "fake_harness":
                await self._finish_fake_task(job, worker_id=worker_id)
            elif kind == "fake_verify":
                await self._finish_fake_verification(job, worker_id=worker_id)
            else:  # Defensive even though the repository validates known kinds.
                raise RunEngineError("unexpected_fake_harness_job")
            completed.append(kind)
        raise RunEngineError("fake_harness_job_limit_exceeded")

    async def _finish_fake_task(self, job: Mapping[str, Any], *, worker_id: str) -> None:
        run_id = RunEngine._required_string(job, "run_id")
        lease_version = RunEngine._required_positive_int(job, "lease_version")
        task = await self.repository.claim_worker_task(
            run_id,
            worker_id=worker_id,
            lease_seconds=30,
        )
        if task is None:
            raise RunEngineError("fake_harness_task_missing")
        context = await self.repository.get_context_manifest(str(task["context_manifest_id"]))
        if context is None or context.run_id != run_id:
            raise RunEngineError("fake_harness_context_missing")
        await self.repository.complete_worker_task(
            str(task["id"]),
            worker_id=worker_id,
            lease_version=int(task["lease_version"]),
            result_ref=f"context:{context.id}",
        )
        await self.repository.transition_run_state(
            run_id,
            "verifying",
            actor={"kind": "service", "id": worker_id},
            reason="fake_harness_completed_typed_context_only",
            idempotency_key=f"run:{run_id}:fake-verifying",
        )
        await self.repository.complete_agent_job(
            str(job["id"]),
            worker_id=worker_id,
            lease_version=lease_version,
            result_ref=f"task:{task['id']}",
        )
        await self.repository.enqueue_agent_job(
            run_id,
            kind="fake_verify",
            payload_ref=f"context:{context.id}",
            payload_digest=context.digest,
            idempotency_key="fake-verify:v1",
            actor={"kind": "service", "id": worker_id},
        )

    async def _finish_fake_verification(self, job: Mapping[str, Any], *, worker_id: str) -> None:
        run_id = RunEngine._required_string(job, "run_id")
        lease_version = RunEngine._required_positive_int(job, "lease_version")
        run = await self.repository.get_run(run_id)
        if run is None:
            raise RunEngineError("run_not_found")
        challenge = await self.repository.get_challenge(str(run["challenge_id"]))
        if challenge is None:
            raise RunEngineError("challenge_not_found")
        manifest = ChallengeManifest.model_validate(challenge["manifest"])
        now = datetime.now(UTC)
        replays = tuple(
            CleanReplay(
                attempt=index,
                reset_id=f"reset_{run_id[-12:]}_{index}",
                passed=True,
                started_from_clean_reset=True,
            )
            for index in range(1, manifest.spec.flag.replay_count + 1)
        )
        proof_body = json.dumps(
            {
                "schema": "ctfmesh.fake-verification-proof/v1",
                "challenge_digest": challenge["digest"],
                "replays": [replay.model_dump(mode="json") for replay in replays],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        reference = await self.engine._artifacts.put_bytes(
            proof_body,
            run_id=run_id,
            mime_type="application/json",
            producer=ActorRef(kind=ActorKind.VERIFIER, id="independent-verifier"),
            classification="internal",
        )
        proof_artifact = RuntimeArtifact(
            id=RunEngine._new_id("artifact"),
            run_id=run_id,
            sha256=reference.sha256,
            name="verification/fake-proof.json",
            media_type="application/json",
            size_bytes=reference.size_bytes,
            classification="internal",
            producer="independent-verifier",
            locator=f"sha256:{reference.sha256}",
            created_at=now,
        )
        await self.repository.add_artifact(proof_artifact.model_dump(mode="json"))
        proof = VerificationProof(
            id=RunEngine._new_id("proof"),
            run_id=run_id,
            artifact_id=proof_artifact.id,
            digest=reference.sha256,
            replays=replays,
            created_at=now,
        )
        await self.repository.record_verification(
            {
                "run_id": run_id,
                "verified": True,
                "exploit_digest": hashlib.sha256(b"fake-declarative-plan").hexdigest(),
                "environment_digest": hashlib.sha256(b"fake-clean-environment").hexdigest(),
                "flag_sha256": hashlib.sha256(b"opaque-verifier-flag-proof").hexdigest(),
                "masked_flag": "CTF{***verified***}",
                "verification_proof_ref": proof.artifact_id,
                "replay_results": [
                    {
                        "attempt": replay.attempt,
                        "reset_id": replay.reset_id,
                        "passed": replay.passed,
                        "started_from_clean_reset": replay.started_from_clean_reset,
                    }
                    for replay in proof.replays
                ],
                "provenance": {
                    "verification_proof_digest": proof.digest,
                    "fixture": "m1-deterministic-only",
                },
            }
        )
        await self.repository.complete_agent_job(
            str(job["id"]),
            worker_id=worker_id,
            lease_version=lease_version,
            result_ref=f"proof:{proof.id}",
        )


__all__ = ["FakeRunHarness", "RunEngine", "RunEngineError"]
