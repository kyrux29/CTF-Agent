"""Artifact-first, evidence-backed CTF triage without autonomous execution.

This is deliberately a narrow first AI slice. It copies only declared regular
files into a disposable run workspace, fingerprints them through the typed
tool runtime, and asks one structured model call for *proposals*. The model
cannot invoke tools, the orchestrator never executes its next actions, and a
triage run can only become ``completed`` — never ``solved``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ctfmesh_db import Repository
from ctfmesh_domain import ActorKind, ActorRef, ChallengeManifest
from ctfmesh_policy import ApprovalState, BudgetRemaining, PolicyDecisionPoint
from ctfmesh_provider_base import (
    TriageBackend,
    TriageCompletion,
    TriageEvidence,
    TriageRequest,
)
from ctfmesh_skills import (
    SkillCategory,
    SkillRegistry,
    SkillSelectionRequest,
    SkillSpec,
    builtin_skill_registry,
    skill_guidance,
)
from ctfmesh_tools import (
    ArtifactInspectTool,
    FilesListTool,
    LocalArtifactStore,
    ToolInvocationContext,
    ToolRegistry,
    ToolRequest,
    ToolRuntime,
)
from pydantic import BaseModel, ConfigDict, Field

from .readonly_workspace import (
    MAX_READONLY_ARTIFACT_BYTES,
    MaterializedArtifact,
    ReadonlyWorkspaceError,
    materialize_declared_artifacts,
    resolve_challenge_root,
)

_MAX_MODEL_EVIDENCE_BYTES = 128 * 1024
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}")
_BEARER_TOKEN = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)
_SECRET_KEY_MARKERS = frozenset(
    {"api_key", "apikey", "authorization", "cookie", "password", "secret", "token", "flag"}
)


class TriageRunError(RuntimeError):
    """Stable, secret-free error exposed to the CLI/control plane."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TriageConfigurationError(TriageRunError):
    """The manifest did not explicitly authorize this read-only triage slice."""


class TriageProposalError(TriageRunError):
    """The model output does not meet evidence or category invariants."""


class TriageRunResult(BaseModel):
    """Safe metadata for a completed triage run; it contains no raw evidence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    run_id: str = Field(min_length=1, max_length=160)
    challenge_id: str = Field(min_length=1, max_length=160)
    status: Literal["completed"]
    category: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=160)
    selected_skills: tuple[str, ...] = Field(min_length=1, max_length=32)
    proposal_artifact_id: str = Field(min_length=1, max_length=160)


@dataclass(frozen=True, slots=True)
class _EvidenceBinding:
    artifact_id: str
    digest: str
    locator: str


class TriageOrchestrator:
    """Run one category-aware, read-only CTF triage operation.

    The caller owns both the provider client and its in-memory API key. This
    class deliberately does not inspect environment variables, create network
    transports, or retain secrets after ``run`` returns.
    """

    def __init__(
        self,
        *,
        repository: Repository,
        artifact_root: Path,
        skills: SkillRegistry | None = None,
    ) -> None:
        self.repository = repository
        self.artifact_root = artifact_root.resolve()
        self.skills = skills or builtin_skill_registry()

    async def run(
        self,
        *,
        manifest: ChallengeManifest,
        challenge_root: Path,
        backend: TriageBackend,
        api_key: str,
        model: str,
        max_output_tokens: int = 900,
        provider_name: str = "openai-responses",
        timeout_seconds: float = 30.0,
    ) -> TriageRunResult:
        """Persist a bounded proposal run without executing model suggestions."""

        selected_skills = self._select_skills(manifest)
        normalized_model = self._require_model(model)
        try:
            resolved_root = await asyncio.to_thread(resolve_challenge_root, challenge_root)
        except ReadonlyWorkspaceError as exc:
            raise TriageConfigurationError(exc.code) from exc
        challenge = await self.repository.create_challenge(
            # Preserve the original declaration shape for later revalidation.
            # In particular, an ``artifact_bundle`` must not acquire empty
            # runtime fields merely because they are Pydantic defaults.
            manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
            name=str(manifest.metadata.name),
        )
        limits = manifest.spec.limits
        run = await self.repository.create_run(
            challenge["id"],
            mode=manifest.spec.mode.value,
            provider=provider_name,
            budget={
                "wall_time_seconds": limits.wall_time_seconds,
                "max_tool_calls": limits.max_tool_calls,
                "max_http_requests": limits.max_http_requests,
                "max_cost_usd": limits.max_cost_usd,
            },
        )
        run_id = run["id"]
        workspace = self.artifact_root / "workspaces" / run_id
        try:
            await self.repository.transition_run(
                run_id,
                "preparing",
                actor={"kind": "system", "id": "triage-orchestrator"},
                reason="prepare_declared_artifacts",
                idempotency_key=f"{run_id}:preparing",
            )
            try:
                materialized = await asyncio.to_thread(
                    materialize_declared_artifacts,
                    resolved_root,
                    workspace,
                    manifest,
                )
            except ReadonlyWorkspaceError as exc:
                raise TriageConfigurationError(exc.code) from exc
            await self.repository.transition_run(
                run_id,
                "running",
                actor={"kind": "system", "id": "triage-orchestrator"},
                reason="read_only_workspace_prepared",
                idempotency_key=f"{run_id}:running",
            )
            result = await self._triage_workspace(
                run_id=run_id,
                challenge_id=challenge["id"],
                manifest=manifest,
                workspace=workspace,
                materialized=materialized,
                selected_skills=selected_skills,
                backend=backend,
                api_key=api_key,
                model=normalized_model,
                max_output_tokens=max_output_tokens,
                timeout_seconds=timeout_seconds,
            )
            await self.repository.transition_run(
                run_id,
                "completed",
                actor={"kind": "system", "id": "triage-orchestrator"},
                reason="proposal_persisted_no_actions_executed",
                idempotency_key=f"{run_id}:completed",
            )
            return result
        except Exception as exc:
            await self._record_failure(run_id, exc)
            if isinstance(exc, TriageRunError):
                raise
            raise TriageRunError("triage_failed") from exc
        finally:
            if workspace.exists():
                await asyncio.to_thread(shutil.rmtree, workspace)

    async def export(self, result: TriageRunResult, output: Path) -> None:
        """Write a safe, reproducible triage report without raw challenge input."""

        root = await asyncio.to_thread(output.resolve)
        await asyncio.to_thread(self._prepare_export_root, root)
        run = await self.repository.get_run(result.run_id)
        if run is None:
            raise TriageRunError("run_not_found")
        artifacts = await self.repository.list_artifacts(result.run_id)
        proposal = next(
            (item for item in artifacts if item["id"] == result.proposal_artifact_id),
            None,
        )
        if proposal is None:
            raise TriageRunError("proposal_artifact_not_found")
        store = LocalArtifactStore(self.artifact_root / "object-store")
        proposal_bytes = await store.get_bytes(proposal["sha256"])
        events = await self.repository.list_events(result.run_id, limit=1000)
        blackboard = await self.repository.blackboard(result.run_id)
        report = {
            "schema": "ctfmesh.triage-report/v1",
            "run": run,
            "category": result.category,
            "model": result.model,
            "selected_skills": list(result.selected_skills),
            "proposal_artifact_id": result.proposal_artifact_id,
            "verification": "not_attempted",
            "execution": "no model-proposed action was executed",
        }
        (root / "triage-report.json").write_text(
            json.dumps(_redact_json(report), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (root / "proposal.json").write_bytes(proposal_bytes)
        (root / "blackboard.json").write_text(
            json.dumps(_redact_json(blackboard), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (root / "trace.jsonl").write_text(
            "".join(json.dumps(_redact_json(event), sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        (root / "README.md").write_text(
            "# CTFMesh triage report\n\n"
            "This report contains evidence-backed *proposals* only. The model did not execute "
            "any suggested action, this run has no verification record, and it cannot establish "
            "a solved challenge. Continue only through an authorized, policy-gated workflow.\n",
            encoding="utf-8",
        )

    def _select_skills(self, manifest: ChallengeManifest) -> tuple[SkillSpec, ...]:
        if manifest.spec.target.type != "artifact_bundle":
            raise TriageConfigurationError("triage_target_must_be_artifact_bundle")
        required_tools = ("artifacts.inspect", "files.list")
        profile_tools = tuple(sorted(set(manifest.spec.tool_profile)))
        missing_tools = {str(tool) for tool in required_tools} - {
            str(tool) for tool in profile_tools
        }
        if missing_tools:
            raise TriageConfigurationError("triage_tools_not_declared")
        profile_skills = tuple(sorted(set(manifest.spec.skill_profile)))
        if not profile_skills:
            raise TriageConfigurationError("triage_skills_not_declared")
        category = SkillCategory(manifest.metadata.category.value)
        requested_categories = tuple(sorted({SkillCategory.COMMON, category}, key=str))
        try:
            approved_digests = tuple(
                sorted(self.skills.get(skill_id).prompt_digest for skill_id in profile_skills)
            )
        except Exception as exc:
            raise TriageConfigurationError("unknown_triage_skill") from exc
        selected = self.skills.select(
            SkillSelectionRequest(
                requested_categories=requested_categories,
                allowed_skill_ids=profile_skills,
                allowed_tools=profile_tools,
                available_capabilities=("workspace.read",),
                approved_prompt_digests=approved_digests,
            )
        )
        if not selected:
            raise TriageConfigurationError("triage_skill_selection_denied")
        if not any(skill.category is category for skill in selected):
            raise TriageConfigurationError("category_triage_skill_not_selected")
        return selected

    async def _triage_workspace(
        self,
        *,
        run_id: str,
        challenge_id: str,
        manifest: ChallengeManifest,
        workspace: Path,
        materialized: tuple[MaterializedArtifact, ...],
        selected_skills: tuple[SkillSpec, ...],
        backend: TriageBackend,
        api_key: str,
        model: str,
        max_output_tokens: int,
        timeout_seconds: float,
    ) -> TriageRunResult:
        limits = manifest.spec.limits
        store = LocalArtifactStore(
            self.artifact_root / "object-store",
            max_artifact_bytes=min(limits.max_artifact_bytes, 16 * 1024 * 1024),
        )
        registry = ToolRegistry()
        registry.register(FilesListTool())
        registry.register(ArtifactInspectTool())
        runtime = ToolRuntime(registry, PolicyDecisionPoint(), artifact_store=store)
        allowed_tools = tuple(sorted({"artifacts.inspect", "files.list"}))
        capabilities = frozenset({"artifact.inspection", "workspace.read"})
        calls_used = 0

        async def invoke_read_only(
            tool: str, arguments: dict[str, Any], key: str
        ) -> dict[str, Any]:
            nonlocal calls_used
            if calls_used >= limits.max_tool_calls:
                raise TriageConfigurationError("triage_tool_budget_exhausted")
            context = ToolInvocationContext(
                run_id=run_id,
                actor=ActorRef(kind=ActorKind.WORKER, id="triage-worker"),
                mode=manifest.spec.mode,
                manifest=manifest,
                allowed_tools=allowed_tools,
                budget_remaining=BudgetRemaining(
                    tool_calls=limits.max_tool_calls - calls_used,
                    http_requests=limits.max_http_requests,
                    cost_usd=limits.max_cost_usd,
                ),
                approval_state=ApprovalState.NOT_REQUESTED,
                workspace_root=str(workspace),
                capabilities=capabilities,
            )
            result = await runtime.invoke(
                ToolRequest(tool=tool, arguments=arguments, idempotency_key=f"{run_id}:{key}"),
                context,
            )
            calls_used += 1
            if result.output is None:
                raise TriageRunError("triage_tool_output_missing")
            await self.repository.append_event(
                run_id,
                "tool.invocation.completed",
                {
                    "tool_name": tool,
                    "elapsed_ms": result.elapsed_ms,
                    "policy_decision": result.policy_reason,
                    "purpose": "static_triage_only",
                },
                actor={"kind": "tool", "id": tool},
                idempotency_key=f"{run_id}:{key}:event",
            )
            return _redact_json(result.output)

        inventory = await invoke_read_only(
            "files.list",
            {"path": ".", "recursive": True, "max_entries": 256},
            "inventory",
        )
        context_payload = {
            "schema": "ctfmesh.triage.context/v1",
            "challenge_name": str(manifest.metadata.name),
            "declared_category": manifest.metadata.category.value,
            "mode": manifest.spec.mode.value,
            "target_type": manifest.spec.target.type,
            "network_access": "not used by artifact-first triage",
            "inventory": inventory,
            "artifacts": [
                {
                    "evidence_id": item.evidence_id,
                    "path": item.relative_path,
                    "role": item.role,
                    "source_size_bytes": item.source_size_bytes,
                    "materialized": item.materialized,
                }
                for item in materialized
            ],
        }
        context_record = await self._store_json_artifact(
            run_id,
            store,
            context_payload,
            name="triage/context.json",
            producer="triage-orchestrator",
            label="context",
        )
        bindings: dict[str, _EvidenceBinding] = {
            "challenge-context": _EvidenceBinding(
                artifact_id=context_record["id"],
                digest=context_record["sha256"],
                locator="triage/context.json",
            )
        }
        evidence: list[TriageEvidence] = [
            TriageEvidence(
                id="challenge-context",
                kind="challenge",
                content=_compact_json(context_payload),
            )
        ]

        for item in materialized:
            if not item.materialized or calls_used >= limits.max_tool_calls:
                continue
            fingerprint = await invoke_read_only(
                "artifacts.inspect",
                {
                    "path": item.relative_path,
                    "max_file_bytes": MAX_READONLY_ARTIFACT_BYTES,
                    "max_header_bytes": 128,
                    "max_strings": 8,
                    "max_string_bytes": 160,
                },
                f"inspect:{item.evidence_id}",
            )
            fingerprint_record = await self._store_json_artifact(
                run_id,
                store,
                {"schema": "ctfmesh.artifact-fingerprint/v1", "fingerprint": fingerprint},
                name=f"triage/fingerprints/{item.evidence_id}.json",
                producer="artifacts.inspect",
                label=f"fingerprint{item.evidence_id.removeprefix('artifact-')}",
            )
            bindings[item.evidence_id] = _EvidenceBinding(
                artifact_id=fingerprint_record["id"],
                digest=fingerprint_record["sha256"],
                locator=f"triage/fingerprints/{item.evidence_id}.json",
            )
            evidence.append(
                TriageEvidence(
                    id=item.evidence_id,
                    kind="tool_observation",
                    content=_compact_json(fingerprint),
                )
            )

        bounded_evidence = self._bound_evidence(evidence)
        selected_guidance = [
            {
                "id": skill.id,
                "version": skill.version,
                "prompt_digest": skill.prompt_digest,
                "guidance": skill_guidance(skill),
            }
            for skill in selected_skills
        ]
        request = TriageRequest(
            model=model,
            max_output_tokens=max_output_tokens,
            objective=(
                "Produce an evidence-backed static triage proposal for the declared "
                f"{manifest.metadata.category.value} CTF category. Reviewed skill guidance: "
                f"{_compact_json(selected_guidance)}"
            ),
            authorized_scope=(
                "Only the supplied read-only artifact fingerprints and challenge context are "
                "authorized. No network, shell, code execution, archive extraction, model "
                "execution, exploit, or flag claim is authorized in this stage."
            ),
            evidence=bounded_evidence,
        )
        completion = await backend.triage(
            request,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
        self._validate_completion(
            completion,
            manifest=manifest,
            bindings=bindings,
            supplied_evidence_ids=frozenset(item.id for item in bounded_evidence),
        )
        proposal_payload = {
            "schema": "ctfmesh.triage-proposal/v1",
            "provider_response_id_present": completion.response_id is not None,
            "declared_category": manifest.metadata.category.value,
            "model": model,
            "model_category": completion.result.category,
            "summary": completion.result.summary,
            "facts": [fact.model_dump(mode="json") for fact in completion.result.facts],
            "hypotheses": [
                hypothesis.model_dump(mode="json") for hypothesis in completion.result.hypotheses
            ],
            "next_actions": [
                action.model_dump(mode="json") for action in completion.result.next_actions
            ],
            "selected_skills": [
                {"id": skill.id, "version": skill.version, "prompt_digest": skill.prompt_digest}
                for skill in selected_skills
            ],
            "execution": "none",
            "verification": "not_attempted",
        }
        proposal_record = await self._store_json_artifact(
            run_id,
            store,
            proposal_payload,
            name="triage/proposal.json",
            producer="openai-responses",
            label="proposal",
        )
        fact_ids = await self._persist_proposals(
            run_id,
            completion=completion,
            bindings=bindings,
        )
        await self.repository.append_event(
            run_id,
            "triage.proposal.received",
            {
                "category": completion.result.category,
                "fact_count": len(completion.result.facts),
                "hypothesis_count": len(completion.result.hypotheses),
                "next_action_count": len(completion.result.next_actions),
                "proposal_artifact_id": proposal_record["id"],
                "selected_skill_ids": [skill.id for skill in selected_skills],
                "facts_persisted": len(fact_ids),
                "actions_executed": 0,
            },
            actor={"kind": "worker", "id": "openai-responses"},
            idempotency_key=f"{run_id}:proposal:received",
        )
        return TriageRunResult(
            run_id=run_id,
            challenge_id=challenge_id,
            status="completed",
            category=manifest.metadata.category.value,
            model=model,
            selected_skills=tuple(skill.id for skill in selected_skills),
            proposal_artifact_id=proposal_record["id"],
        )

    async def _persist_proposals(
        self,
        run_id: str,
        *,
        completion: TriageCompletion,
        bindings: Mapping[str, _EvidenceBinding],
    ) -> tuple[str, ...]:
        fact_ids: list[str] = []
        facts_by_evidence: dict[str, list[str]] = {}
        for index, fact in enumerate(completion.result.facts, start=1):
            fact_id = f"fact_{run_id[-12:]}_{index:02d}"
            evidence = [self._evidence_ref(bindings[item_id]) for item_id in fact.evidence_ids]
            await self.repository.add_fact(
                {
                    "id": fact_id,
                    "run_id": run_id,
                    "statement": _redact_text(fact.statement),
                    "confidence": fact.confidence,
                    "status": "proposed",
                    "evidence": evidence,
                    "created_by": "openai-responses",
                    "actor_kind": "worker",
                }
            )
            fact_ids.append(fact_id)
            for evidence_id in fact.evidence_ids:
                facts_by_evidence.setdefault(evidence_id, []).append(fact_id)
        for index, hypothesis in enumerate(completion.result.hypotheses, start=1):
            supporting_fact_ids = tuple(
                fact_id
                for evidence_id in hypothesis.evidence_ids
                for fact_id in facts_by_evidence.get(evidence_id, ())
            )
            await self.repository.add_hypothesis(
                {
                    "id": f"hyp_{run_id[-12:]}_{index:02d}",
                    "run_id": run_id,
                    "branch_id": "branch_triage",
                    "family": "model_proposal",
                    "statement": _redact_text(hypothesis.statement),
                    "confidence": hypothesis.confidence,
                    "status": "open",
                    "supporting_fact_ids": list(dict.fromkeys(supporting_fact_ids)),
                    "contradicting_fact_ids": [],
                    "falsifiers": [
                        "Independent scoped evidence contradicts or fails to reproduce "
                        "this proposal."
                    ],
                }
            )
        return tuple(fact_ids)

    async def _store_json_artifact(
        self,
        run_id: str,
        store: LocalArtifactStore,
        value: dict[str, Any],
        *,
        name: str,
        producer: str,
        label: str,
    ) -> dict[str, Any]:
        payload = json.dumps(_redact_json(value), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        reference = await store.put_bytes(
            payload,
            run_id=run_id,
            mime_type="application/json",
            producer=ActorRef(kind=ActorKind.SYSTEM, id="triage-orchestrator"),
            classification="internal",
        )
        artifact_id = f"artifact_{run_id[-12:]}_{label}_{reference.sha256[:12]}"
        return await self.repository.add_artifact(
            {
                "id": artifact_id,
                "run_id": run_id,
                "sha256": reference.sha256,
                "name": name,
                "media_type": reference.mime_type,
                "size_bytes": reference.size_bytes,
                "classification": "internal",
                "producer": producer,
                "locator": f"artifact://sha256/{reference.sha256}",
            }
        )

    @staticmethod
    def _evidence_ref(binding: _EvidenceBinding) -> dict[str, str]:
        return {
            "artifact_id": binding.artifact_id,
            "locator": binding.locator,
            "digest": binding.digest,
            "observed_at": "2026-07-26T00:00:00Z",
        }

    @staticmethod
    def _validate_completion(
        completion: TriageCompletion,
        *,
        manifest: ChallengeManifest,
        bindings: Mapping[str, _EvidenceBinding],
        supplied_evidence_ids: frozenset[str],
    ) -> None:
        if completion.result.category not in {manifest.metadata.category.value, "unknown"}:
            raise TriageProposalError("triage_category_conflicts_with_manifest")
        known_ids = frozenset(bindings)
        for fact in completion.result.facts:
            if not set(fact.evidence_ids).issubset(known_ids):
                raise TriageProposalError("fact_cites_unknown_evidence")
            if not set(fact.evidence_ids).issubset(supplied_evidence_ids):
                raise TriageProposalError("fact_cites_unsupplied_evidence")
        for hypothesis in completion.result.hypotheses:
            if not set(hypothesis.evidence_ids).issubset(known_ids):
                raise TriageProposalError("hypothesis_cites_unknown_evidence")
            if not set(hypothesis.evidence_ids).issubset(supplied_evidence_ids):
                raise TriageProposalError("hypothesis_cites_unsupplied_evidence")
        for action in completion.result.next_actions:
            if not set(action.evidence_ids).issubset(known_ids):
                raise TriageProposalError("next_action_cites_unknown_evidence")
            if not set(action.evidence_ids).issubset(supplied_evidence_ids):
                raise TriageProposalError("next_action_cites_unsupplied_evidence")

    @staticmethod
    def _bound_evidence(evidence: Sequence[TriageEvidence]) -> tuple[TriageEvidence, ...]:
        bounded: list[TriageEvidence] = []
        used = 0
        for item in evidence:
            size = len(item.content.encode("utf-8"))
            if used + size > _MAX_MODEL_EVIDENCE_BYTES:
                continue
            bounded.append(item)
            used += size
        if not bounded:
            raise TriageRunError("triage_evidence_empty")
        return tuple(bounded)

    @staticmethod
    def _require_model(model: str) -> str:
        normalized = model.strip()
        if not normalized or len(normalized) > 160:
            raise TriageConfigurationError("triage_model_invalid")
        return normalized

    async def _record_failure(self, run_id: str, exc: Exception) -> None:
        run = await self.repository.get_run(run_id)
        if run is None or run["status"] not in {"preparing", "running"}:
            return
        code = exc.code if isinstance(exc, TriageRunError) else "triage_failed"
        await self.repository.append_event(
            run_id,
            "triage.failed",
            {"code": code},
            actor={"kind": "system", "id": "triage-orchestrator"},
            idempotency_key=f"{run_id}:triage:failed",
        )
        await self.repository.transition_run(
            run_id,
            "failed",
            actor={"kind": "system", "id": "triage-orchestrator"},
            reason=code,
            idempotency_key=f"{run_id}:failed",
        )

    @staticmethod
    def _prepare_export_root(root: Path) -> None:
        if root.exists():
            if not root.is_dir():
                raise TriageRunError("export_root_not_directory")
            if any(root.iterdir()):
                raise TriageRunError("export_root_must_be_empty")
            return
        root.mkdir(parents=True, exist_ok=False)


def _redact_text(value: str) -> str:
    value = _RAW_FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER_TOKEN.sub(r"\1[REDACTED]", value)
    value = _OPENAI_KEY.sub("[REDACTED_API_KEY]", value)
    return _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", value)


def _redact_json(value: Any, *, key: str | None = None) -> Any:
    if key is not None:
        normalized = key.lower().replace("-", "_")
        if normalized in _SECRET_KEY_MARKERS or _SECRET_KEY_MARKERS & set(normalized.split("_")):
            return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_json(child, key=str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, list | tuple):
        return [_redact_json(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _compact_json(value: Any) -> str:
    return json.dumps(
        _redact_json(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


__all__ = [
    "TriageBackend",
    "TriageConfigurationError",
    "TriageOrchestrator",
    "TriageProposalError",
    "TriageRunError",
    "TriageRunResult",
]
