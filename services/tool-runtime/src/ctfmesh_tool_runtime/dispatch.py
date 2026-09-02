"""Durable M3 dispatch from a Pi tool call to one fixed source slot."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from ctfmesh_db import Repository
from ctfmesh_domain import (
    ActorKind,
    ActorRef,
    RuntimeArtifact,
    ToolExecutionAuthority,
    ToolInvocation,
    ToolInvocationRequest,
    ToolInvocationState,
)
from ctfmesh_policy import (
    ApprovalState,
    BudgetRemaining,
    Decision,
    PolicyDecisionPoint,
    PolicyRequest,
    ToolRisk,
)
from ctfmesh_tools import LocalArtifactStore

from .contracts import (
    GatewayToolCall,
    GatewayToolRequest,
    GatewayToolResponse,
    HttpRequestCall,
    RejectedToolResult,
    SourceSlotInvocation,
    ToolGatewayContractError,
    ToolObservationArtifact,
    accepted_result,
    canonical_input_digest,
)
from .http_slot import TargetHttpScopeError, resolve_target_url
from .normalizers import (
    ToolOutputNormalizationError,
    canonical_output_bytes,
    normalize_output,
    observation_summary,
)
from .slots import SourceSlotClient, SourceSlotError, parse_slot_output, source_slot_binding
from .target_capability import TargetCapabilitySigner


class ToolGateway:
    """The sole production path from Pi control requests to a fixed slot.

    The gateway has database access because it owns durable lease,
    idempotency, budget, and audit decisions. Pi Runner has none of those
    privileges and receives only a normalized, artifact-backed observation.
    """

    def __init__(
        self,
        *,
        repository: Repository,
        artifact_root: Path,
        source_slots: tuple[SourceSlotClient, ...],
        policy: PolicyDecisionPoint | None = None,
        max_dispatch_seconds: float = 30.0,
        target_capability_signer: TargetCapabilitySigner | None = None,
    ) -> None:
        if not source_slots:
            raise ValueError("tool_gateway_source_slots_required")
        if (
            isinstance(max_dispatch_seconds, bool)
            or not isinstance(max_dispatch_seconds, int | float)
            or not 1 <= float(max_dispatch_seconds) <= 300
        ):
            raise ValueError("tool_gateway_dispatch_timeout_invalid")
        self._repository = repository
        self._slots = source_slots
        self._policy = policy or PolicyDecisionPoint()
        self._max_dispatch_seconds = float(max_dispatch_seconds)
        # Only the gateway has this key. A source slot receives a one-use
        # capability, not an authority to choose a destination or request.
        self._target_capability_signer = target_capability_signer
        # Artifact paths are created from a gateway-owned root and content
        # digest only. No tool argument is ever used as a filesystem locator.
        self._artifacts = LocalArtifactStore(artifact_root / "tool-gateway")

    async def invoke(
        self,
        request: GatewayToolRequest,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> GatewayToolResponse:
        """Authorize, reserve, dispatch, normalize, and persist one tool call."""

        try:
            authority = await self._repository.get_pi_tool_execution_authority(
                job_id,
                session_id=request.session_id,
                worker_id=worker_id,
                lease_version=lease_version,
            )
        except ValueError:
            return self._rejected(request.call, "tool_authority_denied")

        slot = self._select_source_slot(authority, request.call)
        if slot is None:
            return self._rejected(request.call, "source_slot_unavailable")
        decision, reason = self._pre_dispatch_policy(authority, request.call, slot, worker_id)
        metadata = ToolInvocationRequest(
            tool_call_id=request.call.tool_call_id,
            tool_name=request.call.tool_name,
            tool_version=request.call.tool_version,
            idempotency_key=request.call.idempotency_key,
            input_digest=canonical_input_digest(request.call),
        )
        try:
            invocation = await self._repository.reserve_pi_tool_invocation(
                metadata,
                job_id=job_id,
                session_id=request.session_id,
                worker_id=worker_id,
                lease_version=lease_version,
                policy_decision=decision,
                policy_reason=reason,
            )
        except ValueError:
            return self._rejected(request.call, "tool_reservation_denied")

        if invocation.state is ToolInvocationState.DENIED:
            return self._rejected(
                request.call,
                invocation.policy_reason,
                invocation_id=invocation.id,
            )
        if invocation.state is ToolInvocationState.COMPLETED:
            return await self._cached_result(request.call, invocation.id, invocation)
        if invocation.state is ToolInvocationState.FAILED:
            return self._rejected(
                request.call,
                "tool_invocation_failed",
                invocation_id=invocation.id,
                cached=True,
            )

        # ``RESERVED`` commits first; every subsequent failure becomes a
        # durable terminal result. A duplicate therefore cannot cause a second
        # source read or future target interaction.
        return await self._dispatch_reserved(authority, request.call, invocation.id, slot)

    async def _dispatch_reserved(
        self,
        authority: ToolExecutionAuthority,
        call: GatewayToolCall,
        invocation_id: str,
        slot: SourceSlotClient,
    ) -> GatewayToolResponse:
        timeout = self._dispatch_timeout(authority)
        if timeout <= 0:
            return await self._fail_reserved(call, invocation_id, "tool_dispatch_lease_expired")
        target_capability: str | None = None
        if (
            isinstance(call, HttpRequestCall)
            and authority.challenge_manifest.spec.source is not None
        ):
            signer = self._target_capability_signer
            if signer is None:
                return await self._fail_reserved(
                    call, invocation_id, "target_capability_unavailable"
                )
            try:
                # Use HTTPX's own request construction so the digest covers
                # exactly the URL/body the slot transport will forward. This
                # avoids a second, subtly different JSON serializer at the
                # trust boundary.
                target_url = resolve_target_url(authority.challenge_manifest, call.arguments)
                prepared = httpx.Request(
                    call.arguments.method,
                    target_url,
                    headers={"accept-encoding": "identity", **call.arguments.headers},
                    json=call.arguments.json_body,
                    content=call.arguments.content,
                )
                target_capability = signer.issue(
                    invocation_id=invocation_id,
                    run_id=authority.run_id,
                    challenge_id=authority.challenge_id,
                    method=call.arguments.method,
                    url=str(prepared.url),
                    body=prepared.content,
                    ttl_seconds=max(1, min(60, int(timeout))),
                )
            except (TargetHttpScopeError, ValueError):
                return await self._fail_reserved(
                    call, invocation_id, "target_capability_unavailable"
                )
        try:
            response = await asyncio.wait_for(
                slot.invoke(
                    SourceSlotInvocation(
                        invocation_id=invocation_id,
                        authority=authority,
                        call=call,
                        target_capability=target_capability,
                    )
                ),
                timeout=timeout,
            )
            if response.invocation_id != invocation_id:
                raise SourceSlotError("source_slot_response_mismatch")
            output = parse_slot_output(call, response)
            normalized = normalize_output(call, output)
            body, digest = canonical_output_bytes(normalized)
            reference = await self._artifacts.put_bytes(
                body,
                run_id=authority.run_id,
                mime_type="application/json",
                producer=ActorRef(kind=ActorKind.TOOL, id="tool-gateway"),
                classification="internal",
                branch_id=authority.branch_id,
                task_id=authority.task_id,
                tool_invocation_id=invocation_id,
            )
            if reference.sha256 != digest or reference.size_bytes != len(body):
                raise ToolGatewayContractError("tool_artifact_integrity_mismatch")
            summary = observation_summary(call)
            artifact = RuntimeArtifact(
                id=f"artifact_{uuid4().hex}",
                run_id=authority.run_id,
                sha256=reference.sha256,
                name=f"tools/{call.tool_name}/{invocation_id}.json",
                media_type="application/json",
                size_bytes=reference.size_bytes,
                classification="internal",
                producer="tool-gateway",
                locator=f"sha256:{reference.sha256}",
                created_at=datetime.now(UTC),
            )
            completed = await self._repository.complete_tool_invocation(
                invocation_id,
                artifact=artifact,
                result_summary=summary,
            )
        except TimeoutError:
            return await self._fail_reserved(call, invocation_id, "tool_dispatch_timeout")
        except SourceSlotError as exc:
            return await self._fail_reserved(call, invocation_id, exc.code)
        except ToolOutputNormalizationError as exc:
            return await self._fail_reserved(call, invocation_id, exc.code)
        except (ToolGatewayContractError, ValueError):
            return await self._fail_reserved(call, invocation_id, "tool_dispatch_failed")
        except Exception:  # pragma: no cover - last-line secret/error boundary.
            return await self._fail_reserved(call, invocation_id, "tool_dispatch_failed")
        return accepted_result(
            invocation_id=completed.id,
            call=call,
            artifact=ToolObservationArtifact(
                artifact_id=artifact.id,
                digest=artifact.sha256,
                size_bytes=artifact.size_bytes,
                summary=completed.result_summary or observation_summary(call),
            ),
            cached=False,
            output=normalized.model_dump(mode="json"),
        )

    async def _cached_result(
        self,
        call: GatewayToolCall,
        invocation_id: str,
        invocation: ToolInvocation,
    ) -> GatewayToolResponse:
        """Read exactly the immutable normalized artifact for a duplicate call."""

        artifact_id = invocation.result_artifact_id
        digest = invocation.result_digest
        summary = invocation.result_summary
        if (
            not isinstance(artifact_id, str)
            or not isinstance(digest, str)
            or not isinstance(summary, str)
        ):
            return self._rejected(
                call, "tool_cached_result_unavailable", invocation_id=invocation_id
            )
        try:
            body = await self._artifacts.get_bytes(f"sha256:{digest}")
            payload = json.loads(body)
            output = normalize_output(call, payload)
        except (OSError, ValueError, ToolOutputNormalizationError):
            return self._rejected(
                call, "tool_cached_result_unavailable", invocation_id=invocation_id
            )
        return accepted_result(
            invocation_id=invocation_id,
            call=call,
            artifact=ToolObservationArtifact(
                artifact_id=artifact_id,
                digest=digest,
                size_bytes=len(body),
                summary=summary,
            ),
            cached=True,
            output=output.model_dump(mode="json"),
        )

    async def _fail_reserved(
        self,
        call: GatewayToolCall,
        invocation_id: str,
        code: str,
    ) -> RejectedToolResult:
        try:
            await self._repository.fail_tool_invocation(invocation_id, error_code=code)
        except ValueError:
            # Do not reveal a database/slot failure; the original reservation
            # remains non-retryable and an operator can inspect its audit row.
            code = "tool_completion_failed"
        return self._rejected(call, code, invocation_id=invocation_id)

    def _select_source_slot(
        self,
        authority: ToolExecutionAuthority,
        call: GatewayToolCall,
    ) -> SourceSlotClient | None:
        declared_source = getattr(authority.challenge_manifest.spec, "source", None)
        binding = source_slot_binding(authority.challenge_manifest)
        # A malformed non-null source declaration is not equivalent to no
        # declaration. In particular it must not downgrade to matching a
        # curated static mount as a fallback.
        if declared_source is not None and binding is None:
            return None
        if binding is not None:
            # An archive-backed manifest cannot fall through to a curated M3
            # mount just because both have a similarly named challenge. The
            # backend chose this slot when it materialized the safe archive;
            # the slot repeats challenge/intake matching from its own trusted
            # assignment file before any workspace access.
            compatible = tuple(
                slot
                for slot in self._slots
                if (
                    getattr(slot, "dynamic_assignment", False)
                    and slot.slot_id == binding.slot_id
                    and slot.supports(call)
                )
            )
        else:
            compatible = tuple(
                slot
                for slot in self._slots
                if (
                    not getattr(slot, "dynamic_assignment", False)
                    and slot.challenge_id == authority.challenge_id
                    and slot.supports(call)
                )
            )
        if not compatible:
            return None
        # Stable selection makes a retry reach the same fixed slot without
        # trusting a worker-selected network/container identifier.
        index = int(hashlib.sha256(authority.task_id.encode("utf-8")).hexdigest(), 16) % len(
            compatible
        )
        return compatible[index]

    def _pre_dispatch_policy(
        self,
        authority: ToolExecutionAuthority,
        call: GatewayToolCall,
        slot: SourceSlotClient,
        worker_id: str,
    ) -> tuple[Literal["allow", "deny"], str]:
        """Evaluate non-mutating policy before database budget reservation."""

        # Role membership alone is never enough. An operator-signed manifest
        # must explicitly opt this exact tool into the challenge profile before
        # a source mount is observed or a target alias is contacted. Generic
        # archive intake does not create a run or add this declaration, so an
        # upload cannot grant execution.
        if call.tool_name not in authority.challenge_manifest.spec.tool_profile:
            return "deny", "tool_not_allowed"
        requested_url: str | None = None
        requested_path: str | None = getattr(call.arguments, "path", ".")
        risk = ToolRisk.READ_ONLY
        budget = BudgetRemaining(tool_calls=1, http_requests=0, cost_usd=0.0)
        workspace_root: str | None = str(slot.workspace_root())
        if isinstance(call, HttpRequestCall):
            try:
                requested_url = resolve_target_url(authority.challenge_manifest, call.arguments)
            except TargetHttpScopeError as exc:
                return "deny", exc.code
            requested_path = None
            risk = ToolRisk.TARGET_INTERACTION
            budget = BudgetRemaining(tool_calls=1, http_requests=1, cost_usd=0.0)
            workspace_root = None
        elif not isinstance(requested_path, str):
            requested_path = "."
        # The database does the real atomic budget reservation. This bounded
        # snapshot gives the pure policy engine enough data to validate source
        # or exact-target scope while avoiding a stale client-supplied budget
        # field.
        decision = self._policy.decide(
            PolicyRequest(
                run_id=authority.run_id,
                mode=authority.challenge_manifest.spec.mode,
                actor=ActorRef(kind=ActorKind.WORKER, id=worker_id),
                tool=call.tool_name,
                risk=risk,
                allowed_tools=authority.context_manifest.allowed_tool_ids,
                budget_remaining=budget,
                approval_state=ApprovalState.NOT_REQUESTED,
                requested_url=requested_url,
                workspace_root=workspace_root,
                requested_path=requested_path,
            ),
            authority.challenge_manifest,
        )
        # M3 has no durable approval-request protocol. If a future policy
        # result asks for approval, deny this reservation rather than silently
        # treating an unresolved approval as permission to dispatch.
        if decision.decision is not Decision.ALLOW:
            return "deny", decision.reason_code.value
        return "allow", decision.reason_code.value

    def _dispatch_timeout(self, authority: ToolExecutionAuthority) -> float:
        remaining = (authority.lease_expires_at - datetime.now(UTC)).total_seconds()
        return min(self._max_dispatch_seconds, remaining)

    @staticmethod
    def _rejected(
        call: GatewayToolCall,
        code: str,
        *,
        invocation_id: str | None = None,
        cached: bool = False,
    ) -> RejectedToolResult:
        return RejectedToolResult(
            tool_call_id=call.tool_call_id,
            tool_name=call.tool_name,
            code=code,
            invocation_id=invocation_id,
            cached=cached,
        )


__all__ = ["ToolGateway"]
