"""Reference deny-by-default policy decision point."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from ctfmesh_domain import ChallengeManifest, normalize_exact_host
from pydantic import JsonValue

from .models import (
    ApprovalState,
    Decision,
    PolicyRequest,
    PolicyResult,
    ReasonCode,
    ToolRisk,
)


class PolicyDecisionPoint:
    """Evaluate trusted manifest/task/budget inputs without executing a tool."""

    def decide(self, request: PolicyRequest, manifest: ChallengeManifest) -> PolicyResult:
        if request.mode is not manifest.spec.mode:
            return self._deny(ReasonCode.MODE_MISMATCH)

        if request.tool not in request.allowed_tools:
            return self._deny(ReasonCode.TOOL_NOT_ALLOWED)

        budget_result = self._check_budget(request, manifest)
        if budget_result is not None:
            return budget_result

        if request.approval_state is ApprovalState.DENIED:
            return self._deny(ReasonCode.APPROVAL_DENIED)

        workspace_result = self._check_workspace(request)
        if workspace_result is not None:
            return workspace_result

        endpoint_constraints: dict[str, JsonValue] = {}
        if request.requested_url is not None:
            if request.risk not in {ToolRisk.TARGET_INTERACTION, ToolRisk.HIGH_IMPACT}:
                return self._deny(ReasonCode.RISK_SCOPE_MISMATCH)
            endpoint_constraints = self._authorized_endpoint(request.requested_url, manifest)
            if not endpoint_constraints:
                return self._deny(ReasonCode.SCOPE_NOT_ALLOWED)
        elif request.risk is ToolRisk.TARGET_INTERACTION:
            return self._deny(ReasonCode.SCOPE_REQUIRED)

        if request.risk is ToolRisk.HIGH_IMPACT:
            if request.approval_state is not ApprovalState.APPROVED:
                return PolicyResult(
                    decision=Decision.REQUIRE_APPROVAL,
                    reason_code=ReasonCode.APPROVAL_REQUIRED,
                    constraints=endpoint_constraints,
                )
            return PolicyResult(
                decision=Decision.ALLOW,
                reason_code=ReasonCode.APPROVAL_GRANTED,
                constraints=endpoint_constraints,
            )

        if endpoint_constraints:
            return PolicyResult(
                decision=Decision.ALLOW,
                reason_code=ReasonCode.MANIFEST_SCOPE_MATCH,
                constraints=endpoint_constraints,
            )

        if request.risk is ToolRisk.WORKSPACE_WRITE:
            return PolicyResult(
                decision=Decision.ALLOW,
                reason_code=ReasonCode.WORKSPACE_ALLOWED,
                constraints=self._workspace_constraints(request),
            )

        if request.risk is ToolRisk.READ_ONLY:
            return PolicyResult(
                decision=Decision.ALLOW,
                reason_code=ReasonCode.READ_ONLY_ALLOWED,
                constraints=self._workspace_constraints(request),
            )

        return self._deny(ReasonCode.SCOPE_NOT_ALLOWED)

    @staticmethod
    def _deny(reason: ReasonCode) -> PolicyResult:
        return PolicyResult(decision=Decision.DENY, reason_code=reason)

    def _check_budget(
        self, request: PolicyRequest, manifest: ChallengeManifest
    ) -> PolicyResult | None:
        remaining = request.budget_remaining
        limits = manifest.spec.limits
        if (
            remaining.tool_calls > limits.max_tool_calls
            or remaining.http_requests > limits.max_http_requests
            or remaining.cost_usd > limits.max_cost_usd
        ):
            return self._deny(ReasonCode.BUDGET_INVALID)
        if remaining.tool_calls < 1 or remaining.cost_usd < request.requested_cost_usd:
            return self._deny(ReasonCode.BUDGET_EXHAUSTED)
        if request.risk in {ToolRisk.TARGET_INTERACTION, ToolRisk.HIGH_IMPACT}:
            if request.requested_url is not None and remaining.http_requests < 1:
                return self._deny(ReasonCode.BUDGET_EXHAUSTED)
        return None

    def _authorized_endpoint(
        self, requested_url: str, manifest: ChallengeManifest
    ) -> dict[str, JsonValue]:
        try:
            parsed = urlsplit(requested_url)
            if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                return {}
            if parsed.username is not None or parsed.password is not None:
                return {}
            if parsed.fragment:
                return {}
            host = normalize_exact_host(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return {}

        for endpoint in manifest.spec.target.allowed_endpoints:
            if endpoint.permits(protocol=parsed.scheme, host=host, port=port):
                return {
                    "protocol": parsed.scheme,
                    "host": host,
                    "port": port,
                }
        return {}

    def _check_workspace(self, request: PolicyRequest) -> PolicyResult | None:
        if request.requested_path is None:
            if request.risk is ToolRisk.WORKSPACE_WRITE and request.workspace_root is None:
                return self._deny(ReasonCode.WORKSPACE_SCOPE_REQUIRED)
            return None

        assert request.workspace_root is not None
        root = Path(request.workspace_root)
        if not root.is_absolute():
            return self._deny(ReasonCode.WORKSPACE_SCOPE_DENIED)
        resolved_root = root.resolve(strict=False)
        candidate = Path(request.requested_path)
        if not candidate.is_absolute():
            candidate = resolved_root / candidate
        resolved_candidate = candidate.resolve(strict=False)
        if not resolved_candidate.is_relative_to(resolved_root):
            return self._deny(ReasonCode.WORKSPACE_SCOPE_DENIED)
        return None

    @staticmethod
    def _workspace_constraints(request: PolicyRequest) -> dict[str, JsonValue]:
        if request.workspace_root is None:
            return {}
        return {"workspace_root": str(Path(request.workspace_root).resolve(strict=False))}
