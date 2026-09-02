"""Shared domain/policy imports for the typed tool boundary.

These are direct dependencies of the production package. Keeping the imports
explicit prevents a degraded fallback from accidentally changing authorization
semantics when CTFMesh is installed as a workspace.
"""

from __future__ import annotations

from typing import Protocol

from ctfmesh_domain import (
    ActorKind,
    ActorRef,
    ArtifactRef,
    ChallengeManifest,
    ContractModel,
    RunMode,
)
from ctfmesh_policy import (
    ApprovalState,
    BudgetRemaining,
    Decision,
    PolicyRequest,
    PolicyResult,
    ToolRisk,
)


class PolicyDecisionPointLike(Protocol):
    """Structural boundary matching ``ctfmesh_policy.PolicyDecisionPoint``."""

    def decide(
        self,
        request: PolicyRequest,
        manifest: ChallengeManifest,
    ) -> PolicyResult: ...


__all__ = [
    "ActorKind",
    "ActorRef",
    "ApprovalState",
    "ArtifactRef",
    "BudgetRemaining",
    "ChallengeManifest",
    "ContractModel",
    "Decision",
    "PolicyDecisionPointLike",
    "PolicyRequest",
    "PolicyResult",
    "RunMode",
    "ToolRisk",
]
