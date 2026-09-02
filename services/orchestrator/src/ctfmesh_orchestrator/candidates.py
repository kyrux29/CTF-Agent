"""Artifact persistence helpers for M5 candidate and verifier boundaries.

These helpers own only immutable bytes. The repository remains the sole
authority that binds an artifact to a live lease, queues a verifier job, or
changes a run's status.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from ctfmesh_domain import (
    ActorKind,
    ActorRef,
    ExploitPlanV1,
    RuntimeArtifact,
    VerificationProofEnvelopeV1,
)
from ctfmesh_tools import LocalArtifactStore


class CandidateArtifactService:
    """Write canonical M5 payloads to isolated content-addressed namespaces."""

    def __init__(self, artifact_root: Path) -> None:
        # Candidate plans must be readable by the verifier but are never
        # mounted into Pi Runner or source/tool slots. Proofs need no read
        # path from a worker after the API stores them.
        self._plans = LocalArtifactStore(
            artifact_root / "candidate-plans", max_artifact_bytes=256 * 1024
        )
        self._proofs = LocalArtifactStore(
            artifact_root / "verification-proofs", max_artifact_bytes=256 * 1024
        )

    async def persist_plan(
        self,
        *,
        run_id: str,
        session_id: str,
        tool_call_id: str,
        plan: ExploitPlanV1,
    ) -> RuntimeArtifact:
        """Store exact plan bytes before the repository atomically accepts it.

        An orphaned immutable blob after a rejected transaction is harmless:
        it has no database reference, execution path, or target authority.
        """

        body = plan.canonical_bytes()
        reference = await self._plans.put_bytes(
            body,
            run_id=run_id,
            mime_type="application/json",
            producer=ActorRef(kind=ActorKind.SYSTEM, id="candidate-kernel"),
            classification="internal",
        )
        return RuntimeArtifact(
            id=self._artifact_id("candidate", run_id, session_id, tool_call_id),
            run_id=run_id,
            sha256=reference.sha256,
            name="candidate/exploit-plan-v1.json",
            media_type="application/json",
            size_bytes=reference.size_bytes,
            classification="internal",
            producer="candidate-kernel",
            locator=f"sha256:{reference.sha256}",
            created_at=datetime.now(UTC),
        )

    async def persist_proof(self, proof: VerificationProofEnvelopeV1) -> RuntimeArtifact:
        """Store a signed, raw-flag-free proof before authoritative completion."""

        body = proof.canonical_bytes()
        reference = await self._proofs.put_bytes(
            body,
            run_id=proof.run_id,
            mime_type="application/json",
            producer=ActorRef(kind=ActorKind.VERIFIER, id="independent-verifier"),
            classification="internal",
        )
        return RuntimeArtifact(
            id=self._artifact_id("proof", proof.run_id, proof.candidate_id, reference.sha256),
            run_id=proof.run_id,
            sha256=reference.sha256,
            name="verification/m5-replay-proof-v1.json",
            media_type="application/json",
            size_bytes=reference.size_bytes,
            classification="internal",
            producer="independent-verifier",
            locator=f"sha256:{reference.sha256}",
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _artifact_id(kind: str, *parts: str) -> str:
        """Derive a retry-stable database ID without exposing payload content."""

        digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
        return f"artifact_{kind}_{digest[:32]}"


__all__ = ["CandidateArtifactService"]
