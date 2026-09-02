"""Memory-only reveal of flag-shaped values from Power evidence.

Power observations are immutable sandbox artifacts.  They can contain both
real flags and decoys, so this module deliberately makes *no* verification or
state transition.  It serves either a historical local review request or the
single evidence set that opened a durable candidate-review pause, returns every
syntactically flag-shaped value that can be read, and keeps raw values out of
events and database rows.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ctfmesh_domain import ActorKind
from ctfmesh_tools import LocalArtifactStore

# Keep this detector intentionally broad.  The manifest-owned flag router is
# the only authority that can decide whether a candidate is valid; this scan
# exists to give the operator a complete review queue, including decoys.
_RUNTIME_FLAG_CANDIDATE = re.compile(
    rb"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_-]{1,31}\{[^\s{}]{1,512}\})"
)


@dataclass(frozen=True, slots=True)
class RuntimeCandidateArtifact:
    """One metadata-only Power observation selected from the event ledger."""

    artifact_id: str
    racer_label: str


class RuntimeCandidateRevealService:
    """Scan all recorded Power observations without retaining their values."""

    def __init__(self, *, artifact_root: Path, patterns: Iterable[str] = ()) -> None:
        self._artifact_root = artifact_root
        # The API generated these from the persisted manifest; they are never
        # supplied by the browser.  The broad braced detector below catches
        # unfamiliar CTF formats, while these rules additionally cover an
        # operator-declared non-braced format such as ``FLAG-...``.
        self._configured_patterns = tuple(re.compile(pattern) for pattern in patterns)

    async def reveal(
        self,
        *,
        run_id: str,
        observations: Iterable[RuntimeCandidateArtifact],
        include_broad_detector: bool = True,
    ) -> dict[str, object]:
        """Return every readable flag-shaped value plus explicit scan status.

        The artifacts are already bounded by sandboxd.  There is intentionally
        no arbitrary candidate-count limit here: a response either represents
        every readable, provenance-matching observation or reports which
        observations could not be scanned.  Values exist only in this request
        and the local browser response; they are never written to the ledger.
        """

        store = LocalArtifactStore(
            self._artifact_root,
            max_artifact_bytes=64 * 1024,
            read_only=True,
        )
        candidates: OrderedDict[str, set[str]] = OrderedDict()
        scanned_artifact_count = 0
        unavailable_artifact_count = 0

        for observation in observations:
            try:
                metadata = await store.iter_metadata(observation.artifact_id)
                payload = await store.get_bytes(observation.artifact_id)
            except (OSError, RuntimeError):
                # Never turn a missing or malformed local artifact into a raw
                # error.  ``scan_complete`` tells the operator this queue is
                # incomplete instead of silently dropping a possible flag.
                unavailable_artifact_count += 1
                continue
            if not any(
                item.run_id == run_id
                and item.producer.kind is ActorKind.TOOL
                and item.producer.id == "sandboxd"
                for item in metadata
            ):
                unavailable_artifact_count += 1
                continue
            scanned_artifact_count += 1

            def record(value: str, *, racer_label: str = observation.racer_label) -> None:
                # Keep the response bounded like ctf_flag_submit and reject an
                # accidental empty regex match.  The raw candidate remains
                # request-local even when the same value occurs in many tools.
                if 1 <= len(value) <= 1_024:
                    candidates.setdefault(value, set()).add(racer_label)

            if include_broad_detector:
                for match in _RUNTIME_FLAG_CANDIDATE.finditer(payload):
                    # The pattern is ASCII-only, so this conversion cannot expose
                    # replacement characters or alter what the router would read.
                    record(match.group(1).decode("ascii"))
            if self._configured_patterns:
                # Manifest-owned Power patterns are ASCII bounded. Invalid
                # bytes are irrelevant to the router's configured CTF forms
                # and ignored rather than inventing a replacement value.
                text = payload.decode("utf-8", errors="ignore")
                for pattern in self._configured_patterns:
                    for match in pattern.finditer(text):
                        record(match.group(0))

        return {
            "run_id": run_id,
            "classification": "unverified_runtime_candidate",
            "candidates": [
                {
                    "value": value,
                    "racer_labels": sorted(labels),
                }
                for value, labels in candidates.items()
            ],
            "candidate_count": len(candidates),
            "scanned_artifact_count": scanned_artifact_count,
            "unavailable_artifact_count": unavailable_artifact_count,
            "scan_complete": unavailable_artifact_count == 0,
            "message": (
                "Runtime candidates were revealed for local review. "
                "They are unverified and do not change the run state."
            ),
        }

    async def find_observation_for_candidate(
        self,
        *,
        run_id: str,
        candidate: str,
        observations: Iterable[RuntimeCandidateArtifact],
    ) -> RuntimeCandidateArtifact | None:
        """Find immutable runtime evidence for one explicitly selected value.

        The caller is a local human-confirmation route.  It receives only an
        artifact reference, never a raw value in a durable record; flag-router
        independently repeats this provenance check before it can solve.
        """

        if not 1 <= len(candidate) <= 1_024:
            return None
        encoded = candidate.encode("utf-8")
        store = LocalArtifactStore(
            self._artifact_root,
            max_artifact_bytes=64 * 1024,
            read_only=True,
        )
        for observation in observations:
            try:
                metadata = await store.iter_metadata(observation.artifact_id)
                payload = await store.get_bytes(observation.artifact_id)
            except (OSError, RuntimeError):
                continue
            if not any(
                item.run_id == run_id
                and item.producer.kind is ActorKind.TOOL
                and item.producer.id == "sandboxd"
                for item in metadata
            ):
                continue
            if encoded in payload:
                return observation
        return None


__all__ = ["RuntimeCandidateArtifact", "RuntimeCandidateRevealService"]
