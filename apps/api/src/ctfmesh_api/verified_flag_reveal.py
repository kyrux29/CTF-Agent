"""Memory-only, one-time hand-off for a flag independently observed by a verifier.

The database deliberately contains only a proof and digests. A raw flag can
therefore be made available to the local operator only while this API process
is alive, only after the run reached ``solved``, and only once. Process restart
or expiry destroys the value and requires a fresh verified run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from time import monotonic


class VerifiedFlagRevealError(RuntimeError):
    """Stable error code that never embeds a raw flag or target response."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class _RevealLease:
    run_id: str
    candidate_id: str
    # Exclude this memory-only value from accidental debugging/repr output.
    flag: str = field(repr=False)
    expires_at: float = field(repr=False)


class VerifiedFlagRevealStore:
    """Keep at most one short-lived verifier flag per solved candidate."""

    def __init__(self, *, maximum_leases: int = 32) -> None:
        if maximum_leases < 1:
            raise ValueError("verified_flag_reveal_capacity_invalid")
        self._maximum_leases = maximum_leases
        self._leases: dict[str, _RevealLease] = {}
        self._lock = asyncio.Lock()

    async def issue(
        self,
        *,
        run_id: str,
        candidate_id: str,
        flag: str,
        ttl_seconds: int = 300,
    ) -> None:
        """Replace the same-run lease without persisting or returning its value."""

        if not 1 <= ttl_seconds <= 300 or not flag or len(flag) > 4096:
            raise VerifiedFlagRevealError("verified_flag_reveal_invalid")
        now = monotonic()
        async with self._lock:
            self._drop_expired(now)
            existing = self._leases.get(run_id)
            if existing is None and len(self._leases) >= self._maximum_leases:
                raise VerifiedFlagRevealError("verified_flag_reveal_capacity_exhausted")
            self._leases[run_id] = _RevealLease(
                run_id=run_id,
                candidate_id=candidate_id,
                flag=flag,
                expires_at=now + ttl_seconds,
            )

    async def consume(self, *, run_id: str) -> str:
        """Return and irrevocably discard the one live raw flag lease."""

        now = monotonic()
        async with self._lock:
            self._drop_expired(now)
            lease = self._leases.pop(run_id, None)
            if lease is None:
                raise VerifiedFlagRevealError("verified_flag_reveal_unavailable")
            return lease.flag

    def _drop_expired(self, now: float) -> None:
        for run_id in tuple(self._leases):
            if self._leases[run_id].expires_at <= now:
                self._leases.pop(run_id, None)


__all__ = ["VerifiedFlagRevealError", "VerifiedFlagRevealStore"]
