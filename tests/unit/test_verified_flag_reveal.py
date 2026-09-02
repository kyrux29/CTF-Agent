"""One-time raw-flag hand-off stays process-local and non-reusable."""

from __future__ import annotations

import pytest
from ctfmesh_api.verified_flag_reveal import VerifiedFlagRevealError, VerifiedFlagRevealStore


@pytest.mark.asyncio
async def test_verified_flag_reveal_is_one_time_and_not_rendered_in_repr() -> None:
    store = VerifiedFlagRevealStore()
    raw_flag = "CTF{memory_only_reveal}"

    await store.issue(
        run_id="run-verified-reveal",
        candidate_id="candidate-verified-reveal",
        flag=raw_flag,
    )

    assert raw_flag not in repr(store._leases["run-verified-reveal"])
    assert await store.consume(run_id="run-verified-reveal") == raw_flag
    with pytest.raises(VerifiedFlagRevealError, match="verified_flag_reveal_unavailable"):
        await store.consume(run_id="run-verified-reveal")


@pytest.mark.asyncio
async def test_verified_flag_reveal_refuses_an_invalid_or_oversized_value() -> None:
    store = VerifiedFlagRevealStore()

    with pytest.raises(VerifiedFlagRevealError, match="verified_flag_reveal_invalid"):
        await store.issue(
            run_id="run-invalid-reveal",
            candidate_id="candidate-invalid-reveal",
            flag="",
        )
