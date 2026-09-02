"""P5 tests for trusted category resources and deterministic pack selection."""

from __future__ import annotations

import pytest
from ctfmesh_orchestrator import (
    CategoryPackId,
    category_signals_from_observations,
    reviewed_category_pack,
    reviewed_category_packs,
    select_category_pack,
)


def test_reviewed_category_packs_are_fixed_small_resources_with_digests() -> None:
    packs = reviewed_category_packs()

    assert tuple(pack.id for pack in packs) == tuple(CategoryPackId)
    assert all(pack.filename.endswith(".md") for pack in packs)
    assert all(len(pack.digest) == 64 for pack in packs)
    assert all(pack.text.startswith("# ") for pack in packs)
    # Guidance deliberately gives no static flag-shaped material that could
    # become a false candidate or a substituted contest solution.
    assert all("CTF{" not in pack.text for pack in packs)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("index.php handles an HTTP request", CategoryPackId.WEB),
        ("saved challenge.pcapng contains an EXIF clue", CategoryPackId.FORENSICS),
        ("RSA modulus and ciphertext are supplied", CategoryPackId.CRYPTO),
        ("recover the bytecode from a challenge.apk", CategoryPackId.REV),
        ("libc stack overflow needs a ROP chain", CategoryPackId.PWN),
    ],
)
def test_observation_signals_select_one_pack_without_retaining_source(
    text: str, expected: CategoryPackId
) -> None:
    signals = category_signals_from_observations([text])
    selected = select_category_pack(action_types=(), category_signals=signals)

    assert expected in signals
    assert selected == reviewed_category_pack(expected)
    assert text not in selected.text


def test_gdb_actions_outweigh_ambiguous_reverse_signal_and_empty_defaults_to_web() -> None:
    assert (
        select_category_pack(
            action_types=("gdb.start", "gdb.cmd"),
            category_signals=(CategoryPackId.REV,),
        ).id
        is CategoryPackId.PWN
    )
    assert select_category_pack(action_types=(), category_signals=()).id is CategoryPackId.WEB


def test_selector_rejects_untyped_category_signal() -> None:
    with pytest.raises(ValueError, match="category_pack_signal_invalid"):
        select_category_pack(action_types=(), category_signals=("web.v1",))  # type: ignore[arg-type]
