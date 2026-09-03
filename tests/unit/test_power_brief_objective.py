"""An offline Power run must name the objective it can actually reach.

A local pwn or reverse archive never contains the challenge flag: it lives on
the remote the operator has not declared. The brief nevertheless instructed
every racer to submit an observed candidate, and an observed racer satisfied
that by writing a flag-shaped 32-byte marker into the target through the
challenge's own protocol, reading it back, and submitting its own string.
"""

from __future__ import annotations

import pytest
from ctfmesh_api.power_runs import PowerBriefContext, _power_brief


def _context() -> PowerBriefContext:
    return PowerBriefContext(
        category="pwn",
        files=("zigzag", "desc.txt"),
        excerpt="VAULTRIX note-cache",
        already_tried=(),
    )


def test_offline_brief_states_no_flag_can_appear_here() -> None:
    brief = _power_brief(None, _context())

    assert "the challenge flag cannot appear in this workspace" in brief
    assert "reproducible primitive, not a flag" in brief
    assert "proof of concept" in brief


def test_offline_brief_forbids_writing_a_flag_shaped_marker() -> None:
    """Deny path: the exact behaviour observed on a real local run."""

    brief = _power_brief(None, _context())

    assert "Never invent, guess, or write a flag-shaped string yourself" in brief
    assert "a value you wrote is not evidence" in brief


def test_targeted_brief_keeps_the_candidate_instruction() -> None:
    """A declared target can genuinely disclose a flag; that path is unchanged."""

    brief = _power_brief(("ctf.example.org", 1337), _context())

    assert "ctf_tube tools" in brief
    assert "Submit only a candidate observed in an artifact" in brief
    assert "cannot appear in this workspace" not in brief


@pytest.mark.parametrize("target", (None, ("ctf.example.org", 1337)))
def test_brief_stays_within_its_durable_bound(
    target: tuple[str, int] | None,
) -> None:
    brief = _power_brief(
        target,
        PowerBriefContext(
            category="pwn",
            files=tuple(f"file-{index}" for index in range(200)),
            excerpt="x" * 4_000,
            already_tried=tuple(f"tried-{index}" for index in range(200)),
        ),
        challenge_description="d" * 1_000,
    )

    assert len(brief) <= 2_000
