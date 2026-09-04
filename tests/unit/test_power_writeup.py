"""Tests for the deterministic, redacted verified-Power handoff."""

from __future__ import annotations

import pytest
from ctfmesh_orchestrator.power_writeup import PowerWriteupUnavailable, render_power_writeup


def _run(*, status: str = "solved") -> dict[str, object]:
    return {
        "id": "run_power_writeup_fixture",
        "provider": "power-swarm",
        "status": status,
        "updated_at": "2026-09-04T12:00:00Z",
    }


def _challenge() -> dict[str, object]:
    return {
        "name": "practice-rev",
        "manifest": {"metadata": {"category": "reverse"}},
    }


def test_verified_writeup_keeps_winner_timeline_and_excludes_sensitive_values() -> None:
    """Only fixed receipt vocabulary is eligible for a Markdown export."""

    candidate = "DH{candidate_must_not_be_exported}"
    writeup = render_power_writeup(
        run=_run(),
        challenge=_challenge(),
        events=(
            {
                "type": "power.command.observed",
                "payload": {
                    "label": "B",
                    "action_type": "ctf_shell_exec",
                    "turn_count": 4,
                    "command": "echo " + candidate,
                    "output": candidate,
                },
            },
            {
                "type": "power.candidate.review.confirmed",
                "payload": {"label": "B", "candidate": candidate},
            },
        ),
    )

    assert "source_racer: B" in writeup
    assert "category: reverse" in writeup
    assert "Turn 4: Ran a bounded sandbox analysis command." in writeup
    assert candidate not in writeup
    assert "echo " not in writeup
    assert "raw flag" in writeup.lower()


def test_writeup_requires_checker_backed_winner_provenance() -> None:
    """A solved row alone must not fabricate which racer found the answer."""

    with pytest.raises(PowerWriteupUnavailable, match="power_writeup_source_unavailable"):
        render_power_writeup(run=_run(), challenge=_challenge(), events=())


def test_writeup_rejects_unverified_or_non_power_runs() -> None:
    """The endpoint contract can only represent a terminal verified Power run."""

    with pytest.raises(PowerWriteupUnavailable, match="power_writeup_run_not_verified"):
        render_power_writeup(
            run=_run(status="running"),
            challenge=_challenge(),
            events=(),
        )
