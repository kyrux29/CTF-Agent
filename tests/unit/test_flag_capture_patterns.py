"""Regression coverage for the default flag-capture rules.

Every earlier flag test supplied its own regex, so the *default* rules were
never exercised.  That is why an anchored ``\\b(?:FLAG|HTB|CTF)`` alternation
could ship while missing every competition prefix that merely ends in "ctf":
there is no word boundary between "pico" and "CTF".  These tests run the
shipped constants, not an injected pattern.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from ctfmesh_api.app import (
    _DEFAULT_EXACT_INSTANCE_FLAG_PATTERN,
    _DEFAULT_POWER_FLAG_PATTERN,
    _exact_flag_pattern,
)
from ctfmesh_api.runtime_candidate_reveal import (
    RuntimeCandidateArtifact,
    RuntimeCandidateRevealService,
    _is_placeholder,
)
from ctfmesh_domain import ActorKind, ActorRef
from ctfmesh_flag_router.router import _DEFAULT_FLAG_PATTERN
from ctfmesh_tools import LocalArtifactStore

# Prefixes taken from real competitions.  Eleven of these were unmatchable by
# the previous anchored alternation.
REAL_WORLD_FLAGS = (
    "flag{a_bc}",
    "FLAG{abcd}",
    "CTF{abcd}",
    "HTB{abcd}",
    "picoCTF{r34d_1t}",
    "uiuctf{abcd}",
    "DUCTF{abcd}",
    "corctf{abcd}",
    "csawctf{abcd}",
    "SEKAI{abcd}",
    "actf{abcd}",
    "justCTF{abcd}",
    "crypto{abcd}",
    "TFCCTF{abcd}",
    "grey{abcd}",
    "byuctf{abcd}",
    "b01lers{abcd}",
    "openECSC{abcd}",
    "LITCTF{abcd}",
)


@pytest.mark.parametrize("flag", REAL_WORLD_FLAGS)
@pytest.mark.parametrize(
    "pattern",
    (
        _DEFAULT_POWER_FLAG_PATTERN,
        _DEFAULT_EXACT_INSTANCE_FLAG_PATTERN,
        _DEFAULT_FLAG_PATTERN,
    ),
    ids=("power", "exact-instance", "router"),
)
def test_default_patterns_capture_real_competition_prefixes(pattern: str, flag: str) -> None:
    """A default rule must not depend on an enumerated prefix allowlist."""

    assert re.compile(pattern).search(f"stdout: observed {flag} done") is not None


@pytest.mark.parametrize("flag", REAL_WORLD_FLAGS)
def test_router_default_full_matches_a_bare_candidate(flag: str) -> None:
    """The router applies ``fullmatch``; a captured value must satisfy it."""

    assert re.compile(_DEFAULT_FLAG_PATTERN).fullmatch(flag) is not None


@pytest.mark.parametrize(
    "noise",
    ("SELECT{1}", "printf{%s}", "map{k}", "fmt{x}", "struct{int}", "json{}", "shell{}", "a{b}"),
)
def test_default_pattern_ignores_ordinary_braced_syntax(noise: str) -> None:
    """A four-character body keeps short code punctuation out of the queue."""

    assert re.compile(_DEFAULT_POWER_FLAG_PATTERN).search(noise) is None


@pytest.mark.parametrize(
    "candidate",
    (
        "BKSEC{...}",
        "FLAG{}",
        "picoCTF{...}",
        "FLAG{flag_here}",
        "FLAG{FLAG}",
        "FLAG{redacted}",
        "FLAG{your_flag_here}",
        "FLAG{xxxxxx}",
        "DH{____}",
    ),
)
def test_placeholder_bodies_are_rejected(candidate: str) -> None:
    """CTFMesh echoes the declared format into tool results and briefs."""

    assert _is_placeholder(candidate) is True


@pytest.mark.parametrize(
    "candidate",
    ("picoCTF{r34d_1t}", "flag{a_b_c}", "DUCTF{abcd}", "FLAG{x}", "SEKAI{1}", "FLAG{xy}"),
)
def test_real_bodies_are_kept(candidate: str) -> None:
    assert _is_placeholder(candidate) is False


def test_declared_format_no_longer_replaces_the_generic_rule() -> None:
    """A mistyped prefix must degrade to unnarrowed capture, never to none."""

    mistyped = _exact_flag_pattern("picoctf{*}")
    assert mistyped is not None
    observed = "stdout: picoCTF{r34d_1t}"
    assert re.compile(mistyped).search(observed) is None
    # The generic rule is persisted alongside the declared one, so the run
    # still reaches operator review.
    assert re.compile(_DEFAULT_POWER_FLAG_PATTERN).search(observed) is not None


def test_declared_format_stays_case_exact() -> None:
    """A case-only decoy must not satisfy an operator's declared prefix."""

    pattern = _exact_flag_pattern("DH{*}")
    assert pattern is not None
    assert re.compile(pattern).search("dh{lowercase_prefix}") is None
    assert re.compile(pattern).search("DH{real_body}") is not None


@pytest.mark.parametrize(
    ("declared", "observed", "expected"),
    (
        ("FLAG-*", "FLAG-YWJjZGVm==", "FLAG-YWJjZGVm=="),
        ("FLAG-*", "see FLAG-YWJj== now", "FLAG-YWJj=="),
        ("FLAG-*", "FLAG-abc123", "FLAG-abc123"),
    ),
)
def test_unbraced_format_keeps_trailing_padding(
    declared: str, observed: str, expected: str
) -> None:
    """A trailing ``\\b`` silently dropped base64 padding from a candidate.

    The truncated value still occurred in the artifact bytes, so provenance and
    the router both accepted it: the run could reach ``solved`` with a wrong
    flag.  This is a false positive, which is worse than a miss.
    """

    pattern = _exact_flag_pattern(declared)
    assert pattern is not None
    match = re.compile(pattern).search(observed)
    assert match is not None
    assert match.group(0) == expected


@pytest.mark.asyncio
async def test_reveal_skips_an_echoed_format_and_keeps_the_real_flag(
    tmp_path: Path,
) -> None:
    """The first racer turn commonly echoes the declared format back."""

    run_id = "run-flag-capture-placeholder"
    body = (
        "CTFMesh coordinator: manifest-declared capture pattern is picoCTF{...}\n"
        "stdout: picoCTF{r34l_fl4g_h3re}\n"
    )
    artifact = await LocalArtifactStore(tmp_path).put_bytes(
        body.encode("ascii"),
        run_id=run_id,
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )

    revealed = await RuntimeCandidateRevealService(
        artifact_root=tmp_path,
        patterns=(_DEFAULT_POWER_FLAG_PATTERN,),
    ).reveal(
        run_id=run_id,
        observations=(RuntimeCandidateArtifact(artifact_id=artifact.id, racer_label="A"),),
        include_broad_detector=False,
    )

    assert revealed["candidates"] == [{"value": "picoCTF{r34l_fl4g_h3re}", "racer_labels": ["A"]}]
    assert revealed["candidate_count"] == 1


@pytest.mark.asyncio
async def test_reveal_opens_no_gate_for_a_format_reminder_alone(tmp_path: Path) -> None:
    """Deny path: an echoed format on its own must not pause a race."""

    run_id = "run-flag-capture-reminder-only"
    artifact = await LocalArtifactStore(tmp_path).put_bytes(
        b"Final flag format reminder: BKSEC{...}\n",
        run_id=run_id,
        mime_type="text/plain",
        producer=ActorRef(kind=ActorKind.TOOL, id="sandboxd"),
        classification="secret",
    )

    revealed = await RuntimeCandidateRevealService(
        artifact_root=tmp_path,
        patterns=(_DEFAULT_POWER_FLAG_PATTERN,),
    ).reveal(
        run_id=run_id,
        observations=(RuntimeCandidateArtifact(artifact_id=artifact.id, racer_label="B"),),
        include_broad_detector=False,
    )

    assert revealed["candidates"] == []
    assert revealed["candidate_count"] == 0
