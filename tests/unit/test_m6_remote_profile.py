"""Repository recognition for the one code-owned M6.a remote profile."""

from __future__ import annotations

import pytest
from ctfmesh_api.app import _build_exact_instance_manifest
from ctfmesh_db import database as database_module


def test_exact_instance_manifest_is_the_only_remote_candidate_replay_profile() -> None:
    manifest = _build_exact_instance_manifest(
        intake_id="intake_" + "a" * 32,
        entry_url="https://ctf.example.org/",
        provider="openai",
        slot_id="source-slot-1",
    )

    assert database_module._verification_manifest_profile(manifest, "web.path_traversal") == "m6-ui"
    altered = manifest.model_copy(
        update={
            "spec": manifest.spec.model_copy(
                update={"skill_profile": ("web.triage", "unreviewed.extra")}
            )
        }
    )
    assert database_module._verification_manifest_profile(altered, "web.path_traversal") is None


def test_remote_profile_allows_neutral_builder_to_select_only_reviewed_web_plan() -> None:
    """The browser never has to assert a vulnerability before source review."""

    manifest = _build_exact_instance_manifest(
        intake_id="intake_" + "a" * 32,
        entry_url="https://ctf.example.org/",
        provider="openai",
        slot_id="source-slot-1",
    )
    assert database_module._candidate_technique_is_reviewed(
        manifest,
        task_technique_id="general.review",
        plan_technique_id="web.path_traversal",
    )
    assert not database_module._candidate_technique_is_reviewed(
        manifest,
        task_technique_id="general.review",
        plan_technique_id="web.unreviewed",
    )
    assert not database_module._candidate_technique_is_reviewed(
        manifest,
        task_technique_id="web.sqli_basic",
        plan_technique_id="web.path_traversal",
    )


def test_exact_instance_flag_format_is_literal_derived_and_keeps_a_reviewed_fallback() -> None:
    """An operator hint may narrow capture, never author executable regex."""

    manifest = _build_exact_instance_manifest(
        intake_id="intake_" + "a" * 32,
        entry_url="https://ctf.example.org/",
        provider="openai",
        slot_id="source-slot-1",
        flag_format="HTB{...}",
    )

    assert manifest.spec.flag.patterns == (
        r"\bHTB\{[^\s{}]{1,512}\}",
        r"(?i)\b(?:CTF|FLAG|HTB|PICOCTF)\{[^\s{}]{1,512}\}",
    )
    with pytest.raises(ValueError, match="ui_flag_format_invalid"):
        _build_exact_instance_manifest(
            intake_id="intake_" + "a" * 32,
            entry_url="https://ctf.example.org/",
            provider="openai",
            slot_id="source-slot-1",
            flag_format="(?s).*",
        )
