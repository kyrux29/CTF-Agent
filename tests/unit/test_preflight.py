"""Tests for the deterministic, non-executing M1 preflight pass."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ctfmesh_domain import ChallengeManifest, PreflightObservationKind
from ctfmesh_orchestrator import (
    DeterministicPreflight,
    PreflightPayload,
    canonical_preflight_bytes,
)


def preflight_manifest() -> ChallengeManifest:
    """Build a small valid manifest without granting target network access."""

    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {
                "name": "preflight-source-case",
                "category": "web",
                "tags": ["source"],
            },
            "spec": {
                "mode": "assisted",
                "target": {"type": "artifact_bundle"},
                "artifacts": [{"path": "bundle/source.zip", "role": "source"}],
                "flag": {
                    "patterns": [r"CTF\{[A-Za-z0-9_:-]+\}"],
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": True,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": 600,
                    "max_worker_turns": 10,
                    "max_tool_calls": 16,
                    "max_http_requests": 16,
                    "max_parallel_requests": 1,
                    "max_cost_usd": 1.0,
                    "max_artifact_bytes": 1_000_000,
                },
                "providers": {"preferred": "operator-pending", "fallbacks": []},
                "memory": {
                    "namespace": "preflight-test",
                    "cutoff": "2026-08-28T00:00:00Z",
                    "internet_search": False,
                },
            },
        }
    )


def payload_for_kind(
    payloads: tuple[PreflightPayload, ...], kind: PreflightObservationKind
) -> dict[str, Any]:
    """Get the one typed payload for an observation kind in a readable way."""

    for payload in payloads:
        if payload.kind is kind:
            return payload.payload
    raise AssertionError(f"missing preflight payload: {kind.value}")


def test_preflight_is_deterministic_bounded_and_redacts_source_secrets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return 'ok'\n"
        "SECRET = 'source-only-secret'\n"
        "sample = 'CTF{input_candidate_must_not_escape}'\n",
        encoding="utf-8",
    )
    (source_root / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (source_root / "binary.bin").write_bytes(b"\x00\x01\x02")

    preflight = DeterministicPreflight()
    first = preflight.inspect(
        challenge_digest="a" * 64,
        manifest=preflight_manifest(),
        source_root=source_root,
    )
    second = preflight.inspect(
        challenge_digest="a" * 64,
        manifest=preflight_manifest(),
        source_root=source_root,
    )

    assert {item.kind for item in first} == set(PreflightObservationKind)
    assert [canonical_preflight_bytes(item) for item in first] == [
        canonical_preflight_bytes(item) for item in second
    ]
    inventory = payload_for_kind(first, PreflightObservationKind.FILE_INVENTORY)
    inventory_paths = {item["path"] for item in inventory["files"]}
    assert inventory_paths == {"app.py", "binary.bin", "requirements.txt"}
    routes = payload_for_kind(first, PreflightObservationKind.ROUTE_HEURISTIC)
    assert {item["route"] for item in routes["routes"]} == {"/health"}
    dependencies = payload_for_kind(first, PreflightObservationKind.DEPENDENCY_HEURISTIC)
    signals = {item["signal"] for item in dependencies["dependencies"]}
    assert {"import:flask", "manifest:requirements.txt"}.issubset(signals)
    snippets = payload_for_kind(first, PreflightObservationKind.REDACTED_SOURCE_SNIPPETS)
    encoded_snippets = str(snippets)
    assert "source-only-secret" not in encoded_snippets
    assert "CTF{input_candidate_must_not_escape}" not in encoded_snippets
    assert "REDACTED" in encoded_snippets


def test_preflight_omits_symlinks_and_keeps_manifest_only_mode(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 'outside-secret'", encoding="utf-8")
    (source_root / "safe.py").write_text("print('safe')", encoding="utf-8")
    (source_root / "escape.py").symlink_to(outside)

    preflight = DeterministicPreflight()
    sourced = preflight.inspect(
        challenge_digest="b" * 64,
        manifest=preflight_manifest(),
        source_root=source_root,
    )
    sourced_inventory = payload_for_kind(sourced, PreflightObservationKind.FILE_INVENTORY)
    assert [item["path"] for item in sourced_inventory["files"]] == ["safe.py"]

    manifest_only = preflight.inspect(
        challenge_digest="b" * 64,
        manifest=preflight_manifest(),
    )
    manifest_inventory = payload_for_kind(manifest_only, PreflightObservationKind.FILE_INVENTORY)
    assert manifest_inventory["source_mode"] == "manifest_only"
    assert manifest_inventory["files"] == []
