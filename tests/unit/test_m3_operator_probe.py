"""Unit coverage for the secret-safe M3 operator diagnostic helper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load_probe() -> ModuleType:
    """Load the host-side script without making ``support/`` a product package."""

    script_path = (
        Path(__file__).resolve().parents[2] / "support" / "scripts" / "m3_operator_probe.py"
    )
    specification = importlib.util.spec_from_file_location("ctfmesh_m3_operator_probe", script_path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    # Dataclasses resolve postponed annotations through the module registry.
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


probe: Any = _load_probe()


def _challenge(*, tools: list[str], aliases: dict[str, str]) -> dict[str, object]:
    return {
        "manifest": {
            "spec": {
                "mode": "assisted",
                "target": {"target_aliases": aliases},
                "tool_profile": tools,
                "limits": {
                    "wall_time_seconds": 300,
                    "max_tool_calls": 4,
                    "max_http_requests": 2,
                    "max_cost_usd": 1.0,
                },
            }
        }
    }


def test_manifest_precheck_requires_exact_probe_capabilities_and_budget() -> None:
    mode, budget, tools, aliases = probe._manifest_configuration(
        _challenge(tools=["source.read", "http.request"], aliases={"lab": "http://lab:8080"}),
        require_http=True,
    )
    assert mode == "assisted"
    assert budget["max_tool_calls"] == 4
    assert tools == {"source.read", "http.request"}
    assert aliases == {"lab"}

    with pytest.raises(probe.M3ProbeError, match="m3_probe_tool_profile_incomplete"):
        probe._manifest_configuration(
            _challenge(tools=["source.read"], aliases={"lab": "http://lab:8080"}),
            require_http=True,
        )


def test_cached_pair_checks_one_artifact_without_rendering_observation_text() -> None:
    raw_flag = "CTF{must_never_be_printed_by_probe}"
    artifact = {
        "artifact_id": "artifact-one",
        "digest": "a" * 64,
        "size_bytes": 20,
        "summary": "Bounded source observation.",
    }
    first = {
        "accepted": True,
        "cached": False,
        "tool_name": "source.read",
        "invocation_id": "tool-one",
        "artifact": artifact,
        "result": {"text": raw_flag},
    }
    duplicate = {**first, "cached": True}

    digest, result = probe._accepted_pair(first, duplicate, tool_name="source.read")

    assert digest == "a" * 64
    assert result["text"] == raw_flag
    assert raw_flag not in repr(probe.ProbeReport("run-one", digest, None, None, None, True))
    with pytest.raises(probe.M3ProbeError, match="m3_probe_idempotency_failed"):
        probe._accepted_pair(first, first, tool_name="source.read")


def test_probe_argument_validation_rejects_escape_and_absolute_target_selection() -> None:
    assert probe._source_path("src/app.py") == "src/app.py"
    assert probe._http_path("/health") == "/health"
    with pytest.raises(Exception, match="challenge root"):
        probe._source_path("../secret")
    with pytest.raises(Exception, match="relative-origin"):
        probe._http_path("//outside.example/path")
