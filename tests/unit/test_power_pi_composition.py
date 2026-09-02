"""Regression checks for the M-PI-2 production composition boundary."""

from __future__ import annotations

import ast
from pathlib import Path


def test_power_controller_does_not_import_the_legacy_python_model_adapter() -> None:
    """Power orchestration may provision Pi work, never call a provider itself."""

    source_path = Path("apps/api/src/ctfmesh_api/power_runs.py")
    module = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
        statement.module
        for statement in ast.walk(module)
        if isinstance(statement, ast.ImportFrom) and statement.module is not None
    }
    imported_names = {
        alias.name
        for statement in ast.walk(module)
        if isinstance(statement, ast.ImportFrom)
        for alias in statement.names
    }
    assert "ctfmesh_solver_runtime.model" not in imported_modules
    assert "OpenAICompatibleSolverBackend" not in imported_names


def test_power_compose_profile_has_pi_runner_but_no_python_solver_service() -> None:
    """The only live Power model harness is Pi Runner's `power` profile."""

    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert 'profiles: ["m3-provider", "m3", "m6-ui", "power"]' in compose
    assert "\n  solver-runtime:\n" not in compose
