"""Regression tests for the fixed-scope repository cleanup utility."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]


def _load_cleanup_module() -> ModuleType:
    script = ROOT / "support" / "scripts" / "dev" / "clean.py"
    specification = importlib.util.spec_from_file_location("ctfmesh_cleanup", script)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_clean_all_covers_every_node_workspace_dependency_directory() -> None:
    cleanup = _load_cleanup_module()
    dependencies = getattr(cleanup, "DEPENDENCY_DIRECTORIES")

    assert dependencies == (
        ".venv",
        "node_modules",
        "apps/web/node_modules",
        "services/pi-runner/node_modules",
        "tests/node_modules",
    )
