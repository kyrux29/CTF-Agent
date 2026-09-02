"""Regression coverage for the local-only M6 Compose bootstrap utility."""

from __future__ import annotations

import importlib.util
import stat
from pathlib import Path
from types import ModuleType

import pytest


def _bootstrap_module() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[2]
        / "support"
        / "scripts"
        / "dev"
        / "bootstrap_m6_runtime.py"
    )
    spec = importlib.util.spec_from_file_location("bootstrap_m6_runtime", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bootstrap_writes_private_complete_m6_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bootstrap contains internal wiring only and never a provider key field."""

    module = _bootstrap_module()
    destination = tmp_path / ".env"
    monkeypatch.setattr(module, "DEFAULT_ENV_PATH", destination)

    module.write_new_environment(destination)

    values = dict(
        line.split("=", maxsplit=1)
        for line in destination.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert values["CTFMESH_TOOL_GATEWAY_URL"] == "http://tool-gateway:8081"
    assert values["CTFMESH_PI_CREDENTIAL_BROKER_URL"] == "http://pi-runner-live:8090"
    assert values["CTFMESH_SOURCE_SLOT_1_DYNAMIC_ASSIGNMENT"] == "true"
    assert values["CTFMESH_SOURCE_SLOT_2_DYNAMIC_ASSIGNMENT"] == "true"
    assert set(values) == set(module._FIXED_M6_VALUES) | set(module._TOKEN_NAMES)
    assert all(len(values[name]) >= 32 for name in module._TOKEN_NAMES)
    assert all("API_KEY" not in name for name in values)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_bootstrap_refuses_to_replace_existing_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing private deployment file is never silently rotated or erased."""

    module = _bootstrap_module()
    destination = tmp_path / ".env"
    destination.write_text("KEEP=this-value\n", encoding="utf-8")
    monkeypatch.setattr(module, "DEFAULT_ENV_PATH", destination)

    with pytest.raises(module.BootstrapError, match="m6_runtime_environment_exists"):
        module.write_new_environment(destination)

    assert destination.read_text(encoding="utf-8") == "KEEP=this-value\n"
