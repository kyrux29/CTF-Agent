"""Regression coverage for the private Power Compose bootstrap utility."""

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
        / "bootstrap_power_runtime.py"
    )
    spec = importlib.util.spec_from_file_location("bootstrap_power_runtime", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_power_bootstrap_appends_only_private_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existing M6 configuration survives and no provider-key field is added."""

    module = _bootstrap_module()
    destination = tmp_path / ".env"
    destination.write_text(f"CTFMESH_INTERNAL_RUNNER_TOKEN={'p' * 32}\n", encoding="utf-8")
    monkeypatch.setattr(module, "DEFAULT_ENV_PATH", destination)
    monkeypatch.setattr(module, "_docker_socket_gid", lambda: "1000")

    module.append_power_environment(destination)

    values = dict(
        line.split("=", maxsplit=1)
        for line in destination.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert values["CTFMESH_INTERNAL_RUNNER_TOKEN"] == "p" * 32
    assert values["CTFMESH_POWER_ENABLED"] == "true"
    assert values["CTFMESH_SANDBOXD_SOCKET_GID"] == "1000"
    assert all(len(values[name]) >= 32 for name in module._TOKEN_NAMES)
    assert all("API_KEY" not in name for name in values)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_power_bootstrap_refuses_to_rotate_existing_power_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-run cannot overwrite a live Power service credential."""

    module = _bootstrap_module()
    destination = tmp_path / ".env"
    destination.write_text("CTFMESH_POWER_ENABLED=true\n", encoding="utf-8")
    monkeypatch.setattr(module, "DEFAULT_ENV_PATH", destination)

    with pytest.raises(module.BootstrapError, match="power_runtime_environment_already_configured"):
        module.append_power_environment(destination)

    assert destination.read_text(encoding="utf-8") == "CTFMESH_POWER_ENABLED=true\n"


def test_power_bootstrap_upgrades_the_runner_capability_and_socket_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An older Power .env gains M-PI-2 access without rotating its tokens."""

    module = _bootstrap_module()
    destination = tmp_path / ".env"
    existing = {
        "CTFMESH_POWER_ENABLED": "true",
        "CTFMESH_SANDBOXD_TOKEN": "s" * 32,
        "CTFMESH_FLAG_ROUTER_TOKEN": "f" * 32,
        "CTFMESH_INTERNAL_FLAG_ROUTER_TOKEN": "i" * 32,
    }
    destination.write_text(
        "".join(f"{name}={value}\n" for name, value in existing.items()), encoding="utf-8"
    )
    monkeypatch.setattr(module, "DEFAULT_ENV_PATH", destination)
    monkeypatch.setattr(module, "_docker_socket_gid", lambda: "1000")

    module.append_power_environment(destination)

    result = destination.read_text(encoding="utf-8")
    assert result.count("CTFMESH_SANDBOXD_TOKEN=") == 1
    assert "CTFMESH_SANDBOXD_SOCKET_GID=1000\n" in result
    values = dict(
        line.split("=", maxsplit=1)
        for line in result.splitlines()
        if line and not line.startswith("#")
    )
    assert len(values["CTFMESH_INTERNAL_RUNNER_TOKEN"]) >= 32
