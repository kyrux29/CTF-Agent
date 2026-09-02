"""Configuration and module-entrypoint coverage for the Compose worker."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from ctfmesh_orchestrator.worker import (
    PreflightWorkerConfigurationError,
    load_preflight_worker_config,
)


def test_preflight_worker_config_hides_database_url_and_validates_fixed_boundaries() -> None:
    database_url = "postgresql+asyncpg://ctfmesh:secret-password@postgres:5432/ctfmesh"
    config = load_preflight_worker_config(
        {
            "CTFMESH_DATABASE_URL": database_url,
            "CTFMESH_ARTIFACT_ROOT": "/data/artifacts",
            "CTFMESH_PREFLIGHT_POLL_MS": "750",
        }
    )
    assert config.poll_interval_seconds == 0.75
    assert database_url not in repr(config)

    with pytest.raises(PreflightWorkerConfigurationError, match="artifact_root_not_absolute"):
        load_preflight_worker_config(
            {
                "CTFMESH_DATABASE_URL": database_url,
                "CTFMESH_ARTIFACT_ROOT": "relative-artifacts",
            }
        )
    with pytest.raises(PreflightWorkerConfigurationError, match="poll_interval_invalid"):
        load_preflight_worker_config(
            {
                "CTFMESH_DATABASE_URL": database_url,
                "CTFMESH_ARTIFACT_ROOT": "/data/artifacts",
                "CTFMESH_PREFLIGHT_POLL_MS": "0",
            }
        )


def test_module_entrypoint_fails_closed_when_required_configuration_is_missing() -> None:
    """``python -m`` must execute ``main`` instead of exiting silently."""

    environment = os.environ.copy()
    for name in (
        "CTFMESH_DATABASE_URL",
        "CTFMESH_ARTIFACT_ROOT",
        "CTFMESH_PREFLIGHT_POLL_MS",
    ):
        environment.pop(name, None)
    # nosec B603 - current test interpreter and fixed package module only.
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "ctfmesh_orchestrator.worker"],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 1
    assert "preflight_worker_database_url_invalid" in completed.stderr
