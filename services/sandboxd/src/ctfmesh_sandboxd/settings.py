"""Closed P0 configuration for the opt-in trusted Power workspace manager."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INTERNAL_CONTAINER_BIND_HOST = "0.0.0.0"  # noqa: S104 - no host port is published.
_WORKSPACE_IMAGE = "ctfmesh-ctf-toolkit:0.1"
_ARTIFACT_ROOT = Path("/data/artifacts")


class PowerProfileDisabledError(RuntimeError):
    """Raised instead of starting a socket-owning service without opt-in."""


class SandboxdSettings(BaseSettings):
    """Deployment-owned configuration; it never accepts operator/model input."""

    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_SANDBOXD_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # The global flag stays distinct from sandboxd-specific settings so P2 can
    # use the same explicit feature gate at the API boundary.
    power_enabled: bool = Field(default=False, validation_alias="CTFMESH_POWER_ENABLED")
    bind_host: str = _INTERNAL_CONTAINER_BIND_HOST
    bind_port: int = Field(default=8091, ge=1, le=65_535)
    docker_socket_path: Path = Path("/var/run/docker.sock")
    # The endpoint remains private on the control bridge, but a distinct
    # capability token prevents another attached service from acquiring a
    # workspace merely by knowing the service name.
    sandboxd_token: SecretStr | None = Field(
        default=None,
        validation_alias="CTFMESH_SANDBOXD_TOKEN",
    )
    artifact_root: Path = _ARTIFACT_ROOT
    workspace_image: str = _WORKSPACE_IMAGE
    workspace_memory_mb: int = Field(default=4096, ge=256, le=65_536)
    workspace_cpu_millis: int = Field(default=2000, ge=100, le=16_000)
    workspace_pids: int = Field(default=512, ge=32, le=4096)
    max_challenge_bytes: int = Field(default=512 * 1024 * 1024, ge=1, le=512 * 1024 * 1024)
    work_tmpfs_mb: int = Field(default=1024, ge=64, le=4096)
    tmp_tmpfs_mb: int = Field(default=128, ge=16, le=1024)
    output_limit_bytes: int = Field(default=64 * 1024, ge=1024, le=64 * 1024)
    max_exec_timeout_seconds: int = Field(default=120, ge=1, le=120)

    @field_validator("bind_host")
    @classmethod
    def internal_bind_only(cls, value: str) -> str:
        if value != _INTERNAL_CONTAINER_BIND_HOST:
            raise ValueError("sandboxd must bind the reviewed container interface")
        return value

    @field_validator("docker_socket_path")
    @classmethod
    def fixed_docker_socket(cls, value: Path) -> Path:
        if value != Path("/var/run/docker.sock"):
            raise ValueError("sandboxd must use the reviewed Docker socket path")
        return value

    @field_validator("sandboxd_token", mode="before")
    @classmethod
    def normalize_sandboxd_token(cls, value: Any) -> Any:
        if value is None:
            return None
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 32 or len(raw_value) > 512:
            raise ValueError("sandboxd_token must contain 32..512 characters")
        return SecretStr(raw_value)

    @field_validator("artifact_root")
    @classmethod
    def fixed_artifact_root(cls, value: Path) -> Path:
        if value != _ARTIFACT_ROOT:
            raise ValueError("sandboxd must use the reviewed artifact root")
        return value

    @field_validator("workspace_image")
    @classmethod
    def fixed_workspace_image(cls, value: str) -> str:
        if value != _WORKSPACE_IMAGE:
            raise ValueError("sandboxd must use the reviewed workspace image")
        return value

    def require_power_enabled(self) -> SandboxdSettings:
        """Fail closed before serving any socket-owning profile service."""

        if not self.power_enabled:
            raise PowerProfileDisabledError("power_profile_disabled")
        return self


__all__ = ["PowerProfileDisabledError", "SandboxdSettings"]
