"""Closed deployment settings for the Power flag-router boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_CONTROL_API_URL = "http://api:8000"
_ARTIFACT_ROOT = Path("/data/artifacts")
_INTERNAL_CONTAINER_BIND_HOST = "0.0.0.0"  # noqa: S104 - no host port is published.


class FlagRouterSettings(BaseSettings):
    """Service-owned inputs only; candidate values are never configuration."""

    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_FLAG_ROUTER_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    bind_host: str = _INTERNAL_CONTAINER_BIND_HOST
    bind_port: int = Field(default=8092, ge=1, le=65_535)
    router_token: SecretStr = Field(validation_alias="CTFMESH_FLAG_ROUTER_TOKEN")
    control_api_token: SecretStr = Field(validation_alias="CTFMESH_INTERNAL_FLAG_ROUTER_TOKEN")
    control_api_url: str = _CONTROL_API_URL
    artifact_root: Path = _ARTIFACT_ROOT

    @field_validator("bind_host")
    @classmethod
    def validate_bind_host(cls, value: str) -> str:
        if value != _INTERNAL_CONTAINER_BIND_HOST:
            raise ValueError("flag router must bind the reviewed container interface")
        return value

    @field_validator("control_api_url")
    @classmethod
    def validate_control_api_url(cls, value: str) -> str:
        if value != _CONTROL_API_URL:
            raise ValueError("flag router must use the reviewed Control API origin")
        return value

    @field_validator("artifact_root")
    @classmethod
    def validate_artifact_root(cls, value: Path) -> Path:
        if value != _ARTIFACT_ROOT:
            raise ValueError("flag router must use the reviewed artifact root")
        return value

    @field_validator("router_token", "control_api_token", mode="before")
    @classmethod
    def validate_token(cls, value: Any) -> SecretStr:
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not 32 <= len(raw_value) <= 512:
            raise ValueError("flag router tokens must contain 32..512 characters")
        return SecretStr(raw_value)


__all__ = ["FlagRouterSettings"]
