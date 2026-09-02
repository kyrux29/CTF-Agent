"""Fail-closed environment configuration for the M3 gateway and source slot."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Self, cast

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ToolGatewaySettings(BaseSettings):
    """Trusted configuration for a gateway process, with no provider secret."""

    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: SecretStr
    artifact_root: Path
    tool_gateway_token: SecretStr
    source_slot_token: SecretStr
    # HMAC key shared only with the target connector. It is optional for M3
    # static slots, but dynamic UI source slots fail closed for HTTP without it.
    target_capability_key: SecretStr | None = None
    source_slot_1_challenge_id: str | None = None
    source_slot_1_url: str | None = None
    source_slot_1_dynamic_assignment: bool = False
    source_slot_2_challenge_id: str | None = None
    source_slot_2_url: str | None = None
    source_slot_2_dynamic_assignment: bool = False
    source_slot_workspace_root: Path = Path("/challenge")
    # The gateway never mounts this path. It passes the fixed mount metadata
    # into its second policy check only; the slot independently resolves it at
    # invocation time after validating backend-written assignment metadata.
    source_slot_dynamic_workspace_root: Path = Path("/slot/challenge")
    # Bound only on an internal Compose network; service has no published port.
    bind_host: str = "0.0.0.0"  # noqa: S104
    bind_port: int = Field(default=8081, ge=1, le=65_535)
    dispatch_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)

    @field_validator("database_url")
    @classmethod
    def async_database_driver_required(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.startswith(("sqlite+aiosqlite://", "postgresql+asyncpg://")):
            raise ValueError("tool_gateway_database_url_invalid")
        return value

    @field_validator("tool_gateway_token", "source_slot_token")
    @classmethod
    def bounded_token(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 16 or len(raw) > 512:
            raise ValueError("tool_gateway_token_invalid")
        return value

    @field_validator("target_capability_key")
    @classmethod
    def bounded_target_capability_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value()
        if len(raw) < 32 or len(raw) > 512:
            raise ValueError("target_capability_key_invalid")
        return value

    @field_validator("source_slot_1_challenge_id", "source_slot_2_challenge_id", mode="before")
    @classmethod
    def blank_challenge_slot_is_unconfigured(cls, value: Any) -> Any:
        """Treat Compose's empty default as absent, never as a valid slot ID."""

        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("source_slot_workspace_root", "source_slot_dynamic_workspace_root")
    @classmethod
    def absolute_workspace_root(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("source_slot_workspace_root_invalid")
        return value

    @model_validator(mode="after")
    def source_slot_pairs_are_complete(self) -> ToolGatewaySettings:
        configured = 0
        for challenge_id, url, dynamic_assignment in (
            (
                self.source_slot_1_challenge_id,
                self.source_slot_1_url,
                self.source_slot_1_dynamic_assignment,
            ),
            (
                self.source_slot_2_challenge_id,
                self.source_slot_2_url,
                self.source_slot_2_dynamic_assignment,
            ),
        ):
            if url is None:
                if challenge_id is not None or dynamic_assignment:
                    raise ValueError("source_slot_configuration_incomplete")
                continue
            if dynamic_assignment:
                if challenge_id is not None:
                    raise ValueError("source_slot_dynamic_configuration_invalid")
                configured += 1
                continue
            if challenge_id is None:
                raise ValueError("source_slot_configuration_incomplete")
            if not challenge_id or any(character.isspace() for character in challenge_id):
                raise ValueError("source_slot_challenge_id_invalid")
            configured += 1
        if configured == 0:
            raise ValueError("source_slot_configuration_missing")
        return self

    @property
    def database_dsn(self) -> str:
        return self.database_url.get_secret_value()

    @classmethod
    def from_environment(cls) -> Self:
        """Load required settings from the process environment.

        Pydantic validates these fields at runtime, but its generated settings
        constructor is statically represented as requiring every field. The
        typed callable cast documents the intentional environment-only entry
        point without weakening validation or exposing a partial configuration.
        """

        constructor = cast(Callable[[], Self], cls)
        return constructor()

    def __repr_args__(self) -> Any:
        hidden = {
            "database_url",
            "tool_gateway_token",
            "source_slot_token",
            "target_capability_key",
        }
        return ((key, value) for key, value in super().__repr_args__() if key not in hidden)


class SourceSlotSettings(BaseSettings):
    """Trusted configuration for one source-only fixed container."""

    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    source_slot_id: str
    source_slot_challenge_id: str | None = None
    source_slot_root: Path = Path("/challenge")
    # Dynamic slots receive a backend-owned assignment file at a sibling path
    # such as ``/slot/assignment.json``. It must never be placed in the
    # archive mount ``/slot/challenge``.
    source_slot_dynamic_assignment: bool = False
    source_slot_assignment_path: Path | None = None
    # Dynamic M6.a slots can reach exactly this internal connector. Static M3
    # source slots retain their reviewed local-lab transport topology.
    target_connector_url: str | None = None
    source_slot_token: SecretStr
    # Bound only on its private slot network; service has no published port.
    bind_host: str = "0.0.0.0"  # noqa: S104
    bind_port: int = Field(default=8082, ge=1, le=65_535)

    @field_validator("source_slot_id", "source_slot_challenge_id")
    @classmethod
    def bounded_slot_identifiers(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value or len(value) > 160 or any(character.isspace() for character in value):
            raise ValueError("source_slot_identifier_invalid")
        return value

    @field_validator("source_slot_root")
    @classmethod
    def source_root_must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("source_slot_root_invalid")
        return value

    @field_validator("source_slot_assignment_path")
    @classmethod
    def assignment_path_must_be_absolute(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("source_slot_assignment_path_invalid")
        return value

    @field_validator("target_connector_url", mode="before")
    @classmethod
    def fixed_target_connector_url(cls, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().rstrip("/")
        if not normalized:
            return None
        if normalized != "http://target-connector:8083":
            raise ValueError("target_connector_url_invalid")
        return normalized

    @field_validator("source_slot_token")
    @classmethod
    def source_slot_token_is_bounded(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 16 or len(raw) > 512:
            raise ValueError("source_slot_token_invalid")
        return value

    @model_validator(mode="after")
    def assignment_mode_is_closed_world(self) -> SourceSlotSettings:
        """Keep curated static and archive-backed dynamic slots disjoint."""

        if self.source_slot_dynamic_assignment:
            if self.source_slot_challenge_id is not None:
                raise ValueError("source_slot_dynamic_configuration_invalid")
            assignment_path = self.source_slot_assignment_path
            if assignment_path is None:
                raise ValueError("source_slot_assignment_path_required")
            if self.target_connector_url is None:
                raise ValueError("target_connector_url_required")
            root = self.source_slot_root.resolve(strict=False)
            if assignment_path.resolve(strict=False).is_relative_to(root):
                raise ValueError("source_slot_assignment_path_inside_source_root")
        else:
            if self.source_slot_challenge_id is None:
                raise ValueError("source_slot_challenge_id_required")
            if self.source_slot_assignment_path is not None:
                raise ValueError("source_slot_assignment_path_unexpected")
            if self.target_connector_url is not None:
                raise ValueError("target_connector_url_unexpected")
        return self

    @classmethod
    def from_environment(cls) -> Self:
        """Load the fixed slot configuration from its trusted environment."""

        constructor = cast(Callable[[], Self], cls)
        return constructor()

    def __repr_args__(self) -> Any:
        return (
            (key, value) for key, value in super().__repr_args__() if key != "source_slot_token"
        )


__all__ = ["SourceSlotSettings", "ToolGatewaySettings"]
