"""Validated API settings. Secrets are never included in representations."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CTFMESH_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = "development"
    # Power is an explicit opt-in deployment profile. P0 records the setting
    # now so later API routes cannot silently treat an unknown environment flag
    # as authorization to start a solver workspace.
    power_enabled: bool = False
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8000, ge=1, le=65_535)
    database_url: SecretStr = SecretStr("sqlite+aiosqlite:///./.artifacts/ctfmesh.db")
    artifact_root: Path = Path(".artifacts/artifacts")
    # Optional by default so an API-only local development stack does not
    # accidentally expose runner endpoints. When set, this shared service
    # credential is compared in constant time by the internal route boundary.
    internal_runner_token: SecretStr | None = None
    # M5 deliberately separates the verifier identity from Pi Runner. A
    # runner credential therefore cannot claim/complete a replay job, and a
    # verifier credential cannot submit a model candidate.
    internal_verifier_token: SecretStr | None = None
    # Power's flag router is distinct from both Pi Runner and verifier replay.
    # It may submit only a digest-bound, independently observed completion.
    internal_flag_router_token: SecretStr | None = None
    # Power execution talks only to these reviewed control-network services.
    # They are deployment-owned, never selected by the browser or challenge.
    power_sandboxd_url: str | None = None
    power_sandboxd_token: SecretStr | None = None
    power_flag_router_url: str | None = None
    power_flag_router_token: SecretStr | None = None
    # An optional read-only operator corpus. Empty/missing roots simply make
    # local retrieval unavailable; they do not enable filesystem selection.
    power_knowledge_root: Path | None = None
    # The control API can relay Pi tool calls only to this static internal
    # gateway origin. It is not a target/provider URL and is never supplied by
    # an operator request or model tool argument.
    tool_gateway_url: str | None = None
    tool_gateway_token: SecretStr | None = None
    # The live Pi runner exposes this private control-network endpoint solely
    # to receive a per-run, in-memory provider credential lease. The URL is
    # deployment-owned and intentionally cannot be supplied by the browser.
    pi_credential_broker_url: str | None = None
    # Source roots are fixed named-volume mount points owned by the API. A UI
    # archive may be copied into one of them only after intake validation; a
    # request never chooses a host path, bind mount, or Docker resource.
    source_slot_1_root: Path | None = None
    source_slot_2_root: Path | None = None
    # Browser archive triage has a request-local credential boundary, but the
    # API itself must never have direct Internet egress. In Docker, this is
    # the one reviewed internal CONNECT-proxy origin; host-local development
    # deliberately leaves it unset and therefore fails closed.
    provider_proxy_url: str | None = None
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    @field_validator("bind_host")
    @classmethod
    def no_public_bind_in_development(cls, value: str, info: object) -> str:
        del info
        if not value.strip():
            raise ValueError("bind_host cannot be empty")
        return value.strip()

    @field_validator("database_url")
    @classmethod
    def async_database_driver_required(cls, value: SecretStr) -> SecretStr:
        raw_value = value.get_secret_value()
        allowed = ("sqlite+aiosqlite://", "postgresql+asyncpg://")
        if not raw_value.startswith(allowed):
            raise ValueError("database_url must use a supported async driver")
        return value

    @field_validator("internal_runner_token", mode="before")
    @classmethod
    def normalize_internal_runner_token(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, SecretStr):
            raw_value = value.get_secret_value()
        else:
            raw_value = str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 16 or len(raw_value) > 512:
            raise ValueError("internal_runner_token must contain 16..512 characters")
        return SecretStr(raw_value)

    @field_validator("internal_verifier_token", mode="before")
    @classmethod
    def normalize_internal_verifier_token(cls, value: Any) -> Any:
        if value is None:
            return None
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 16 or len(raw_value) > 512:
            raise ValueError("internal_verifier_token must contain 16..512 characters")
        return SecretStr(raw_value)

    @field_validator("internal_flag_router_token", mode="before")
    @classmethod
    def normalize_internal_flag_router_token(cls, value: Any) -> Any:
        if value is None:
            return None
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 16 or len(raw_value) > 512:
            raise ValueError("internal_flag_router_token must contain 16..512 characters")
        return SecretStr(raw_value)

    @field_validator("power_sandboxd_token", "power_flag_router_token", mode="before")
    @classmethod
    def normalize_power_service_token(cls, value: Any) -> Any:
        if value is None:
            return None
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 16 or len(raw_value) > 512:
            raise ValueError("power_service_token must contain 16..512 characters")
        return SecretStr(raw_value)

    @field_validator("power_sandboxd_url", mode="before")
    @classmethod
    def normalize_power_sandboxd_url(cls, value: Any) -> Any:
        if value is None or not str(value).strip():
            return None
        if str(value).strip() != "http://sandboxd:8091":
            raise ValueError("power_sandboxd_url must be the reviewed internal sandboxd origin")
        return "http://sandboxd:8091"

    @field_validator("power_flag_router_url", mode="before")
    @classmethod
    def normalize_power_flag_router_url(cls, value: Any) -> Any:
        if value is None or not str(value).strip():
            return None
        if str(value).strip() != "http://flag-router:8092":
            raise ValueError(
                "power_flag_router_url must be the reviewed internal flag-router origin"
            )
        return "http://flag-router:8092"

    @field_validator("power_knowledge_root", mode="before")
    @classmethod
    def normalize_power_knowledge_root(cls, value: Any) -> Any:
        if value is None or value == "":
            return None
        path = Path(value)
        if not path.is_absolute() or path != Path("/data/knowledge/writeups"):
            raise ValueError("power_knowledge_root must be the reviewed local knowledge mount")
        return path

    @field_validator("tool_gateway_token", mode="before")
    @classmethod
    def normalize_tool_gateway_token(cls, value: Any) -> Any:
        if value is None:
            return None
        raw_value = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not raw_value.strip():
            return None
        if len(raw_value) < 16 or len(raw_value) > 512:
            raise ValueError("tool_gateway_token must contain 16..512 characters")
        return SecretStr(raw_value)

    @field_validator("tool_gateway_url", mode="before")
    @classmethod
    def normalize_tool_gateway_url(cls, value: Any) -> Any:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @field_validator("pi_credential_broker_url", mode="before")
    @classmethod
    def normalize_pi_credential_broker_url(cls, value: Any) -> Any:
        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized:
            return None
        # Keep this service on the reviewed control bridge. The API is never
        # allowed to turn a submitted provider key into a generic outbound
        # request, even through a configuration typo.
        if normalized != "http://pi-runner-live:8090":
            raise ValueError("pi_credential_broker_url must be the reviewed internal runner origin")
        return normalized

    @field_validator("source_slot_1_root", "source_slot_2_root", mode="before")
    @classmethod
    def absolute_source_slot_root(cls, value: Any) -> Any:
        if value is None or value == "":
            return None
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("source_slot_root must be an absolute path")
        return path

    @field_validator("provider_proxy_url", mode="before")
    @classmethod
    def normalize_provider_proxy_url(cls, value: Any) -> Any:
        """Accept only the fixed internal proxy, never an operator URL."""

        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized:
            return None
        # The Docker Compose service name and port are part of the reviewed
        # topology. Rejecting every other value prevents a browser request,
        # dotenv edit, or deployment typo from redirecting a supplied key.
        if normalized != "http://provider-proxy:3128":
            raise ValueError("provider_proxy_url must be the reviewed internal proxy origin")
        return normalized

    @model_validator(mode="after")
    def complete_tool_gateway_configuration(self) -> Settings:
        if (self.tool_gateway_url is None) != (self.tool_gateway_token is None):
            raise ValueError("tool_gateway_url and tool_gateway_token must be configured together")
        if self.pi_credential_broker_url is not None and self.internal_runner_token is None:
            raise ValueError("pi_credential_broker_url requires internal_runner_token")
        power_values = (
            self.power_sandboxd_url,
            self.power_sandboxd_token,
            self.power_flag_router_url,
            self.power_flag_router_token,
        )
        # Compose keeps the reviewed service origins visible even in the
        # normal profile, where both private tokens are blank. Once either
        # token is supplied, however, incomplete Power wiring must fail rather
        # than leaving a half-authorized execution path.
        if (
            self.power_sandboxd_token is not None or self.power_flag_router_token is not None
        ) and not all(value is not None for value in power_values):
            raise ValueError("Power service configuration must be complete")
        return self

    @field_validator("cors_origins")
    @classmethod
    def explicit_local_cors_origins(cls, values: list[str]) -> list[str]:
        if not values or "*" in values:
            raise ValueError("cors_origins must be an explicit non-empty allowlist")
        normalized: list[str] = []
        for value in values:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                raise ValueError("cors origin must be an absolute HTTP(S) origin")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("cors origin cannot contain credentials")
            try:
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("cors origin must contain a valid port") from exc
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("cors origin cannot contain path, query, or fragment")
            normalized.append(value.rstrip("/"))
        if len(normalized) != len(set(normalized)):
            raise ValueError("cors_origins cannot contain duplicates")
        return normalized

    @property
    def database_dsn(self) -> str:
        return self.database_url.get_secret_value()

    def __repr_args__(self) -> Any:
        return (
            (key, value)
            for key, value in super().__repr_args__()
            if key
            not in {
                "database_url",
                "internal_runner_token",
                "internal_verifier_token",
                "internal_flag_router_token",
                "power_sandboxd_token",
                "power_flag_router_token",
                "tool_gateway_token",
            }
        )
