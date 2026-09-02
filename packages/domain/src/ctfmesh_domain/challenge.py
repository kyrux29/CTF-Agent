"""Challenge manifest contract and authorization-scope validation."""

from __future__ import annotations

import ipaddress
import math
import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from .base import ContractModel, FrozenSequence, Identifier, NonEmptyText, UtcDatetime
from .core import RunMode

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ChallengeCategory(StrEnum):
    """CTF disciplines used to select declarative skills and tool profiles."""

    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    OSINT = "osint"
    MISC = "misc"
    AI_ML = "ai_ml"
    MOBILE = "mobile"
    BLOCKCHAIN = "blockchain"
    HARDWARE = "hardware"
    STEGO = "stego"
    PROGRAMMING = "programming"


class ArtifactRole(StrEnum):
    """Typed input roles, including common offline CTF challenge materials."""

    SOURCE = "source"
    DESCRIPTION = "description"
    ATTACHMENT = "attachment"
    ARCHIVE = "archive"
    BINARY = "binary"
    BYTECODE = "bytecode"
    WASM = "wasm"
    PCAP = "pcap"
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    LOG = "log"
    FIRMWARE = "firmware"
    MOBILE_APP = "mobile_app"
    CONTRACT = "contract"
    TRANSACTION_DATA = "transaction_data"
    DATASET = "dataset"
    MODEL = "model"
    MEDIA = "media"
    DOCUMENT = "document"
    CIPHERTEXT = "ciphertext"
    KEY_MATERIAL = "key_material"
    WORDLIST = "wordlist"
    TESTCASE = "testcase"


def normalize_exact_host(value: str) -> str:
    """Normalize a literal hostname/IP while rejecting pattern-like scopes."""

    candidate = value.strip().lower().rstrip(".")
    if not candidate or any(character in candidate for character in "*?/@#"):
        raise ValueError("host must be a single exact hostname or IP address")
    if "://" in candidate or any(character.isspace() for character in candidate):
        raise ValueError("host must not contain a scheme or whitespace")

    ip_candidate = (
        candidate[1:-1] if candidate.startswith("[") and candidate.endswith("]") else candidate
    )
    try:
        return ipaddress.ip_address(ip_candidate).compressed
    except ValueError:
        pass

    if len(candidate) > 253:
        raise ValueError("hostname is too long")
    labels = candidate.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("host is not a valid exact hostname")
    return candidate


def _safe_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise ValueError("path must remain relative to the challenge directory")
    return str(path)


def _is_public_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "." in host and not host.endswith((".local", ".internal", ".test"))
    return address.is_global


class ChallengeMetadata(ContractModel):
    name: Identifier
    category: ChallengeCategory
    tags: FrozenSequence[Identifier] = Field(default_factory=tuple)

    @field_validator("category", mode="before")
    @classmethod
    def _parse_category(cls, value: Any) -> Any:
        return ChallengeCategory(value) if isinstance(value, str) else value


class AllowedEndpoint(ContractModel):
    host: str
    ports: FrozenSequence[int] = Field(min_length=1)
    # Power's reviewed tube capability is a raw TCP connection rather than a
    # generic URL fetch. It still has to be named by one exact host/port in a
    # challenge manifest before sandboxd is allowed to connect.
    protocols: FrozenSequence[Literal["http", "https", "tcp"]] = Field(min_length=1)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(port, bool) or port < 1 or port > 65_535 for port in values):
            raise ValueError("ports must be integers in the range 1..65535")
        if len(values) != len(set(values)):
            raise ValueError("ports must be unique")
        return values

    @field_validator("protocols")
    @classmethod
    def _validate_protocols(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("protocols must be unique")
        return values

    def permits(self, *, protocol: str, host: str, port: int) -> bool:
        return (
            protocol in self.protocols
            and normalize_exact_host(host) == self.host
            and port in self.ports
        )


class HealthcheckSpec(ContractModel):
    url: NonEmptyText
    expected_status: int = Field(ge=100, le=599)


def _canonical_target_alias_url(value: str) -> str:
    """Validate one named, origin-only target route for typed HTTP calls.

    A worker supplies only an alias and a relative path.  Keeping aliases at
    origin scope means URL joining can never reinterpret a worker-provided
    path as a new authority, credential, query, or fragment.
    """

    if any(character in value for character in "\r\n\t\x00\\"):
        raise ValueError("target alias URL contains forbidden characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target alias URL contains an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("target alias URL must be an origin-only HTTP(S) URL")
    host = normalize_exact_host(parsed.hostname)
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{rendered_host}:{effective_port}"


class TargetSpec(ContractModel):
    type: Literal["docker_compose", "remote", "artifact_bundle"]
    compose_file: str | None = None
    service: Identifier | None = None
    healthcheck: HealthcheckSpec | None = None
    allowed_endpoints: FrozenSequence[AllowedEndpoint] = Field(default_factory=tuple)
    # An operator-declared alias is the only target selector exposed to a
    # worker. The value is normalized to an origin; path/query remain in the
    # separate typed request contract at the tool boundary.
    target_aliases: dict[Identifier, NonEmptyText] = Field(default_factory=dict)
    reset_url: str | None = None

    @field_validator("compose_file")
    @classmethod
    def _validate_compose_file(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _safe_relative_path(value)

    @field_validator("target_aliases")
    @classmethod
    def _validate_target_aliases(cls, values: dict[str, str]) -> dict[str, str]:
        return {alias: _canonical_target_alias_url(url) for alias, url in values.items()}

    @model_validator(mode="after")
    def _validate_unique_scope(self) -> TargetSpec:
        if self.type == "docker_compose" and (self.compose_file is None or self.service is None):
            raise ValueError("docker_compose target requires compose_file and service")
        if self.type == "remote" and (self.compose_file is not None or self.service is not None):
            raise ValueError("remote target cannot declare compose_file or service")
        if self.type == "artifact_bundle":
            forbidden_fields = {
                "compose_file",
                "service",
                "healthcheck",
                "allowed_endpoints",
                "target_aliases",
                "reset_url",
            }
            declared_forbidden_fields = self.model_fields_set & forbidden_fields
            if declared_forbidden_fields:
                fields = ", ".join(sorted(declared_forbidden_fields))
                raise ValueError(
                    "artifact_bundle target cannot declare runtime or HTTP/network fields: "
                    f"{fields}"
                )
            return self

        tcp_only = all(
            protocol == "tcp"
            for endpoint in self.allowed_endpoints
            for protocol in endpoint.protocols
        )
        if self.healthcheck is None:
            # TCP CTF services frequently have no HTTP endpoint. A tcp-only
            # remote target is still fully constrained by allowed_endpoints,
            # but cannot honestly claim an HTTP health check or URL alias.
            if (
                self.allowed_endpoints
                and tcp_only
                and self.type == "remote"
                and not self.target_aliases
                and self.reset_url is None
            ):
                return self
            raise ValueError(f"{self.type} target requires healthcheck")
        if not self.allowed_endpoints:
            raise ValueError(f"{self.type} target requires at least one allowed_endpoint")

        triples: set[tuple[str, str, int]] = set()
        for endpoint in self.allowed_endpoints:
            for protocol in endpoint.protocols:
                for port in endpoint.ports:
                    triple = (protocol, endpoint.host, port)
                    if triple in triples:
                        raise ValueError("allowed endpoint scope contains duplicates")
                    triples.add(triple)

        for alias_url in self.target_aliases.values():
            alias = urlsplit(alias_url)
            alias_port = alias.port or (443 if alias.scheme == "https" else 80)
            if alias.hostname is None or not any(
                endpoint.permits(
                    protocol=alias.scheme,
                    host=alias.hostname,
                    port=alias_port,
                )
                for endpoint in self.allowed_endpoints
            ):
                raise ValueError("target alias URL is outside allowed_endpoints")

        parsed = urlsplit(self.healthcheck.url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("healthcheck URL must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("healthcheck URL cannot contain credentials")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError("healthcheck URL contains an invalid port") from exc
        if not any(
            endpoint.permits(protocol=parsed.scheme, host=parsed.hostname, port=port)
            for endpoint in self.allowed_endpoints
        ):
            raise ValueError("healthcheck URL is outside allowed_endpoints")
        if self.reset_url is not None:
            reset = urlsplit(self.reset_url)
            if reset.scheme not in {"http", "https"} or reset.hostname is None:
                raise ValueError("reset URL must be an absolute HTTP(S) URL")
            if reset.username is not None or reset.password is not None or reset.fragment:
                raise ValueError("reset URL cannot contain credentials or a fragment")
            try:
                reset_port = reset.port or (443 if reset.scheme == "https" else 80)
            except ValueError as exc:
                raise ValueError("reset URL contains an invalid port") from exc
            if not any(
                endpoint.permits(protocol=reset.scheme, host=reset.hostname, port=reset_port)
                for endpoint in self.allowed_endpoints
            ):
                raise ValueError("reset URL is outside allowed_endpoints")
        return self


class ChallengeArtifact(ContractModel):
    path: str
    role: ArtifactRole

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return _safe_relative_path(value)

    @field_validator("role", mode="before")
    @classmethod
    def _parse_role(cls, value: Any) -> Any:
        return ArtifactRole(value) if isinstance(value, str) else value


class FlagSourcePolicy(ContractModel):
    allow_from_target_response: bool
    allow_from_target_filesystem: bool
    deny_from_input_artifacts: Literal[True]


class FlagSpec(ContractModel):
    patterns: FrozenSequence[NonEmptyText] = Field(min_length=1)
    source_policy: FlagSourcePolicy
    replay_count: int = Field(ge=1, le=100)

    @field_validator("patterns")
    @classmethod
    def _validate_patterns(cls, patterns: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid flag pattern: {exc}") from exc
        return patterns


class ChallengeLimits(ContractModel):
    wall_time_seconds: int = Field(gt=0, le=86_400)
    max_worker_turns: int = Field(gt=0, le=100_000)
    max_tool_calls: int = Field(gt=0, le=1_000_000)
    max_http_requests: int = Field(gt=0, le=10_000_000)
    max_parallel_requests: int = Field(gt=0, le=10_000)
    max_cost_usd: float = Field(gt=0, le=1_000_000)
    max_artifact_bytes: int = Field(gt=0, le=1_099_511_627_776)

    @model_validator(mode="after")
    def _validate_consistent_limits(self) -> ChallengeLimits:
        if self.max_parallel_requests > self.max_http_requests:
            raise ValueError("max_parallel_requests cannot exceed max_http_requests")
        if not math.isfinite(self.max_cost_usd):
            raise ValueError("max_cost_usd must be finite")
        return self


class ProviderSpec(ContractModel):
    preferred: Identifier
    fallbacks: FrozenSequence[Identifier] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def _validate_distinct_providers(self) -> ProviderSpec:
        if self.preferred in self.fallbacks or len(self.fallbacks) != len(set(self.fallbacks)):
            raise ValueError("provider preference order must not contain duplicates")
        return self


class MemorySpec(ContractModel):
    namespace: Identifier
    cutoff: UtcDatetime
    internet_search: bool


class SourceBindingSpec(ContractModel):
    """Bind reviewed extracted source to one fixed, service-owned slot.

    The binding is intentionally an opaque intake receipt plus a small
    deployment slot identifier.  It is *not* an operator supplied filesystem
    path, volume name, container name, or URL.  The API materializer and the
    source slot independently check the same binding before source can be
    observed by a tool.
    """

    intake_id: str = Field(
        min_length=39,
        max_length=39,
        pattern=r"^intake_[0-9a-f]{32}$",
    )
    slot_id: Literal["source-slot-1", "source-slot-2"]


class ChallengeSpec(ContractModel):
    mode: RunMode
    target: TargetSpec
    artifacts: FrozenSequence[ChallengeArtifact] = Field(min_length=1)
    flag: FlagSpec
    limits: ChallengeLimits
    providers: ProviderSpec
    memory: MemorySpec
    tool_profile: FrozenSequence[Identifier] = Field(default_factory=tuple)
    skill_profile: FrozenSequence[Identifier] = Field(default_factory=tuple)
    # Optional so existing reviewed static manifests retain their v0.1 shape.
    # When set, this is the only dynamic source selector accepted by the M6.a
    # exact-instance lane.  Tool callers still receive neither value.
    source: SourceBindingSpec | None = None

    @field_validator("mode", mode="before")
    @classmethod
    def _parse_mode(cls, value: Any) -> Any:
        return RunMode(value) if isinstance(value, str) else value

    @field_validator("tool_profile", "skill_profile")
    @classmethod
    def _validate_distinct_profile_entries(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("profile entries must not contain duplicates")
        return values

    @model_validator(mode="after")
    def _validate_contest_boundary(self) -> ChallengeSpec:
        if self.source is not None:
            if self.mode is not RunMode.ASSISTED:
                raise ValueError("source binding is limited to assisted mode")
            if self.target.type != "remote":
                raise ValueError("source binding requires a remote target")
        if self.mode is RunMode.CONTEST:
            if self.memory.internet_search:
                raise ValueError("contest mode cannot enable public internet search")
            public_hosts = [
                endpoint.host
                for endpoint in self.target.allowed_endpoints
                if _is_public_host(endpoint.host)
            ]
            if public_hosts:
                raise ValueError("contest mode cannot authorize public Internet targets")
        return self


class ChallengeManifest(ContractModel):
    api_version: Literal["ctfmesh.io/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["Challenge"]
    metadata: ChallengeMetadata
    spec: ChallengeSpec
