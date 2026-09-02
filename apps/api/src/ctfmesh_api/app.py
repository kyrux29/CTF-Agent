"""FastAPI composition root and product-facing contracts."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from ctfmesh_db import Database, Repository
from ctfmesh_domain import (
    AgentBridgeEvent,
    AgentJobKind,
    ChallengeManifest,
    ExploitCandidateSubmission,
    FindingSubmission,
    HintCard,
    HintDirective,
    RunMode,
    TaskDelegationRequest,
    VerifierCompletionV1,
    normalize_exact_host,
)
from ctfmesh_orchestrator.candidates import CandidateArtifactService
from ctfmesh_orchestrator.power_budget import PowerRunBudget
from ctfmesh_orchestrator.power_race import (
    PowerModelAssignment,
    PowerRaceConfiguration,
    PowerRaceConfigurationError,
    PowerRaceProvider,
    PowerRacerAssignment,
)
from ctfmesh_orchestrator.run_engine import RunEngine
from ctfmesh_orchestrator.scheduler import hint_template, hint_templates
from ctfmesh_provider_base import ProviderTriageError
from ctfmesh_skills import SkillCategory, builtin_skill_registry, mcp_source_profiles_for
from ctfmesh_solver_runtime.flag_router import HttpFlagRouterClient, HttpFlagRouterClientError
from ctfmesh_solver_runtime.sandboxd import HttpSandboxdClient, SandboxdClientError
from ctfmesh_tool_runtime import (
    GatewayToolCall,
    GatewayToolRequest,
    HttpToolGatewayClient,
    ToolGatewayClient,
)
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from .archive_intake import (
    ARCHIVE_TRIAGE_DEFAULT_TIMEOUT_SECONDS,
    ARCHIVE_TRIAGE_HARD_MAX_OUTPUT_TOKENS,
    ARCHIVE_TRIAGE_HARD_MAX_TIMEOUT_SECONDS,
    ARCHIVE_TRIAGE_MAX_OUTPUT_TOKENS,
    ARCHIVE_TRIAGE_MIN_OUTPUT_TOKENS,
    ARCHIVE_TRIAGE_MIN_TIMEOUT_SECONDS,
    MAX_ARCHIVE_UPLOAD_BYTES,
    ArchiveIntakeError,
    ArchiveIntakeService,
    ArchiveTriageProgressStage,
)
from .power_runs import (
    PowerRunController,
    PowerRunLaunch,
    power_brief_context_from_intake,
)
from .provider_registry import (
    ArchiveTriageProvider,
    ArchiveTriageProviderFactory,
    ArchiveTriageProviderSession,
    archive_triage_provider_descriptors,
    create_archive_triage_provider_session,
)
from .runtime_candidate_reveal import (
    RuntimeCandidateArtifact,
    RuntimeCandidateRevealService,
)
from .settings import Settings
from .verified_flag_reveal import VerifiedFlagRevealError, VerifiedFlagRevealStore

_CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_TRIAGE_REQUEST_PATH = re.compile(r"^/v1/archive-intakes/intake_[0-9a-f]{32}/triage(?:/stream)?$")
MAX_TRIAGE_REQUEST_BYTES = 16 * 1024
# A browser-supplied flag format is a *hint*, never arbitrary regular
# expression input.  The service turns this small literal grammar into a
# reviewed capture pattern before it reaches Pi or the verifier.  This avoids
# regex injection/ReDoS while retaining common CTF forms such as ``HTB{...}``
# and ``FLAG_...``.
_EXACT_FLAG_FORMAT_MAX_LENGTH = 96
_POWER_CHALLENGE_DESCRIPTION_MAX_LENGTH = 1_000
_EXACT_FLAG_FORMAT_LITERAL = re.compile(r"^[A-Za-z0-9_@:+.{}-]+$")
_EXACT_FLAG_BODY_PATTERN = r"[A-Za-z0-9_:\-]{1,512}"
_DEFAULT_EXACT_INSTANCE_FLAG_PATTERN = (
    rf"(?i)\b(?:CTF|FLAG|HTB|PICOCTF)\{{{_EXACT_FLAG_BODY_PATTERN}\}}"
)
# Power retains its historically reviewed fallback set, while an operator may
# add one literal-derived format per run.  Do not accept browser-authored
# regex: the same literal validation used by the exact-instance flow keeps
# this expression bounded and reviewable.
_DEFAULT_POWER_FLAG_PATTERN = rf"(?i)\b(?:FLAG|HTB|CTF)\{{{_EXACT_FLAG_BODY_PATTERN}\}}"
_POWER_ACTIVITY_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[A-Za-z0-9_:\-]{1,512}\}")
_POWER_ACTIVITY_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_POWER_ACTIVITY_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{16,})\b")
_POWER_ACTIVITY_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)
_ARCHIVE_TRIAGE_STREAM_SCHEMA = "ctfmesh.archive-triage-stream/v1"
_ARCHIVE_TRIAGE_PROGRESS_SUMMARIES = {
    ArchiveTriageProgressStage.REQUEST_ACCEPTED: "Request accepted.",
    ArchiveTriageProgressStage.RECEIPT_LOADED: "Local receipt loaded.",
    ArchiveTriageProgressStage.EVIDENCE_PREPARED: "Metadata evidence prepared.",
    ArchiveTriageProgressStage.PROVIDER_REQUEST_STARTED: "Request sent to the AI provider.",
    ArchiveTriageProgressStage.PROVIDER_RESPONSE_RECEIVED: "Provider response received.",
    ArchiveTriageProgressStage.RESULT_VALIDATED: "Structured response validated.",
    ArchiveTriageProgressStage.RESULT_SAVED: "Triage receipt updated.",
}
_RUN_ACTIVITY_SUMMARIES: dict[str, tuple[str, str]] = {
    "run.created": ("queued", "Run created."),
    "run.state.changed": ("state", "Run state updated."),
    "agent.job.queued": ("queued", "Reviewed work queued."),
    "agent.job.claimed": ("working", "A worker picked up reviewed work."),
    "agent.session.ready": ("working", "AI session ready."),
    "agent.turn.started": ("working", "AI turn started."),
    "agent.turn.completed": ("working", "AI turn completed."),
    "tool.requested": ("tool", "Scoped tool request started."),
    "tool.completed": ("tool", "Scoped tool result recorded."),
    "tool.failed": ("tool", "Scoped tool request ended."),
    "verification.queued": ("verify", "Independent verification queued."),
    "verification.completed": ("verify", "Independent verification completed."),
    "verification.failed": ("verify", "Independent verification did not pass."),
    "power.scope.declared": ("scope", "Power target scope declared."),
    "power.pi.sessions.started": ("working", "Power Pi sessions queued."),
    "power.pi.session.queued": ("queued", "Power session queued."),
    "power.pi.session.ready": ("working", "Power session reached a safe boundary."),
    "power.pi.steer.queued": ("queued", "Power instruction queued."),
    "power.pi.steer.applied": ("working", "Power instruction applied."),
    "power.pi.abort.requested": ("state", "Power sibling abort requested."),
    "power.pi.session.aborted": ("state", "Power session aborted."),
    "power.pi.session.failed": ("state", "Power session stopped safely."),
    "power.pi.provision.failed": ("state", "Power workspace setup failed."),
    "power.autoprompter.progress": ("working", "AutoPrompter progress updated."),
    "power.budget.progress": ("working", "Power budget reservation updated."),
    "power.swarm.started": ("working", "Power swarm started."),
    "power.swarm.progress": ("working", "Power swarm progress updated."),
    "power.command.observed": ("tool", "Power command receipt updated."),
    "power.pi.activity": ("working", "Power Pi update recorded."),
    "power.pi.tool_transcript": ("tool", "Power tool transcript recorded."),
    "power.pi.usage": ("working", "Power Pi usage updated."),
    "power.candidate.review.requested": ("review", "A flag-format candidate awaits review."),
    "power.candidate.review.rejected": ("working", "Candidate rejected; racers resumed."),
    "power.candidate.review.confirmed": (
        "verify",
        "Reviewed candidate sent to independent verification.",
    ),
    "power.swarm.completed": ("state", "Power swarm completed."),
    "power.swarm.cancelled": ("state", "Power swarm cancellation requested."),
    "power.swarm.failed": ("state", "Power swarm stopped."),
}
_PUBLIC_PROVIDER_ERROR_CODES = frozenset(
    {
        "missing_api_key",
        "timeout",
        "transport_error",
        "http_error",
        "response_too_large",
        "triage_cites_unknown_evidence",
        "malformed_response",
        "missing_choice",
        "incomplete_response",
        "incomplete_max_output_tokens",
        "incomplete_content_filter",
        "missing_output_text",
        "provider_tool_call_forbidden",
        "malformed_structured_output",
        "triage_schema_violation",
        "model_refusal",
    }
)


def _redact_power_activity_text(value: str, *, maximum: int | None = None) -> str:
    """Redact a Pi feed before it reaches the append-only event boundary.

    Pi Runner has the same defense, but the internal API repeats it so an
    accidental or compromised runner cannot write a flag, credential, or
    session token into the durable operator timeline.
    """

    safe = _POWER_ACTIVITY_RAW_FLAG.sub("[REDACTED_FLAG]", value)
    safe = _POWER_ACTIVITY_BEARER.sub("Bearer [REDACTED]", safe)
    safe = _POWER_ACTIVITY_API_KEY.sub("[REDACTED_API_KEY]", safe)
    safe = _POWER_ACTIVITY_SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", safe)
    return safe if maximum is None else safe[:maximum]


def _normalize_power_challenge_description(value: str | None) -> str | None:
    """Keep one operator-supplied challenge note useful and safe for Pi.

    The description is context, not trusted policy or evidence. Normalize it
    into a compact single paragraph and redact accidental secrets before it
    becomes part of the durable Power brief.
    """

    if value is None:
        return None
    normalized = " ".join(value.split())
    if not normalized:
        return None
    return _redact_power_activity_text(normalized, maximum=_POWER_CHALLENGE_DESCRIPTION_MAX_LENGTH)


def _normalize_exact_flag_format(value: str | None) -> str | None:
    """Validate one literal CTF flag hint without accepting a user regex.

    Supported forms are a prefix (``FLAG_`` or ``HTB{``) and one template
    marker (``HTB{...}`` or ``FLAG-...``).  The result is intentionally kept
    as the normalized operator display value; :func:`_exact_flag_pattern`
    performs the only regex construction with ``re.escape``.
    """

    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if (
        len(normalized) > _EXACT_FLAG_FORMAT_MAX_LENGTH
        or not _EXACT_FLAG_FORMAT_LITERAL.fullmatch(normalized)
        or normalized.count("...") > 1
    ):
        raise ValueError("ui_flag_format_invalid")

    if "..." in normalized:
        prefix, suffix = normalized.split("...", 1)
        # A braced format is intentionally limited to the familiar
        # ``PREFIX{...}`` shape.  Other supported templates contain no braces,
        # so punctuation cannot accidentally become regex syntax.
        braced = prefix.endswith("{") and suffix == "}"
        unbraced = "{" not in normalized and "}" not in normalized
        if len(prefix.rstrip("{")) < 2 or not (braced or unbraced):
            raise ValueError("ui_flag_format_invalid")
        return normalized

    if normalized.endswith("{"):
        if normalized.count("{") != 1 or normalized.count("}") != 0 or len(normalized) < 3:
            raise ValueError("ui_flag_format_invalid")
        return normalized
    if "{" in normalized or "}" in normalized or len(normalized) < 2:
        raise ValueError("ui_flag_format_invalid")
    return normalized


def _exact_flag_pattern(flag_format: str | None) -> str | None:
    """Build one bounded, case-insensitive capture regex from a literal hint."""

    normalized = _normalize_exact_flag_format(flag_format)
    if normalized is None:
        return None
    if "..." in normalized:
        prefix, suffix = normalized.split("...", 1)
        return rf"(?i)\b{re.escape(prefix)}{_EXACT_FLAG_BODY_PATTERN}{re.escape(suffix)}"
    if normalized.endswith("{"):
        return rf"(?i)\b{re.escape(normalized)}{_EXACT_FLAG_BODY_PATTERN}\}}"
    return rf"(?i)\b{re.escape(normalized)}{_EXACT_FLAG_BODY_PATTERN}\b"


RunEngineFactory = Callable[[Repository, Path], RunEngine]
ToolGatewayFactory = Callable[[Repository, Path], ToolGatewayClient]


class PiCredentialLeaseError(RuntimeError):
    """Stable, key-free error raised by the private Pi lease relay."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PiCredentialLeaseClient:
    """Private API-to-runner credential relay used only by M6.a launch."""

    def __init__(self, *, base_url: str, runner_token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._runner_token = runner_token

    async def grant(
        self,
        *,
        run_id: str,
        provider: str,
        model: str,
        api_key: str,
        ttl_seconds: int,
        session_id: str | None = None,
    ) -> str:
        """Install one in-memory credential lease without logging its key."""

        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(3.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    "/internal/credential-leases",
                    headers={"X-CTFMESH-Runner-Token": self._runner_token},
                    json={
                        "run_id": run_id,
                        **({"session_id": session_id} if session_id is not None else {}),
                        "provider": provider,
                        "model": model,
                        "api_key": api_key,
                        "ttl_seconds": ttl_seconds,
                    },
                )
        except (httpx.HTTPError, ValueError) as exc:
            raise PiCredentialLeaseError("pi_credential_lease_unavailable") from exc
        if response.status_code != 200:
            raise PiCredentialLeaseError("pi_credential_lease_rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PiCredentialLeaseError("pi_credential_lease_invalid_response") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("accepted") is not True
            or not isinstance(payload.get("expires_at"), str)
            or len(payload["expires_at"]) > 64
        ):
            raise PiCredentialLeaseError("pi_credential_lease_invalid_response")
        # ``expires_at`` is a code-owned timestamp returned to the UI; the
        # response contract intentionally contains neither key nor transcript.
        return payload["expires_at"]


PiCredentialLeaseFactory = Callable[["Settings"], PiCredentialLeaseClient | None]


def configured_tool_gateway_factory(settings: Settings) -> ToolGatewayFactory | None:
    """Build the static control-to-gateway relay from trusted deployment config."""

    if settings.tool_gateway_url is None or settings.tool_gateway_token is None:
        return None
    client = HttpToolGatewayClient(
        base_url=settings.tool_gateway_url,
        token=settings.tool_gateway_token.get_secret_value(),
    )
    return lambda _repository, _artifact_root: client


def configured_pi_credential_lease_client(settings: Settings) -> PiCredentialLeaseClient | None:
    """Build only the reviewed API-to-live-runner credential relay."""

    if settings.pi_credential_broker_url is None or settings.internal_runner_token is None:
        return None
    return PiCredentialLeaseClient(
        base_url=settings.pi_credential_broker_url,
        runner_token=settings.internal_runner_token.get_secret_value(),
    )


def configured_archive_provider_factory(settings: Settings) -> ArchiveTriageProviderFactory | None:
    """Build the provider boundary only when the reviewed proxy is present.

    A request-local API key never grants direct egress. This closure captures
    only the settings-validated Docker service origin; provider IDs and
    endpoints still come from the code-owned registry.
    """

    proxy_url = settings.provider_proxy_url
    if proxy_url is None:
        return None

    def create_session(provider: ArchiveTriageProvider) -> ArchiveTriageProviderSession:
        return create_archive_triage_provider_session(provider, proxy_url=proxy_url)

    return create_session


class ManifestDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    manifest: dict[str, Any]


class RunBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    wall_time_seconds: int = Field(default=300, gt=0, le=86_400)
    max_tool_calls: int = Field(default=30, gt=0, le=1_000_000)
    max_http_requests: int = Field(default=20, gt=0, le=10_000_000)
    max_cost_usd: float = Field(default=1, gt=0, le=1_000_000)


class CreateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    challenge_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    mode: RunMode = RunMode.ASSISTED
    provider: str = Field(
        default="operator-pending",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    budget: RunBudget = Field(default_factory=RunBudget)

    @field_validator("mode", mode="before")
    @classmethod
    def parse_mode(cls, value: Any) -> Any:
        return RunMode(value) if isinstance(value, str) else value


class SteeringRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    message: str = Field(min_length=1, max_length=2000)


class HintCardCreateRequest(BaseModel):
    """Public create shape for a catalog-backed human hypothesis only."""

    model_config = ConfigDict(extra="forbid", strict=True)

    template_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    directive: HintDirective | None = None
    target_ref: str = Field(
        default="run:all",
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    priority: int = Field(default=3, ge=1, le=5)
    note: str = Field(default="", max_length=500)

    @field_validator("directive", mode="before")
    @classmethod
    def parse_directive(cls, value: Any) -> Any:
        return HintDirective(value) if isinstance(value, str) else value


class HintCardPatchRequest(BaseModel):
    """Partial local edit; status/evidence stay kernel-owned."""

    model_config = ConfigDict(extra="forbid", strict=True)

    directive: HintDirective | None = None
    target_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    priority: int | None = Field(default=None, ge=1, le=5)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("directive", mode="before")
    @classmethod
    def parse_directive(cls, value: Any) -> Any:
        return HintDirective(value) if isinstance(value, str) else value


class InternalRunnerClaimRequest(BaseModel):
    """Authenticated runner claim request; public callers cannot use this shape."""

    model_config = ConfigDict(extra="forbid", strict=True)

    runner_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    lease_seconds: int = Field(default=30, ge=5, le=300)
    # Normal Pi runners leave this unset and consume the global durable queue.
    # A trusted operator probe may bind itself to the diagnostic run it just
    # created, so it can never lease work belonging to a concurrent real run.
    run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )


class InternalRunnerLeaseRequest(BaseModel):
    """Every internal mutation carries the exact durable claim lease."""

    model_config = ConfigDict(extra="forbid", strict=True)

    runner_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    lease_version: int = Field(ge=1, le=1_000_000)


class InternalSessionActivationRequest(InternalRunnerLeaseRequest):
    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )


class InternalFlagCapturePatternsResponse(BaseModel):
    """Safe manifest configuration returned to the limited builder tool."""

    model_config = ConfigDict(extra="forbid", strict=True)

    flag_capture_patterns: tuple[str, ...] = Field(min_length=1, max_length=8)

    @field_validator("flag_capture_patterns")
    @classmethod
    def validate_patterns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not 1 <= len(value) <= 512:
                raise ValueError("flag_capture_pattern_invalid")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError("flag_capture_pattern_invalid") from exc
        return values


class InternalPowerFlagPatternsResponse(BaseModel):
    """Manifest-owned Power flag rules for the independent flag router.

    The endpoint that returns this model is available only to the flag-router
    service.  It has no candidate value and therefore cannot turn an API or
    runner request into a self-verifying flag submission.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    patterns: tuple[str, ...] = Field(min_length=1, max_length=8)

    @field_validator("patterns")
    @classmethod
    def validate_patterns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not 1 <= len(value) <= 512:
                raise ValueError("power_flag_pattern_invalid")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError("power_flag_pattern_invalid") from exc
        return values


class InternalAgentEventBatchRequest(InternalRunnerLeaseRequest):
    # JSON has arrays, not tuples. Keep the HTTP boundary ergonomic while the
    # repository receives an immutable tuple for deterministic processing.
    events: list[AgentBridgeEvent] = Field(min_length=1, max_length=128)


class InternalTurnCompletionRequest(InternalRunnerLeaseRequest):
    result_ref: str = Field(
        min_length=1,
        max_length=200,
        # A candidate result only records that independent verifier work was
        # queued. It is deliberately not a solve/flag claim.
        pattern=r"^(?:candidate|finding|agent):[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )


class InternalFindingSubmissionRequest(InternalRunnerLeaseRequest):
    finding: FindingSubmission


class InternalCandidateSubmissionRequest(InternalRunnerLeaseRequest):
    """A Pi role proposes an immutable declarative plan, never a raw flag."""

    candidate: ExploitCandidateSubmission


class InternalVerifierClaimRequest(BaseModel):
    """Authenticated claim request for the separate M5 verifier service."""

    model_config = ConfigDict(extra="forbid", strict=True)

    verifier_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    lease_seconds: int = Field(default=30, ge=5, le=300)


class InternalVerifierLeaseRequest(BaseModel):
    """Every verifier mutation is bound to the exact durable lease version."""

    model_config = ConfigDict(extra="forbid", strict=True)

    verifier_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    lease_version: int = Field(ge=1, le=1_000_000)


class InternalVerifierCompletionRequest(InternalVerifierLeaseRequest):
    completion: VerifierCompletionV1


class InternalRemoteFlagLeaseRequest(InternalVerifierLeaseRequest):
    """Ephemeral verifier-to-API hand-off; the flag is never made durable."""

    candidate_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    flag: SecretStr = Field(min_length=1, max_length=4096)


class InternalVerifierFailureRequest(InternalVerifierLeaseRequest):
    reason: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_:-]*$",
    )


class InternalPowerFlagCompletionRequest(BaseModel):
    """Independent router completion with a memory-only, one-time reveal value."""

    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    # This raw value has a deliberately narrow lifetime: the flag router has
    # independently re-read it from an immutable sandbox artifact and the API
    # keeps it only in ``VerifiedFlagRevealStore`` after durable verification.
    # It must never be added to the event payload, run result or database.
    flag: SecretStr = Field(min_length=1, max_length=4096)
    flag_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)
    masked_flag: str = Field(min_length=1, max_length=128)
    observation_artifact_id: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71
    )
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)


class InternalTaskDelegationRequest(InternalRunnerLeaseRequest):
    """A master tool call; the kernel, not Pi, creates the child task."""

    delegation: TaskDelegationRequest


class InternalToolRequest(InternalRunnerLeaseRequest):
    """One closed-world worker tool call relayed to the M3 gateway.

    The request deliberately carries a typed relative operation instead of a
    filesystem root, slot address, target URL, or generic function name.  The
    gateway revalidates it and derives all execution authority from the
    durable job/session lease.
    """

    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    call: GatewayToolCall


class InternalPowerToolRequest(InternalRunnerLeaseRequest):
    """One closed-world Power custom-tool request from a leased Pi session."""

    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    action: Literal[
        "exec",
        "pty_start",
        "pty_send",
        "pty_read",
        "pty_close",
        "tube_connect",
        "tube_send",
        "tube_receive",
        "tube_close",
        "flag_submit",
    ]
    # The reviewed Pi adapter sets this only for a named custom tool.  It is
    # not an arbitrary model string and is used solely to fingerprint repeated
    # ``ctf_fs_read`` paths without persisting a path or command.
    tool_name: (
        Literal[
            "ctf_shell_exec",
            "ctf_fs_list",
            "ctf_fs_read",
            "ctf_fs_write",
            "ctf_pty_start",
            "ctf_pty_send",
            "ctf_pty_read",
            "ctf_pty_close",
            "ctf_gdb_start",
            "ctf_gdb_cmd",
            "ctf_gdb_close",
            "ctf_tube_connect",
            "ctf_tube_send",
            "ctf_tube_recv",
            "ctf_tube_close",
            "ctf_flag_submit",
        ]
        | None
    ) = None
    # Each action is parsed again through a strict Pydantic model below. A
    # generic dictionary here permits one static HTTP route while preserving a
    # closed discriminant rather than a model-selected URL or function name.
    arguments: dict[str, Any]


class InternalPowerUsageRequest(InternalRunnerLeaseRequest):
    """One secret-free Pi usage delta for the currently leased Power turn."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    input_tokens: int = Field(ge=0, le=10_000_000)
    output_tokens: int = Field(ge=0, le=10_000_000)
    cache_read_tokens: int = Field(ge=0, le=10_000_000)
    cache_write_tokens: int = Field(ge=0, le=10_000_000)
    cost_usd: float = Field(ge=0, le=1_000_000)
    compacted: int = Field(ge=0, le=1_000)


class InternalPowerActivityRequest(InternalRunnerLeaseRequest):
    """One short, redacted operator-visible Pi message under an active lease."""

    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    kind: Literal["prompt", "response"]
    # The runner redacts first; the API applies the same redaction before the
    # append-only event is built. This is visible Pi prose, not hidden
    # reasoning or raw provider diagnostics.
    content: str = Field(min_length=1, max_length=2_000)


class InternalPowerToolTranscriptRequest(InternalRunnerLeaseRequest):
    """One redacted, bounded terminal record for a completed Power tool."""

    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    tool: str = Field(min_length=5, max_length=64, pattern=r"^ctf_[a-z0-9_]{2,59}$")
    command: str = Field(min_length=1, max_length=2_000)
    output: str = Field(min_length=1, max_length=6_000)
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    timed_out: bool
    output_truncated: bool
    idempotency_key: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )


class InternalPowerSteerCompletionRequest(InternalRunnerLeaseRequest):
    """State hint from the owner runner; it cannot widen a Power authority."""

    model_config = ConfigDict(extra="forbid", strict=True)

    delivered_while_streaming: bool


class _PowerExecArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    command: list[str] = Field(min_length=1, max_length=128)
    timeout_seconds: int = Field(ge=1, le=120)
    working_directory: Literal["/challenge", "/work"]

    @field_validator("command")
    @classmethod
    def valid_command(cls, values: list[str]) -> list[str]:
        if any(not 1 <= len(value) <= 4_096 or "\0" in value for value in values):
            raise ValueError("power_command_invalid")
        return values


class _PowerPtySendArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)
    data: str = Field(max_length=64 * 1024)


class _PowerPtyReadArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)
    max_bytes: int = Field(ge=1, le=64 * 1024)
    wait_ms: int = Field(ge=0, le=30_000)
    kind: Literal["pty", "gdb"]


class _PowerPtyCloseArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pty_id: str = Field(pattern=r"^pty_[0-9a-f]{32}$", min_length=36, max_length=36)


class _PowerTubeConnectArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    host: str = Field(
        min_length=1,
        max_length=253,
        pattern=r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    )
    port: int = Field(ge=1, le=65_535)
    timeout_seconds: int = Field(ge=1, le=120)


class _PowerTubeSendArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)
    data_base64: str = Field(
        min_length=1,
        max_length=64 * 1024,
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    )


class _PowerTubeReceiveArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)
    delimiter_base64: str = Field(
        min_length=1,
        max_length=4_096,
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    )
    max_bytes: int = Field(ge=1, le=64 * 1024)
    timeout_seconds: int = Field(ge=1, le=120)


class _PowerTubeCloseArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tube_id: str = Field(pattern=r"^tube_[0-9a-f]{32}$", min_length=37, max_length=37)


class _PowerFlagArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    candidate: SecretStr = Field(min_length=1, max_length=1_024)
    observation_artifact_id: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71
    )
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)


def _parse_power_tool_arguments(
    action: str, arguments: dict[str, Any]
) -> (
    _PowerExecArguments
    | _PowerPtySendArguments
    | _PowerPtyReadArguments
    | _PowerPtyCloseArguments
    | _PowerTubeConnectArguments
    | _PowerTubeSendArguments
    | _PowerTubeReceiveArguments
    | _PowerTubeCloseArguments
    | _PowerFlagArguments
):
    """Parse one closed Power action before any private service is contacted.

    The explicit table is intentionally verbose: it makes adding an action a
    reviewable API change instead of granting the model a generic RPC method.
    """

    parsers: dict[str, type[BaseModel]] = {
        "exec": _PowerExecArguments,
        "pty_start": _PowerExecArguments,
        "pty_send": _PowerPtySendArguments,
        "pty_read": _PowerPtyReadArguments,
        "pty_close": _PowerPtyCloseArguments,
        "tube_connect": _PowerTubeConnectArguments,
        "tube_send": _PowerTubeSendArguments,
        "tube_receive": _PowerTubeReceiveArguments,
        "tube_close": _PowerTubeCloseArguments,
        "flag_submit": _PowerFlagArguments,
    }
    try:
        return parsers[action].model_validate(arguments)  # type: ignore[return-value]
    except (KeyError, ValidationError) as exc:
        raise ValueError("power_tool_arguments_invalid") from exc


def _power_fs_read_fingerprint(
    tool_name: str | None,
    arguments: _PowerExecArguments
    | _PowerPtySendArguments
    | _PowerPtyReadArguments
    | _PowerPtyCloseArguments
    | _PowerTubeConnectArguments
    | _PowerTubeSendArguments
    | _PowerTubeReceiveArguments
    | _PowerTubeCloseArguments
    | _PowerFlagArguments,
) -> str | None:
    """Return a stable private fingerprint for the reviewed ``ctf_fs_read`` ABI.

    Only the trusted adapter can label a call as ``ctf_fs_read``.  Its fixed
    argv shape ensures the final value is the normalized workspace path.  The
    control plane stores the resulting digest only, never the path itself.
    """

    if tool_name != "ctf_fs_read" or not isinstance(arguments, _PowerExecArguments):
        return None
    command = arguments.command
    if len(command) != 4 or command[0:2] != ["head", "-c"]:
        raise ValueError("power_fs_read_contract_invalid")
    path = command[3]
    if not path.startswith(("/challenge/", "/work/")):
        raise ValueError("power_fs_read_contract_invalid")
    return hashlib.sha256(f"ctfmesh.power.fs-read.v1:{path}".encode()).hexdigest()


def _power_observation_response(observation: Any) -> dict[str, Any]:
    """Project a sandbox observation into M-PI-1's bounded custom-tool ABI."""

    return {
        "artifact": {
            "id": observation.stdout_artifact_id,
            "sha256": observation.stdout_sha256,
            "sizeBytes": observation.stdout_artifact_size_bytes,
        },
        "stdout": observation.stdout,
        "stderr": observation.stderr,
        "exitCode": observation.exit_code,
        "timedOut": observation.timed_out,
        "outputTruncated": observation.output_truncated,
        **(
            {}
            if observation.interactive_id is None
            else {
                "interactiveId": observation.interactive_id,
                "interactiveKind": observation.interactive_kind,
            }
        ),
    }


class InternalAgentFailureRequest(InternalRunnerLeaseRequest):
    reason: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_:-]*$",
    )


class ArchiveTriageRequest(BaseModel):
    """A one-shot local secret boundary for an archive triage request."""

    model_config = ConfigDict(extra="forbid", strict=True)

    # Never infer a provider from a submitted key. The caller must select one
    # reviewed provider explicitly so a credential cannot be misrouted.
    provider: ArchiveTriageProvider
    model: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
    )
    api_key: SecretStr = Field(min_length=1, max_length=8192)
    # Presets are UI conveniences. The server owns both ends of the interval,
    # so a custom value can reduce/tune a request but cannot enlarge the
    # reviewed provider envelope.
    max_output_tokens: int = Field(
        default=ARCHIVE_TRIAGE_MAX_OUTPUT_TOKENS,
        ge=ARCHIVE_TRIAGE_MIN_OUTPUT_TOKENS,
        le=ARCHIVE_TRIAGE_HARD_MAX_OUTPUT_TOKENS,
    )
    # "Unlimited" in the UI resolves to a 24-hour emergency watchdog. A
    # numeric contract keeps cancellation and validation explicit at every
    # boundary while the browser can abort the active stream at any time.
    timeout_seconds: int = Field(
        default=ARCHIVE_TRIAGE_DEFAULT_TIMEOUT_SECONDS,
        ge=ARCHIVE_TRIAGE_MIN_TIMEOUT_SECONDS,
        le=ARCHIVE_TRIAGE_HARD_MAX_TIMEOUT_SECONDS,
    )
    # The browser checkbox maps to a real request contract. It records an
    # explicit one-time operator decision for the fixed provider egress, while
    # the server still refuses arbitrary endpoints, tools, and target traffic.
    provider_egress_acknowledged: Literal[True]

    @field_validator("provider", mode="before")
    @classmethod
    def parse_provider(cls, value: Any) -> Any:
        return ArchiveTriageProvider(value) if isinstance(value, str) else value


class ExactInstanceTargetRequest(BaseModel):
    """A single operator-declared origin for the assisted Web lane."""

    model_config = ConfigDict(extra="forbid", strict=True)

    entry_url: str = Field(min_length=8, max_length=2048)
    # This deliberately accepts a tiny literal format language rather than a
    # user-authored regex.  It may help extraction, but it is not evidence and
    # cannot make a candidate or run verified by itself.
    flag_format: str | None = Field(default=None, max_length=_EXACT_FLAG_FORMAT_MAX_LENGTH)

    @field_validator("flag_format")
    @classmethod
    def validate_flag_format(cls, value: str | None) -> str | None:
        return _normalize_exact_flag_format(value)


class ExactInstanceExecutionRequest(BaseModel):
    """Ephemeral model selection and key; nothing here is persisted."""

    model_config = ConfigDict(extra="forbid", strict=True)

    provider: Literal["openai", "gemini", "deepseek"]
    model: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$",
    )
    api_key: SecretStr = Field(min_length=1, max_length=8192)
    provider_egress_acknowledged: Literal[True]
    target_access_acknowledged: Literal[True]


class ExactInstanceRunRequest(BaseModel):
    """Atomic browser launch request for the narrow M6.a vertical slice."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target: ExactInstanceTargetRequest
    execution: ExactInstanceExecutionRequest
    budget: RunBudget = Field(
        default_factory=lambda: RunBudget(
            wall_time_seconds=900,
            max_tool_calls=120,
            max_http_requests=80,
            max_cost_usd=3.0,
        )
    )


class PowerTargetRequest(BaseModel):
    """One optional public TCP endpoint for a Power workspace tube."""

    model_config = ConfigDict(extra="forbid", strict=True)

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65_535)

    @field_validator("host")
    @classmethod
    def public_exact_host(cls, value: str) -> str:
        try:
            host = normalize_exact_host(value)
        except ValueError as exc:
            raise ValueError("power_target_invalid") from exc
        if not _is_public_exact_instance_host(host):
            raise ValueError("power_target_not_public")
        return host


class PowerRacerRequest(BaseModel):
    """One visible A/B/C assignment; credentials live in a separate map."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    label: Literal["A", "B", "C"]
    provider: PowerRaceProvider
    model: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$",
    )
    temperature: float = Field(ge=0, le=2)

    @field_validator("provider", mode="before")
    @classmethod
    def parse_provider(cls, value: Any) -> Any:
        return PowerRaceProvider(value) if isinstance(value, str) else value


class PowerBudgetRequest(BaseModel):
    """Finite safety caps; the UI's unlimited convenience maps to these maxima."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    wall_time_seconds: int = Field(ge=60, le=86_400)
    max_cost_usd: float = Field(gt=0, le=1_000)
    max_turn_cost_usd: float = Field(gt=0, le=1_000)


class PowerRunRequest(BaseModel):
    """Browser launch for an isolated, fixed-size Power race."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target: PowerTargetRequest | None = None
    authorized_target: bool = False
    # Network remains off unless a target is both supplied and explicitly
    # acknowledged. ``open_egress`` is retained as a transparent UI setting,
    # but the current reviewed workspace image has no generic egress route.
    open_egress: bool = False
    racer_count: Literal[3] = 3
    contest_offline: bool = False
    # A user-facing template such as ``picoCTF{...}``.  This is a capture
    # hint, not a regex and not a flag value.  It is bound to the new run's
    # manifest so the independent router can re-read the same rule later.
    flag_format: str | None = Field(default=None, max_length=_EXACT_FLAG_FORMAT_MAX_LENGTH)
    # A short operator note such as the challenge objective or supplied hint.
    # It is normalized/redacted before the shared Pi brief is made durable.
    challenge_description: str | None = Field(
        default=None, max_length=_POWER_CHALLENGE_DESCRIPTION_MAX_LENGTH
    )
    racers: list[PowerRacerRequest] = Field(min_length=3, max_length=3)
    provider_keys: dict[PowerRaceProvider, SecretStr] = Field(min_length=1, max_length=3)
    budget: PowerBudgetRequest

    @field_validator("flag_format")
    @classmethod
    def validate_flag_format(cls, value: str | None) -> str | None:
        return _normalize_exact_flag_format(value)

    @field_validator("challenge_description")
    @classmethod
    def validate_challenge_description(cls, value: str | None) -> str | None:
        return _normalize_power_challenge_description(value)

    @field_validator("provider_keys", mode="before")
    @classmethod
    def parse_provider_keys(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError("power_provider_keys_invalid")
        parsed: dict[PowerRaceProvider, SecretStr] = {}
        for raw_provider, raw_key in value.items():
            try:
                provider = PowerRaceProvider(str(raw_provider))
            except ValueError as exc:
                raise ValueError("power_provider_keys_invalid") from exc
            if provider in parsed:
                raise ValueError("power_provider_keys_invalid")
            key = raw_key if isinstance(raw_key, SecretStr) else SecretStr(str(raw_key))
            if not key.get_secret_value().strip() or len(key.get_secret_value()) > 8192:
                raise ValueError("power_provider_key_invalid")
            parsed[provider] = key
        return parsed


_EXACT_INSTANCE_MIN_WALL_SECONDS = 60
_EXACT_INSTANCE_MAX_WALL_SECONDS = 900
_EXACT_INSTANCE_MAX_TOOL_CALLS = 120
_EXACT_INSTANCE_MAX_HTTP_REQUESTS = 80
_EXACT_INSTANCE_MIN_COST_USD = 0.1
_EXACT_INSTANCE_MAX_COST_USD = 3.0


class ArchiveTriageProgressEvent(BaseModel):
    """A public control-plane checkpoint, never a model reasoning token."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["ctfmesh.archive-triage-stream/v1"] = "ctfmesh.archive-triage-stream/v1"
    kind: Literal["progress"] = "progress"
    sequence: int = Field(ge=1)
    stage: ArchiveTriageProgressStage
    summary: str = Field(min_length=1, max_length=160)


class ArchiveTriageResultEvent(BaseModel):
    """The terminal successful receipt on the archive progress stream."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["ctfmesh.archive-triage-stream/v1"] = "ctfmesh.archive-triage-stream/v1"
    kind: Literal["result"] = "result"
    sequence: int = Field(ge=1)
    intake: dict[str, Any]


class ArchiveTriageErrorEvent(BaseModel):
    """A terminal secret-safe error for a stream whose HTTP headers already began."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["ctfmesh.archive-triage-stream/v1"] = "ctfmesh.archive-triage-stream/v1"
    kind: Literal["error"] = "error"
    sequence: int = Field(ge=1)
    code: str = Field(min_length=1, max_length=160, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1, max_length=240)
    provider_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_]*$",
    )


class CandidateRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    confirm: bool


class CandidateReviewConfirmationRequest(BaseModel):
    """One browser-selected raw value with an intentionally narrow lifetime."""

    model_config = ConfigDict(extra="forbid", strict=True)

    confirm: Literal[True]
    candidate: SecretStr

    @field_validator("candidate")
    @classmethod
    def validate_candidate(cls, value: SecretStr) -> SecretStr:
        candidate = value.get_secret_value()
        if not 1 <= len(candidate) <= 1_024:
            raise ValueError("candidate_review_candidate_invalid")
        return value


def error(status_code: int, code: str, message: str, *, details: Any = None) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, "details": details},
    )


def archive_triage_stream_line(
    event: ArchiveTriageProgressEvent | ArchiveTriageResultEvent | ArchiveTriageErrorEvent,
) -> str:
    """Serialize exactly one versioned NDJSON event without provider diagnostics."""

    return event.model_dump_json() + "\n"


def run_activity_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Project an append-only event to a compact, secret-free activity item.

    The operator gets meaningful progress without seeing a raw model response,
    source file, target URL, flag, tool payload, provider diagnostic or event
    payload. A new event type has a stable generic rendering until reviewed UI
    vocabulary is deliberately added here.
    """

    sequence = event.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        return None
    event_type = event.get("type")
    stage, summary = _RUN_ACTIVITY_SUMMARIES.get(
        event_type if isinstance(event_type, str) else "",
        ("activity", "Run activity updated."),
    )
    return {
        "schema_version": "ctfmesh.run-activity-stream/v1",
        "sequence": sequence,
        "stage": stage,
        "summary": summary,
    }


def required_idempotency_key(request: Request) -> str:
    """Require an explicit retry key for every mutable Hint Card operation."""

    value = request.headers.get("idempotency-key")
    if value is None or not _IDEMPOTENCY_KEY.fullmatch(value):
        raise error(
            422,
            "idempotency_key_required",
            "A valid Idempotency-Key header is required for this write.",
        )
    return value


async def archive_lifecycle_guard(request: Request) -> AsyncIterator[None]:
    """Serialize archive launch and permanent removal in one API process."""

    async with request.app.state.archive_lifecycle_lock:
        yield


def safe_validation_errors(exc: ValidationError | RequestValidationError) -> list[dict[str, str]]:
    return [
        {
            "path": ".".join(str(part) for part in item["loc"]),
            "reason_code": str(item["type"]),
            "message": str(item["msg"]),
        }
        for item in exc.errors()
    ]


def archive_error_status(code: str) -> int:
    if code in {
        "archive_upload_too_large",
        "archive_entry_count_exceeded",
        "archive_entry_too_large",
        "archive_expanded_bytes_exceeded",
        "archive_compression_ratio_exceeded",
    }:
        return 413
    if code == "archive_intake_not_found":
        return 404
    if code == "archive_intake_remove_failed":
        return 503
    return 422


def _configured_ui_source_slots(settings: Settings) -> tuple[tuple[str, Path], ...]:
    """Return only fixed, deployment-configured archive source destinations."""

    candidates = (
        ("source-slot-1", settings.source_slot_1_root),
        ("source-slot-2", settings.source_slot_2_root),
    )
    return tuple((slot_id, root) for slot_id, root in candidates if root is not None)


def _is_public_exact_instance_host(host: str) -> bool:
    """Reject the address classes that must never leave a source slot.

    DNS is intentionally not resolved in the API process. The target connector
    repeats this policy on each resolved address immediately before its only
    external socket is opened.
    """

    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return not host.endswith((".local", ".localhost", ".internal", ".test"))


def _build_exact_instance_manifest(
    *,
    intake_id: str,
    entry_url: str,
    provider: str,
    slot_id: str,
    flag_format: str | None = None,
    budget: RunBudget | None = None,
) -> ChallengeManifest:
    """Construct the one code-owned manifest shape for M6.a browser launch.

    ``flag_format`` is converted to a literal-derived capture pattern here,
    rather than letting a browser or model author a regex.  The generic
    reviewed fallback remains in the manifest, so a mistaken operator hint
    cannot suppress valid candidate verification.
    """

    resolved_budget = budget or RunBudget(
        wall_time_seconds=900,
        max_tool_calls=120,
        max_http_requests=80,
        max_cost_usd=3.0,
    )
    candidate = entry_url.strip()
    try:
        parsed = urlsplit(candidate)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError("ui_instance_url_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("ui_instance_url_invalid")
    try:
        host = normalize_exact_host(parsed.hostname)
    except ValueError as exc:
        raise ValueError("ui_instance_url_invalid") from exc
    if not _is_public_exact_instance_host(host):
        raise ValueError("ui_instance_target_not_public")
    port = explicit_port or (443 if parsed.scheme == "https" else 80)
    rendered_host = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{rendered_host}:{port}"
    selected_flag_pattern = _exact_flag_pattern(flag_format)
    flag_patterns = (
        (_DEFAULT_EXACT_INSTANCE_FLAG_PATTERN,)
        if selected_flag_pattern is None
        else (selected_flag_pattern, _DEFAULT_EXACT_INSTANCE_FLAG_PATTERN)
    )
    # The intake ID is generated by ArchiveIntakeService, not a browser field.
    # Its suffix makes a stable manifest name without exposing the uploaded
    # filename, which could itself contain a secret or a misleading instruction.
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {
                "name": f"ui-{intake_id.removeprefix('intake_')}",
                "category": "web",
                "tags": ["ui-exact-instance", "source-available"],
            },
            "spec": {
                "mode": "assisted",
                "target": {
                    "type": "remote",
                    "healthcheck": {"url": f"{origin}/", "expected_status": 200},
                    "allowed_endpoints": [
                        {"host": host, "ports": [port], "protocols": [parsed.scheme]}
                    ],
                    "target_aliases": {"target": origin},
                },
                # This logical artifact declaration gives preflight a typed
                # source role. The actual bytes are supplied only by the
                # trusted source binding, never by this manifest path.
                "artifacts": [{"path": "archive.bin", "role": "source"}],
                "flag": {
                    # The format-derived pattern is a search/capture hint,
                    # not proof. Candidate plans are still checked against
                    # this manifest and independently replayed by verifier.
                    "patterns": list(flag_patterns),
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": False,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 2,
                },
                "limits": {
                    "wall_time_seconds": resolved_budget.wall_time_seconds,
                    "max_worker_turns": 120,
                    "max_tool_calls": resolved_budget.max_tool_calls,
                    "max_http_requests": resolved_budget.max_http_requests,
                    "max_parallel_requests": 4,
                    "max_cost_usd": resolved_budget.max_cost_usd,
                    "max_artifact_bytes": 1_073_741_824,
                },
                "providers": {"preferred": provider, "fallbacks": []},
                "memory": {
                    "namespace": "ui-exact-instance",
                    "cutoff": "2026-08-31T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": [
                    "source.list",
                    "source.read",
                    "source.search",
                    "source.manifest",
                    "artifacts.inspect",
                    "transform.apply",
                    "http.request",
                ],
                "skill_profile": ["web.triage"],
                "source": {"intake_id": intake_id, "slot_id": slot_id},
            },
        }
    )


def _build_power_manifest(
    *,
    intake_id: str,
    target: PowerTargetRequest | None,
    budget: PowerBudgetRequest,
    flag_format: str | None = None,
) -> ChallengeManifest:
    """Construct the fixed Power manifest from a validated archive receipt.

    An optional target declares exactly one TCP host/port.  It is deliberately
    represented in the manifest before sandboxd receives the same tube list,
    so a browser cannot turn a model/tool action into ambient network access.
    """

    target_spec: dict[str, Any]
    if target is None:
        target_spec = {"type": "artifact_bundle"}
    else:
        target_spec = {
            "type": "remote",
            "allowed_endpoints": [
                {"host": target.host, "ports": [target.port], "protocols": ["tcp"]}
            ],
        }
    selected_flag_pattern = _exact_flag_pattern(flag_format)
    flag_patterns = (
        (_DEFAULT_POWER_FLAG_PATTERN,)
        if selected_flag_pattern is None
        else (selected_flag_pattern, _DEFAULT_POWER_FLAG_PATTERN)
    )
    return ChallengeManifest.model_validate(
        {
            "apiVersion": "ctfmesh.io/v1alpha1",
            "kind": "Challenge",
            "metadata": {
                "name": f"power-{intake_id.removeprefix('intake_')}",
                "category": "misc",
                "tags": ["power-profile", "archive-intake"],
            },
            "spec": {
                "mode": "assisted",
                "target": target_spec,
                "artifacts": [{"path": "archive.bin", "role": "archive"}],
                "flag": {
                    # The custom rule is constructed only from a literal
                    # template.  The fallback preserves the documented Power
                    # formats if an operator hint is inaccurate.  The router
                    # re-reads these persisted patterns itself before it can
                    # complete a run.
                    "patterns": list(flag_patterns),
                    "source_policy": {
                        "allow_from_target_response": True,
                        "allow_from_target_filesystem": True,
                        "deny_from_input_artifacts": True,
                    },
                    "replay_count": 1,
                },
                "limits": {
                    "wall_time_seconds": budget.wall_time_seconds,
                    "max_worker_turns": 106,
                    "max_tool_calls": 1_000,
                    "max_http_requests": 10_000,
                    "max_parallel_requests": 3,
                    "max_cost_usd": budget.max_cost_usd,
                    "max_artifact_bytes": 1_073_741_824,
                },
                "providers": {"preferred": "power-swarm", "fallbacks": []},
                "memory": {
                    "namespace": "power-local-techniques",
                    "cutoff": "2026-09-01T00:00:00Z",
                    "internet_search": False,
                },
                "tool_profile": ["shell.exec", "pty.start", "tube.connect", "tube.send"],
                "skill_profile": ["power.reviewed-packs"],
            },
        }
    )


def _power_race_configuration(body: PowerRunRequest) -> PowerRaceConfiguration:
    """Translate a public, key-free mapping to P6's typed race configuration."""

    if {racer.label for racer in body.racers} != {"A", "B", "C"}:
        raise PowerRaceConfigurationError("power_race_racer_mapping_invalid")
    turn_cost = round(body.budget.max_turn_cost_usd * 1_000_000)
    race_assignments = tuple(
        PowerRacerAssignment(
            racer_id=f"racer-{racer.label.lower()}",
            label=racer.label,
            model_assignment=PowerModelAssignment(
                provider=racer.provider,
                model=racer.model,
                temperature=racer.temperature,
                max_turn_cost_microusd=turn_cost,
            ),
        )
        for racer in sorted(body.racers, key=lambda item: item.label)
    )
    required_providers = {assignment.model_assignment.provider for assignment in race_assignments}
    if not required_providers.issubset(body.provider_keys):
        raise PowerRaceConfigurationError("power_race_provider_key_missing")
    return PowerRaceConfiguration(
        # The first racer provides the bounded reconnaissance adapter. It is
        # a costed call in the same ledger, not a privileged fourth model.
        autoprompter=race_assignments[0].model_assignment,
        racers=race_assignments,
        budget=PowerRunBudget(
            max_cost_microusd=round(body.budget.max_cost_usd * 1_000_000),
            max_wall_time_seconds=body.budget.wall_time_seconds,
        ),
    )


def _validate_exact_instance_budget(budget: RunBudget) -> RunBudget:
    """Keep browser-launched custom values inside the reviewed hard ceiling.

    ``RunBudget`` remains deliberately broader for manifest-defined API runs.
    The exact-instance route may tune a smaller value, but must never use that
    broader contract to silently create a wider browser-launched manifest.
    """

    if not (
        _EXACT_INSTANCE_MIN_WALL_SECONDS
        <= budget.wall_time_seconds
        <= _EXACT_INSTANCE_MAX_WALL_SECONDS
        and budget.max_tool_calls <= _EXACT_INSTANCE_MAX_TOOL_CALLS
        and budget.max_http_requests <= _EXACT_INSTANCE_MAX_HTTP_REQUESTS
        and _EXACT_INSTANCE_MIN_COST_USD <= budget.max_cost_usd <= _EXACT_INSTANCE_MAX_COST_USD
    ):
        raise ValueError("ui_exact_instance_budget_not_allowed")
    return budget


def _ui_provider_marker(provider: str, model: str) -> str:
    """Persist only a short, non-secret run identity for idempotency/audit."""

    model_digest = hashlib.sha256(model.encode("utf-8")).hexdigest()[:16]
    return f"ui-{provider}-{model_digest}"


def _pi_provider(provider: str) -> str:
    """Map one browser selector onto Pi's reviewed native provider IDs."""

    providers = {"openai": "openai", "gemini": "google", "deepseek": "deepseek"}
    try:
        return providers[provider]
    except KeyError as exc:  # pragma: no cover - request Literal is the first gate.
        raise ValueError("ui_provider_invalid") from exc


def public_provider_error_code(code: str) -> str:
    """Keep provider implementation error strings out of the public contract."""

    return code if code in _PUBLIC_PROVIDER_ERROR_CODES else "provider_failure"


def require_internal_runner(request: Request) -> None:
    """Gate `/internal/*` routes behind a configured service-to-service token.

    Compose also places the runner on an internal-only network, but the API's
    loopback port is still a defense boundary. A missing token fails closed and
    neither branch reports or logs credential material.
    """

    configured = request.app.state.settings.internal_runner_token
    if configured is None:
        raise error(
            503,
            "internal_runner_not_configured",
            "The internal Pi runner boundary is not configured.",
        )
    supplied = request.headers.get("x-ctfmesh-runner-token")
    expected = configured.get_secret_value()
    if (
        supplied is None
        or len(supplied) > 512
        or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
    ):
        raise error(401, "internal_runner_unauthorized", "Internal runner authentication failed.")


def require_internal_verifier(request: Request) -> None:
    """Gate the independent verifier without sharing Pi Runner authority."""

    configured = request.app.state.settings.internal_verifier_token
    if configured is None:
        raise error(
            503,
            "internal_verifier_not_configured",
            "The independent verifier boundary is not configured.",
        )
    supplied = request.headers.get("x-ctfmesh-verifier-token")
    expected = configured.get_secret_value()
    if (
        supplied is None
        or len(supplied) > 512
        or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
    ):
        raise error(401, "internal_verifier_unauthorized", "Verifier authentication failed.")


def require_internal_flag_router(request: Request) -> None:
    """Gate Power completion behind an identity distinct from all other workers."""

    configured = request.app.state.settings.internal_flag_router_token
    if configured is None:
        raise error(
            503,
            "internal_flag_router_not_configured",
            "The Power flag router boundary is not configured.",
        )
    supplied = request.headers.get("x-ctfmesh-flag-router-token")
    expected = configured.get_secret_value()
    if (
        supplied is None
        or len(supplied) > 512
        or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
    ):
        raise error(401, "internal_flag_router_unauthorized", "Flag router authentication failed.")


def internal_repository_error(exc: ValueError) -> HTTPException:
    """Expose only stable repository codes at the internal protocol boundary."""

    code = str(exc)
    if not _CORRELATION_ID.fullmatch(code):
        code = "internal_runner_request_rejected"
    status_code = 404 if code.endswith("_not_found") or code == "run_not_found" else 409
    return error(status_code, code, "Internal runner request was rejected.")


def parse_content_length(value: str | None) -> int | None:
    """Apply a cheap header-level rejection before streaming the real body.

    The intake service still counts every received byte because this header is
    optional and client controlled.
    """

    if value is None:
        return None
    if not value.isascii() or not value.isdecimal():
        raise ArchiveIntakeError("archive_content_length_invalid")
    if len(value) > len(str(MAX_ARCHIVE_UPLOAD_BYTES)):
        raise ArchiveIntakeError("archive_upload_too_large")
    parsed = int(value)
    if parsed > MAX_ARCHIVE_UPLOAD_BYTES:
        raise ArchiveIntakeError("archive_upload_too_large")
    return parsed


def _ensure_sqlite_parent(database_dsn: str) -> None:
    database_path = database_dsn.split("///", maxsplit=1)[-1]
    if database_path and database_path != ":memory:":
        Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def create_app(
    settings: Settings | None = None,
    *,
    archive_provider_factory: ArchiveTriageProviderFactory | None = None,
    run_engine_factory: RunEngineFactory | None = None,
    tool_gateway_factory: ToolGatewayFactory | None = None,
    pi_credential_lease_factory: PiCredentialLeaseFactory | None = None,
) -> FastAPI:
    configuration = settings or Settings()
    provider_factory = archive_provider_factory or configured_archive_provider_factory(
        configuration
    )
    engine_factory = run_engine_factory or (
        lambda repository, artifact_root: RunEngine(
            repository=repository,
            artifact_root=artifact_root,
        )
    )
    gateway_factory = tool_gateway_factory or configured_tool_gateway_factory(configuration)
    credential_lease_client = (
        configured_pi_credential_lease_client(configuration)
        if pi_credential_lease_factory is None
        else pi_credential_lease_factory(configuration)
    )
    started_at = monotonic()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        artifact_root = configuration.artifact_root.resolve()
        await asyncio.to_thread(artifact_root.mkdir, parents=True, exist_ok=True)
        database_dsn = configuration.database_dsn
        if database_dsn.startswith("sqlite"):
            await asyncio.to_thread(_ensure_sqlite_parent, database_dsn)
        database = Database(database_dsn)
        await database.create_schema()
        # Archive receipts are filesystem-backed and intentionally independent
        # from a manifest/run. A raw upload therefore cannot become a solved
        # CTF record merely by reaching this API.
        archive_intakes = ArchiveIntakeService(artifact_root)
        await archive_intakes.prepare()
        repository = Repository(database)
        app.state.database = database
        app.state.repository = repository
        # The API only creates durable work. It never runs a fake consumer or
        # dispatches a model/tool while serving an operator request.
        app.state.run_engine = engine_factory(repository, artifact_root)
        # M3's gateway is opt-in at composition time.  An API-only process
        # remains fail-closed: Pi can never turn an unavailable gateway into a
        # direct local filesystem or target request.
        app.state.tool_gateway = (
            None if gateway_factory is None else gateway_factory(repository, artifact_root)
        )
        app.state.archive_intakes = archive_intakes
        app.state.settings = configuration
        app.state.artifact_root = artifact_root
        # Removal and UI launch must not race between the repository reference
        # check and filesystem mutation. This is an ordering aid for the local
        # single-operator API; durable manifests remain the source of truth.
        app.state.archive_lifecycle_lock = asyncio.Lock()
        # One API process owns exact-instance launch selection in v0.1. The
        # durable run and the source slot independently revalidate this choice
        # after a restart, so the lock is an ordering aid, never authority.
        app.state.exact_instance_launch_lock = asyncio.Lock()
        app.state.pi_credential_leases = credential_lease_client
        # Raw remote flags have no durable representation. This store is
        # intentionally process-local, non-serializable and one-time only.
        app.state.verified_flag_reveals = VerifiedFlagRevealStore()
        power_settings_ready = all(
            value is not None
            for value in (
                configuration.power_sandboxd_url,
                configuration.power_sandboxd_token,
                configuration.power_flag_router_url,
                configuration.power_flag_router_token,
            )
        )
        if (
            configuration.power_enabled
            and power_settings_ready
            and credential_lease_client is not None
        ):
            # ``power_settings_ready`` is a runtime guard. Assigning locals
            # keeps the optional deployment settings narrow for the typed
            # controller constructor as well as at runtime.
            sandboxd_url = configuration.power_sandboxd_url
            sandboxd_token = configuration.power_sandboxd_token
            flag_router_url = configuration.power_flag_router_url
            flag_router_token = configuration.power_flag_router_token
            if (
                sandboxd_url is None
                or sandboxd_token is None
                or flag_router_url is None
                or flag_router_token is None
            ):
                raise RuntimeError("power_runtime_configuration_invalid")
            app.state.power_runs = PowerRunController(
                repository=repository,
                sandboxd_url=sandboxd_url,
                sandboxd_token=sandboxd_token,
                credential_leases=credential_lease_client,
            )
        else:
            app.state.power_runs = None
        # The content-addressed plan/proof stores are intentionally separate
        # from generic runtime artifacts. Only their digests cross the
        # verifier protocol; Pi Runner never mounts either directory.
        app.state.candidate_artifacts = CandidateArtifactService(artifact_root)
        try:
            yield
        finally:
            power_runs: PowerRunController | None = app.state.power_runs
            if power_runs is not None:
                await power_runs.aclose()
            await database.close()

    app = FastAPI(
        title="CTFMesh Control API",
        version="0.1.0",
        description="Evidence-first orchestration for authorized multi-category CTF labs.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=configuration.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        # The archive name is display-only; the intake service ignores it for
        # path creation and detects format from the streamed bytes.
        allow_headers=[
            "Content-Type",
            "Idempotency-Key",
            "X-Archive-Name",
            "X-Confirm-Remove",
            "X-Correlation-ID",
        ],
    )

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "request_validation_failed",
                    "message": "Request validation failed.",
                    "details": safe_validation_errors(exc),
                }
            },
        )

    @app.middleware("http")
    async def correlation_id(request: Request, call_next: Any) -> Response:
        incoming = request.headers.get("x-correlation-id", "")
        correlation = incoming if _CORRELATION_ID.fullmatch(incoming) else f"req_{uuid4().hex}"
        request.state.correlation_id = correlation
        # The archive upload route streams up to its explicit archive quota.
        # Triage is JSON-only and carries one short-lived key, so fail closed
        # before parsing a chunked or unexpectedly large body.
        if request.method == "POST" and _TRIAGE_REQUEST_PATH.fullmatch(request.url.path):
            content_length = request.headers.get("content-length")
            if (
                content_length is None
                or not content_length.isascii()
                or not content_length.isdecimal()
                or len(content_length) > len(str(MAX_TRIAGE_REQUEST_BYTES))
                or int(content_length) > MAX_TRIAGE_REQUEST_BYTES
            ):
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": {
                            "code": "archive_triage_request_too_large",
                            "message": "Archive triage request is too large.",
                            "details": None,
                        }
                    },
                )
                response.headers["X-Correlation-ID"] = correlation
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["Referrer-Policy"] = "no-referrer"
                return response
        response: Response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ctfmesh-api",
            "version": "0.1.0",
            "uptime_seconds": round(monotonic() - started_at, 3),
        }

    @app.get("/v1/ready")
    async def ready(request: Request, response: Response) -> dict[str, Any]:
        checks: dict[str, dict[str, Any]] = {}
        try:
            await asyncio.wait_for(request.app.state.database.ping(), timeout=2)
            checks["database"] = {"status": "ok"}
        except (TimeoutError, OSError, RuntimeError) as exc:
            checks["database"] = {"status": "unavailable", "reason": type(exc).__name__}
        artifact_root: Path = request.app.state.artifact_root
        checks["artifact_store"] = {
            "status": "ok" if await asyncio.to_thread(artifact_root.is_dir) else "unavailable",
            "backend": "local-content-addressed",
        }
        is_ready = all(check["status"] == "ok" for check in checks.values())
        if not is_ready:
            response.status_code = 503
        return {"status": "ready" if is_ready else "not_ready", "checks": checks}

    @app.get("/v1/runtime/capabilities")
    async def runtime_capabilities(request: Request) -> dict[str, Any]:
        """Expose a secret-free deployment snapshot for fail-closed UI actions.

        This reports configuration presence, not external provider or target
        reachability. It lets the workspace explain a missing M6 service
        before accepting a launch request without revealing a URL or token.
        """

        exact_checks = {
            "source_slots": bool(_configured_ui_source_slots(request.app.state.settings)),
            "tool_gateway": request.app.state.tool_gateway is not None,
            "credential_lease": request.app.state.pi_credential_leases is not None,
            "independent_verifier": (
                request.app.state.settings.internal_verifier_token is not None
            ),
        }
        missing = [name for name, configured in exact_checks.items() if not configured]
        power_checks = {
            "power_profile": request.app.state.settings.power_enabled,
            "sandboxd": request.app.state.settings.power_sandboxd_url is not None
            and request.app.state.settings.power_sandboxd_token is not None,
            "flag_router": request.app.state.settings.power_flag_router_url is not None
            and request.app.state.settings.power_flag_router_token is not None
            and request.app.state.settings.internal_flag_router_token is not None,
            "pi_credential_lease": request.app.state.pi_credential_leases is not None,
        }
        power_missing = [name for name, configured in power_checks.items() if not configured]
        return {
            "schema_version": "ctfmesh.runtime-capabilities/v1",
            "archive_intake": {"status": "ready"},
            "provider_triage": {
                "status": "ready" if provider_factory is not None else "unavailable"
            },
            "exact_instance": {
                "status": "ready" if not missing else "unavailable",
                "missing": missing,
            },
            "power": {
                "status": "ready" if not power_missing else "unavailable",
                "missing": power_missing,
            },
        }

    @app.post("/internal/agent-jobs/claim")
    async def claim_internal_agent_job(
        body: InternalRunnerClaimRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Lease one Pi-only job; the runner never receives a DB connection."""

        require_internal_runner(request)
        try:
            job = await request.app.state.repository.claim_agent_job(
                worker_id=body.runner_id,
                lease_seconds=body.lease_seconds,
                run_id=body.run_id,
                kinds=tuple(
                    kind.value
                    for kind in (
                        AgentJobKind.START_SESSION,
                        AgentJobKind.RUN_TURN,
                        AgentJobKind.STEER,
                        AgentJobKind.ABORT,
                        AgentJobKind.DISPOSE,
                        AgentJobKind.POWER_SESSION_START,
                        AgentJobKind.POWER_STEER,
                        AgentJobKind.POWER_ABORT,
                    )
                ),
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        return {"job": job}

    @app.post("/internal/agent-jobs/{job_id}/work")
    async def get_internal_agent_job_work(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Resolve a claimed job into a sealed, target-free work envelope."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.get_pi_agent_job_work(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-work")
    async def get_internal_power_pi_job_work(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Resolve a leased Power job without exposing a service credential."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.get_power_pi_job_work(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-start-completion")
    async def complete_internal_power_pi_start(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_power_pi_start(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-start-lease-renewal")
    async def renew_internal_power_pi_start_lease(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Extend a live Power model turn while its session is authorized."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.renew_power_pi_start_lease(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-steer-completion")
    async def complete_internal_power_pi_steer(
        job_id: str,
        body: InternalPowerSteerCompletionRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_power_pi_steer(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                delivered_while_streaming=body.delivered_while_streaming,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-abort-completion")
    async def complete_internal_power_pi_abort(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_power_pi_abort(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-failure")
    async def fail_internal_power_pi_job(
        job_id: str,
        body: InternalAgentFailureRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Record a bounded session-local Power failure for the exact lease."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.fail_power_pi_job(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                reason=body.reason,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/session-reservation")
    async def reserve_internal_pi_session(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Reserve a durable Pi session ID before constructing the SDK object."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.reserve_pi_session(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/session-activation")
    async def activate_internal_pi_session(
        job_id: str,
        body: InternalSessionActivationRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Acknowledge that Pi was created and queue the first turn atomically."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.activate_pi_session(
                job_id,
                session_id=body.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/events")
    async def append_internal_agent_events(
        job_id: str,
        body: InternalAgentEventBatchRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Append bounded redacted lifecycle events under the active job lease."""

        require_internal_runner(request)
        try:
            events = await request.app.state.repository.append_pi_agent_events(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                events=tuple(body.events),
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        return {"items": events}

    @app.post("/internal/agent-jobs/{job_id}/turn-completion")
    async def complete_internal_pi_turn(
        job_id: str,
        body: InternalTurnCompletionRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Release a turn only through the durable session/task boundary."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_pi_turn(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                result_ref=body.result_ref,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/steer-completion")
    async def complete_internal_pi_steer(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_pi_steer(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/abort-completion")
    async def complete_internal_pi_abort(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_pi_abort(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/dispose-completion")
    async def complete_internal_pi_dispose(
        job_id: str,
        body: InternalRunnerLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_internal_runner(request)
        try:
            return await request.app.state.repository.complete_pi_dispose(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/finding-submissions")
    async def submit_internal_pi_finding(
        job_id: str,
        body: InternalFindingSubmissionRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Accept a worker finding only after checking role, lease and evidence IDs."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.submit_pi_finding(
                body.finding,
                job_id=job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/candidate-submissions")
    async def submit_internal_pi_candidate(
        job_id: str,
        body: InternalCandidateSubmissionRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Persist one typed candidate then queue an independent verifier job.

        This route is Pi-authenticated but never accepts a run ID, target URL,
        arbitrary code, or raw flag. The repository derives run/task/context
        authority from the currently leased turn twice: before immutable bytes
        are written and again inside the state/event transaction.
        """

        require_internal_runner(request)
        try:
            plan = body.candidate.issued_plan()
            scope = await request.app.state.repository.get_pi_candidate_submission_scope(
                job_id,
                session_id=body.candidate.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            plan_artifact = await request.app.state.candidate_artifacts.persist_plan(
                run_id=scope["run_id"],
                session_id=body.candidate.session_id,
                tool_call_id=body.candidate.tool_call_id,
                plan=plan,
            )
            return await request.app.state.repository.submit_pi_candidate(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                submission=body.candidate,
                plan=plan,
                plan_artifact=plan_artifact,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        except (OSError, RuntimeError):
            # Content-addressed storage errors are never allowed to turn into
            # an in-memory candidate or disclose filesystem details.
            raise error(
                503,
                "candidate_artifact_unavailable",
                "Candidate artifact storage is unavailable.",
            ) from None

    @app.post("/internal/agent-jobs/{job_id}/task-delegations")
    async def delegate_internal_pi_task(
        job_id: str,
        body: InternalTaskDelegationRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Let a master request one child through the typed kernel boundary."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.delegate_pi_task(
                body.delegation,
                job_id=job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/verification-jobs/claim")
    async def claim_internal_verification_job(
        body: InternalVerifierClaimRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Lease only M5 verifier work to the separately authenticated service."""

        require_internal_verifier(request)
        try:
            job = await request.app.state.repository.claim_agent_job(
                worker_id=body.verifier_id,
                lease_seconds=body.lease_seconds,
                kinds=(AgentJobKind.VERIFY.value,),
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        return {"job": job}

    @app.post("/internal/verification-jobs/{job_id}/work")
    async def get_internal_verification_job_work(
        job_id: str,
        body: InternalVerifierLeaseRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Return only the four replay inputs; lab selection remains code-owned."""

        require_internal_verifier(request)
        try:
            return await request.app.state.repository.get_verification_job_work(
                job_id,
                worker_id=body.verifier_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/verification-jobs/{job_id}/remote-flag-lease")
    async def stage_internal_remote_flag_reveal(
        job_id: str,
        body: InternalRemoteFlagLeaseRequest,
        request: Request,
    ) -> dict[str, bool]:
        """Accept a verifier-only ephemeral flag before durable completion.

        The accompanying lease is readable only after the same run becomes
        ``solved`` through the normal proof completion route. It disappears on
        expiry, reveal, or API restart; it is never emitted as an event.
        """

        require_internal_verifier(request)
        raw_flag = ""
        try:
            work = await request.app.state.repository.get_verification_job_work(
                job_id,
                worker_id=body.verifier_id,
                lease_version=body.lease_version,
            )
            candidate = work.get("candidate")
            if (
                "replay_target" not in work
                or not isinstance(candidate, dict)
                or candidate.get("id") != body.candidate_id
                or not isinstance(candidate.get("run_id"), str)
            ):
                raise ValueError("remote_flag_lease_not_allowed")
            raw_flag = body.flag.get_secret_value()
            await request.app.state.verified_flag_reveals.issue(
                run_id=candidate["run_id"],
                candidate_id=body.candidate_id,
                flag=raw_flag,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        except VerifiedFlagRevealError as exc:
            raise error(503, exc.code, "Verified flag reveal is temporarily unavailable.") from exc
        finally:
            raw_flag = ""
        return {"accepted": True}

    @app.post("/internal/verification-jobs/{job_id}/completion")
    async def complete_internal_verification_job(
        job_id: str,
        body: InternalVerifierCompletionRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Let an independent replay proof perform the only M5 SOLVED transition."""

        require_internal_verifier(request)
        proof_artifact = None
        try:
            # Resolve the active lease before writing a proof sidecar. This is
            # repeated in the repository completion transaction, so a raced
            # cancellation or stale lease remains fail-closed.
            work = await request.app.state.repository.get_verification_job_work(
                job_id,
                worker_id=body.verifier_id,
                lease_version=body.lease_version,
            )
            proof = body.completion.proof
            if proof is not None:
                candidate = work["candidate"]
                if (
                    not isinstance(candidate, dict)
                    or proof.run_id != candidate.get("run_id")
                    or proof.candidate_id != body.completion.candidate_id
                    or proof.plan_artifact_digest != candidate.get("plan_artifact_digest")
                ):
                    raise ValueError("verification_proof_binding_mismatch")
                proof_artifact = await request.app.state.candidate_artifacts.persist_proof(proof)
            return await request.app.state.repository.complete_verification_job(
                job_id,
                worker_id=body.verifier_id,
                lease_version=body.lease_version,
                completion=body.completion,
                proof_artifact=proof_artifact,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        except (OSError, RuntimeError):
            raise error(
                503,
                "verification_proof_storage_unavailable",
                "Verification proof storage is unavailable.",
            ) from None

    @app.post("/internal/verification-jobs/{job_id}/failure")
    async def fail_internal_verification_job(
        job_id: str,
        body: InternalVerifierFailureRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Record verifier unavailability without letting a run self-solve."""

        require_internal_verifier(request)
        try:
            return await request.app.state.repository.fail_verification_job(
                job_id,
                worker_id=body.verifier_id,
                lease_version=body.lease_version,
                reason=body.reason,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/power/flag-completions")
    async def complete_internal_power_flag(
        body: InternalPowerFlagCompletionRequest,
        request: Request,
    ) -> dict[str, bool]:
        """Accept only flag-router's independently observed completion request."""

        require_internal_flag_router(request)
        try:
            accepted = await request.app.state.repository.complete_power_flag(
                run_id=body.run_id,
                flag_sha256=body.flag_sha256,
                masked_flag=body.masked_flag,
                observation_artifact_id=body.observation_artifact_id,
                observation_sha256=body.observation_sha256,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        if accepted:
            try:
                await request.app.state.verified_flag_reveals.issue(
                    run_id=body.run_id,
                    candidate_id=f"power:{body.flag_sha256}",
                    flag=body.flag.get_secret_value(),
                )
            except VerifiedFlagRevealError:
                # Durable verification is the authority. A full or transient
                # UI reveal store must not undo a verified solve, and neither
                # the raw value nor an error representation reaches the trace.
                pass
            finally:
                body.flag = SecretStr("")
        return {"accepted": accepted}

    @app.get("/internal/power/runs/{run_id}/flag-patterns")
    async def get_internal_power_flag_patterns(run_id: str, request: Request) -> dict[str, Any]:
        """Return the stored manifest rule only to the independent router.

        The active Power API cannot supply a rule with a candidate submission:
        the router obtains it again from the durable challenge manifest over
        its separate service credential.
        """

        require_internal_flag_router(request)
        try:
            patterns = await request.app.state.repository.get_power_flag_patterns(run_id)
            return InternalPowerFlagPatternsResponse(patterns=patterns).model_dump(mode="json")
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/tool-requests")
    async def invoke_internal_pi_tool(
        job_id: str,
        body: InternalToolRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Relay one Pi custom-tool request through the typed M3 gateway.

        Pi Runner authenticates only to this control API.  It receives neither
        a slot endpoint nor source/target mount details; the gateway resolves
        the active lease and performs its own durable policy/budget check.
        """

        require_internal_runner(request)
        gateway: ToolGatewayClient | None = request.app.state.tool_gateway
        if gateway is None:
            raise error(
                503,
                "tool_gateway_unavailable",
                "The reviewed tool gateway is not configured.",
            )
        try:
            response = await gateway.invoke(
                GatewayToolRequest(session_id=body.session_id, call=body.call),
                job_id=job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except Exception:
            # Do not disclose source paths, container/network details, or
            # untrusted tool output if a gateway implementation is unhealthy.
            raise error(
                503,
                "tool_gateway_unavailable",
                "The reviewed tool gateway is unavailable.",
            ) from None
        return response.model_dump(mode="json")

    @app.post("/internal/agent-jobs/{job_id}/power-usage")
    async def report_internal_power_pi_usage(
        job_id: str,
        body: InternalPowerUsageRequest,
        request: Request,
    ) -> dict[str, bool]:
        """Append bounded Pi counters and debit observed cost without a transcript.

        This endpoint is intentionally post-turn telemetry.  It accepts no
        prompt, completion, model name, target, command, artifact body or API
        key.  A positive provider-calculated cost can only debit the durable
        budget; it can never credit a previous debit or widen a future cap.
        """

        require_internal_runner(request)
        try:
            authority = await request.app.state.repository.get_power_pi_tool_authority(
                job_id,
                session_id=body.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            # The same settled Pi session can be reported after a transient
            # control transport failure.  The bounded counter tuple makes the
            # ledger/event write idempotent without a transcript identifier.
            usage_fingerprint = hashlib.sha256(
                (
                    f"{body.session_id}:{job_id}:{body.input_tokens}:{body.output_tokens}:"
                    f"{body.cache_read_tokens}:{body.cache_write_tokens}:{body.cost_usd:.9f}:"
                    f"{body.compacted}"
                ).encode("ascii")
            ).hexdigest()
            accepted = True
            if body.cost_usd > 0:
                debit = await request.app.state.repository.debit_budget(
                    authority["run_id"],
                    dimension="max_cost_usd",
                    amount=body.cost_usd,
                    idempotency_key=f"power-pi-usage:{body.session_id}:{usage_fingerprint}",
                )
                accepted = bool(debit["accepted"])
            await request.app.state.repository.append_event(
                authority["run_id"],
                "power.pi.usage",
                {
                    "summary": f"Racer {authority['label']}: Pi usage settled.",
                    "label": authority["label"],
                    "input_tokens": body.input_tokens,
                    "output_tokens": body.output_tokens,
                    "cache_read_tokens": body.cache_read_tokens,
                    "cache_write_tokens": body.cache_write_tokens,
                    "cost_usd": body.cost_usd,
                    "compacted": body.compacted,
                    "budget_accepted": accepted,
                },
                actor={"kind": "service", "id": body.runner_id},
                idempotency_key=f"power-pi-usage-event:{body.session_id}:{usage_fingerprint}",
            )
            return {"accepted": accepted}
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-activity")
    async def report_internal_power_pi_activity(
        job_id: str,
        body: InternalPowerActivityRequest,
        request: Request,
    ) -> dict[str, bool]:
        """Append one safe Pi prompt/visible-response snippet for the operator.

        The browser needs a concise explanation of a racer's current direction
        to steer it productively.  This deliberately accepts neither hidden
        thinking nor tool inputs/outputs.  The raw provider message remains in
        Pi's private local session file; only a redacted visible-text excerpt
        becomes an append-only event.
        """

        require_internal_runner(request)
        try:
            authority = await request.app.state.repository.get_power_pi_tool_authority(
                job_id,
                session_id=body.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            content = _redact_power_activity_text(body.content.strip(), maximum=2_000)
            if not content:
                raise ValueError("power_pi_activity_invalid")
            await request.app.state.repository.append_event(
                authority["run_id"],
                "power.pi.activity",
                {
                    "summary": f"Racer {authority['label']}: Pi {body.kind} recorded.",
                    "session_id": body.session_id,
                    "label": authority["label"],
                    "message_kind": body.kind,
                    "content": content,
                },
                actor={"kind": "service", "id": body.runner_id},
                idempotency_key=f"power-pi-activity:{uuid4().hex}",
            )
            return {"accepted": True}
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-tool-transcript")
    async def report_internal_power_tool_transcript(
        job_id: str,
        body: InternalPowerToolTranscriptRequest,
        request: Request,
    ) -> dict[str, bool]:
        """Append a bounded terminal view without replacing immutable evidence.

        The runner supplies only a completed custom-tool record under an
        active session lease. Both boundaries redact independently. This keeps
        commands and useful stdout/stderr visible to a local operator while
        raw flags and credentials remain outside the append-only timeline.
        """

        require_internal_runner(request)
        try:
            authority = await request.app.state.repository.get_power_pi_tool_authority(
                job_id,
                session_id=body.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            command = _redact_power_activity_text(body.command.strip(), maximum=2_000)
            output = _redact_power_activity_text(body.output.strip(), maximum=6_000)
            if not command or not output:
                raise ValueError("power_tool_transcript_invalid")
            await request.app.state.repository.append_event(
                authority["run_id"],
                "power.pi.tool_transcript",
                {
                    "summary": f"Racer {authority['label']}: {body.tool} completed.",
                    "session_id": body.session_id,
                    "label": authority["label"],
                    "tool": body.tool,
                    "command": command,
                    "output": output,
                    "exit_code": body.exit_code,
                    "timed_out": body.timed_out,
                    "output_truncated": body.output_truncated or "[TRUNCATED]" in output,
                },
                actor={"kind": "service", "id": body.runner_id},
                # Keep an acknowledged tool receipt stable across a runner
                # retry, without allowing the model to choose a database key.
                # Hashing also keeps the durable key safely below the 200-byte
                # repository ceiling when a session identifier is long.
                idempotency_key=(
                    "power-pi-tool-transcript:"
                    + hashlib.sha256(
                        f"{body.session_id}:{body.idempotency_key}".encode("ascii")
                    ).hexdigest()
                ),
            )
            return {"accepted": True}
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/power-tool-requests")
    async def invoke_internal_power_pi_tool(
        job_id: str,
        body: InternalPowerToolRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Run exactly one Power custom-tool action through private authorities.

        Pi supplies only an action plus validated arguments.  The repository
        resolves the active job/session to a workspace; this handler owns the
        sandboxd and flag-router credentials, which never cross to the runner.
        """

        require_internal_runner(request)
        settings: Settings = request.app.state.settings
        if settings.power_sandboxd_url is None or settings.power_sandboxd_token is None:
            raise error(
                503, "power_tool_runtime_unavailable", "The Power tool runtime is unavailable."
            )
        arguments: (
            _PowerExecArguments
            | _PowerPtySendArguments
            | _PowerPtyReadArguments
            | _PowerPtyCloseArguments
            | _PowerTubeConnectArguments
            | _PowerTubeSendArguments
            | _PowerTubeReceiveArguments
            | _PowerTubeCloseArguments
            | _PowerFlagArguments
            | None
        ) = None
        try:
            authority = await request.app.state.repository.get_power_pi_tool_authority(
                job_id,
                session_id=body.session_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            arguments = _parse_power_tool_arguments(body.action, body.arguments)
            recon_fingerprint = _power_fs_read_fingerprint(body.tool_name, arguments)
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

        sandbox = HttpSandboxdClient(
            base_url=settings.power_sandboxd_url,
            token=settings.power_sandboxd_token.get_secret_value(),
        )
        workspace_id = authority["workspace_id"]

        async def record_completed_action(
            *,
            observation_artifact_id: str | None,
            observation_artifact_ids: tuple[str, ...] = (),
            observation_received: bool,
            action_summary: str,
        ) -> bool:
            """Append a deliberately metadata-only Power activity receipt.

            The immutable artifact already contains the observation.  This
            receipt makes the racer visibly active without duplicating a
            command, path, target, output, candidate, token, or model text in
            the event ledger.  It is telemetry only: a telemetry outage must
            never cause a successful tool action to be replayed.
            """

            try:
                return await request.app.state.repository.record_power_pi_action(
                    authority["run_id"],
                    label=authority["label"],
                    runner_id=body.runner_id,
                    action=body.action,
                    observation_artifact_id=observation_artifact_id,
                    observation_artifact_ids=observation_artifact_ids,
                    observation_received=observation_received,
                    action_summary=action_summary,
                    recon_fingerprint=recon_fingerprint,
                )
            except Exception:
                # The private tool result is authoritative.  Do not expose a
                # persistence failure here or retry the completed command.
                return False

        async def recorded_observation(observation: Any) -> dict[str, Any]:
            """Record an observation and activate a format-matching review gate.

            The artifact is saved before detection so a candidate is always
            evidence-bound.  Detection uses only the manifest-derived flag
            formats (not the broad UI review detector), records no candidate
            bytes, and gives Pi only a stop-at-boundary signal.
            """

            response = _power_observation_response(observation)
            observation_artifact_ids = (response["artifact"]["id"],)
            # sandboxd stores an empty stderr stream too. It cannot contain a
            # candidate, so avoid adding the shared empty CAS object to every
            # racer receipt and keep review scans proportional to evidence.
            if (
                observation.stderr_artifact_id is not None
                and observation.stderr_artifact_size_bytes > 0
            ):
                observation_artifact_ids += (observation.stderr_artifact_id,)
            duplicate = await record_completed_action(
                observation_artifact_id=response["artifact"]["id"],
                observation_artifact_ids=observation_artifact_ids,
                observation_received=True,
                action_summary="Typed sandbox action completed.",
            )
            try:
                patterns = await request.app.state.repository.get_power_flag_patterns(
                    authority["run_id"]
                )
                reviewed = await RuntimeCandidateRevealService(
                    artifact_root=request.app.state.artifact_root,
                    patterns=patterns,
                ).reveal(
                    run_id=authority["run_id"],
                    observations=(
                        *(
                            RuntimeCandidateArtifact(
                                artifact_id=artifact_id,
                                racer_label=authority["label"],
                            )
                            for artifact_id in observation_artifact_ids
                        ),
                    ),
                    # Candidate-gate behavior follows the flag format given
                    # at launch. The broader detector remains an explicit
                    # operator-only review aid at the public reveal route.
                    include_broad_detector=False,
                )
                candidate_count = reviewed["candidate_count"]
                if isinstance(candidate_count, int) and candidate_count > 0:
                    candidates = reviewed.get("candidates")
                    first_candidate = (
                        candidates[0].get("value")
                        if isinstance(candidates, list)
                        and candidates
                        and isinstance(candidates[0], dict)
                        else None
                    )
                    candidate_evidence = (
                        None
                        if not isinstance(first_candidate, str)
                        else await RuntimeCandidateRevealService(
                            artifact_root=request.app.state.artifact_root,
                            patterns=patterns,
                        ).find_observation_for_candidate(
                            run_id=authority["run_id"],
                            candidate=first_candidate,
                            observations=(
                                RuntimeCandidateArtifact(
                                    artifact_id=artifact_id,
                                    racer_label=authority["label"],
                                )
                                for artifact_id in observation_artifact_ids
                            ),
                        )
                    )
                    if candidate_evidence is None:
                        raise RuntimeError("power_candidate_evidence_unavailable")
                    gate = await request.app.state.repository.pause_power_candidate_review(
                        authority["run_id"],
                        session_id=body.session_id,
                        runner_id=body.runner_id,
                        observation_artifact_id=candidate_evidence.artifact_id,
                        candidate_count=candidate_count,
                    )
                    if gate["paused"]:
                        # This typed field carries neither a raw candidate nor
                        # a source path. Pi uses it only to finish this native
                        # turn at a safe boundary while the browser asks the
                        # operator to reveal and review local candidates.
                        response["candidateReviewRequired"] = True
                        response["candidateCount"] = candidate_count
            except (OSError, RuntimeError, ValueError, re.error):
                # Candidate review is an optimisation gate, never grounds to
                # replay or fail an action already completed by sandboxd. The
                # explicit browser reveal remains available from the stored
                # immutable artifact if this best-effort scan is unavailable.
                pass
            if duplicate:
                # This server-owned nudge is returned only to the Pi turn that
                # repeated a reviewed fs_read.  It contains no source path or
                # sibling output, but directs the racer to choose new evidence
                # before it spends another full context window on recon.
                response["stderr"] = (f"{response['stderr']}\n" if response["stderr"] else "") + (
                    "CTFMesh coordinator: this file was already inspected; "
                    "choose a distinct evidence path."
                )
            return response

        async def recorded_channel_state(state: Literal["open", "closed"]) -> dict[str, str]:
            """Return a state-only channel result with no user-controlled payload."""

            await record_completed_action(
                observation_artifact_id=None,
                observation_received=False,
                action_summary="Typed channel action completed.",
            )
            return {"state": state}

        try:
            if body.action == "exec":
                if not isinstance(arguments, _PowerExecArguments):  # defensive narrowed dispatch
                    raise ValueError("power_tool_arguments_invalid")
                observation = await sandbox.exec(
                    workspace_id,
                    command=tuple(arguments.command),
                    timeout_seconds=arguments.timeout_seconds,
                    working_directory=arguments.working_directory,
                )
                return await recorded_observation(observation)
            if body.action == "pty_start":
                if not isinstance(arguments, _PowerExecArguments):
                    raise ValueError("power_tool_arguments_invalid")
                observation = await sandbox.pty_start(
                    workspace_id,
                    command=tuple(arguments.command),
                    timeout_seconds=arguments.timeout_seconds,
                    working_directory=arguments.working_directory,
                    kind="gdb" if arguments.command[0] == "gdb" else "pty",
                )
                return await recorded_observation(observation)
            if body.action == "pty_send":
                if not isinstance(arguments, _PowerPtySendArguments):
                    raise ValueError("power_tool_arguments_invalid")
                await sandbox.pty_send(workspace_id, pty_id=arguments.pty_id, data=arguments.data)
                return await recorded_channel_state("open")
            if body.action == "pty_read":
                if not isinstance(arguments, _PowerPtyReadArguments):
                    raise ValueError("power_tool_arguments_invalid")
                observation = await sandbox.pty_send_read(
                    workspace_id,
                    pty_id=arguments.pty_id,
                    data="",
                    max_bytes=arguments.max_bytes,
                    wait_ms=arguments.wait_ms,
                    kind=arguments.kind,
                )
                return await recorded_observation(observation)
            if body.action == "pty_close":
                if not isinstance(arguments, _PowerPtyCloseArguments):
                    raise ValueError("power_tool_arguments_invalid")
                await sandbox.pty_close(workspace_id, pty_id=arguments.pty_id)
                return await recorded_channel_state("closed")
            if body.action == "tube_connect":
                if not isinstance(arguments, _PowerTubeConnectArguments):
                    raise ValueError("power_tool_arguments_invalid")
                observation = await sandbox.tube_connect(
                    workspace_id,
                    host=arguments.host,
                    port=arguments.port,
                    timeout_seconds=arguments.timeout_seconds,
                )
                return await recorded_observation(observation)
            if body.action == "tube_send":
                if not isinstance(arguments, _PowerTubeSendArguments):
                    raise ValueError("power_tool_arguments_invalid")
                await sandbox.tube_send(
                    workspace_id,
                    tube_id=arguments.tube_id,
                    data_base64=arguments.data_base64,
                )
                return await recorded_channel_state("open")
            if body.action == "tube_receive":
                if not isinstance(arguments, _PowerTubeReceiveArguments):
                    raise ValueError("power_tool_arguments_invalid")
                observation = await sandbox.tube_recv_until(
                    workspace_id,
                    tube_id=arguments.tube_id,
                    delimiter_base64=arguments.delimiter_base64,
                    max_bytes=arguments.max_bytes,
                    timeout_seconds=arguments.timeout_seconds,
                )
                return await recorded_observation(observation)
            if body.action == "tube_close":
                if not isinstance(arguments, _PowerTubeCloseArguments):
                    raise ValueError("power_tool_arguments_invalid")
                await sandbox.tube_close(workspace_id, tube_id=arguments.tube_id)
                return await recorded_channel_state("closed")
            if not isinstance(arguments, _PowerFlagArguments):
                raise ValueError("power_tool_arguments_invalid")
            # A runner must never bypass the browser candidate gate. The Pi
            # adapter normally holds this action locally; retain the control
            # boundary denial as defense in depth for stale or forged clients.
            raise error(
                409,
                "power_candidate_operator_review_required",
                "A Power candidate must be confirmed through local operator review.",
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc
        except (SandboxdClientError, HttpFlagRouterClientError):
            # Private dependency errors deliberately do not disclose a service
            # address, a command, raw output, or an observed flag candidate.
            raise error(
                503, "power_tool_runtime_unavailable", "The Power tool runtime is unavailable."
            ) from None
        finally:
            # This only clears the request-local object reference. It must not
            # be recorded in logs/events, and Python cannot zero immutable text.
            if isinstance(arguments, _PowerFlagArguments):
                arguments.candidate = SecretStr("")

    @app.post("/internal/agent-jobs/{job_id}/failure")
    async def fail_internal_pi_job(
        job_id: str,
        body: InternalAgentFailureRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Persist a secret-free terminal failure for the active lease only."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.fail_pi_agent_job(
                job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
                reason=body.reason,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/session-state")
    async def get_internal_pi_session_state(
        job_id: str,
        body: InternalSessionActivationRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Serve the `state.get` custom tool without exposing target details."""

        require_internal_runner(request)
        try:
            return await request.app.state.repository.pi_run_state_view(
                body.session_id,
                job_id=job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/internal/agent-jobs/{job_id}/flag-capture-patterns")
    async def get_internal_flag_capture_patterns(
        job_id: str,
        body: InternalSessionActivationRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Return only manifest-owned capture configuration to a builder turn.

        This route intentionally reuses the same active-turn lease checks as
        ``state.get`` but projects away run state, operator hints, target
        details, source evidence, credentials, and any candidate value.
        """

        require_internal_runner(request)
        try:
            capture = await request.app.state.repository.pi_flag_capture_patterns_view(
                body.session_id,
                job_id=job_id,
                worker_id=body.runner_id,
                lease_version=body.lease_version,
            )
            return InternalFlagCapturePatternsResponse.model_validate(capture).model_dump(
                mode="json"
            )
        except ValueError as exc:
            raise internal_repository_error(exc) from exc

    @app.post("/v1/challenges/validate")
    async def validate_challenge(document: ManifestDocument) -> dict[str, Any]:
        try:
            manifest = ChallengeManifest.model_validate(document.manifest)
        except ValidationError as exc:
            return {
                "valid": False,
                "errors": safe_validation_errors(exc),
            }
        return {
            "valid": True,
            # Preserve the declared-field shape: serializing every Pydantic
            # default would make an offline artifact bundle look as though it
            # declared empty network/runtime fields on a later re-import.
            "manifest": manifest.model_dump(
                mode="json",
                by_alias=True,
                exclude_unset=True,
            ),
            "scope": [
                endpoint.model_dump(mode="json")
                for endpoint in manifest.spec.target.allowed_endpoints
            ],
        }

    @app.post("/v1/challenges", status_code=201)
    async def import_challenge(document: ManifestDocument, request: Request) -> dict[str, Any]:
        try:
            manifest = ChallengeManifest.model_validate(document.manifest)
        except ValidationError as exc:
            raise error(
                422,
                "invalid_manifest",
                "Challenge manifest was rejected.",
                details=safe_validation_errors(exc),
            ) from exc
        return await request.app.state.repository.create_challenge(
            manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
            name=str(manifest.metadata.name),
        )

    @app.get("/v1/challenges")
    async def list_challenges(
        request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 50
    ) -> dict[str, Any]:
        """List operator-imported manifests without exposing local artifact contents."""

        return {"items": await request.app.state.repository.list_challenges(limit=limit)}

    @app.post("/v1/archive-intakes", status_code=201)
    async def create_archive_intake(request: Request) -> dict[str, Any]:
        """Receive one bounded offline archive without treating it as executable input."""

        try:
            # Use the raw request stream rather than multipart. This keeps the
            # upload quota under our control and avoids framework spooling of an
            # untrusted archive before ArchiveIntakeService can inspect it.
            declared_size = parse_content_length(request.headers.get("content-length"))
            return await request.app.state.archive_intakes.ingest_stream(
                request.stream(),
                original_name=request.headers.get("x-archive-name"),
                declared_size=declared_size,
            )
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive intake was rejected.",
            ) from exc

    @app.get("/v1/archive-intakes")
    async def list_archive_intakes(
        request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 50
    ) -> dict[str, Any]:
        """List small, redacted receipt summaries for workspace history."""

        try:
            return {"items": await request.app.state.archive_intakes.list_intakes(limit=limit)}
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive history is unavailable.",
            ) from exc

    @app.get("/v1/archive-intakes/{intake_id}")
    async def get_archive_intake(intake_id: str, request: Request) -> dict[str, Any]:
        try:
            return await request.app.state.archive_intakes.get_intake(intake_id)
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive intake is unavailable.",
            ) from exc

    @app.delete("/v1/archive-intakes/{intake_id}")
    async def remove_archive_intake(
        intake_id: str,
        request: Request,
        _archive_lifecycle: Annotated[None, Depends(archive_lifecycle_guard)],
    ) -> dict[str, str | bool]:
        """Permanently remove one unused archive after exact confirmation."""

        confirmation = request.headers.get("x-confirm-remove", "")
        if confirmation != intake_id:
            raise error(
                422,
                "archive_remove_confirmation_required",
                "Exact archive removal confirmation is required.",
            )
        try:
            # Resolve the receipt before the database query so malformed or
            # planted paths never become a repository-side existence oracle.
            await request.app.state.archive_intakes.get_intake(intake_id)
            if await request.app.state.repository.archive_intake_has_durable_reference(intake_id):
                raise error(
                    409,
                    "archive_intake_in_use",
                    "This archive is retained by a challenge or run.",
                )
            return await request.app.state.archive_intakes.remove_intake(intake_id)
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive intake could not be removed.",
            ) from exc

    @app.get("/v1/archive-triage/providers")
    async def list_archive_triage_providers() -> dict[str, list[dict[str, str]]]:
        """Expose the fixed, non-secret provider allowlist for local operators."""

        return {
            "items": [
                {
                    "id": descriptor.id.value,
                    "label": descriptor.label,
                    "key_label": descriptor.key_label,
                    "output_contract": descriptor.output_contract.value,
                }
                for descriptor in archive_triage_provider_descriptors()
            ]
        }

    @app.get("/v1/skill-catalog")
    async def get_skill_catalog(
        category: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return checked-in skill/MCP provenance only; this route performs no fetches.

        The catalog is useful to inspect why a category has a reviewed local
        prompt profile and which *local* read-only MCP facade it may use. It
        does not install upstream skills, expose a remote MCP endpoint, or
        grant runtime permissions.
        """

        selected_category: SkillCategory | None = None
        if category is not None:
            try:
                selected_category = SkillCategory(category)
            except ValueError as exc:
                raise error(422, "skill_category_invalid", "Unknown CTF skill category.") from exc
        skills = builtin_skill_registry().list_specs()
        if selected_category is not None:
            skills = tuple(spec for spec in skills if spec.category is selected_category)
            profiles = mcp_source_profiles_for(selected_category)
        else:
            profiles = tuple(
                profile
                for skill_category in SkillCategory
                for profile in mcp_source_profiles_for(skill_category)
            )
        return {
            "skills": [spec.model_dump(mode="json") for spec in skills],
            "mcp_profiles": [profile.model_dump(mode="json") for profile in profiles],
        }

    @app.post("/v1/archive-intakes/{intake_id}/candidate-flags/reveal")
    async def reveal_archive_candidate_flags(
        intake_id: str,
        body: CandidateRevealRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        # A flag-shaped value inside an uploaded file is input evidence, not a
        # verified answer. Require an explicit UI/operator confirmation before
        # returning it to the active caller.
        if not body.confirm:
            raise error(
                422,
                "candidate_reveal_confirmation_required",
                "Explicit confirmation is required before revealing input candidates.",
            )
        try:
            revealed = await request.app.state.archive_intakes.reveal_candidate_flags(intake_id)
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Candidate flag reveal is unavailable.",
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        return revealed

    @app.post("/v1/runs/{run_id}/candidate-flags/reveal")
    async def reveal_runtime_candidate_flags(
        run_id: str,
        body: CandidateRevealRequest,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        """Reveal all Power-runtime candidates only on explicit local demand.

        This is a read-only review surface.  It rescans immutable sandboxd
        observations and never appends raw values to the durable event ledger.
        """

        if not body.confirm:
            raise error(
                422,
                "candidate_reveal_confirmation_required",
                "Explicit confirmation is required before revealing runtime candidates.",
            )
        run = await request.app.state.repository.get_run(run_id)
        if run is None:
            raise error(404, "run_not_found", "Run does not exist.")
        if run.get("provider") != "power-swarm":
            raise error(
                409,
                "runtime_candidate_reveal_not_power_run",
                "Runtime candidate reveal is available only for Power runs.",
            )
        try:
            observations = await request.app.state.repository.list_power_pi_observation_artifacts(
                run_id
            )
            patterns = await request.app.state.repository.get_power_flag_patterns(run_id)
            reveal = await RuntimeCandidateRevealService(
                artifact_root=request.app.state.artifact_root,
                patterns=patterns,
            ).reveal(
                run_id=run_id,
                observations=tuple(
                    RuntimeCandidateArtifact(
                        artifact_id=item["artifact_id"], racer_label=item["label"]
                    )
                    for item in observations
                ),
            )
        except (OSError, RuntimeError, ValueError, re.error):
            raise error(
                503,
                "runtime_candidate_reveal_unavailable",
                "Runtime candidate reveal is unavailable.",
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return reveal

    @app.post("/v1/runs/{run_id}/candidate-review/reject")
    async def reject_runtime_candidate_review(
        run_id: str,
        body: CandidateRevealRequest,
        request: Request,
    ) -> dict[str, object]:
        """Resume live racers after the local operator rejects the queue.

        This endpoint contains no candidate field. The durable repository
        changes a pending candidate gate back to ``running`` and enqueues a
        bounded, source-free steer for each available racer.
        """

        if not body.confirm:
            raise error(
                422,
                "candidate_review_confirmation_required",
                "Explicit confirmation is required before resuming the race.",
            )
        try:
            result = await request.app.state.repository.reject_power_candidate_review(
                run_id,
                requested_by="local-operator",
                idempotency_key=required_idempotency_key(request),
            )
        except ValueError as exc:
            code = str(exc)
            if code in {"run_not_found", "power_candidate_review_not_pending"}:
                raise error(
                    404 if code == "run_not_found" else 409,
                    code,
                    "Candidate review is not pending.",
                ) from exc
            raise internal_repository_error(exc) from exc
        return {
            "accepted": True,
            "status": "running",
            "resumed_racer_count": result["racer_count"],
        }

    @app.post("/v1/runs/{run_id}/candidate-review/confirm")
    async def confirm_runtime_candidate_review(
        run_id: str,
        body: CandidateReviewConfirmationRequest,
        request: Request,
        response: Response,
    ) -> dict[str, object]:
        """Send one human-confirmed observed candidate to flag-router.

        The browser supplies a raw value only in this request. It is matched to
        a provenance-checked immutable sandbox artifact, forwarded directly to
        the independent flag-router, then discarded. Neither the event ledger
        nor the run result stores it.
        """

        idempotency_key = required_idempotency_key(request)
        candidate = body.candidate.get_secret_value()
        try:
            run = await request.app.state.repository.get_run(run_id)
            if run is None:
                raise error(404, "run_not_found", "Run does not exist.")
            if run.get("provider") != "power-swarm":
                raise error(
                    409,
                    "candidate_review_not_power_run",
                    "Candidate review is available only for Power runs.",
                )
            if not await request.app.state.repository.power_candidate_review_pending(run_id):
                raise error(
                    409,
                    "power_candidate_review_not_pending",
                    "There is no runtime candidate awaiting review.",
                )
            observations = await request.app.state.repository.list_power_pi_observation_artifacts(
                run_id
            )
            evidence = await RuntimeCandidateRevealService(
                artifact_root=request.app.state.artifact_root,
            ).find_observation_for_candidate(
                run_id=run_id,
                candidate=candidate,
                observations=tuple(
                    RuntimeCandidateArtifact(
                        artifact_id=item["artifact_id"], racer_label=item["label"]
                    )
                    for item in observations
                ),
            )
            if evidence is None:
                raise error(
                    409,
                    "candidate_review_candidate_not_observed",
                    "The selected candidate was not found in retained runtime evidence.",
                )
            settings: Settings = request.app.state.settings
            if settings.power_flag_router_url is None or settings.power_flag_router_token is None:
                raise error(
                    503,
                    "power_flag_router_unavailable",
                    "Independent flag verification is unavailable.",
                )
            accepted = await HttpFlagRouterClient(
                base_url=settings.power_flag_router_url,
                token=settings.power_flag_router_token.get_secret_value(),
            ).submit(
                run_id=run_id,
                candidate=candidate,
                observation_artifact_id=evidence.artifact_id,
                observation_sha256=evidence.artifact_id.removeprefix("sha256:"),
            )
            if not accepted:
                # A human can select a plausible decoy. The independent
                # router is authoritative for that decision; once it rejects
                # the candidate, resume the same Pi sessions immediately
                # without writing the value into a durable record.
                resumed = await request.app.state.repository.reject_power_candidate_review(
                    run_id,
                    requested_by="local-operator",
                    idempotency_key=idempotency_key,
                )
                response.headers["Cache-Control"] = "no-store"
                return {
                    "accepted": False,
                    "status": "running",
                    "resumed_racer_count": resumed["racer_count"],
                }
            confirmation_key = (
                "power-candidate-review-confirmed:"
                + hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
            )
            await request.app.state.repository.append_event(
                run_id,
                "power.candidate.review.confirmed",
                {"summary": "Operator confirmed a runtime candidate for independent verification."},
                actor={"kind": "human", "id": "local-operator"},
                idempotency_key=confirmation_key,
            )
            controller: PowerRunController | None = request.app.state.power_runs
            if controller is not None:
                await controller.accepted_flag(run_id=run_id, winner_session_id=None)
            response.headers["Cache-Control"] = "no-store"
            return {"accepted": True, "status": "solved"}
        except (OSError, RuntimeError, HttpFlagRouterClientError):
            # Raw candidate text and private endpoint details must never be
            # reflected in browser errors, event payloads, or server logs.
            raise error(
                503,
                "candidate_review_verification_unavailable",
                "Independent candidate verification is unavailable.",
            ) from None
        finally:
            # SecretStr cannot zero the original immutable text, but clearing
            # both references narrows its request lifetime and prevents reuse.
            body.candidate = SecretStr("")
            candidate = ""

    @app.post("/v1/archive-intakes/{intake_id}/runs", status_code=202)
    async def launch_exact_instance_run(
        intake_id: str,
        body: ExactInstanceRunRequest,
        request: Request,
        response: Response,
        _archive_lifecycle: Annotated[None, Depends(archive_lifecycle_guard)],
    ) -> dict[str, Any]:
        """Create one fully scoped UI run without persisting its API key.

        The launch is intentionally narrow: a validated archive receipt, one
        public HTTP(S) origin, and one browser-selected reviewed provider.
        The API constructs the manifest itself; it never accepts source paths,
        model tools, a Docker definition, arbitrary egress, or raw flags.
        """

        idempotency_key = required_idempotency_key(request)
        slots = _configured_ui_source_slots(request.app.state.settings)
        lease_client = request.app.state.pi_credential_leases
        if not slots or request.app.state.tool_gateway is None:
            raise error(
                503,
                "ui_exact_instance_runtime_unavailable",
                "The exact-instance runtime is not configured.",
            )
        if lease_client is None:
            raise error(
                503,
                "pi_credential_lease_unavailable",
                "The private model credential runtime is not configured.",
            )
        try:
            native_provider = _pi_provider(body.execution.provider)
            _validate_exact_instance_budget(body.budget)
            # Verify the receipt before allocating any finite source slot.
            await request.app.state.archive_intakes.get_intake(intake_id)
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive intake is unavailable.",
            ) from exc
        except ValueError as exc:
            code = str(exc)
            if code == "ui_exact_instance_budget_not_allowed":
                raise error(
                    422,
                    code,
                    "Keep the exact-instance budget within the reviewed hard limits.",
                ) from exc
            raise error(422, code, "The selected provider is unavailable.") from exc

        provider_marker = _ui_provider_marker(body.execution.provider, body.execution.model)
        launch_lock: asyncio.Lock = request.app.state.exact_instance_launch_lock
        async with launch_lock:
            existing = await request.app.state.repository.get_run_by_start_idempotency_key(
                idempotency_key
            )
            if existing is not None:
                challenge = await request.app.state.repository.get_challenge(
                    existing["challenge_id"]
                )
                if challenge is None:
                    raise error(
                        409, "idempotency_conflict", "Run launch conflicts with a prior request."
                    )
                try:
                    stored_manifest = ChallengeManifest.model_validate(challenge["manifest"])
                    source = stored_manifest.spec.source
                    if source is None:
                        raise ValueError("source_binding_missing")
                    expected_manifest = _build_exact_instance_manifest(
                        intake_id=intake_id,
                        entry_url=body.target.entry_url,
                        provider=native_provider,
                        slot_id=source.slot_id,
                        flag_format=body.target.flag_format,
                        budget=body.budget,
                    )
                except (TypeError, ValueError) as exc:
                    raise error(
                        409,
                        "idempotency_conflict",
                        "Run launch conflicts with a prior request.",
                    ) from exc
                if (
                    stored_manifest != expected_manifest
                    or existing["provider"] != provider_marker
                    or existing["budget"] != body.budget.model_dump()
                ):
                    raise error(
                        409, "idempotency_conflict", "Run launch conflicts with a prior request."
                    )
                response.headers["Cache-Control"] = "no-store"
                return {
                    "run_id": existing["id"],
                    "challenge_id": existing["challenge_id"],
                    "status": existing["status"],
                    "scope": {
                        "entry_origin": stored_manifest.spec.target.target_aliases["target"],
                        "source_slot": source.slot_id,
                    },
                    "progress": {
                        "console_url": f"/v1/runs/{existing['id']}/console",
                        "activity_stream_url": f"/v1/runs/{existing['id']}/activity/stream",
                    },
                }

            occupied_slots = await request.app.state.repository.list_active_source_slot_ids()
            selected = next(
                ((slot_id, root) for slot_id, root in slots if slot_id not in occupied_slots),
                None,
            )
            if selected is None:
                raise error(
                    409,
                    "source_slot_unavailable",
                    "Both source slots are in use. Finish or cancel a run before starting another.",
                )
            slot_id, slot_root = selected
            try:
                manifest = _build_exact_instance_manifest(
                    intake_id=intake_id,
                    entry_url=body.target.entry_url,
                    provider=native_provider,
                    slot_id=slot_id,
                    flag_format=body.target.flag_format,
                    budget=body.budget,
                )
            except (TypeError, ValueError) as exc:
                code = str(exc)
                if code == "ui_flag_format_invalid":
                    raise error(
                        422,
                        code,
                        "Use a literal flag prefix such as HTB{ or a template such as HTB{...}.",
                    ) from exc
                if code not in {"ui_instance_url_invalid", "ui_instance_target_not_public"}:
                    code = "ui_instance_url_invalid"
                raise error(422, code, "The instance URL is not an allowed public origin.") from exc
            challenge = await request.app.state.repository.create_challenge(
                manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
                name=str(manifest.metadata.name),
            )
            try:
                await request.app.state.archive_intakes.materialize_source_slot(
                    intake_id,
                    slot_root=slot_root,
                    slot_id=slot_id,
                    challenge_id=challenge["id"],
                )
            except ArchiveIntakeError as exc:
                raise error(
                    archive_error_status(exc.code),
                    exc.code,
                    "Validated archive source could not be prepared.",
                ) from exc
            try:
                run = await request.app.state.run_engine.start(
                    challenge_id=challenge["id"],
                    mode=RunMode.ASSISTED.value,
                    provider=provider_marker,
                    budget=body.budget.model_dump(),
                    idempotency_key=idempotency_key,
                )
            except ValueError as exc:
                code = str(exc)
                raise error(
                    409 if code == "idempotency_conflict" else 422,
                    code,
                    "Run could not be created.",
                ) from exc

            api_key = body.execution.api_key.get_secret_value()
            try:
                lease_expires_at = await lease_client.grant(
                    run_id=run["id"],
                    provider=native_provider,
                    model=body.execution.model,
                    api_key=api_key,
                    ttl_seconds=min(900, max(60, body.budget.wall_time_seconds)),
                )
            except PiCredentialLeaseError as exc:
                # No session/turn is authorized without a private lease. A
                # queued preflight is cancelled before it can become Pi work;
                # this operation emits no key or model string into the ledger.
                with suppress(ValueError):
                    await request.app.state.repository.request_pi_abort(
                        run["id"],
                        idempotency_key=f"launch-credential-failure:{idempotency_key}",
                        requested_by="control-api",
                    )
                raise error(
                    503,
                    exc.code,
                    "The model credential could not be prepared. No solve was started.",
                ) from exc
            finally:
                # Python cannot zero immutable strings, but dropping this last
                # local reference prevents request-local key reuse or storage.
                api_key = ""

        response.headers["Cache-Control"] = "no-store"
        return {
            "run_id": run["id"],
            "challenge_id": challenge["id"],
            "status": run["status"],
            "scope": {
                "entry_origin": manifest.spec.target.target_aliases["target"],
                "source_slot": slot_id,
            },
            "credential_lease_expires_at": lease_expires_at,
            "progress": {
                "console_url": f"/v1/runs/{run['id']}/console",
                "activity_stream_url": f"/v1/runs/{run['id']}/activity/stream",
            },
        }

    @app.post("/v1/archive-intakes/{intake_id}/power-runs", status_code=202)
    async def launch_power_run(
        intake_id: str,
        body: PowerRunRequest,
        request: Request,
        response: Response,
        _archive_lifecycle: Annotated[None, Depends(archive_lifecycle_guard)],
    ) -> dict[str, Any]:
        """Start the opt-in, exactly-three-racer Power path from one receipt."""

        idempotency_key = required_idempotency_key(request)
        controller: PowerRunController | None = request.app.state.power_runs
        if controller is None:
            raise error(
                503,
                "power_runtime_unavailable",
                "The Power runtime is not configured. Start the Power Compose profile first.",
            )
        if body.open_egress:
            # The reviewed P5 workspace image is networkless. Presenting this
            # explicit rejection is safer than accepting a setting the runtime
            # cannot enforce as a one-host tube capability.
            raise error(
                422,
                "power_open_egress_unavailable",
                "Open egress is not available; declare one target host and port instead.",
            )
        if body.target is not None and not body.authorized_target:
            raise error(
                422,
                "power_target_authorization_required",
                "Confirm that the declared target is an authorized CTF instance.",
            )
        try:
            intake = await request.app.state.archive_intakes.get_intake(intake_id)
            archive = intake.get("archive")
            archive_digest = archive.get("sha256") if isinstance(archive, dict) else None
            if not isinstance(archive_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", archive_digest
            ):
                raise ArchiveIntakeError("archive_intake_invalid")
            race = _power_race_configuration(body)
            manifest = _build_power_manifest(
                intake_id=intake_id,
                target=body.target,
                budget=body.budget,
                flag_format=body.flag_format,
            )
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive intake is unavailable.",
            ) from exc
        except (PowerRaceConfigurationError, ValueError) as exc:
            raise error(422, str(exc), "The Power race configuration is invalid.") from exc

        target = None if body.target is None else (body.target.host, body.target.port)
        launch_scope: dict[str, Any] = {
            "summary": "Power archive run declared.",
            "racer_count": body.racer_count,
            "target_kind": "tcp" if target is not None else "offline",
            "target_host": target[0] if target is not None else None,
            "target_port": target[1] if target is not None else None,
            "contest_offline": body.contest_offline,
            "flag_format_configured": body.flag_format is not None,
            "challenge_description_configured": body.challenge_description is not None,
        }
        try:
            challenge = await request.app.state.repository.create_challenge(
                manifest.model_dump(mode="json", by_alias=True, exclude_unset=True),
                name=str(manifest.metadata.name),
            )
            run = await request.app.state.repository.create_power_run(
                challenge["id"],
                mode=RunMode.ASSISTED.value,
                provider="power-swarm",
                budget={
                    "wall_time_seconds": body.budget.wall_time_seconds,
                    "max_tool_calls": 1_000,
                    "max_http_requests": 10_000,
                    "max_cost_usd": body.budget.max_cost_usd,
                },
                idempotency_key=idempotency_key,
                launch_scope=launch_scope,
            )
            if run["status"] == "running":
                await controller.start(
                    run_id=run["id"],
                    launch=PowerRunLaunch(
                        archive_digest=archive_digest,
                        configuration=race,
                        provider_keys=body.provider_keys,
                        target=target,
                        contest_offline=body.contest_offline,
                        flag_format=body.flag_format,
                        challenge_description=body.challenge_description,
                        # Build the one small racer orientation from the
                        # redacted public receipt.  The archive itself stays
                        # untrusted and is read only through sandboxd tools.
                        brief_context=power_brief_context_from_intake(intake),
                    ),
                )
        except ValueError as exc:
            code = str(exc)
            raise error(
                409 if code == "idempotency_conflict" else 422,
                code,
                "Power run could not be created.",
            ) from exc
        finally:
            # The supplied map is required only while composing in-memory
            # providers. It is never placed in the manifest, event, run row,
            # workspace RPC, sandbox environment or tool runtime.
            body.provider_keys = {provider: SecretStr("") for provider in body.provider_keys}

        response.headers["Cache-Control"] = "no-store"
        return {
            "run_id": run["id"],
            "challenge_id": challenge["id"],
            "status": run["status"],
            "scope": {"target": "tcp" if target is not None else "offline"},
            "progress": {
                "console_url": f"/v1/runs/{run['id']}/console",
                "activity_stream_url": f"/v1/runs/{run['id']}/activity/stream",
            },
        }

    @app.post("/v1/archive-intakes/{intake_id}/triage")
    async def triage_archive_intake(
        intake_id: str,
        body: ArchiveTriageRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Call the configured provider once with metadata-only evidence."""

        # SecretStr avoids accidental representation in validation errors. The
        # key is extracted only at the provider boundary and cleared in finally;
        # it is never added to the receipt, DB, or event stream.
        api_key = ""
        provider_session = None
        try:
            if provider_factory is None:
                # Preserve the normal unknown-intake contract without ever
                # constructing a network transport. This is intentionally a
                # fail-closed host-development path, not a direct fallback.
                await request.app.state.archive_intakes.get_intake(intake_id)
                raise error(
                    503,
                    "archive_triage_provider_egress_unavailable",
                    "Archive triage egress is not configured for this runtime.",
                )
            api_key = body.api_key.get_secret_value()
            provider_session = provider_factory(body.provider)
            return await request.app.state.archive_intakes.run_triage(
                intake_id,
                backend=provider_session.backend,
                api_key=api_key,
                model=body.model,
                provider=provider_session.descriptor.id.value,
                output_contract=provider_session.descriptor.output_contract.value,
                max_output_tokens=body.max_output_tokens,
                timeout_seconds=body.timeout_seconds,
            )
        except ArchiveIntakeError as exc:
            raise error(
                archive_error_status(exc.code),
                exc.code,
                "Archive triage was rejected.",
            ) from exc
        except ProviderTriageError as exc:
            raise error(
                502,
                "archive_triage_provider_failed",
                "The provider did not return a usable triage result.",
                details={"provider_code": public_provider_error_code(exc.code)},
            ) from exc
        finally:
            # This does not scrub every Python allocation, but it prevents this
            # request-local values from retaining the credential any longer.
            # SecretStr is mutable here, so clear the parsed request object as
            # well before FastAPI releases it after the request lifecycle.
            api_key = ""
            body.api_key = SecretStr("")
            if provider_session is not None:
                try:
                    await provider_session.aclose()
                except Exception:
                    # Cleanup must not replace a result/error or surface a
                    # transport diagnostic after the request has ended. Drop
                    # the last local reference without logging it instead.
                    provider_session = None

    @app.post("/v1/archive-intakes/{intake_id}/triage/stream")
    async def stream_archive_intake_triage(
        intake_id: str,
        body: ArchiveTriageRequest,
        request: Request,
    ) -> StreamingResponse:
        """Stream code-owned triage checkpoints and one terminal event.

        The stream describes control-plane stages only. The API never forwards
        provider reasoning tokens, prompts, response bodies, credentials, raw
        flags, or archive excerpts to this channel.
        """

        if provider_factory is None:
            # Preserve the JSON endpoint's fail-closed status before streaming
            # headers begin, and release the parsed secret on every branch.
            try:
                await request.app.state.archive_intakes.get_intake(intake_id)
            except ArchiveIntakeError as exc:
                raise error(
                    archive_error_status(exc.code),
                    exc.code,
                    "Archive triage was rejected.",
                ) from exc
            finally:
                body.api_key = SecretStr("")
            raise error(
                503,
                "archive_triage_provider_egress_unavailable",
                "Archive triage egress is not configured for this runtime.",
            )
        # Capture the narrowed callable before entering the async generator.
        # The application factory is immutable for this app instance, while a
        # dedicated name prevents optional-state ambiguity inside `execute`.
        provider_session_factory = provider_factory

        # The plaintext value is retained only by this active response
        # generator. The request model is cleared before any stream frame is
        # emitted, and generator cancellation clears the final local reference.
        api_key = body.api_key.get_secret_value()
        body.api_key = SecretStr("")
        provider = body.provider
        model = body.model
        max_output_tokens = body.max_output_tokens
        timeout_seconds = body.timeout_seconds

        async def generate() -> AsyncIterator[str]:
            nonlocal api_key
            event_queue: asyncio.Queue[
                ArchiveTriageProgressEvent | ArchiveTriageResultEvent | ArchiveTriageErrorEvent
            ] = asyncio.Queue()
            sequence = 0

            async def emit_progress(stage: ArchiveTriageProgressStage) -> None:
                nonlocal sequence
                sequence += 1
                await event_queue.put(
                    ArchiveTriageProgressEvent(
                        sequence=sequence,
                        stage=stage,
                        summary=_ARCHIVE_TRIAGE_PROGRESS_SUMMARIES[stage],
                    )
                )

            async def execute() -> None:
                nonlocal api_key, sequence
                provider_session: ArchiveTriageProviderSession | None = None
                terminal: ArchiveTriageResultEvent | ArchiveTriageErrorEvent | None = None
                try:
                    await emit_progress(ArchiveTriageProgressStage.REQUEST_ACCEPTED)
                    provider_session = provider_session_factory(provider)
                    result = await request.app.state.archive_intakes.run_triage(
                        intake_id,
                        backend=provider_session.backend,
                        api_key=api_key,
                        model=model,
                        provider=provider_session.descriptor.id.value,
                        output_contract=provider_session.descriptor.output_contract.value,
                        max_output_tokens=max_output_tokens,
                        timeout_seconds=timeout_seconds,
                        progress=emit_progress,
                    )
                    sequence += 1
                    terminal = ArchiveTriageResultEvent(sequence=sequence, intake=result)
                except asyncio.CancelledError:
                    raise
                except ArchiveIntakeError as exc:
                    sequence += 1
                    terminal = ArchiveTriageErrorEvent(
                        sequence=sequence,
                        code=exc.code,
                        message="Archive triage was rejected.",
                    )
                except ProviderTriageError as exc:
                    sequence += 1
                    terminal = ArchiveTriageErrorEvent(
                        sequence=sequence,
                        code="archive_triage_provider_failed",
                        message="The provider did not return a usable triage result.",
                        provider_code=public_provider_error_code(exc.code),
                    )
                except Exception:
                    # Streaming headers already started, so return one generic
                    # terminal frame without reflecting the causal exception.
                    sequence += 1
                    terminal = ArchiveTriageErrorEvent(
                        sequence=sequence,
                        code="archive_triage_internal_error",
                        message="Archive triage failed safely.",
                    )
                finally:
                    api_key = ""
                    if provider_session is not None:
                        with suppress(Exception):
                            async with asyncio.timeout(2):
                                await provider_session.aclose()
                    if terminal is not None:
                        await event_queue.put(terminal)

            execution = asyncio.create_task(execute())
            try:
                while not await request.is_disconnected():
                    try:
                        event = await asyncio.wait_for(event_queue.get(), timeout=0.25)
                    except TimeoutError:
                        continue
                    yield archive_triage_stream_line(event)
                    if isinstance(event, ArchiveTriageResultEvent | ArchiveTriageErrorEvent):
                        await execution
                        break
            finally:
                if not execution.done():
                    execution.cancel()
                with suppress(asyncio.CancelledError):
                    await execution
                api_key = ""

        return StreamingResponse(
            generate(),
            media_type="application/x-ndjson",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/v1/challenges/{challenge_id}")
    async def get_challenge(challenge_id: str, request: Request) -> dict[str, Any]:
        challenge = await request.app.state.repository.get_challenge(challenge_id)
        if challenge is None:
            raise error(404, "challenge_not_found", "Challenge does not exist.")
        return challenge

    @app.get("/v1/hint-templates")
    async def get_hint_templates() -> dict[str, list[dict[str, Any]]]:
        """Expose only checked-in reviewed HintTemplate metadata."""

        return {"items": [template.model_dump(mode="json") for template in hint_templates()]}

    @app.post("/v1/runs", status_code=201)
    async def create_run(body: CreateRunRequest, request: Request) -> dict[str, Any]:
        # An explicit retry key is separate from correlation/tracing. Legacy
        # callers still get a safe per-request default, but a client retry can
        # use this header after a transport failure without duplicating a run.
        explicit_idempotency_key = request.headers.get("idempotency-key")
        if explicit_idempotency_key is not None and not _IDEMPOTENCY_KEY.fullmatch(
            explicit_idempotency_key
        ):
            raise error(
                422,
                "invalid_idempotency_key",
                "Idempotency-Key must be a safe 1–200 character identifier.",
            )
        idempotency_key = explicit_idempotency_key or f"run-start:{request.state.correlation_id}"
        try:
            return await request.app.state.run_engine.start(
                challenge_id=body.challenge_id,
                mode=body.mode.value,
                provider=body.provider,
                budget=body.budget.model_dump(),
                idempotency_key=idempotency_key,
            )
        except ValueError as exc:
            code = str(exc)
            status_code = 404 if code == "challenge_not_found" else 422
            if code == "idempotency_conflict":
                status_code = 409
            raise error(status_code, code, "Run could not be created.") from exc

    @app.get("/v1/runs")
    async def list_runs(
        request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 50
    ) -> dict[str, Any]:
        return {"items": await request.app.state.repository.list_runs(limit=limit)}

    @app.get("/v1/runs/{run_id}")
    async def get_run(run_id: str, request: Request) -> dict[str, Any]:
        run = await request.app.state.repository.get_run(run_id)
        if run is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return run

    @app.post("/v1/runs/{run_id}/flag-reveal")
    async def reveal_verified_remote_flag(
        run_id: str,
        body: CandidateRevealRequest,
        request: Request,
        response: Response,
    ) -> dict[str, str | bool]:
        """Reveal a remote flag once, only after durable independent proof."""

        if not body.confirm:
            raise error(
                422,
                "verified_flag_reveal_confirmation_required",
                "Explicit confirmation is required before revealing a verified flag.",
            )
        run = await request.app.state.repository.get_run(run_id)
        if run is None:
            raise error(404, "run_not_found", "Run does not exist.")
        if run["status"] != "solved":
            raise error(
                409,
                "verified_flag_reveal_not_solved",
                "A flag can be revealed only after independent verification succeeds.",
            )
        try:
            flag = await request.app.state.verified_flag_reveals.consume(run_id=run_id)
        except VerifiedFlagRevealError as exc:
            raise error(
                410,
                exc.code,
                "The one-time verified flag lease is unavailable. Start a new verified run.",
            ) from exc
        response.headers["Cache-Control"] = "no-store"
        return {"flag": flag, "one_time": True}

    @app.get("/v1/runs/{run_id}/hints")
    async def get_run_hints(run_id: str, request: Request) -> dict[str, list[dict[str, Any]]]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_hint_cards(run_id)}

    @app.post("/v1/runs/{run_id}/hints", status_code=201)
    async def create_run_hint(
        run_id: str,
        body: HintCardCreateRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Attach a reviewed human hypothesis; it cannot add a new capability."""

        template = hint_template(body.template_id)
        if template is None:
            raise error(
                422,
                "hint_template_not_found",
                "Hint template is not in the reviewed catalog.",
            )
        idempotency_key = required_idempotency_key(request)
        now = datetime.now(UTC)
        try:
            card = HintCard(
                id=f"hint_{uuid4().hex}",
                run_id=run_id,
                template_id=template.id,
                template_version=template.version,
                technique_id=template.technique_id,
                category=template.category,
                directive=body.directive or template.default_directive,
                target_ref=body.target_ref,
                priority=body.priority,
                note=body.note,
                actor_id="local-user",
                created_at=now,
                updated_at=now,
            )
            return await request.app.state.repository.create_hint_card(
                card,
                template=template,
                idempotency_key=idempotency_key,
            )
        except (ValidationError, ValueError) as exc:
            # Pydantic's formatted validation text can echo the submitted
            # note. Never return it: notes may accidentally contain a flag or
            # credential even though the domain contract rejects them.
            if isinstance(exc, ValidationError):
                raise error(422, "hint_card_invalid", "Hint Card fields are invalid.") from exc
            code = str(exc)
            if code == "run_not_found":
                raise error(404, code, "Run does not exist.") from exc
            status = (
                422
                if code
                in {
                    "hint_note_contains_secret",
                    "hint_template_card_mismatch",
                    "hint_card_initial_status_invalid",
                }
                else 409
            )
            raise error(status, code, "Hint Card could not be attached.") from exc

    @app.patch("/v1/runs/{run_id}/hints/{hint_id}")
    async def patch_run_hint(
        run_id: str,
        hint_id: str,
        body: HintCardPatchRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Edit guidance fields only; lifecycle evidence remains kernel-owned."""

        idempotency_key = required_idempotency_key(request)
        existing = next(
            (
                item
                for item in await request.app.state.repository.list_hint_cards(run_id)
                if item["id"] == hint_id
            ),
            None,
        )
        if existing is None:
            if await request.app.state.repository.get_run(run_id) is None:
                raise error(404, "run_not_found", "Run does not exist.")
            raise error(404, "hint_card_not_found", "Hint Card does not exist.")
        template = hint_template(str(existing["template_id"]))
        if template is None:
            raise error(
                409,
                "hint_template_not_found",
                "Stored Hint Card has no reviewed template.",
            )
        try:
            return await request.app.state.repository.update_hint_card(
                run_id,
                hint_id,
                directive=body.directive or HintDirective(str(existing["directive"])),
                target_ref=(
                    body.target_ref if body.target_ref is not None else str(existing["target_ref"])
                ),
                priority=body.priority if body.priority is not None else int(existing["priority"]),
                note=body.note if body.note is not None else str(existing["note"]),
                template=template,
                idempotency_key=idempotency_key,
                actor_id="local-user",
            )
        except (ValidationError, ValueError) as exc:
            if isinstance(exc, ValidationError):
                raise error(422, "hint_card_invalid", "Hint Card fields are invalid.") from exc
            code = str(exc)
            if code in {"run_not_found", "hint_card_not_found"}:
                raise error(404, code, "Hint Card is unavailable.") from exc
            status = (
                422 if code in {"hint_note_contains_secret", "hint_template_card_mismatch"} else 409
            )
            raise error(status, code, "Hint Card could not be updated.") from exc

    @app.delete("/v1/runs/{run_id}/hints/{hint_id}")
    async def delete_run_hint(run_id: str, hint_id: str, request: Request) -> dict[str, Any]:
        """Soft-dismiss guidance while retaining the append-only audit trail."""

        idempotency_key = required_idempotency_key(request)
        try:
            return await request.app.state.repository.dismiss_hint_card(
                run_id,
                hint_id,
                idempotency_key=idempotency_key,
                actor_id="local-user",
            )
        except ValueError as exc:
            code = str(exc)
            if code in {"run_not_found", "hint_card_not_found"}:
                raise error(404, code, "Hint Card is unavailable.") from exc
            raise error(409, code, "Hint Card could not be dismissed.") from exc

    @app.get("/v1/runs/{run_id}/branches")
    async def get_run_branches(run_id: str, request: Request) -> dict[str, list[dict[str, Any]]]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_run_branches(run_id)}

    @app.get("/v1/runs/{run_id}/events")
    async def get_events(
        run_id: str,
        request: Request,
        after: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        items = await request.app.state.repository.list_events(run_id, after=after, limit=limit)
        return {
            "items": items,
            "next_cursor": items[-1]["sequence"] if items else after,
        }

    @app.get("/v1/runs/{run_id}/blackboard")
    async def get_blackboard(run_id: str, request: Request) -> dict[str, Any]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return await request.app.state.repository.blackboard(run_id)

    @app.get("/v1/runs/{run_id}/artifacts")
    async def get_artifacts(run_id: str, request: Request) -> dict[str, Any]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_artifacts(run_id)}

    @app.get("/v1/runs/{run_id}/agent-sessions")
    async def get_agent_sessions(run_id: str, request: Request) -> dict[str, Any]:
        """Expose lifecycle metadata only; transcript and credentials stay runner-local."""

        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_agent_sessions(run_id)}

    @app.get("/v1/runs/{run_id}/verifications")
    async def get_verifications(run_id: str, request: Request) -> dict[str, Any]:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_verifications(run_id)}

    @app.get("/v1/runs/{run_id}/candidates")
    async def get_exploit_candidates(run_id: str, request: Request) -> dict[str, Any]:
        """Expose verification lifecycle without exposing candidate plan bodies."""

        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_exploit_candidates(run_id)}

    async def transition(run_id: str, request: Request, state: str) -> dict[str, Any]:
        try:
            return await request.app.state.repository.transition_run(
                run_id,
                state,
                actor={"kind": "human", "id": "local-user"},
                reason=f"human_{state}",
                idempotency_key=f"transition:{request.state.correlation_id}",
            )
        except ValueError as exc:
            code = str(exc)
            if code == "run_not_found":
                raise error(404, code, "Run does not exist.") from exc
            raise error(409, "invalid_run_transition", code) from exc

    @app.post("/v1/runs/{run_id}/pause")
    async def pause_run(run_id: str, request: Request) -> dict[str, Any]:
        return await transition(run_id, request, "paused")

    @app.post("/v1/runs/{run_id}/resume")
    async def resume_run(run_id: str, request: Request) -> dict[str, Any]:
        return await transition(run_id, request, "running")

    @app.post("/v1/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, request: Request, response: Response) -> dict[str, Any]:
        # A live Pi session is aborted only by its runner at an explicit queue
        # boundary. Pre-session runs retain the synchronous transition because
        # there is no session process to stop yet.
        # The Power controller first queues durable Power-abort jobs and
        # cleanup. The generic Pi jobs below belong to the v0.1 layout;
        # neither request handler reaches into a live session.
        power_runs: PowerRunController | None = request.app.state.power_runs
        if power_runs is not None:
            await power_runs.cancel(run_id)
        try:
            abort_jobs = await request.app.state.repository.request_pi_abort(
                run_id,
                idempotency_key=f"pi-abort:{request.state.correlation_id}",
                requested_by="local-user",
            )
        except ValueError as exc:
            code = str(exc)
            if code == "run_not_found":
                raise error(404, code, "Run does not exist.") from exc
            raise error(409, code, "Run cancellation could not be requested.") from exc
        if abort_jobs:
            response.status_code = 202
            return {
                "accepted": True,
                "status": "cancellation_requested",
                # M4 can have a master and up to two bounded worker sessions.
                # Every live session gets its own abort job; no request handler
                # ever reaches into Pi directly.
                "agent_job_ids": [job["id"] for job in abort_jobs],
            }
        return {"accepted": True, "status": "cancelled", "agent_job_ids": []}

    @app.post("/v1/runs/{run_id}/steer", status_code=202)
    async def steer_run(run_id: str, body: SteeringRequest, request: Request) -> dict[str, Any]:
        # Do not put operator prose into the public event stream. The kernel
        # makes a sanitized request runnable only after Pi is at an idle safe
        # boundary.
        try:
            steer = await request.app.state.repository.queue_agent_steer(
                run_id,
                message=body.message,
                idempotency_key=f"steer:{request.state.correlation_id}",
                requested_by="local-user",
            )
        except ValueError as exc:
            code = str(exc)
            if code == "run_not_found":
                raise error(404, code, "Run does not exist.") from exc
            raise error(409, code, "Steering could not be queued.") from exc
        return {
            "accepted": True,
            "steer_id": steer["id"],
            "state": steer["state"],
            "message_sha256": steer["message_digest"],
        }

    @app.get("/v1/runs/{run_id}/power-sessions")
    async def get_power_sessions(run_id: str, request: Request) -> dict[str, Any]:
        """Show credential-free Power Pi session state for the operator desk."""

        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")
        return {"items": await request.app.state.repository.list_power_pi_sessions(run_id)}

    @app.post("/v1/runs/{run_id}/power-sessions/{session_id}/steer", status_code=202)
    async def steer_power_session(
        run_id: str,
        session_id: str,
        body: SteeringRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Queue one safe-boundary steer for one named Power Pi session."""

        try:
            steer = await request.app.state.repository.queue_power_pi_steer(
                run_id,
                session_id=session_id,
                message=body.message,
                idempotency_key=required_idempotency_key(request),
                requested_by="local-user",
            )
        except ValueError as exc:
            code = str(exc)
            if code == "run_not_found":
                raise error(404, code, "Run does not exist.") from exc
            raise error(409, code, "Power steering could not be queued.") from exc
        return {
            "accepted": True,
            "steer_id": steer["id"],
            "state": steer["state"],
            "message_sha256": steer["message_digest"],
        }

    @app.get("/v1/runs/{run_id}/console")
    async def console_snapshot(run_id: str, request: Request) -> dict[str, Any]:
        from ctfmesh_orchestrator import build_console_snapshot

        try:
            return await build_console_snapshot(request.app.state.repository, run_id)
        except ValueError as exc:
            raise error(404, "run_not_found", "Run does not exist.") from exc

    @app.get("/v1/runs/{run_id}/events/stream")
    async def stream_events(
        run_id: str,
        request: Request,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> StreamingResponse:
        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")

        async def generate() -> AsyncIterator[str]:
            cursor = after
            idle_cycles = 0
            while idle_cycles < 150 and not await request.is_disconnected():
                events = await request.app.state.repository.list_events(
                    run_id, after=cursor, limit=100
                )
                if events:
                    idle_cycles = 0
                    for event in events:
                        cursor = event["sequence"]
                        yield f"id: {cursor}\nevent: {event['type']}\ndata: {json.dumps(event)}\n\n"
                else:
                    idle_cycles += 1
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.2)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/v1/runs/{run_id}/activity/stream")
    async def stream_safe_activity(
        run_id: str,
        request: Request,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> StreamingResponse:
        """Stream only reviewed progress vocabulary for the operator desk."""

        if await request.app.state.repository.get_run(run_id) is None:
            raise error(404, "run_not_found", "Run does not exist.")

        async def generate() -> AsyncIterator[str]:
            cursor = after
            idle_cycles = 0
            while idle_cycles < 150 and not await request.is_disconnected():
                events = await request.app.state.repository.list_events(
                    run_id, after=cursor, limit=100
                )
                if events:
                    idle_cycles = 0
                    for event in events:
                        sequence = event.get("sequence")
                        if isinstance(sequence, int) and not isinstance(sequence, bool):
                            cursor = sequence
                        activity = run_activity_event(event)
                        if activity is not None:
                            yield (
                                f"id: {activity['sequence']}\nevent: activity\n"
                                f"data: {json.dumps(activity, separators=(',', ':'))}\n\n"
                            )
                else:
                    idle_cycles += 1
                    yield ": keepalive\n\n"
                await asyncio.sleep(0.2)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.websocket("/v1/runs/{run_id}/stream")
    async def websocket_events(websocket: WebSocket, run_id: str) -> None:
        if await websocket.app.state.repository.get_run(run_id) is None:
            await websocket.close(code=4404, reason="run_not_found")
            return
        await websocket.accept()
        try:
            cursor_text = websocket.query_params.get("after", "0")
            cursor = max(0, int(cursor_text))
            while True:
                events = await websocket.app.state.repository.list_events(
                    run_id, after=cursor, limit=100
                )
                for event in events:
                    cursor = event["sequence"]
                    await websocket.send_json(event)
                await asyncio.sleep(0.2)
        except (WebSocketDisconnect, ValueError):
            return

    return app
