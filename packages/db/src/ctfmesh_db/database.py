"""Async database and transactional repository implementation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from urllib.parse import urlsplit
from uuid import uuid4

from ctfmesh_domain import (
    AgentBridgeEvent,
    AgentJobKind,
    AgentRole,
    AgentSession,
    AgentSessionState,
    ChallengeManifest,
    ContextBudgetSlice,
    ContextEvidenceRef,
    ContextManifest,
    ExploitCandidateSubmission,
    ExploitPlanV1,
    FindingSubmission,
    HintCard,
    HintCategory,
    HintDirective,
    HintOutcome,
    HintStatus,
    HintTemplate,
    PreflightObservation,
    RuntimeArtifact,
    RuntimeTask,
    TaskDelegationRequest,
    ToolExecutionAuthority,
    ToolInvocation,
    ToolInvocationRequest,
    ToolInvocationState,
    VerifierCompletionV1,
    agent_role_tool_ids,
)
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import (
    AgentJobRow,
    AgentSessionRow,
    AgentSteerRow,
    ArtifactRow,
    Base,
    BudgetLedgerRow,
    ChallengeRow,
    ContextManifestRow,
    EventRow,
    ExperimentRow,
    ExploitCandidateRow,
    FactRow,
    HintCardRow,
    HypothesisRow,
    IdempotencyRecordRow,
    OutboxRow,
    PowerPiSessionRow,
    PowerPiSteerRow,
    PreflightObservationRow,
    RunBranchRow,
    RunRow,
    RunSequenceRow,
    ToolInvocationRow,
    VerificationAttemptRow,
    VerificationRow,
    WorkerTaskRow,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def canonical_json(value: Mapping[str, Any] | list[Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def digest_json(value: Mapping[str, Any] | list[Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_:-]{0,159}$")
_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_API_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "raw_flag",
        "secret",
        "token",
    }
)
_SAFE_SECRET_METADATA_KEYS = frozenset({"flag_sha256", "masked_flag"})
_ACTOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ACTOR_KINDS = frozenset({"human", "worker", "system", "tool", "verifier", "service"})
_MAX_EVENT_PAYLOAD_BYTES = 1024 * 1024
_MAX_CONTEXT_MANIFEST_BYTES = 256 * 1024
_MAX_LEASE_SECONDS = 3600
_RUNTIME_JOB_KINDS = frozenset(kind.value for kind in AgentJobKind)
_PI_AGENT_JOB_KINDS = frozenset(
    {
        AgentJobKind.START_SESSION.value,
        AgentJobKind.RUN_TURN.value,
        AgentJobKind.STEER.value,
        AgentJobKind.ABORT.value,
        AgentJobKind.DISPOSE.value,
    }
)
_PI_START_OR_TURN_JOB_KINDS = frozenset(
    {
        AgentJobKind.START_SESSION.value,
        AgentJobKind.RUN_TURN.value,
        AgentJobKind.STEER.value,
    }
)
_PI_TEARDOWN_JOB_KINDS = frozenset({AgentJobKind.ABORT.value, AgentJobKind.DISPOSE.value})
_POWER_PI_JOB_KINDS = frozenset(
    {
        AgentJobKind.POWER_SESSION_START.value,
        AgentJobKind.POWER_STEER.value,
        AgentJobKind.POWER_ABORT.value,
    }
)
_POWER_PI_RUNNABLE_JOB_KINDS = frozenset(
    {AgentJobKind.POWER_SESSION_START.value, AgentJobKind.POWER_STEER.value}
)
_POWER_PI_TEARDOWN_JOB_KINDS = frozenset({AgentJobKind.POWER_ABORT.value})
_POWER_PI_ROLES = frozenset({"autoprompter", "racer"})
_POWER_PI_SESSION_STATES = frozenset(
    {"starting", "ready", "running", "aborting", "aborted", "failed"}
)
_POWER_PI_PROVIDERS = frozenset({"openai", "google", "deepseek"})
_POWER_PI_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_POWER_PI_WORKSPACE_ID = re.compile(r"^ws_[0-9a-f]{32}$")
_HINT_ACTIVE_STATUS = HintStatus.ACTIVE.value
_MAX_ACTIVE_WORKER_BRANCHES = 2
_STALL_TURN_THRESHOLD = 2
_CONTEXT_REF = re.compile(r"^context:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_SESSION_REF = re.compile(r"^session:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_STEER_REF = re.compile(r"^steer:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_CANDIDATE_REF = re.compile(r"^candidate:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_TOOL_INVOCATION_REF = re.compile(r"^tool:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_POWER_SESSION_REF = re.compile(r"^power-session:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
_POWER_STEER_REF = re.compile(r"^power-steer:([A-Za-z0-9][A-Za-z0-9_.:-]{0,159})$")
# M5 deliberately has a closed set of local Web labs.  Keep this mapping in
# the persistence boundary so a model cannot bind a reviewed technique to a
# different manifest/lab merely by submitting an otherwise valid plan.
_M5_LAB_TECHNIQUES = {
    "web.path_traversal": "web-path-traversal",
    "web.authz_boundary": "web-authz-boundary",
    "web.sqli_basic": "web-sqli-basic",
}
_M5_LAB_TARGETS = {
    "web-path-traversal": ("lab-path-traversal", "http://lab-path-traversal:8080"),
    "web-authz-boundary": ("lab-authz-boundary", "http://lab-authz-boundary:8080"),
    "web-sqli-basic": ("lab-sqli-basic", "http://lab-sqli-basic:8080"),
}
_M5_REPLAY_COUNT = 2
_M5_LAB_TARGET_DIGESTS = {
    lab_id: hashlib.sha256(f"ctfmesh.m5.lab-target.v1:{lab_id}".encode()).hexdigest()
    for lab_id in _M5_LAB_TECHNIQUES.values()
}


@dataclass(frozen=True, slots=True)
class PowerPiSessionSpec:
    """Trusted, non-secret session provisioned by the Power composition root.

    The identifier and workspace are created before this reaches persistence.
    That eliminates a queue race where Pi could claim a start job before its
    disposable workspace existed.  Keys intentionally never appear here.
    """

    id: str
    label: str
    role: str
    provider: str
    model: str
    temperature: float
    workspace_id: str


_M6_UI_MANIFEST_NAME = re.compile(r"^ui-[0-9a-f]{32}$")
_M6_UI_TOOL_PROFILE = (
    "source.list",
    "source.read",
    "source.search",
    "source.manifest",
    "artifacts.inspect",
    "transform.apply",
    "http.request",
)
_M6_UI_SKILL_PROFILE = ("web.triage",)
# Wall time is charged in fixed buckets so concurrent racers never disagree on
# the amount behind one idempotency key.  Five seconds keeps a minute-scale cap
# accurate enough while making a collision a replay instead of a conflict.
_WALL_TIME_BUCKET_SECONDS = 5.0
_WALL_TIME_MAX_BUCKETS_PER_CALL = 512

_BUDGET_DIMENSIONS = frozenset(
    {"wall_time_seconds", "max_tool_calls", "max_http_requests", "max_cost_usd"}
)
_RUN_TRANSITIONS = {
    "created": {"preparing", "cancelled"},
    "preparing": {"running", "failed", "cancelled"},
    "running": {
        "paused",
        "verifying",
        "completed",
        "failed",
        "cancelled",
        "budget_exhausted",
    },
    "paused": {"running", "cancelled"},
    "verifying": {"running", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
    "budget_exhausted": set(),
    "solved": set(),
}


def _is_supported_m5_lab_manifest(manifest: ChallengeManifest, technique_id: str) -> bool:
    """Pin M5 candidates to one code-reviewed local target profile.

    The replay worker intentionally receives no operator-controlled target
    URL. Requiring this exact manifest shape also prevents a Pi turn from
    observing one target and submitting a plan later rebound to a different
    M5 lab merely by reusing a technique identifier.
    """

    lab_id = _M5_LAB_TECHNIQUES.get(technique_id)
    if lab_id is None or manifest.metadata.name != lab_id:
        return False
    profile = _M5_LAB_TARGETS.get(lab_id)
    if profile is None:
        return False
    service, origin = profile
    target = manifest.spec.target
    healthcheck = target.healthcheck
    if len(target.allowed_endpoints) != 1:
        return False
    endpoint = target.allowed_endpoints[0]
    return (
        target.type == "docker_compose"
        and target.compose_file == "docker-compose.yml"
        and target.service == service
        and target.reset_url is None
        and healthcheck is not None
        and healthcheck.url == f"{origin}/health"
        and healthcheck.expected_status == 200
        and target.target_aliases == {"lab": origin}
        and endpoint.host == service
        and tuple(endpoint.ports) == (8080,)
        and tuple(endpoint.protocols) == ("http",)
        and manifest.spec.flag.replay_count == _M5_REPLAY_COUNT
        and manifest.spec.flag.source_policy.allow_from_target_response
        and not manifest.spec.flag.source_policy.allow_from_target_filesystem
    )


def _is_supported_m6_exact_instance_manifest(
    manifest: ChallengeManifest,
    technique_id: str,
) -> bool:
    """Recognize only the code-owned, assisted remote replay profile.

    The remote verifier receives the sealed origin only after this complete
    shape check. This prevents a hand-authored generic remote manifest from
    turning the independent verifier into an unrestricted HTTP client.
    """

    if technique_id not in _M5_LAB_TECHNIQUES:
        return False
    source = manifest.spec.source
    target = manifest.spec.target
    healthcheck = target.healthcheck
    if source is None or _M6_UI_MANIFEST_NAME.fullmatch(manifest.metadata.name) is None:
        return False
    if tuple(manifest.metadata.tags) != ("ui-exact-instance", "source-available"):
        return False
    if (
        manifest.spec.mode.value != "assisted"
        or target.type != "remote"
        or target.compose_file is not None
        or target.service is not None
        or target.reset_url is not None
        or len(target.allowed_endpoints) != 1
        or set(target.target_aliases) != {"target"}
        or healthcheck is None
        or tuple(manifest.spec.tool_profile) != _M6_UI_TOOL_PROFILE
        or tuple(manifest.spec.skill_profile) != _M6_UI_SKILL_PROFILE
        or len(manifest.spec.artifacts) != 1
        or manifest.spec.artifacts[0].path != "archive.bin"
        or manifest.spec.artifacts[0].role.value != "source"
        or manifest.spec.flag.replay_count != _M5_REPLAY_COUNT
        or not manifest.spec.flag.source_policy.allow_from_target_response
        or manifest.spec.flag.source_policy.allow_from_target_filesystem
        or manifest.spec.memory.internet_search
    ):
        return False
    origin = target.target_aliases["target"]
    try:
        parsed = urlsplit(origin)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    endpoint = target.allowed_endpoints[0]
    return (
        healthcheck.url == f"{origin}/"
        and healthcheck.expected_status == 200
        and parsed.hostname is not None
        and endpoint.permits(protocol=parsed.scheme, host=parsed.hostname, port=port)
        and source.slot_id in {"source-slot-1", "source-slot-2"}
    )


def _verification_manifest_profile(
    manifest: ChallengeManifest,
    technique_id: str,
) -> Literal["m5", "m6-ui"] | None:
    """Choose a reviewed replay profile without giving a candidate a choice."""

    if _is_supported_m5_lab_manifest(manifest, technique_id):
        return "m5"
    if _is_supported_m6_exact_instance_manifest(manifest, technique_id):
        return "m6-ui"
    return None


def _candidate_technique_is_reviewed(
    manifest: ChallengeManifest,
    *,
    task_technique_id: str,
    plan_technique_id: str,
) -> bool:
    """Bind a plan to a task without making M6's initial review unusable.

    M5 stays one technique per task. M6.a begins with a deliberately neutral
    ``general.review`` task so the browser does not assert a bug class before
    source inspection. That exact code-owned profile may submit one of the
    three review-approved Web plans after the same strict manifest validation
    that selects the remote verifier. A hinted/specific task remains bound to
    its one declared technique.
    """

    profile = _verification_manifest_profile(manifest, plan_technique_id)
    if profile is None:
        return False
    return task_technique_id == plan_technique_id or (
        profile == "m6-ui"
        and task_technique_id == "general.review"
        and plan_technique_id in _M5_LAB_TECHNIQUES
    )


def _m6_remote_origin_digest(origin: str) -> str:
    """Bind a remote verifier proof to the exact canonical manifest origin."""

    return hashlib.sha256(f"ctfmesh.m6.remote-origin.v1:{origin}".encode()).hexdigest()


def _is_secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in _SAFE_SECRET_METADATA_KEYS:
        return False
    parts = set(normalized.split("_"))
    return normalized in _SECRET_KEYS or bool(parts & _SECRET_KEYS)


def _redact_text(value: str) -> str:
    value = _RAW_FLAG.sub("[REDACTED_FLAG]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    return _API_KEY.sub("[REDACTED_API_KEY]", value)


def redact_event_payload(value: Any, *, key: str | None = None) -> Any:
    """Return a JSON-compatible copy safe for append-only traces."""

    if key is not None and _is_secret_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): redact_event_payload(child, key=str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_event_payload(child) for child in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _contains_plaintext_secret(value: Any, *, key: str | None = None) -> bool:
    if key is not None and _is_secret_key(key):
        return not (
            value is None
            or isinstance(value, str)
            and value.lower() in {"", "[redacted]", "<redacted>"}
        )
    if isinstance(value, dict):
        return any(
            _contains_plaintext_secret(child, key=str(child_key))
            for child_key, child in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_plaintext_secret(child) for child in value)
    return isinstance(value, str) and bool(
        _RAW_FLAG.search(value) or _BEARER.search(value) or _API_KEY.search(value)
    )


def _validate_run_budget(budget: dict[str, Any], manifest: dict[str, Any]) -> None:
    limit_values = manifest.get("spec", {}).get("limits", {})
    required = ("wall_time_seconds", "max_tool_calls", "max_http_requests", "max_cost_usd")
    if any(key not in budget for key in required):
        raise ValueError("bounded_run_budget_required")
    for key in required:
        value = budget[key]
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"invalid_budget:{key}")
        if not math.isfinite(float(value)) or value <= 0:
            raise ValueError(f"invalid_budget:{key}")
        manifest_limit = limit_values.get(key)
        if isinstance(manifest_limit, int | float) and value > manifest_limit:
            raise ValueError(f"budget_exceeds_manifest:{key}")
    unknown = set(budget) - set(required)
    if unknown:
        raise ValueError(f"unknown_budget_fields:{','.join(sorted(unknown))}")


def _validate_actor(actor: dict[str, str]) -> None:
    if not isinstance(actor, dict) or set(actor) != {"kind", "id"}:
        raise ValueError("invalid_event_actor")
    kind = actor["kind"]
    actor_id = actor["id"]
    if (
        not isinstance(kind, str)
        or kind not in _ACTOR_KINDS
        or not isinstance(actor_id, str)
        or not _ACTOR_ID.fullmatch(actor_id)
    ):
        raise ValueError("invalid_event_actor")


def _validate_idempotency_key(value: str) -> None:
    if not value.strip() or len(value) > 200:
        raise ValueError("invalid_idempotency_key")


def _validate_lease_owner(value: str) -> None:
    if not _ACTOR_ID.fullmatch(value):
        raise ValueError("invalid_lease_owner")


def _validate_runtime_failure_code(value: str) -> None:
    if not _RUNTIME_FAILURE_CODE.fullmatch(value):
        raise ValueError("invalid_runtime_failure_code")


def _require_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(UTC)


def _stored_utc(value: datetime) -> datetime:
    """Normalize a value read from a database driver without weakening inputs.

    PostgreSQL preserves the offset for ``DateTime(timezone=True)``. SQLite
    stores UTC text without one, so SQLAlchemy returns a naïve value there.
    Every repository write already originates from ``utc_now`` or a validated
    aware input; treating a SQLite read as UTC keeps lease checks portable.
    """

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_runtime_reference(value: str | None, pattern: re.Pattern[str], code: str) -> str:
    """Read one typed internal reference without accepting a filesystem/URL path."""

    if not isinstance(value, str):
        raise ValueError(code)
    match = pattern.fullmatch(value)
    if match is None:
        raise ValueError(code)
    return match.group(1)


def _event_chain_hash(
    *,
    previous_hash: str,
    payload: bytes,
    metadata: Mapping[str, Any],
) -> str:
    """Hash immutable event metadata and canonical payload into one run chain."""

    return hashlib.sha256(
        previous_hash.encode("ascii") + b"\x00" + payload + b"\x00" + canonical_json(dict(metadata))
    ).hexdigest()


class DatabaseUnavailableError(RuntimeError):
    """Stable, secret-free health-check failure exposed to the control plane."""


class Database:
    """Owns the SQLAlchemy engine without leaking it into the domain package."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.engine: AsyncEngine = create_async_engine(url, echo=echo, pool_pre_ping=True)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    async def create_schema(self) -> None:
        """Bootstrap an empty schema for tests and the local development profile.

        Deployed environments must run ``alembic -c packages/db/alembic.ini
        upgrade head`` before starting the API. Keeping this small bootstrap
        avoids making unit tests depend on an external migration command while
        making the production migration boundary explicit.
        """
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            # Unit/local SQLite bootstraps intentionally bypass Alembic, so
            # install the same append-only guard the 0002 migration creates.
            # PostgreSQL deployments receive its equivalent trigger from
            # Alembic before this helper is ever called.
            if connection.dialect.name == "sqlite":
                await connection.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS run_events_no_update
                        BEFORE UPDATE ON run_events
                        BEGIN
                            SELECT RAISE(ABORT, 'run_events_append_only');
                        END
                        """
                    )
                )
                await connection.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS run_events_no_delete
                        BEFORE DELETE ON run_events
                        BEGIN
                            SELECT RAISE(ABORT, 'run_events_append_only');
                        END
                        """
                    )
                )

    async def drop_schema(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)

    async def ping(self) -> None:
        try:
            async with self.sessions() as session:
                await session.execute(text("SELECT 1"))
        except (SQLAlchemyError, OSError) as exc:
            raise DatabaseUnavailableError("database_unavailable") from exc

    async def close(self) -> None:
        await self.engine.dispose()


class Repository:
    """Transactional event + projection repository.

    Per-run locks make the SQLite development profile deterministic. PostgreSQL
    additionally obtains a row lock on ``run_sequences`` for cross-process
    sequence allocation.
    """

    def __init__(self, database: Database) -> None:
        self.database = database
        self._run_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._challenge_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._start_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._job_claim_lock = asyncio.Lock()
        self._task_claim_lock = asyncio.Lock()
        # SQLite does not implement row-level ``FOR UPDATE`` locks. This
        # guard makes tool reservation deterministic in the local profile;
        # PostgreSQL also locks the run row below for cross-process safety.
        self._tool_reservation_lock = asyncio.Lock()

    async def create_challenge(self, manifest: dict[str, Any], *, name: str) -> dict[str, Any]:
        digest = digest_json(manifest)
        if not name.strip():
            raise ValueError("challenge_name_required")
        async with self._challenge_locks[digest]:
            try:
                async with self.database.sessions() as session, session.begin():
                    existing = await session.scalar(
                        select(ChallengeRow).where(ChallengeRow.digest == digest)
                    )
                    if existing is not None:
                        return self._challenge(existing)
                    row = ChallengeRow(
                        id=new_id("challenge"),
                        name=name,
                        manifest=manifest,
                        digest=digest,
                        created_at=utc_now(),
                    )
                    session.add(row)
                return self._challenge(row)
            except IntegrityError:
                # A second process may have committed the same content digest
                # after our initial read. Resolve that race idempotently.
                async with self.database.sessions() as session:
                    existing = await session.scalar(
                        select(ChallengeRow).where(ChallengeRow.digest == digest)
                    )
                    if existing is None:
                        raise
                    return self._challenge(existing)

    async def get_challenge(self, challenge_id: str) -> dict[str, Any] | None:
        async with self.database.sessions() as session:
            row = await session.get(ChallengeRow, challenge_id)
            return None if row is None else self._challenge(row)

    async def list_challenges(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recently imported manifests without materializing any artifact input."""

        if limit < 1:
            raise ValueError("limit_must_be_positive")
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(ChallengeRow)
                    .order_by(ChallengeRow.created_at.desc())
                    .limit(min(limit, 100))
                )
            ).all()
            return [self._challenge(row) for row in rows]

    async def archive_intake_has_durable_reference(self, intake_id: str) -> bool:
        """Return whether a challenge already depends on one archive intake.

        Archive bytes live in the artifact store rather than this database, so
        permanent removal must first prove that no durable challenge can lead
        an operator back to those bytes. JSON traversal stays in Python to keep
        the query portable across the SQLite and PostgreSQL profiles. The
        generated Power challenge name is also checked because that legacy
        manifest shape predates an explicit ``spec.source`` binding.
        """

        if re.fullmatch(r"intake_[0-9a-f]{32}", intake_id) is None:
            raise ValueError("archive_intake_id_invalid")
        suffix = intake_id.removeprefix("intake_")
        generated_names = {f"ui-{suffix}", f"power-{suffix}"}
        async with self.database.sessions() as session:
            rows = (await session.execute(select(ChallengeRow.name, ChallengeRow.manifest))).all()
        for name, manifest in rows:
            if name in generated_names:
                return True
            if not isinstance(manifest, dict):
                continue
            spec = manifest.get("spec")
            source = spec.get("source") if isinstance(spec, dict) else None
            if isinstance(source, dict) and source.get("intake_id") == intake_id:
                return True
        return False

    async def create_run(
        self,
        challenge_id: str,
        *,
        mode: str,
        budget: dict[str, Any],
        provider: str = "operator-pending",
    ) -> dict[str, Any]:
        now = utc_now()
        row = RunRow(
            id=new_id("run"),
            challenge_id=challenge_id,
            status="created",
            mode=mode,
            provider=provider,
            budget=budget,
            result=None,
            created_at=now,
            updated_at=now,
        )
        async with self.database.sessions() as session, session.begin():
            challenge = await session.get(ChallengeRow, challenge_id)
            if challenge is None:
                raise ValueError("challenge_not_found")
            manifest_mode = challenge.manifest.get("spec", {}).get("mode")
            if mode != manifest_mode:
                raise ValueError("run_mode_must_match_manifest")
            _validate_run_budget(budget, challenge.manifest)
            session.add(row)
            session.add(RunSequenceRow(run_id=row.id, current=0))
            await session.flush()
            await self._append_event_row(
                session,
                row.id,
                "run.created",
                {"challenge_id": challenge_id, "mode": mode, "provider": provider},
                actor={"kind": "system", "id": "control-api"},
                idempotency_key=f"{row.id}:created",
            )
        return self._run(row)

    async def create_preparing_run(
        self,
        challenge_id: str,
        *,
        mode: str,
        budget: dict[str, Any],
        provider: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Atomically create a product run, move it to preparing, and queue preflight.

        ``create_run`` remains the low-level compatibility path used by the
        historical read-only triage adapter. Product composition roots must use
        this method through ``RunEngine.start`` so a run is never merely a
        passive database row awaiting an in-memory scheduler.
        """

        _validate_idempotency_key(idempotency_key)
        request_digest = digest_json(
            {
                "challenge_id": challenge_id,
                "mode": mode,
                "provider": provider,
                "budget": budget,
            }
        )
        async with self._start_locks[idempotency_key]:
            try:
                async with self.database.sessions() as session, session.begin():
                    existing = await session.scalar(
                        select(RunRow).where(RunRow.start_idempotency_key == idempotency_key)
                    )
                    if existing is not None:
                        if existing.start_request_digest != request_digest:
                            raise ValueError("idempotency_conflict")
                        return self._run(existing)

                    challenge = await session.get(ChallengeRow, challenge_id)
                    if challenge is None:
                        raise ValueError("challenge_not_found")
                    manifest_mode = challenge.manifest.get("spec", {}).get("mode")
                    if mode != manifest_mode:
                        raise ValueError("run_mode_must_match_manifest")
                    _validate_run_budget(budget, challenge.manifest)

                    now = utc_now()
                    row = RunRow(
                        id=new_id("run"),
                        challenge_id=challenge_id,
                        status="created",
                        mode=mode,
                        provider=provider,
                        budget=budget,
                        result=None,
                        start_idempotency_key=idempotency_key,
                        start_request_digest=request_digest,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                    session.add(RunSequenceRow(run_id=row.id, current=0))
                    await session.flush()
                    await self._append_event_row(
                        session,
                        row.id,
                        "run.created",
                        {"challenge_id": challenge_id, "mode": mode, "provider": provider},
                        actor={"kind": "system", "id": "run-engine"},
                        idempotency_key=f"{row.id}:created",
                    )
                    row.status = "preparing"
                    row.updated_at = utc_now()
                    await self._append_event_row(
                        session,
                        row.id,
                        "run.state.changed",
                        {
                            "previous_status": "created",
                            "status": "preparing",
                            "reason": "preflight_enqueued",
                        },
                        actor={"kind": "system", "id": "run-engine"},
                        idempotency_key=f"{row.id}:preparing",
                    )
                    await self._enqueue_agent_job_row(
                        session,
                        run_id=row.id,
                        kind="preflight",
                        payload_ref=f"challenge:{challenge_id}",
                        payload_digest=challenge.digest,
                        idempotency_key="preflight:v1",
                        deadline_at=None,
                        actor={"kind": "system", "id": "run-engine"},
                    )
                return self._run(row)
            except IntegrityError as exc:
                # A separate process may have won the unique idempotency race.
                async with self.database.sessions() as session:
                    existing = await session.scalar(
                        select(RunRow).where(RunRow.start_idempotency_key == idempotency_key)
                    )
                    if existing is None:
                        raise
                    if existing.start_request_digest != request_digest:
                        raise ValueError("idempotency_conflict") from exc
                    return self._run(existing)

    async def create_power_run(
        self,
        challenge_id: str,
        *,
        mode: str,
        budget: dict[str, Any],
        provider: str,
        idempotency_key: str,
        launch_scope: dict[str, Any],
    ) -> dict[str, Any]:
        """Create and start one Power coordinator run without a Pi job.

        The Power controller is an API-owned task composed from typed service
        clients; it is not a Pi session and therefore must not enqueue a Pi
        preflight job.  The safe scope is included in the idempotency digest
        and durable event, never a provider key, target URL path, command or
        flag value.
        """

        _validate_idempotency_key(idempotency_key)
        request_digest = digest_json(
            {
                "challenge_id": challenge_id,
                "mode": mode,
                "provider": provider,
                "budget": budget,
                "launch_scope": launch_scope,
            }
        )
        async with self._start_locks[idempotency_key]:
            try:
                async with self.database.sessions() as session, session.begin():
                    existing = await session.scalar(
                        select(RunRow).where(RunRow.start_idempotency_key == idempotency_key)
                    )
                    if existing is not None:
                        if existing.start_request_digest != request_digest:
                            raise ValueError("idempotency_conflict")
                        return self._run(existing)
                    challenge = await session.get(ChallengeRow, challenge_id)
                    if challenge is None:
                        raise ValueError("challenge_not_found")
                    if mode != challenge.manifest.get("spec", {}).get("mode"):
                        raise ValueError("run_mode_must_match_manifest")
                    _validate_run_budget(budget, challenge.manifest)
                    now = utc_now()
                    row = RunRow(
                        id=new_id("run"),
                        challenge_id=challenge_id,
                        status="created",
                        mode=mode,
                        provider=provider,
                        budget=budget,
                        result=None,
                        start_idempotency_key=idempotency_key,
                        start_request_digest=request_digest,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                    session.add(RunSequenceRow(run_id=row.id, current=0))
                    await session.flush()
                    await self._append_event_row(
                        session,
                        row.id,
                        "run.created",
                        {"challenge_id": challenge_id, "mode": mode, "provider": provider},
                        actor={"kind": "system", "id": "power-controller"},
                        idempotency_key=f"{row.id}:created",
                    )
                    row.status = "running"
                    row.updated_at = utc_now()
                    await self._append_event_row(
                        session,
                        row.id,
                        "run.state.changed",
                        {
                            "previous_status": "created",
                            "status": "running",
                            "reason": "power_controller_started",
                        },
                        actor={"kind": "system", "id": "power-controller"},
                        idempotency_key=f"{row.id}:running",
                    )
                    await self._append_event_row(
                        session,
                        row.id,
                        "power.scope.declared",
                        launch_scope,
                        actor={"kind": "human", "id": "local-user"},
                        idempotency_key=f"{row.id}:scope",
                    )
                return self._run(row)
            except IntegrityError as exc:
                async with self.database.sessions() as session:
                    existing = await session.scalar(
                        select(RunRow).where(RunRow.start_idempotency_key == idempotency_key)
                    )
                    if existing is None:
                        raise
                    if existing.start_request_digest != request_digest:
                        raise ValueError("idempotency_conflict") from exc
                    return self._run(existing)

    async def create_power_pi_sessions(
        self,
        run_id: str,
        *,
        archive_digest: str,
        brief: str,
        sessions: tuple[PowerPiSessionSpec, ...],
        target: tuple[str, int] | None,
    ) -> list[dict[str, Any]]:
        """Atomically publish the four already-provisioned Power Pi sessions.

        A caller must create disposable workspaces before this transaction and
        destroy them if it fails.  The durable start jobs are inserted only
        after every row has a trusted workspace ID, therefore a fast runner
        cannot race into an unmaterialized workspace.  No model key, flag,
        command, or target URL is ever persisted here.
        """

        if not _SHA256.fullmatch(archive_digest):
            raise ValueError("power_pi_archive_digest_invalid")
        if not 1 <= len(brief) <= 4_000 or _contains_plaintext_secret(brief):
            raise ValueError("power_pi_brief_invalid")
        if len(sessions) != 4:
            raise ValueError("power_pi_session_count_invalid")
        if target is None:
            target_host: str | None = None
            target_port: int | None = None
        else:
            target_host, target_port = target
            if (
                not isinstance(target_host, str)
                or not 1 <= len(target_host) <= 253
                or any(character.isspace() for character in target_host)
                or isinstance(target_port, bool)
                or not isinstance(target_port, int)
                or not 1 <= target_port <= 65_535
            ):
                raise ValueError("power_pi_target_invalid")
        expected_layout = (("auto", "autoprompter"), ("A", "racer"), ("B", "racer"), ("C", "racer"))
        if tuple((item.label, item.role) for item in sessions) != expected_layout:
            raise ValueError("power_pi_session_layout_invalid")
        if len({item.id for item in sessions}) != len(sessions):
            raise ValueError("power_pi_session_id_duplicate")
        for item in sessions:
            if (
                _ACTOR_ID.fullmatch(item.id) is None
                or item.role not in _POWER_PI_ROLES
                or item.provider not in _POWER_PI_PROVIDERS
                or _POWER_PI_MODEL.fullmatch(item.model) is None
                or isinstance(item.temperature, bool)
                or not isinstance(item.temperature, int | float)
                or not math.isfinite(item.temperature)
                or not 0 <= item.temperature <= 2
                or _POWER_PI_WORKSPACE_ID.fullmatch(item.workspace_id) is None
            ):
                raise ValueError("power_pi_session_spec_invalid")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status != "running":
                    raise ValueError("power_pi_run_not_active")
                existing = (
                    await session.scalars(
                        select(PowerPiSessionRow)
                        .where(PowerPiSessionRow.run_id == run_id)
                        .order_by(PowerPiSessionRow.created_at, PowerPiSessionRow.id)
                    )
                ).all()
                if existing:
                    if len(existing) != 4:
                        raise ValueError("power_pi_session_layout_conflict")
                    return [self._power_pi_session(row) for row in existing]
                now = utc_now()
                rows: list[PowerPiSessionRow] = []
                for item in sessions:
                    job = await self._enqueue_agent_job_row(
                        session,
                        run_id=run_id,
                        kind=AgentJobKind.POWER_SESSION_START.value,
                        payload_ref=f"power-session:{item.id}",
                        payload_digest=archive_digest,
                        idempotency_key=f"power-pi-start:{item.id}",
                        deadline_at=None,
                        actor={"kind": "system", "id": "power-pi-controller"},
                    )
                    row = PowerPiSessionRow(
                        id=item.id,
                        run_id=run_id,
                        start_job_id=job.id,
                        label=item.label,
                        role=item.role,
                        provider=item.provider,
                        model=item.model,
                        temperature=float(item.temperature),
                        archive_digest=archive_digest,
                        brief=brief,
                        target_host=target_host,
                        target_port=target_port,
                        workspace_id=item.workspace_id,
                        state="starting",
                        runner_id=None,
                        session_store_key=f"power-pi-{item.id}",
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                    rows.append(row)
                    await self._append_event_row(
                        session,
                        run_id,
                        "power.pi.session.queued",
                        {
                            "session_id": row.id,
                            "label": row.label,
                            "role": row.role,
                            "job_id": job.id,
                        },
                        actor={"kind": "system", "id": "power-pi-controller"},
                        idempotency_key=f"power-pi-session:{row.id}:queued",
                    )
            return [self._power_pi_session(row) for row in rows]

    async def list_power_pi_sessions(self, run_id: str) -> list[dict[str, Any]]:
        """Return credential-free Power session lifecycle metadata."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(PowerPiSessionRow)
                    .where(PowerPiSessionRow.run_id == run_id)
                    .order_by(PowerPiSessionRow.created_at, PowerPiSessionRow.id)
                )
            ).all()
            return [self._power_pi_session(row) for row in rows]

    async def _lock_power_run_and_job(
        self,
        session: AsyncSession,
        job_id: str,
    ) -> tuple[RunRow, AgentJobRow]:
        """Lock one Power lifecycle transaction in the canonical order.

        The runner claims several jobs concurrently.  Reading the immutable
        ``run_id`` first lets every Power mutation acquire ``runs`` before
        ``agent_jobs``.  This matches controller transactions and prevents the
        PostgreSQL cycle previously created by job -> run versus run -> job.
        """

        run_id = await session.scalar(select(AgentJobRow.run_id).where(AgentJobRow.id == job_id))
        if run_id is None:
            raise ValueError("agent_job_not_found")
        run = await session.get(RunRow, run_id, with_for_update=True)
        if run is None:
            raise ValueError("run_not_found")
        job = await session.scalar(
            select(AgentJobRow).where(AgentJobRow.id == job_id).with_for_update()
        )
        if job is None:
            raise ValueError("agent_job_not_found")
        if job.run_id != run.id:
            raise ValueError("agent_job_run_mismatch")
        return run, job

    async def get_power_pi_job_work(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Resolve exactly one leased Power job to its sealed runner payload."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job, worker_id=worker_id, lease_version=lease_version, now=now
            )
            if job.kind in _POWER_PI_RUNNABLE_JOB_KINDS and run.status != "running":
                raise ValueError("power_pi_job_run_not_active")
            if job.kind in _POWER_PI_TEARDOWN_JOB_KINDS and run.status not in {
                "cancelled",
                "solved",
            }:
                raise ValueError("power_pi_teardown_run_not_terminal")
            if job.kind == AgentJobKind.POWER_STEER.value:
                steer_id = _parse_runtime_reference(
                    job.payload_ref, _POWER_STEER_REF, "power_pi_steer_ref_invalid"
                )
                steer = await session.get(PowerPiSteerRow, steer_id, with_for_update=True)
                if steer is None or steer.run_id != job.run_id or steer.state != "queued":
                    raise ValueError("power_pi_steer_not_available")
                power_session = await session.get(
                    PowerPiSessionRow, steer.session_id, with_for_update=True
                )
                if power_session is None or power_session.state not in {"ready", "running"}:
                    raise ValueError("power_pi_steer_not_at_safe_boundary")
                if power_session.state == "ready":
                    # An idle additional turn acquires the same durable
                    # session ownership before Pi can invoke a tool.
                    power_session.state = "running"
                    power_session.runner_id = worker_id
                    power_session.updated_at = now
                elif power_session.runner_id != worker_id:
                    # Pi's in-memory SDK session lives in exactly one runner.
                    # Do not move an active session to another consumer merely
                    # because it claimed a steer job first.
                    raise ValueError("power_pi_steer_runner_mismatch")
                return {
                    "job": self._agent_job(job),
                    "session": self._power_pi_session(power_session),
                    "steer": self._power_pi_steer(steer),
                }
            session_id = _parse_runtime_reference(
                job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
            )
            power_session = await session.get(PowerPiSessionRow, session_id, with_for_update=True)
            if power_session is None or power_session.run_id != job.run_id:
                raise ValueError("power_pi_session_not_found")
            if job.kind == AgentJobKind.POWER_SESSION_START.value:
                if power_session.state not in {"starting", "running"}:
                    raise ValueError("power_pi_session_not_starting")
                power_session.state = "running"
                power_session.runner_id = worker_id
                power_session.updated_at = now
            elif job.kind == AgentJobKind.POWER_ABORT.value:
                if power_session.state not in {"aborting", "running", "ready", "starting"}:
                    raise ValueError("power_pi_session_not_abortable")
                power_session.state = "aborting"
                power_session.runner_id = worker_id
                power_session.updated_at = now
            else:
                raise ValueError("invalid_power_pi_job_kind")
            return {"job": self._agent_job(job), "session": self._power_pi_session(power_session)}

    async def complete_power_pi_start(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Release a startup lease after Pi reaches its next safe boundary."""

        return await self._complete_power_pi_running_job(
            job_id,
            worker_id=worker_id,
            lease_version=lease_version,
            expected_kind=AgentJobKind.POWER_SESSION_START,
            result_ref="power-session",
        )

    async def renew_power_pi_start_lease(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        lease_seconds: int = 30,
    ) -> dict[str, Any]:
        """Extend one live Power start lease without changing ownership.

        A Pi model turn may outlast the short claim window. The runner renews
        only while the durable session remains running; an abort fence changes
        that state, so the next heartbeat fails closed and interrupts Pi.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if isinstance(lease_seconds, bool) or not 5 <= lease_seconds <= 300:
            raise ValueError("invalid_lease_seconds")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job, worker_id=worker_id, lease_version=lease_version, now=now
            )
            if job.kind != AgentJobKind.POWER_SESSION_START.value:
                raise ValueError("power_pi_job_lease_lost")
            session_id = _parse_runtime_reference(
                job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
            )
            power_session = await session.get(PowerPiSessionRow, session_id, with_for_update=True)
            if (
                # A candidate gate pauses new tool authority, but the live Pi
                # turn must retain its lease long enough to settle at the
                # reviewed safe boundary instead of being mistaken for a
                # failed racer.
                run.status not in {"running", "paused"}
                or power_session is None
                or power_session.run_id != job.run_id
                or power_session.runner_id != worker_id
                or power_session.state != "running"
            ):
                raise ValueError("power_pi_job_lease_lost")
            job.lease_expires_at = now + timedelta(seconds=lease_seconds)
            job.updated_at = now
            return self._agent_job(job)

    async def _complete_power_pi_running_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        expected_kind: AgentJobKind,
        result_ref: str,
    ) -> dict[str, Any]:
        """Finish a start-like Power job without inferring a solver outcome."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            _run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=expected_kind,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
            )
            power_session = await session.get(PowerPiSessionRow, session_id, with_for_update=True)
            if (
                power_session is None
                or power_session.run_id != job.run_id
                or power_session.runner_id != worker_id
            ):
                raise ValueError("power_pi_session_runner_mismatch")
            # A concurrent verified flag fences the loser as aborting. A stale
            # start completion must preserve that terminal direction instead
            # of resurrecting it to ready.
            if power_session.state == "running":
                power_session.state = "ready"
            power_session.updated_at = now
            self._complete_power_pi_job_row(job, now=now)
            await self._note_idle_power_run(session, job.run_id, worker_id=worker_id)
            await self._append_event_row(
                session,
                job.run_id,
                "power.pi.session.ready",
                {"session_id": power_session.id, "label": power_session.label, "job_id": job.id},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"power-pi-session:{power_session.id}:ready",
            )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.completed",
                {
                    "job_id": job.id,
                    "kind": job.kind,
                    "result_ref": f"{result_ref}:{power_session.id}",
                },
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
            return self._agent_job(job)

    async def _note_idle_power_run(
        self,
        session: AsyncSession,
        run_id: str,
        *,
        worker_id: str,
    ) -> None:
        """Record that no session or queued job can advance this run.

        A racer's batch loop lives inside its ``power_session_start`` job. When
        the loop ends the job completes and the session returns to ``ready``,
        and nothing queues further work, so the run stays ``running`` while the
        console keeps presenting a live race. An operator watching that has no
        way to tell a thinking racer from a finished one.

        The status deliberately does not change. ``running`` is what
        ``queue_power_steer`` and the candidate gate require, and an idle run is
        meant to be resumable: steering one of these sessions is how an
        operator redirects a racer that has run out of ideas. This is the
        missing signal, not a new terminal state.
        """

        live_session = await session.scalar(
            select(func.count())
            .select_from(PowerPiSessionRow)
            .where(
                PowerPiSessionRow.run_id == run_id,
                PowerPiSessionRow.state.notin_(("ready", "failed", "aborted")),
            )
        )
        if live_session:
            return
        pending_job = await session.scalar(
            select(func.count())
            .select_from(AgentJobRow)
            .where(AgentJobRow.run_id == run_id, AgentJobRow.state.in_(("queued", "leased")))
        )
        if pending_job:
            return
        pending_steer = await session.scalar(
            select(func.count())
            .select_from(PowerPiSteerRow)
            .where(PowerPiSteerRow.run_id == run_id, PowerPiSteerRow.state == "queued")
        )
        if pending_steer:
            return
        idle = await session.scalars(
            select(PowerPiSessionRow.label).where(
                PowerPiSessionRow.run_id == run_id,
                PowerPiSessionRow.state == "ready",
            )
        )
        await self._append_event_row(
            session,
            run_id,
            "power.sessions.idle",
            {
                "summary": "Every Power session is idle; steer a racer or stop the run.",
                "idle_labels": sorted(idle.all()),
            },
            actor={"kind": "service", "id": worker_id},
            idempotency_key=f"power-sessions-idle:{run_id}:{utc_now().isoformat()}",
        )

    async def complete_power_pi_steer(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        delivered_while_streaming: bool,
    ) -> dict[str, Any]:
        """Persist a steer delivered at Pi's next safe model boundary."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not isinstance(delivered_while_streaming, bool):
            raise ValueError("power_pi_steer_delivery_invalid")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            _run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.POWER_STEER,
                now=now,
            )
            steer_id = _parse_runtime_reference(
                job.payload_ref, _POWER_STEER_REF, "power_pi_steer_ref_invalid"
            )
            steer = await session.get(PowerPiSteerRow, steer_id, with_for_update=True)
            if steer is None or steer.state != "queued":
                raise ValueError("power_pi_steer_not_available")
            power_session = await session.get(
                PowerPiSessionRow, steer.session_id, with_for_update=True
            )
            if power_session is None or power_session.runner_id != worker_id:
                raise ValueError("power_pi_session_runner_mismatch")
            steer.state = "applied"
            steer.applied_at = now
            if power_session.state not in {"running", "aborting", "aborted"}:
                raise ValueError("power_pi_steer_session_not_running")
            # A streaming steer shares the original startup job's authority;
            # completing its own queue item must not revoke that ownership.
            # A turn started from an idle session is now settled, so restore
            # the normal safe boundary for a later follow-up.
            if not delivered_while_streaming and power_session.state == "running":
                power_session.state = "ready"
            power_session.updated_at = now
            self._complete_power_pi_job_row(job, now=now)
            await self._append_event_row(
                session,
                job.run_id,
                "power.pi.steer.applied",
                {"steer_id": steer.id, "session_id": power_session.id},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"power-pi-steer:{steer.id}:applied",
            )
            return self._agent_job(job)

    async def complete_power_pi_abort(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Acknowledge local Pi disposal; controller owns delayed workspace destroy."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            _run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.POWER_ABORT,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
            )
            power_session = await session.get(PowerPiSessionRow, session_id, with_for_update=True)
            if power_session is None or power_session.runner_id != worker_id:
                raise ValueError("power_pi_session_runner_mismatch")
            power_session.state = "aborted"
            power_session.updated_at = now
            # The start job may be leased while its local Pi operation is
            # interrupted by this abort. Terminalize that paired queue row so
            # it cannot be reclaimed forever after a cancelled/solved run.
            start_job = await session.get(
                AgentJobRow, power_session.start_job_id, with_for_update=True
            )
            if start_job is not None and start_job.state not in {
                "completed",
                "failed",
                "cancelled",
            }:
                start_job.state = "cancelled"
                start_job.lease_owner = None
                start_job.lease_expires_at = None
                start_job.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "agent.job.cancelled",
                    {
                        "job_id": start_job.id,
                        "kind": start_job.kind,
                        "reason": "power_session_aborted",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"job:{start_job.id}:power-session-aborted",
                )
            self._complete_power_pi_job_row(job, now=now)
            await self._append_event_row(
                session,
                job.run_id,
                "power.pi.session.aborted",
                {"session_id": power_session.id, "job_id": job.id},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"power-pi-session:{power_session.id}:aborted",
            )
            return self._agent_job(job)

    async def fail_power_pi_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        reason: str,
    ) -> dict[str, Any]:
        """Record one session-local Power failure without making a model claim.

        A racer start failure must not fabricate a global outcome or stop
        healthy siblings. A steer failure is narrower still: it terminates
        only that queued correction and returns an idle racer to ``ready``.
        Only the independent flag router can ever transition the run to
        ``solved``.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        _validate_runtime_failure_code(reason)
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job, worker_id=worker_id, lease_version=lease_version, now=now
            )
            steer: PowerPiSteerRow | None = None
            if job.kind == AgentJobKind.POWER_STEER.value:
                steer_id = _parse_runtime_reference(
                    job.payload_ref, _POWER_STEER_REF, "power_pi_steer_ref_invalid"
                )
                steer = await session.get(PowerPiSteerRow, steer_id, with_for_update=True)
                if steer is None or steer.run_id != job.run_id:
                    raise ValueError("power_pi_steer_not_available")
                power_session = await session.get(
                    PowerPiSessionRow, steer.session_id, with_for_update=True
                )
            else:
                session_id = _parse_runtime_reference(
                    job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
                )
                power_session = await session.get(
                    PowerPiSessionRow, session_id, with_for_update=True
                )
            if power_session is None or power_session.run_id != job.run_id:
                raise ValueError("power_pi_session_not_found")
            job.state = "failed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            if steer is not None:
                # A failed operator correction is local to that queue item.
                # It must not kill a healthy Pi session that is still running
                # its original turn or can safely accept a later correction.
                steer.state = "failed"
                start_job = await session.get(
                    AgentJobRow, power_session.start_job_id, with_for_update=True
                )
                if power_session.state == "running" and (
                    start_job is None or start_job.state != "leased"
                ):
                    power_session.state = "ready"
                power_session.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "power.pi.steer.failed",
                    {"session_id": power_session.id, "job_id": job.id, "reason": reason},
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=(f"power-pi-steer:{steer.id}:failed:{job.id}:{lease_version}"),
                )
            elif job.kind != AgentJobKind.POWER_ABORT.value:
                power_session.state = "failed"
                power_session.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "power.pi.session.failed",
                    {"session_id": power_session.id, "job_id": job.id, "reason": reason},
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=(
                        f"power-pi-session:{power_session.id}:failed:{job.id}:{lease_version}"
                    ),
                )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.failed",
                {"job_id": job.id, "kind": job.kind, "reason": reason},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:failed:{lease_version}",
            )
            if job.kind == AgentJobKind.POWER_SESSION_START.value and run.status == "running":
                active_racers = await session.scalar(
                    select(func.count())
                    .select_from(PowerPiSessionRow)
                    .where(
                        PowerPiSessionRow.run_id == run.id,
                        PowerPiSessionRow.role == "racer",
                        PowerPiSessionRow.state.in_(["starting", "ready", "running"]),
                    )
                )
                if active_racers == 0:
                    run.status = "failed"
                    run.updated_at = now
                    await self._append_event_row(
                        session,
                        run.id,
                        "run.state.changed",
                        {
                            "previous_status": "running",
                            "status": "failed",
                            "reason": "all_power_racers_failed",
                        },
                        actor={"kind": "service", "id": worker_id},
                        idempotency_key=f"run:{run.id}:all-power-racers-failed",
                    )
                elif run.status == "running":
                    # A racer can also be the last one to stop while siblings
                    # are merely idle. That leaves a run nothing can advance
                    # and no terminal transition to announce it, so the idle
                    # signal has to be raised from the failure path too.
                    await self._note_idle_power_run(session, run.id, worker_id=worker_id)
            return self._agent_job(job)

    async def queue_power_pi_steer(
        self,
        run_id: str,
        *,
        session_id: str,
        message: str,
        idempotency_key: str,
        requested_by: str,
    ) -> dict[str, Any]:
        """Queue one sanitized Power steer for a ready or streaming session."""

        _validate_idempotency_key(idempotency_key)
        _validate_lease_owner(requested_by)
        if not 1 <= len(message.strip()) <= 2_000 or _contains_plaintext_secret(message):
            raise ValueError("power_pi_steer_invalid")
        if _ACTOR_ID.fullmatch(session_id) is None:
            raise ValueError("power_pi_session_id_invalid")
        safe_message = _redact_text(message.strip())
        message_digest = hashlib.sha256(safe_message.encode("utf-8")).hexdigest()
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status != "running":
                    raise ValueError("power_pi_run_not_active")
                existing = await session.scalar(
                    select(PowerPiSteerRow).where(
                        PowerPiSteerRow.run_id == run_id,
                        PowerPiSteerRow.idempotency_key == idempotency_key,
                    )
                )
                if existing is not None:
                    if (
                        existing.message_digest != message_digest
                        or existing.session_id != session_id
                    ):
                        raise ValueError("idempotency_conflict")
                    return self._power_pi_steer(existing)
                power_session = await session.get(
                    PowerPiSessionRow, session_id, with_for_update=True
                )
                if (
                    power_session is None
                    or power_session.run_id != run_id
                    or power_session.state not in {"ready", "running"}
                ):
                    raise ValueError("power_pi_session_not_available")
                pending = await session.scalar(
                    select(PowerPiSteerRow)
                    .join(AgentJobRow, AgentJobRow.id == PowerPiSteerRow.job_id)
                    .where(
                        PowerPiSteerRow.session_id == session_id,
                        PowerPiSteerRow.state == "queued",
                        AgentJobRow.state.in_(["queued", "leased"]),
                    )
                    .order_by(PowerPiSteerRow.created_at, PowerPiSteerRow.id)
                    .limit(1)
                    .with_for_update(of=PowerPiSteerRow)
                )
                if pending is not None:
                    # Browser retries and fast repeated clicks must converge
                    # on one in-flight correction. Pi SDK sessions are not
                    # reentrant, so a second distinct steer waits for the
                    # current queue item to settle before it can be accepted.
                    if pending.message_digest == message_digest:
                        return self._power_pi_steer(pending)
                    raise ValueError("power_pi_steer_already_pending")
                now = utc_now()
                steer_id = new_id("power-steer")
                job = await self._enqueue_agent_job_row(
                    session,
                    run_id=run_id,
                    kind=AgentJobKind.POWER_STEER.value,
                    payload_ref=f"power-steer:{steer_id}",
                    payload_digest=message_digest,
                    idempotency_key=f"power-pi-steer:{steer_id}",
                    deadline_at=None,
                    actor={"kind": "human", "id": requested_by},
                )
                steer = PowerPiSteerRow(
                    id=steer_id,
                    run_id=run_id,
                    session_id=session_id,
                    job_id=job.id,
                    message=safe_message,
                    message_digest=message_digest,
                    state="queued",
                    idempotency_key=idempotency_key,
                    requested_by=requested_by,
                    created_at=now,
                    applied_at=None,
                )
                session.add(steer)
                await self._append_event_row(
                    session,
                    run_id,
                    "power.pi.steer.queued",
                    {"steer_id": steer.id, "session_id": session_id, "job_id": job.id},
                    actor={"kind": "human", "id": requested_by},
                    idempotency_key=f"power-pi-steer:{steer.id}:queued",
                )
                return self._power_pi_steer(steer)

    async def request_power_pi_abort(
        self,
        run_id: str,
        *,
        winner_session_id: str | None,
        requested_by: str,
    ) -> list[dict[str, Any]]:
        """Fence Power tools, then queue durable aborts for selected sessions.

        ``winner_session_id`` excludes the accepted racer from the sibling
        abort queue; its workspace still receives controller-owned delayed
        destruction after the verifier result is durable.
        """

        _validate_lease_owner(requested_by)
        if winner_session_id is not None and _ACTOR_ID.fullmatch(winner_session_id) is None:
            raise ValueError("power_pi_session_id_invalid")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status not in {"running", "cancelled", "solved"}:
                    raise ValueError("power_pi_run_not_abortable")
                # Once an abort fence is requested no queued startup/steer
                # can later wake up and recreate a disposed Power session.
                # A currently leased job is allowed to reach its next Pi safe
                # boundary, but session state below independently denies new
                # custom-tool calls before that completion arrives.
                queued_runnable_jobs = (
                    await session.scalars(
                        select(AgentJobRow)
                        .where(
                            AgentJobRow.run_id == run_id,
                            AgentJobRow.kind.in_(_POWER_PI_RUNNABLE_JOB_KINDS),
                            AgentJobRow.state == "queued",
                        )
                        .with_for_update()
                    )
                ).all()
                now = utc_now()
                for queued_job in queued_runnable_jobs:
                    queued_job.state = "cancelled"
                    queued_job.updated_at = now
                    await self._append_event_row(
                        session,
                        run_id,
                        "agent.job.cancelled",
                        {
                            "job_id": queued_job.id,
                            "kind": queued_job.kind,
                            "reason": "power_abort_requested",
                        },
                        actor={"kind": "service", "id": requested_by},
                        idempotency_key=f"job:{queued_job.id}:power-abort-cancelled",
                    )
                # Older deployments may already have completed an abort while
                # its paired start lease remained reclaimable. Reconcile only
                # those terminal sessions here so a repeated user cancel is
                # idempotent and never creates a hot loop of stale claims.
                aborted_sessions = (
                    await session.scalars(
                        select(PowerPiSessionRow)
                        .where(
                            PowerPiSessionRow.run_id == run_id,
                            PowerPiSessionRow.state == "aborted",
                        )
                        .with_for_update()
                    )
                ).all()
                for power_session in aborted_sessions:
                    start_job = await session.get(
                        AgentJobRow, power_session.start_job_id, with_for_update=True
                    )
                    if start_job is None or start_job.state not in {"queued", "leased"}:
                        continue
                    start_job.state = "cancelled"
                    start_job.lease_owner = None
                    start_job.lease_expires_at = None
                    start_job.updated_at = now
                    await self._append_event_row(
                        session,
                        run_id,
                        "agent.job.cancelled",
                        {
                            "job_id": start_job.id,
                            "kind": start_job.kind,
                            "reason": "power_aborted_session_reconciled",
                        },
                        actor={"kind": "service", "id": requested_by},
                        idempotency_key=f"job:{start_job.id}:power-aborted-reconciled",
                    )
                rows = (
                    await session.scalars(
                        select(PowerPiSessionRow)
                        .where(
                            PowerPiSessionRow.run_id == run_id,
                            PowerPiSessionRow.state.in_(
                                ["starting", "ready", "running", "aborting"]
                            ),
                        )
                        .order_by(PowerPiSessionRow.created_at, PowerPiSessionRow.id)
                        .with_for_update()
                    )
                ).all()
                jobs: list[AgentJobRow] = []
                for power_session in rows:
                    if winner_session_id is not None and power_session.id == winner_session_id:
                        continue
                    power_session.state = "aborting"
                    power_session.updated_at = now
                    job = await self._enqueue_agent_job_row(
                        session,
                        run_id=run_id,
                        kind=AgentJobKind.POWER_ABORT.value,
                        payload_ref=f"power-session:{power_session.id}",
                        payload_digest=power_session.archive_digest,
                        idempotency_key=f"power-pi-abort:{power_session.id}",
                        deadline_at=None,
                        actor={"kind": "service", "id": requested_by},
                    )
                    jobs.append(job)
                    await self._append_event_row(
                        session,
                        run_id,
                        "power.pi.abort.requested",
                        {"session_id": power_session.id, "job_id": job.id},
                        actor={"kind": "service", "id": requested_by},
                        idempotency_key=f"power-pi-session:{power_session.id}:abort-requested",
                    )
                return [self._agent_job(job) for job in jobs]

    async def get_power_pi_tool_authority(
        self,
        job_id: str,
        *,
        session_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, str]:
        """Return server-derived Power workspace authority for one live lease.

        The Pi process never receives this resolver's service credentials and
        cannot select a workspace through its tool parameters.  A solved,
        cancelled, or aborting session is fenced before sandboxd is contacted.
        """

        _validate_lease_owner(worker_id)
        if _ACTOR_ID.fullmatch(session_id) is None:
            raise ValueError("power_pi_session_id_invalid")
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            run, job = await self._lock_power_run_and_job(session, job_id)
            self._require_power_pi_job_lease(
                job, worker_id=worker_id, lease_version=lease_version, now=now
            )
            if job.kind not in _POWER_PI_RUNNABLE_JOB_KINDS:
                raise ValueError("power_pi_tool_job_not_runnable")
            power_session = await session.get(PowerPiSessionRow, session_id, with_for_update=True)
            # A sibling may already be between model tool calls when another
            # racer observes a format match. Return a stable, value-free code
            # so its local Pi batch also reaches the candidate-review boundary
            # instead of treating the pause as an opaque tool failure.
            if run.status == "paused":
                raise ValueError("power_candidate_review_required")
            if (
                run.status != "running"
                or power_session is None
                or power_session.run_id != job.run_id
                or power_session.runner_id != worker_id
                or power_session.state != "running"
                or power_session.workspace_id is None
            ):
                raise ValueError("power_pi_tool_not_authorized")
            if job.kind == AgentJobKind.POWER_STEER.value:
                steer_id = _parse_runtime_reference(
                    job.payload_ref, _POWER_STEER_REF, "power_pi_steer_ref_invalid"
                )
                steer = await session.get(PowerPiSteerRow, steer_id)
                if steer is None or steer.session_id != session_id or steer.state != "queued":
                    raise ValueError("power_pi_tool_steer_not_authorized")
            elif (
                _parse_runtime_reference(
                    job.payload_ref, _POWER_SESSION_REF, "power_pi_session_ref_invalid"
                )
                != session_id
            ):
                raise ValueError("power_pi_tool_session_mismatch")
            # The label is fixed by the server when the session is provisioned.
            # It lets the control API publish safe racer progress without ever
            # receiving a model transcript, command, path, or tool output.
            return {
                "run_id": run.id,
                "workspace_id": power_session.workspace_id,
                "label": power_session.label,
            }

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        async with self.database.sessions() as session:
            row = await session.get(RunRow, run_id)
            return None if row is None else self._run(row)

    async def get_power_flag_patterns(self, run_id: str) -> tuple[str, ...]:
        """Read the persisted Power manifest rule for the flag-router only.

        Candidate data never enters this projection.  The tag guard prevents a
        Power service credential from being used as a general challenge-rule
        oracle for the standard verifier profiles.
        """

        async with self.database.sessions() as session:
            run = await session.get(RunRow, run_id)
            if run is None:
                raise ValueError("run_not_found")
            challenge = await session.get(ChallengeRow, run.challenge_id)
            if challenge is None:
                raise ValueError("challenge_not_found")
            try:
                manifest = ChallengeManifest.model_validate(challenge.manifest)
            except (TypeError, ValueError) as exc:
                raise ValueError("stored_challenge_manifest_invalid") from exc
            if "power-profile" not in manifest.metadata.tags:
                raise ValueError("power_flag_patterns_not_available")
            return tuple(manifest.spec.flag.patterns)

    async def get_run_by_start_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return one prior product-run start without exposing its request body.

        The UI exact-instance launch uses this lookup before source-slot
        materialization. A browser retry can therefore receive the original
        durable run rather than replacing a slot while that run is active.
        """

        _validate_idempotency_key(idempotency_key)
        async with self.database.sessions() as session:
            row = await session.scalar(
                select(RunRow).where(RunRow.start_idempotency_key == idempotency_key)
            )
            return None if row is None else self._run(row)

    async def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit_must_be_positive")
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(RunRow).order_by(RunRow.created_at.desc()).limit(min(limit, 100))
                )
            ).all()
            return [self._run(row) for row in rows]

    async def list_active_source_slot_ids(self) -> frozenset[str]:
        """Return slots held by non-terminal source-bound runs only.

        Source binding remains part of the canonical challenge manifest. This
        read projection avoids a second mutable authority record; the v0.1
        API serializes launch selection and slots verify their own assignment
        before reading anything from the mounted source tree.
        """

        active_statuses = ("created", "preparing", "ready", "running", "paused", "verifying")
        async with self.database.sessions() as session:
            rows = (
                await session.execute(
                    select(RunRow, ChallengeRow)
                    .join(ChallengeRow, ChallengeRow.id == RunRow.challenge_id)
                    .where(RunRow.status.in_(active_statuses))
                )
            ).all()
        slots: set[str] = set()
        for _run, challenge in rows:
            source = challenge.manifest.get("spec", {}).get("source")
            if isinstance(source, dict):
                slot_id = source.get("slot_id")
                if slot_id in {"source-slot-1", "source-slot-2"}:
                    slots.add(slot_id)
        return frozenset(slots)

    async def append_event(
        self,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor: dict[str, str],
        idempotency_key: str,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        if not _EVENT_TYPE.fullmatch(event_type):
            raise ValueError("invalid_event_type")
        if not idempotency_key.strip() or len(idempotency_key) > 200:
            raise ValueError("invalid_idempotency_key")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                row = await self._append_event_row(
                    session,
                    run_id,
                    event_type,
                    payload,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                )
            return self._event(row)

    async def record_power_pi_action(
        self,
        run_id: str,
        *,
        label: str,
        runner_id: str,
        action: str,
        observation_artifact_id: str | None,
        observation_artifact_ids: tuple[str, ...] = (),
        observation_received: bool,
        action_summary: str,
        recon_fingerprint: str | None = None,
    ) -> bool:
        """Append one Power receipt and atomically mark repeated file recon.

        The fingerprint is a SHA-256 of the normalized path made by the
        reviewed runner adapter.  Neither the path nor argv reaches the event
        ledger.  Serializing the lookup and append under the run lock makes a
        simultaneous A/B ``fs_read`` deterministically mark the later action
        as a duplicate rather than asking the three racers to rediscover it.
        """

        if label not in {"auto", "A", "B", "C"}:
            raise ValueError("power_pi_label_invalid")
        _validate_lease_owner(runner_id)
        if action not in {
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
        }:
            raise ValueError("power_pi_action_invalid")
        if not 1 <= len(action_summary) <= 160:
            raise ValueError("power_pi_action_summary_invalid")
        if observation_artifact_id is not None and not re.fullmatch(
            r"sha256:[0-9a-f]{64}", observation_artifact_id
        ):
            raise ValueError("power_pi_observation_artifact_invalid")
        if len(observation_artifact_ids) > 2 or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None
            for artifact_id in observation_artifact_ids
        ):
            raise ValueError("power_pi_observation_artifacts_invalid")
        if len(set(observation_artifact_ids)) != len(observation_artifact_ids):
            raise ValueError("power_pi_observation_artifacts_invalid")
        if (
            observation_artifact_id is not None
            and observation_artifact_ids
            and (observation_artifact_id not in observation_artifact_ids)
        ):
            raise ValueError("power_pi_observation_artifacts_invalid")
        if recon_fingerprint is not None and _SHA256.fullmatch(recon_fingerprint) is None:
            raise ValueError("power_pi_recon_fingerprint_invalid")

        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                duplicate = False
                if recon_fingerprint is not None:
                    previous = (
                        await session.scalars(
                            select(EventRow).where(
                                EventRow.run_id == run_id,
                                EventRow.event_type == "power.command.observed",
                            )
                        )
                    ).all()
                    duplicate = any(
                        row.payload.get("recon_fingerprint") == recon_fingerprint
                        for row in previous
                    )
                payload: dict[str, Any] = {
                    "summary": f"Racer {label}: {action} (running).",
                    "label": label,
                    "state": "bumped" if duplicate else "running",
                    "action_type": action,
                    "action_summary": action_summary,
                    "observation_received": observation_received,
                }
                if observation_artifact_id is not None:
                    payload["observation_artifact_id"] = observation_artifact_id
                if observation_artifact_ids:
                    # The immutable ids are metadata only.  A normal exec has
                    # distinct stdout and stderr artifacts, both of which are
                    # eligible evidence for explicit candidate review.
                    payload["observation_artifact_ids"] = list(observation_artifact_ids)
                if recon_fingerprint is not None:
                    payload["recon_fingerprint"] = recon_fingerprint
                    payload["duplicate_recon"] = duplicate
                await self._append_event_row(
                    session,
                    run_id,
                    "power.command.observed",
                    payload,
                    actor={"kind": "service", "id": runner_id},
                    idempotency_key=f"power-pi-tool:{uuid4().hex}",
                )
                if duplicate:
                    await self._append_event_row(
                        session,
                        run_id,
                        "power.recon.duplicate",
                        {
                            "summary": f"Racer {label}: duplicate file reconnaissance detected.",
                            "label": label,
                            "recon_fingerprint": recon_fingerprint,
                        },
                        actor={"kind": "service", "id": runner_id},
                        idempotency_key=f"power-pi-recon-duplicate:{uuid4().hex}",
                    )
                return duplicate

    async def list_power_pi_observation_artifacts(self, run_id: str) -> list[dict[str, str]]:
        """Return Power observation references without reading their artifact bodies.

        The caller may use these metadata-only references to perform an
        explicit local candidate reveal.  Raw tool output and candidate text
        remain in immutable artifacts rather than the database/event payload.
        """

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(EventRow)
                    .where(
                        EventRow.run_id == run_id,
                        EventRow.event_type == "power.command.observed",
                    )
                    .order_by(EventRow.sequence)
                )
            ).all()
        observations: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            label = row.payload.get("label")
            if label not in {"auto", "A", "B", "C"}:
                continue
            raw_artifact_ids = row.payload.get("observation_artifact_ids")
            artifact_ids = (
                raw_artifact_ids
                if isinstance(raw_artifact_ids, list)
                else [row.payload.get("observation_artifact_id")]
            )
            for artifact_id in artifact_ids:
                if (
                    not isinstance(artifact_id, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None
                ):
                    continue
                # Keep the same artifact once per racer. This preserves every
                # source label while avoiding needless repeat reads after retries.
                key = (artifact_id, label)
                if key not in seen:
                    observations.append({"artifact_id": artifact_id, "label": label})
                    seen.add(key)
        return observations

    async def pause_power_candidate_review(
        self,
        run_id: str,
        *,
        session_id: str,
        runner_id: str,
        observation_artifact_ids: tuple[str, ...],
        candidate_count: int,
    ) -> dict[str, Any]:
        """Pause one live Power run after a format-matching observation.

        This is a candidate gate, not flag verification.  It records only the
        reviewed session, immutable artifact references and count; raw values
        stay in the artifact until the local operator explicitly reveals them.
        Concurrent racers may reach the same paused gate idempotently.
        """

        _validate_lease_owner(runner_id)
        if _ACTOR_ID.fullmatch(session_id) is None:
            raise ValueError("power_pi_session_id_invalid")
        if not 1 <= len(observation_artifact_ids) <= 2:
            raise ValueError("power_pi_observation_artifact_count_invalid")
        if any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None
            for artifact_id in observation_artifact_ids
        ):
            raise ValueError("power_pi_observation_artifact_invalid")
        if len(set(observation_artifact_ids)) != len(observation_artifact_ids):
            raise ValueError("power_pi_observation_artifact_duplicate")
        if isinstance(candidate_count, bool) or not 1 <= candidate_count <= 1_024:
            raise ValueError("power_candidate_review_count_invalid")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                power_session = await session.get(
                    PowerPiSessionRow, session_id, with_for_update=True
                )
                if (
                    power_session is None
                    or power_session.run_id != run_id
                    or power_session.runner_id != runner_id
                    or power_session.state != "running"
                ):
                    raise ValueError("power_candidate_review_session_not_active")
                if run.status == "paused":
                    # A second in-flight racer must also see the gate and
                    # finish its current native Pi turn. Preserve its output
                    # reference as an append-only companion to the original
                    # request so the automatic queue cannot lose candidates
                    # that arrived during the same pause window.
                    gate_key = (
                        "power-candidate-review-observed:"
                        f"{session_id}:{observation_artifact_ids[0]}"
                    )
                    existing = await session.scalar(
                        select(EventRow).where(
                            EventRow.run_id == run_id,
                            EventRow.idempotency_key == gate_key,
                        )
                    )
                    if existing is None:
                        await self._append_event_row(
                            session,
                            run_id,
                            "power.candidate.review.observed",
                            {
                                "summary": (
                                    "Additional runtime candidate output is awaiting review."
                                ),
                                "session_id": session_id,
                                "label": power_session.label,
                                "observation_artifact_id": observation_artifact_ids[0],
                                "observation_artifact_ids": list(observation_artifact_ids),
                                "candidate_count": candidate_count,
                            },
                            actor={"kind": "service", "id": runner_id},
                            idempotency_key=gate_key,
                        )
                    return {"paused": True, "newly_paused": False}
                if run.status != "running":
                    raise ValueError("power_candidate_review_run_not_active")
                now = utc_now()
                run.status = "paused"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run_id,
                    "run.state.changed",
                    {
                        "previous_status": "running",
                        "status": "paused",
                        "reason": "power_candidate_review_required",
                    },
                    actor={"kind": "system", "id": "power-candidate-gate"},
                    idempotency_key=(
                        f"power-candidate-review:{session_id}:{observation_artifact_ids[0]}"
                    ),
                )
                await self._append_event_row(
                    session,
                    run_id,
                    "power.candidate.review.requested",
                    {
                        "summary": "A runtime flag candidate requires operator review.",
                        "session_id": session_id,
                        "label": power_session.label,
                        # Keep the singular reference for older readers while
                        # retaining both streams for the automatic local queue.
                        "observation_artifact_id": observation_artifact_ids[0],
                        "observation_artifact_ids": list(observation_artifact_ids),
                        "candidate_count": candidate_count,
                    },
                    actor={"kind": "service", "id": runner_id},
                    idempotency_key=(
                        "power-candidate-review-requested:"
                        f"{session_id}:{observation_artifact_ids[0]}"
                    ),
                )
                return {"paused": True, "newly_paused": True}

    async def power_candidate_review_pending(self, run_id: str) -> bool:
        """Return whether the latest durable candidate-gate decision is pending."""

        async with self.database.sessions() as session:
            run = await session.get(RunRow, run_id)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "paused":
                return False
            latest = await session.scalar(
                select(EventRow)
                .where(
                    EventRow.run_id == run_id,
                    EventRow.event_type.in_(
                        [
                            "power.candidate.review.requested",
                            "power.candidate.review.observed",
                            "power.candidate.review.rejected",
                            "power.candidate.review.confirmed",
                        ]
                    ),
                )
                .order_by(EventRow.sequence.desc())
                .limit(1)
            )
            return latest is not None and latest.event_type in {
                "power.candidate.review.requested",
                "power.candidate.review.observed",
            }

    async def get_power_candidate_review_queue(self, run_id: str) -> dict[str, Any]:
        """Return provenance references for the current paused candidate queue.

        The method deliberately returns artifact identifiers and labels only.
        A request-local API service reads those immutable artifacts to reveal
        values to the local operator; raw candidate strings never enter the
        event ledger or this persistence contract.
        """

        async with self.database.sessions() as session:
            run = await session.get(RunRow, run_id)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "paused":
                raise ValueError("power_candidate_review_not_pending")
            events = list(
                (
                    await session.scalars(
                        select(EventRow)
                        .where(
                            EventRow.run_id == run_id,
                            EventRow.event_type.in_(
                                [
                                    "power.candidate.review.requested",
                                    "power.candidate.review.observed",
                                    "power.candidate.review.rejected",
                                    "power.candidate.review.confirmed",
                                ]
                            ),
                        )
                        .order_by(EventRow.sequence.desc())
                    )
                ).all()
            )
            queue_events: list[EventRow] = []
            for event in events:
                if event.event_type in {
                    "power.candidate.review.rejected",
                    "power.candidate.review.confirmed",
                }:
                    raise ValueError("power_candidate_review_not_pending")
                queue_events.append(event)
                if event.event_type == "power.candidate.review.requested":
                    break
            if (
                not queue_events
                or queue_events[-1].event_type != "power.candidate.review.requested"
            ):
                raise ValueError("power_candidate_review_not_pending")
            observations: list[dict[str, str]] = []
            seen: set[tuple[str, str]] = set()
            for event in reversed(queue_events):
                label = event.payload.get("label")
                candidate_count = event.payload.get("candidate_count")
                raw_artifact_ids = event.payload.get("observation_artifact_ids")
                artifact_ids = (
                    raw_artifact_ids
                    if isinstance(raw_artifact_ids, list)
                    else [event.payload.get("observation_artifact_id")]
                )
                if (
                    not isinstance(label, str)
                    or label not in {"auto", "A", "B", "C"}
                    or isinstance(candidate_count, bool)
                    or not isinstance(candidate_count, int)
                    or not 1 <= candidate_count <= 1_024
                    or not 1 <= len(artifact_ids) <= 2
                ):
                    raise ValueError("power_candidate_review_queue_invalid")
                validated_artifact_ids: list[str] = []
                for artifact_id in artifact_ids:
                    if (
                        not isinstance(artifact_id, str)
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None
                    ):
                        raise ValueError("power_candidate_review_queue_invalid")
                    validated_artifact_ids.append(artifact_id)
                if len(set(validated_artifact_ids)) != len(validated_artifact_ids):
                    raise ValueError("power_candidate_review_queue_invalid")
                for artifact_id in validated_artifact_ids:
                    key = (artifact_id, label)
                    if key not in seen:
                        observations.append({"artifact_id": artifact_id, "label": label})
                        seen.add(key)
            return {"observations": tuple(observations)}

    async def reject_power_candidate_review(
        self,
        run_id: str,
        *,
        requested_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Resume every available racer after an operator rejects a candidate.

        The generated steer deliberately contains no candidate value.  Each
        ready/streaming racer receives a distinct-evidence continuation inside
        its existing Pi session after the run becomes runnable again.
        """

        _validate_lease_owner(requested_by)
        _validate_idempotency_key(idempotency_key)
        action_key = (
            "power-candidate-review-rejected:"
            + hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
        )
        message = (
            "The operator rejected the candidate. Continue with a distinct evidence path, "
            "avoid repeated reads, and seek a fresh observed candidate."
        )
        message_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                previous = await session.scalar(
                    select(EventRow).where(
                        EventRow.run_id == run_id,
                        EventRow.idempotency_key == action_key,
                    )
                )
                if previous is not None:
                    return {
                        "resumed": True,
                        "racer_count": int(previous.payload.get("racer_count", 0)),
                    }
                if run.status != "paused":
                    raise ValueError("power_candidate_review_not_pending")
                latest = await session.scalar(
                    select(EventRow)
                    .where(
                        EventRow.run_id == run_id,
                        EventRow.event_type.in_(
                            [
                                "power.candidate.review.requested",
                                "power.candidate.review.observed",
                                "power.candidate.review.rejected",
                                "power.candidate.review.confirmed",
                            ]
                        ),
                    )
                    .order_by(EventRow.sequence.desc())
                    .limit(1)
                )
                if latest is None or latest.event_type not in {
                    "power.candidate.review.requested",
                    "power.candidate.review.observed",
                }:
                    raise ValueError("power_candidate_review_not_pending")
                now = utc_now()
                run.status = "running"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run_id,
                    "run.state.changed",
                    {
                        "previous_status": "paused",
                        "status": "running",
                        "reason": "human_candidate_review_rejected",
                    },
                    actor={"kind": "human", "id": requested_by},
                    idempotency_key=f"{action_key}:state",
                )
                racers = (
                    await session.scalars(
                        select(PowerPiSessionRow)
                        .where(
                            PowerPiSessionRow.run_id == run_id,
                            PowerPiSessionRow.role == "racer",
                            PowerPiSessionRow.state.in_(["ready", "running"]),
                        )
                        .order_by(PowerPiSessionRow.created_at, PowerPiSessionRow.id)
                        .with_for_update()
                    )
                ).all()
                for power_session in racers:
                    steer_id = new_id("power-steer")
                    job = await self._enqueue_agent_job_row(
                        session,
                        run_id=run_id,
                        kind=AgentJobKind.POWER_STEER.value,
                        payload_ref=f"power-steer:{steer_id}",
                        payload_digest=message_digest,
                        idempotency_key=f"power-candidate-review-resume:{power_session.id}:{action_key[-12:]}",
                        deadline_at=None,
                        actor={"kind": "human", "id": requested_by},
                    )
                    session.add(
                        PowerPiSteerRow(
                            id=steer_id,
                            run_id=run_id,
                            session_id=power_session.id,
                            job_id=job.id,
                            message=message,
                            message_digest=message_digest,
                            state="queued",
                            idempotency_key=f"power-candidate-review-resume:{power_session.id}:{action_key[-12:]}",
                            requested_by=requested_by,
                            created_at=now,
                            applied_at=None,
                        )
                    )
                    await self._append_event_row(
                        session,
                        run_id,
                        "power.pi.steer.queued",
                        {"steer_id": steer_id, "session_id": power_session.id, "job_id": job.id},
                        actor={"kind": "human", "id": requested_by},
                        idempotency_key=f"power-candidate-review-resume-steer:{steer_id}",
                    )
                await self._append_event_row(
                    session,
                    run_id,
                    "power.candidate.review.rejected",
                    {
                        "summary": "Operator rejected the runtime candidate; racers resumed.",
                        "racer_count": len(racers),
                    },
                    actor={"kind": "human", "id": requested_by},
                    idempotency_key=action_key,
                )
                return {"resumed": True, "racer_count": len(racers)}

    async def _append_event_row(
        self,
        session: AsyncSession,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor: dict[str, str],
        idempotency_key: str,
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> EventRow:
        if not _EVENT_TYPE.fullmatch(event_type):
            raise ValueError("invalid_event_type")
        _validate_idempotency_key(idempotency_key)
        _validate_actor(actor)
        safe_payload = redact_event_payload(payload)
        if not isinstance(safe_payload, dict):
            raise ValueError("event_payload_must_be_object")
        encoded_payload = canonical_json(safe_payload)
        if len(encoded_payload) > _MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError("event_payload_too_large")
        payload_sha256 = hashlib.sha256(encoded_payload).hexdigest()
        # Lock before checking idempotency. If two processes race with the same
        # key, the waiter must query after the winner commits rather than hit the
        # unique constraint with a stale pre-lock read.
        sequence_row = await session.get(RunSequenceRow, run_id, with_for_update=True)
        if sequence_row is None:
            raise ValueError("run_not_found")
        duplicate = await session.scalar(
            select(EventRow).where(
                EventRow.run_id == run_id,
                EventRow.idempotency_key == idempotency_key,
            )
        )
        if duplicate is not None:
            if (
                duplicate.event_type != event_type
                or duplicate.payload_sha256 != payload_sha256
                or duplicate.actor != actor
            ):
                raise ValueError("idempotency_conflict")
            return duplicate
        previous_hash = ""
        if sequence_row.current > 0:
            previous = await session.scalar(
                select(EventRow).where(
                    EventRow.run_id == run_id,
                    EventRow.sequence == sequence_row.current,
                )
            )
            if previous is None:
                raise ValueError("event_chain_missing_previous_event")
            previous_hash = previous.event_hash
            if previous_hash and not _SHA256.fullmatch(previous_hash):
                raise ValueError("event_chain_corrupt")
        sequence_row.current += 1
        event_id = new_id("evt")
        created_at = utc_now()
        event_hash = _event_chain_hash(
            previous_hash=previous_hash,
            payload=encoded_payload,
            metadata={
                "event_id": event_id,
                "run_id": run_id,
                "sequence": sequence_row.current,
                "event_type": event_type,
                "schema_version": 1,
                "actor": actor,
                "correlation_id": correlation_id,
                "causation_id": causation_id,
                "idempotency_key": idempotency_key,
                "created_at": _iso(created_at),
            },
        )
        row = EventRow(
            event_id=event_id,
            run_id=run_id,
            sequence=sequence_row.current,
            event_type=event_type,
            schema_version=1,
            actor=actor,
            correlation_id=correlation_id,
            causation_id=causation_id,
            idempotency_key=idempotency_key,
            payload=safe_payload,
            payload_sha256=payload_sha256,
            prev_hash=previous_hash,
            event_hash=event_hash,
            created_at=created_at,
        )
        session.add(row)
        # An outbox record is emitted inside the same transaction as its
        # immutable event. Consumers can safely retry publication using the
        # event ID without asking a model to recreate the mutation.
        session.add(
            OutboxRow(
                id=new_id("outbox"),
                run_id=run_id,
                event_id=event_id,
                event_type=event_type,
                payload_ref=f"event:{event_id}",
                payload_digest=payload_sha256,
                published_at=None,
                attempts=0,
                created_at=created_at,
            )
        )
        return row

    async def transition_run(
        self,
        run_id: str,
        status: str,
        *,
        actor: dict[str, str],
        reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Compatibility transition that keeps its historical event names."""

        return await self._transition_run(
            run_id,
            status,
            actor=actor,
            reason=reason,
            idempotency_key=idempotency_key,
            event_type=f"run.{status}",
            include_target_status=False,
        )

    async def transition_run_state(
        self,
        run_id: str,
        status: str,
        *,
        actor: dict[str, str],
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Transition through the durable kernel's canonical state event."""

        return await self._transition_run(
            run_id,
            status,
            actor=actor,
            reason=reason,
            idempotency_key=idempotency_key,
            event_type="run.state.changed",
            include_target_status=True,
        )

    async def complete_power_flag(
        self,
        *,
        run_id: str,
        flag_sha256: str,
        masked_flag: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        """Record P2's only completion path after independent observation checking.

        The flag-router has already re-read immutable sandbox output and keeps
        the raw candidate out of this method. The resulting event and run row
        contain only a digest, safe masked preview and observation reference.
        """

        if (
            not _SHA256.fullmatch(flag_sha256)
            or not _SHA256.fullmatch(observation_sha256)
            or not observation_artifact_id.startswith("sha256:")
            or observation_artifact_id.removeprefix("sha256:") != observation_sha256
            or not 1 <= len(masked_flag) <= 128
        ):
            raise ValueError("power_flag_completion_invalid")
        idempotency_key = f"power-flag:{flag_sha256}:{observation_sha256}"
        result = {
            "profile": "power",
            "verifier": "flag-router",
            "flag_sha256": flag_sha256,
            "masked_flag": masked_flag,
            "observation_artifact_id": observation_artifact_id,
            "observation_sha256": observation_sha256,
        }
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                row = await session.get(RunRow, run_id, with_for_update=True)
                if row is None:
                    raise ValueError("run_not_found")
                if row.status == "solved":
                    if row.result == result:
                        return True
                    raise ValueError("power_flag_completion_conflict")
                # A candidate-gated Power run is paused precisely so a local
                # operator can select one observed value. The independent
                # flag-router may complete that reviewed value, while model
                # tools remain fenced until the operator rejects and resumes.
                if row.status not in {"running", "paused"}:
                    raise ValueError("power_flag_run_not_active")
                row.status = "solved"
                row.result = result
                row.updated_at = utc_now()
                await self._append_event_row(
                    session,
                    run_id,
                    "power.flag.verified",
                    result,
                    actor={"kind": "verifier", "id": "flag-router"},
                    idempotency_key=idempotency_key,
                )
        return True

    async def list_run_branches(self, run_id: str) -> list[dict[str, Any]]:
        """Return scheduler metadata without exposing any Pi transcript."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(RunBranchRow)
                    .where(RunBranchRow.run_id == run_id)
                    .order_by(RunBranchRow.created_at, RunBranchRow.id)
                )
            ).all()
            return [self._run_branch(row) for row in rows]

    async def list_hint_cards(self, run_id: str) -> list[dict[str, Any]]:
        """List local operator cards, including notes marked as untrusted data."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(HintCardRow)
                    .where(HintCardRow.run_id == run_id)
                    .order_by(HintCardRow.created_at, HintCardRow.id)
                )
            ).all()
            return [self._hint_card(row) for row in rows]

    async def create_hint_card(
        self,
        card: HintCard,
        *,
        template: HintTemplate,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist one active human hypothesis and apply its fixed scheduler effect.

        The API supplies only a catalog-selected template plus a typed card.
        This repository never interprets the free-text note when it creates a
        branch, task, context, or event payload.
        """

        _validate_idempotency_key(idempotency_key)
        if card.run_id == "" or card.status is not HintStatus.ACTIVE:
            raise ValueError("hint_card_initial_status_invalid")
        if (
            card.template_id != template.id
            or card.template_version != template.version
            or card.technique_id != template.technique_id
            or card.category != template.category
        ):
            raise ValueError("hint_template_card_mismatch")
        async with self._run_locks[card.run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, card.run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status not in {"running", "paused"}:
                    raise ValueError("hint_card_run_not_active")
                existing = await session.scalar(
                    select(HintCardRow)
                    .where(
                        HintCardRow.run_id == card.run_id,
                        HintCardRow.idempotency_key == idempotency_key,
                    )
                    .with_for_update()
                )
                if existing is not None:
                    if not self._hint_card_matches_create(existing, card):
                        raise ValueError("idempotency_conflict")
                    return self._hint_card(existing)
                row = HintCardRow(
                    id=card.id,
                    run_id=card.run_id,
                    template_id=card.template_id,
                    template_version=card.template_version,
                    technique_id=card.technique_id,
                    category=card.category.value,
                    directive=card.directive.value,
                    target_ref=card.target_ref,
                    priority=card.priority,
                    note=card.note,
                    epistemic_status=card.epistemic_status,
                    status=card.status.value,
                    evidence_refs=list(card.evidence_refs),
                    actor_id=card.actor_id,
                    idempotency_key=idempotency_key,
                    created_at=card.created_at,
                    updated_at=card.updated_at,
                )
                session.add(row)
                # Never put the note into an append-only event. The digest is
                # enough to audit the exact UI mutation without turning its
                # untrusted prose into runner-visible prompt material.
                await self._append_event_row(
                    session,
                    card.run_id,
                    "human.hint_card.added",
                    self._hint_event_payload(row, action="added"),
                    actor={"kind": "human", "id": card.actor_id},
                    idempotency_key=f"hint:{row.id}:added",
                )
                await self._apply_hint_scheduler_effect(
                    session, run=run, card=row, template=template
                )
                await self._queue_hint_state_notice(
                    session,
                    run=run,
                    hint_id=row.id,
                    event_key="added",
                )
        return self._hint_card(row)

    async def update_hint_card(
        self,
        run_id: str,
        hint_id: str,
        *,
        directive: HintDirective,
        target_ref: str,
        priority: int,
        note: str,
        template: HintTemplate,
        idempotency_key: str,
        actor_id: str,
    ) -> dict[str, Any]:
        """Revise an active card without allowing the operator to assert facts."""

        _validate_idempotency_key(idempotency_key)
        _validate_lease_owner(actor_id)
        now = utc_now()
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status not in {"running", "paused"}:
                    raise ValueError("hint_card_run_not_active")
                row = await session.get(HintCardRow, hint_id, with_for_update=True)
                if row is None or row.run_id != run_id:
                    raise ValueError("hint_card_not_found")
                if row.status != HintStatus.ACTIVE.value:
                    raise ValueError("hint_card_not_active")
                if row.template_id != template.id or row.template_version != template.version:
                    raise ValueError("hint_template_card_mismatch")
                # Construct through the strict domain model before mutating
                # storage so the 500-character / secret-free note invariant is
                # identical for create and patch paths.
                updated = HintCard(
                    id=row.id,
                    run_id=row.run_id,
                    template_id=row.template_id,
                    template_version=row.template_version,
                    technique_id=row.technique_id,
                    category=HintCategory(row.category),
                    directive=directive,
                    target_ref=target_ref,
                    priority=priority,
                    note=note,
                    status=HintStatus(row.status),
                    evidence_refs=tuple(row.evidence_refs),
                    actor_id=actor_id,
                    created_at=_stored_utc(row.created_at),
                    updated_at=now,
                )
                payload = self._hint_event_payload_from_card(updated, action="updated")
                previous_event = await session.scalar(
                    select(EventRow).where(
                        EventRow.run_id == run_id,
                        EventRow.idempotency_key == idempotency_key,
                    )
                )
                if previous_event is not None:
                    if (
                        previous_event.event_type != "human.hint_card.updated"
                        or previous_event.payload.get("request_digest") != payload["request_digest"]
                    ):
                        raise ValueError("idempotency_conflict")
                    return self._hint_card(row)
                row.directive = updated.directive.value
                row.target_ref = updated.target_ref
                row.priority = updated.priority
                row.note = updated.note
                row.actor_id = updated.actor_id
                row.updated_at = now
                await self._append_event_row(
                    session,
                    run_id,
                    "human.hint_card.updated",
                    payload,
                    actor={"kind": "human", "id": actor_id},
                    idempotency_key=idempotency_key,
                )
                await self._apply_hint_scheduler_effect(
                    session, run=run, card=row, template=template
                )
                await self._queue_hint_state_notice(
                    session,
                    run=run,
                    hint_id=row.id,
                    event_key=f"updated:{hashlib.sha256(payload['request_digest'].encode()).hexdigest()[:16]}",
                )
        return self._hint_card(row)

    async def dismiss_hint_card(
        self,
        run_id: str,
        hint_id: str,
        *,
        idempotency_key: str,
        actor_id: str,
    ) -> dict[str, Any]:
        """Soft-dismiss a card while retaining both the row and audit event."""

        _validate_idempotency_key(idempotency_key)
        _validate_lease_owner(actor_id)
        now = utc_now()
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status not in {"running", "paused"}:
                    raise ValueError("hint_card_run_not_active")
                row = await session.get(HintCardRow, hint_id, with_for_update=True)
                if row is None or row.run_id != run_id:
                    raise ValueError("hint_card_not_found")
                previous_event = await session.scalar(
                    select(EventRow).where(
                        EventRow.run_id == run_id,
                        EventRow.idempotency_key == idempotency_key,
                    )
                )
                if previous_event is not None:
                    if previous_event.event_type != "human.hint_card.updated":
                        raise ValueError("idempotency_conflict")
                    return self._hint_card(row)
                if row.status == HintStatus.ACTIVE.value:
                    row.status = HintStatus.DISMISSED.value
                    row.actor_id = actor_id
                    row.updated_at = now
                elif row.status != HintStatus.DISMISSED.value:
                    raise ValueError("hint_card_not_dismissable")
                payload = self._hint_event_payload(row, action="dismissed")
                await self._append_event_row(
                    session,
                    run_id,
                    "human.hint_card.updated",
                    payload,
                    actor={"kind": "human", "id": actor_id},
                    idempotency_key=idempotency_key,
                )
                await self._queue_hint_state_notice(
                    session,
                    run=run,
                    hint_id=row.id,
                    event_key="dismissed",
                )
        return self._hint_card(row)

    async def _transition_run(
        self,
        run_id: str,
        status: str,
        *,
        actor: dict[str, str],
        reason: str | None,
        idempotency_key: str | None,
        event_type: str,
        include_target_status: bool,
    ) -> dict[str, Any]:
        if status == "solved":
            raise ValueError("solved_requires_verified_replay")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                row = await session.get(RunRow, run_id, with_for_update=True)
                if row is None:
                    raise ValueError("run_not_found")
                if idempotency_key is not None:
                    previous_event = await session.scalar(
                        select(EventRow).where(
                            EventRow.run_id == run_id,
                            EventRow.idempotency_key == idempotency_key,
                        )
                    )
                    if previous_event is not None:
                        if previous_event.event_type != event_type:
                            raise ValueError("idempotency_conflict")
                        return self._run(row)
                if status not in _RUN_TRANSITIONS.get(row.status, set()):
                    raise ValueError(f"invalid_run_transition:{row.status}:{status}")
                previous = row.status
                row.status = status
                row.updated_at = utc_now()
                payload: dict[str, Any] = {"previous_status": previous, "reason": reason}
                if include_target_status:
                    payload["status"] = status
                await self._append_event_row(
                    session,
                    run_id,
                    event_type,
                    payload,
                    actor=actor,
                    idempotency_key=idempotency_key or f"transition:{uuid4().hex}",
                )
                if previous == "paused" and status == "running":
                    # Queued hint/state notices intentionally survive a pause.
                    # Re-expose them only after the run becomes runnable, at
                    # the same idle-safe boundary used for human steering.
                    ready_sessions = (
                        await session.scalars(
                            select(AgentSessionRow)
                            .where(
                                AgentSessionRow.run_id == run_id,
                                AgentSessionRow.state == AgentSessionState.READY.value,
                            )
                            .order_by(AgentSessionRow.created_at, AgentSessionRow.id)
                        )
                    ).all()
                    for agent_session in ready_sessions:
                        await self._enqueue_pending_agent_steers(
                            session,
                            agent_session=agent_session,
                            actor={"kind": "system", "id": "run-engine"},
                        )
        return self._run(row)

    @staticmethod
    def _hint_card_matches_create(row: HintCardRow, card: HintCard) -> bool:
        """Compare retry payloads without making generated IDs/timestamps authority."""

        return (
            row.template_id == card.template_id
            and row.template_version == card.template_version
            and row.technique_id == card.technique_id
            and row.category == card.category.value
            and row.directive == card.directive.value
            and row.target_ref == card.target_ref
            and row.priority == card.priority
            and row.note == card.note
            and row.epistemic_status == card.epistemic_status
            and row.status == card.status.value
            and tuple(row.evidence_refs) == tuple(card.evidence_refs)
            and row.actor_id == card.actor_id
        )

    @staticmethod
    def _hint_event_payload_from_card(card: HintCard, *, action: str) -> dict[str, Any]:
        """Build an audit payload that deliberately excludes the raw note."""

        note_digest = hashlib.sha256(card.note.encode("utf-8")).hexdigest()
        request = {
            "template_id": card.template_id,
            "template_version": card.template_version,
            "technique_id": card.technique_id,
            "category": card.category.value,
            "directive": card.directive.value,
            "target_ref": card.target_ref,
            "priority": card.priority,
            "status": card.status.value,
            "evidence_refs": list(card.evidence_refs),
            "note_sha256": note_digest,
            "action": action,
        }
        return {
            "hint_id": card.id,
            **request,
            # A request digest makes updates idempotent without retaining the
            # operator prose in an immutable event/outbox record.
            "request_digest": digest_json(request),
        }

    def _hint_event_payload(self, row: HintCardRow, *, action: str) -> dict[str, Any]:
        """Adapt one stored card to its secret-free event representation."""

        return self._hint_event_payload_from_card(self._hint_card_model(row), action=action)

    async def _apply_hint_scheduler_effect(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        card: HintCardRow,
        template: HintTemplate,
    ) -> None:
        """Apply only the fixed M4 effects associated with a template directive."""

        directive = HintDirective(card.directive)
        if directive is HintDirective.AVOID:
            # An avoid card cannot retroactively erase evidence. It suspends
            # matching queued work and the gateway separately denies a future
            # tool dispatch even if a worker was already leased.
            branch_filters = [
                RunBranchRow.run_id == run.id,
                RunBranchRow.technique_id == card.technique_id,
                RunBranchRow.state == "active",
            ]
            if card.target_ref != "run:all":
                branch_filters.append(RunBranchRow.branch_scope == card.target_ref)
            branches = (
                await session.scalars(select(RunBranchRow).where(*branch_filters).with_for_update())
            ).all()
            for branch in branches:
                branch.state = "suspended"
                branch.updated_at = utc_now()
                await self._append_event_row(
                    session,
                    run.id,
                    "branch.suspended",
                    {"branch_id": branch.id, "reason": "active_avoid_hint", "hint_id": card.id},
                    actor={"kind": "system", "id": "scheduler"},
                    idempotency_key=f"branch:{branch.id}:avoid:{card.id}",
                )
            task_filters = [
                WorkerTaskRow.run_id == run.id,
                WorkerTaskRow.technique_id == card.technique_id,
                WorkerTaskRow.state == "queued",
            ]
            if card.target_ref != "run:all":
                task_filters.append(WorkerTaskRow.branch_scope == card.target_ref)
            queued_tasks = (
                await session.scalars(select(WorkerTaskRow).where(*task_filters).with_for_update())
            ).all()
            for task in queued_tasks:
                task.state = "cancelled"
                task.updated_at = utc_now()
                start_job = await session.scalar(
                    select(AgentJobRow)
                    .where(
                        AgentJobRow.run_id == run.id,
                        AgentJobRow.kind == AgentJobKind.START_SESSION.value,
                        AgentJobRow.payload_ref == f"context:{task.context_manifest_id}",
                        AgentJobRow.state == "queued",
                    )
                    .with_for_update()
                )
                if start_job is not None:
                    start_job.state = "cancelled"
                    start_job.updated_at = utc_now()
                    await self._append_event_row(
                        session,
                        run.id,
                        "agent.job.cancelled",
                        {
                            "job_id": start_job.id,
                            "kind": start_job.kind,
                            "reason": "active_avoid_hint",
                            "hint_id": card.id,
                        },
                        actor={"kind": "system", "id": "scheduler"},
                        idempotency_key=f"job:{start_job.id}:avoid:{card.id}",
                    )
                await self._append_event_row(
                    session,
                    run.id,
                    "task.cancelled",
                    {"task_id": task.id, "reason": "active_avoid_hint", "hint_id": card.id},
                    actor={"kind": "system", "id": "scheduler"},
                    idempotency_key=f"task:{task.id}:avoid:{card.id}",
                )
            return

        matching_branch_filters = [
            RunBranchRow.run_id == run.id,
            RunBranchRow.technique_id == card.technique_id,
            RunBranchRow.state == "active",
        ]
        if card.target_ref != "run:all":
            matching_branch_filters.append(RunBranchRow.branch_scope == card.target_ref)
        matching_branches = (
            await session.scalars(
                select(RunBranchRow).where(*matching_branch_filters).with_for_update()
            )
        ).all()
        if directive is HintDirective.PRIORITIZE:
            for branch in matching_branches:
                previous = branch.priority
                branch.priority = max(previous, card.priority / 5.0)
                branch.updated_at = utc_now()
                await self._append_event_row(
                    session,
                    run.id,
                    "branch.prioritized",
                    {
                        "branch_id": branch.id,
                        "hint_id": card.id,
                        "previous_priority": previous,
                        "priority": branch.priority,
                    },
                    actor={"kind": "system", "id": "scheduler"},
                    idempotency_key=f"branch:{branch.id}:hint-priority:{card.id}",
                )
            if matching_branches:
                return

        # Explore/require_probe create an initial bounded branch. A prioritize
        # card seeds one only when the portfolio does not yet contain that
        # technique, which keeps the UI action meaningful after preflight.
        await self._enqueue_hint_scheduler_task(session, run=run, card=card, template=template)

    async def _enqueue_hint_scheduler_task(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        card: HintCardRow,
        template: HintTemplate,
    ) -> None:
        """Create at most one reviewed worker task from a HintTemplate.

        This is the scheduler's only task-creation path that bypasses a master
        request.  It builds all IDs, context, fingerprints, and tool allowlists
        itself and never consumes ``card.note``.
        """

        observations = (
            await session.scalars(
                select(PreflightObservationRow)
                .where(PreflightObservationRow.run_id == run.id)
                .order_by(PreflightObservationRow.created_at, PreflightObservationRow.id)
                .limit(4)
            )
        ).all()
        if not observations:
            await self._append_hint_scheduler_deferred(
                session, run.id, card, "preflight_evidence_missing"
            )
            return
        active_tasks = (
            await session.scalars(
                select(WorkerTaskRow)
                .where(
                    WorkerTaskRow.run_id == run.id,
                    WorkerTaskRow.role != AgentRole.MASTER.value,
                    WorkerTaskRow.state.in_(["queued", "leased"]),
                )
                .with_for_update()
            )
        ).all()
        if len(active_tasks) >= _MAX_ACTIVE_WORKER_BRANCHES:
            await self._append_hint_scheduler_deferred(
                session, run.id, card, "worker_capacity_reached"
            )
            return
        active_roles = {task.role for task in active_tasks}
        candidates = list(template.recommended_roles)
        if HintDirective(card.directive) is HintDirective.REQUIRE_PROBE:
            # A bounded probe should prefer the reviewed HTTP role when it is
            # available; otherwise the source role can establish the control.
            candidates.sort(key=lambda role: role is not AgentRole.HTTP_TESTER)
        role = next(
            (candidate for candidate in candidates if candidate.value not in active_roles), None
        )
        if role is None:
            await self._append_hint_scheduler_deferred(
                session, run.id, card, "role_diversity_required"
            )
            return
        challenge = await session.get(ChallengeRow, run.challenge_id)
        if challenge is None:
            raise ValueError("challenge_not_found")
        evidence_ids = tuple(observation.id for observation in observations)
        fingerprint = self._scheduler_attempt_fingerprint(
            tool_id="scheduler.hint_template",
            challenge_digest=challenge.digest,
            branch_scope=card.target_ref,
            canonical_input={
                "template_id": template.id,
                "template_version": template.version,
                "directive": card.directive,
                "role": role.value,
                "evidence_ids": list(evidence_ids),
            },
        )
        previous = await session.scalar(
            select(WorkerTaskRow).where(
                WorkerTaskRow.run_id == run.id,
                WorkerTaskRow.attempt_fingerprint == fingerprint,
            )
        )
        if previous is not None:
            await self._append_hint_scheduler_deferred(
                session, run.id, card, "attempt_fingerprint_exists"
            )
            return
        now = utc_now()
        raw_wall_limit = run.budget.get("wall_time_seconds", 300)
        wall_limit = (
            int(raw_wall_limit)
            if isinstance(raw_wall_limit, int | float) and not isinstance(raw_wall_limit, bool)
            else 300
        )
        deadline = now + timedelta(seconds=min(max(wall_limit, 1), 900))
        requires_control = HintDirective(card.directive) is HintDirective.REQUIRE_PROBE
        objective = template.branch_seed
        if requires_control:
            objective = f"{objective} Include one control: {template.falsifiers[0]}."
        context_id = new_id("ctx")
        task_id = new_id("task")
        branch_id = new_id("branch")
        active_hint_refs = await self._active_hint_refs(
            session,
            run_id=run.id,
            technique_id=card.technique_id,
            branch_scope=card.target_ref,
        )
        context = ContextManifest.issue(
            id=context_id,
            run_id=run.id,
            task_id=task_id,
            challenge_digest=challenge.digest,
            role=role.value,
            objective=objective,
            allowed_tool_ids=agent_role_tool_ids(role),
            evidence_refs=tuple(
                ContextEvidenceRef(
                    observation_id=observation.id,
                    artifact_id=observation.artifact_id,
                    digest=observation.digest,
                )
                for observation in observations
            ),
            hypothesis_refs=(),
            # Cards enter context only as immutable IDs. Their optional note
            # remains UI/state data rather than a system-prompt instruction.
            active_hint_refs=active_hint_refs,
            attempt_fingerprints=(fingerprint,),
            budget_slice=ContextBudgetSlice(
                tool_calls=min(4, int(run.budget.get("max_tool_calls", 4))),
                input_tokens=6_000,
                output_tokens=1_200,
            ),
            created_at=now,
            expires_at=deadline,
        )
        encoded_context = canonical_json(context.model_dump(mode="json", by_alias=True))
        if len(encoded_context) > _MAX_CONTEXT_MANIFEST_BYTES:
            raise ValueError("context_manifest_too_large")
        family = f"m4-{role.value}-{fingerprint[:24]}"
        session.add(
            ContextManifestRow(
                id=context.id,
                run_id=context.run_id,
                task_id=context.task_id,
                document=encoded_context.decode("utf-8"),
                digest=context.digest,
                size_bytes=len(encoded_context),
                expires_at=context.expires_at,
                created_at=context.created_at,
            )
        )
        session.add(
            RunBranchRow(
                id=branch_id,
                run_id=run.id,
                family=family,
                state="active",
                technique_id=card.technique_id,
                branch_scope=card.target_ref,
                priority=card.priority / 5.0,
                novelty=1.0,
                evidence_strength=min(1.0, len(observations) / 4.0),
                expected_value=0.8 if requires_control else 0.6,
                normalized_cost=0.5 if role is AgentRole.HTTP_TESTER else 0.25,
                repetition_penalty=0.0,
                consecutive_no_observation=0,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            WorkerTaskRow(
                id=task_id,
                run_id=run.id,
                branch_id=branch_id,
                role=role.value,
                objective=objective,
                required_evidence=list(evidence_ids),
                context_manifest_id=context.id,
                technique_id=card.technique_id,
                branch_scope=card.target_ref,
                attempt_fingerprint=fingerprint,
                state="queued",
                lease_owner=None,
                lease_version=0,
                lease_expires_at=None,
                attempts=0,
                deadline_at=deadline,
                created_at=now,
                updated_at=now,
            )
        )
        start_job = await self._enqueue_agent_job_row(
            session,
            run_id=run.id,
            kind=AgentJobKind.START_SESSION.value,
            payload_ref=f"context:{context.id}",
            payload_digest=context.digest,
            idempotency_key=f"pi-session:{task_id}:v1",
            deadline_at=deadline,
            actor={"kind": "system", "id": "scheduler"},
        )
        await self._append_event_row(
            session,
            run.id,
            "branch.created",
            {
                "branch_id": branch_id,
                "family": family,
                "technique_id": card.technique_id,
                "hint_id": card.id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"branch:{branch_id}:created",
        )
        await self._append_event_row(
            session,
            run.id,
            "task.queued",
            {
                "task_id": task_id,
                "branch_id": branch_id,
                "context_manifest_id": context.id,
                "attempt_fingerprint": fingerprint,
                "hint_id": card.id,
                "session_job_id": start_job.id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"task:{task_id}:queued",
        )

    async def _append_hint_scheduler_deferred(
        self,
        session: AsyncSession,
        run_id: str,
        card: HintCardRow,
        reason: str,
    ) -> None:
        """Explain a bounded scheduler refusal in the immutable event stream."""

        await self._append_event_row(
            session,
            run_id,
            "hint.scheduler.deferred",
            {
                "hint_id": card.id,
                "technique_id": card.technique_id,
                "directive": card.directive,
                "reason": reason,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"hint:{card.id}:scheduler:{reason}",
        )

    async def _active_hint_refs(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        technique_id: str,
        branch_scope: str,
    ) -> tuple[str, ...]:
        """Return card IDs only; the raw note never belongs in a manifest."""

        rows = (
            await session.scalars(
                select(HintCardRow)
                .where(
                    HintCardRow.run_id == run_id,
                    HintCardRow.technique_id == technique_id,
                    HintCardRow.status == _HINT_ACTIVE_STATUS,
                    HintCardRow.target_ref.in_(["run:all", branch_scope]),
                )
                .order_by(HintCardRow.priority.desc(), HintCardRow.created_at, HintCardRow.id)
                .limit(32)
            )
        ).all()
        return tuple(row.id for row in rows)

    async def _has_active_avoid_hint(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        technique_id: str,
        branch_scope: str,
    ) -> bool:
        """Check the persistent avoid gate before creating/dispatching work."""

        row = await session.scalar(
            select(HintCardRow.id)
            .where(
                HintCardRow.run_id == run_id,
                HintCardRow.technique_id == technique_id,
                HintCardRow.directive == HintDirective.AVOID.value,
                HintCardRow.status == HintStatus.ACTIVE.value,
                HintCardRow.target_ref.in_(["run:all", branch_scope]),
            )
            .limit(1)
        )
        return row is not None

    @staticmethod
    def _scheduler_attempt_fingerprint(
        *,
        tool_id: str,
        challenge_digest: str,
        branch_scope: str,
        canonical_input: Mapping[str, Any],
    ) -> str:
        """Use the execution plan's canonical task/attempt fingerprint shape."""

        return hashlib.sha256(
            tool_id.encode("utf-8")
            + b"\x00"
            + challenge_digest.encode("ascii")
            + b"\x00"
            + branch_scope.encode("utf-8")
            + b"\x00"
            + canonical_json(dict(canonical_input))
        ).hexdigest()

    async def _queue_hint_state_notice(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        hint_id: str,
        event_key: str,
    ) -> None:
        """Wake the master at a safe boundary without delivering a raw note."""

        master = await session.scalar(
            select(AgentSessionRow)
            .where(
                AgentSessionRow.run_id == run.id,
                AgentSessionRow.role == AgentRole.MASTER.value,
                AgentSessionRow.state.in_(
                    [AgentSessionState.READY.value, AgentSessionState.RUNNING.value]
                ),
            )
            .order_by(AgentSessionRow.created_at.desc(), AgentSessionRow.id)
            .limit(1)
            .with_for_update()
        )
        if master is None:
            return
        message = "Hint state changed; call state.get."
        message_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
        notice_key = (
            f"hint-state:{hashlib.sha256(f'{hint_id}:{event_key}'.encode()).hexdigest()[:32]}"
        )
        existing = await session.scalar(
            select(AgentSteerRow).where(
                AgentSteerRow.run_id == run.id,
                AgentSteerRow.idempotency_key == notice_key,
            )
        )
        if existing is not None:
            return
        steer = AgentSteerRow(
            id=new_id("steer"),
            run_id=run.id,
            session_id=master.id,
            message=message,
            message_digest=message_digest,
            state="queued",
            idempotency_key=notice_key,
            requested_by="scheduler",
            created_at=utc_now(),
            applied_at=None,
        )
        session.add(steer)
        await self._append_event_row(
            session,
            run.id,
            "hint.state.notice_queued",
            {"hint_id": hint_id, "session_id": master.id, "steer_id": steer.id},
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"hint:{hint_id}:notice:{event_key}",
        )
        await self._enqueue_pending_agent_steers(
            session,
            agent_session=master,
            actor={"kind": "system", "id": "scheduler"},
        )

    async def _complete_branch_from_task(
        self,
        session: AsyncSession,
        *,
        task: WorkerTaskRow,
        confidence: float,
        observed: bool,
    ) -> None:
        """Close or stall a branch after one bounded worker-task outcome."""

        branch = await session.get(RunBranchRow, task.branch_id, with_for_update=True)
        if branch is None or branch.run_id != task.run_id:
            raise ValueError("task_branch_missing")
        previous_state = branch.state
        if observed:
            branch.state = "completed"
            branch.evidence_strength = max(branch.evidence_strength, confidence)
            branch.consecutive_no_observation = 0
        else:
            branch.consecutive_no_observation += 1
            if branch.consecutive_no_observation >= _STALL_TURN_THRESHOLD:
                branch.state = "stalled"
        branch.updated_at = utc_now()
        if branch.state != previous_state:
            await self._append_event_row(
                session,
                task.run_id,
                "branch.completed" if branch.state == "completed" else "branch.stalled",
                {
                    "branch_id": branch.id,
                    "state": branch.state,
                    "consecutive_no_observation": branch.consecutive_no_observation,
                },
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"branch:{branch.id}:{branch.state}:{task.id}",
            )

    async def _advance_master_stall(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        agent_session: AgentSessionRow,
        task: WorkerTaskRow,
    ) -> None:
        """Retry one empty master turn, then select a bounded fallback.

        A master message with no reviewed control call is not a reliable
        scheduling decision.  One retry lets a transient model/schema issue
        recover without making the model's prose authoritative.  After the
        second observation-free turn, the kernel selects a fixed source/HTTP
        review task from an active Hint Card.  It never invents a technique
        from raw model text, and safely records a defer when no reviewed card
        exists to justify a fallback.
        """

        branch = await session.get(RunBranchRow, task.branch_id, with_for_update=True)
        if branch is None or branch.run_id != run_id:
            raise ValueError("master_stall_branch_missing")
        recent_events = (
            await session.scalars(
                select(EventRow)
                .where(
                    EventRow.run_id == run_id,
                    EventRow.event_type == "agent.task.delegated",
                )
                .order_by(EventRow.sequence.desc())
                .limit(32)
            )
        ).all()
        # A valid delegation is not a schema stall merely because a master
        # also returned prose.  The immutable control event, not the prose,
        # is the source of truth for this distinction.
        if any(
            event.payload.get("parent_session_id") == agent_session.id for event in recent_events
        ):
            return
        if branch.consecutive_no_observation < _STALL_TURN_THRESHOLD:
            context_row = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            if context_row is None:
                raise ValueError("master_stall_context_missing")
            context = self._context_manifest_from_row(context_row)
            retry = await self._enqueue_agent_job_row(
                session,
                run_id=run_id,
                kind=AgentJobKind.RUN_TURN.value,
                payload_ref=f"session:{agent_session.id}",
                payload_digest=context.digest,
                idempotency_key=(
                    f"pi-turn:{agent_session.id}:master-stall:{branch.consecutive_no_observation}"
                ),
                deadline_at=None,
                actor={"kind": "system", "id": "scheduler"},
            )
            await self._append_event_row(
                session,
                run_id,
                "scheduler.master.retry_queued",
                {
                    "branch_id": branch.id,
                    "session_id": agent_session.id,
                    "job_id": retry.id,
                    "consecutive_no_observation": branch.consecutive_no_observation,
                },
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=(
                    f"master-stall:{branch.id}:retry:{branch.consecutive_no_observation}"
                ),
            )
            return
        await self._enqueue_deterministic_fallback(
            session,
            run_id=run_id,
            source_task=task,
        )

    async def _enqueue_deterministic_fallback(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        source_task: WorkerTaskRow,
    ) -> None:
        """Create one static evidence-review task after a master stall.

        The candidate card is ranked from persisted metadata only.  Free-form
        notes are intentionally absent from the objective, fingerprint,
        events, and ContextManifest.  With no active card, refusing to invent
        a technique is the correct deterministic fallback.
        """

        cards = (
            await session.scalars(
                select(HintCardRow)
                .where(
                    HintCardRow.run_id == run_id,
                    HintCardRow.status == HintStatus.ACTIVE.value,
                    HintCardRow.directive != HintDirective.AVOID.value,
                )
                .order_by(HintCardRow.priority.desc(), HintCardRow.created_at, HintCardRow.id)
                .with_for_update()
            )
        ).all()
        if not cards:
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "active_reviewed_hint_required", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:no-active-hint",
            )
            return
        observations = (
            await session.scalars(
                select(PreflightObservationRow)
                .where(PreflightObservationRow.run_id == run_id)
                .order_by(PreflightObservationRow.created_at, PreflightObservationRow.id)
                .limit(4)
            )
        ).all()
        if not observations:
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "preflight_evidence_missing", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:no-preflight-evidence",
            )
            return
        active_workers = (
            await session.scalars(
                select(WorkerTaskRow)
                .where(
                    WorkerTaskRow.run_id == run_id,
                    WorkerTaskRow.role != AgentRole.MASTER.value,
                    WorkerTaskRow.state.in_(["queued", "leased"]),
                )
                .with_for_update()
            )
        ).all()
        if len(active_workers) >= _MAX_ACTIVE_WORKER_BRANCHES:
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "worker_capacity_reached", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:worker-capacity",
            )
            return

        # Source review is lower-cost by default; a probe-required card moves
        # HTTP first.  A currently active role is excluded to preserve the
        # two-worker diversity invariant.
        active_roles = {task.role for task in active_workers}
        card = cards[0]
        role_order = (
            (AgentRole.HTTP_TESTER, AgentRole.SOURCE_AUDITOR)
            if card.directive == HintDirective.REQUIRE_PROBE.value
            else (AgentRole.SOURCE_AUDITOR, AgentRole.HTTP_TESTER)
        )
        role = next((item for item in role_order if item.value not in active_roles), None)
        if role is None:
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "worker_role_diversity_required", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:role-diversity",
            )
            return
        if await self._has_active_avoid_hint(
            session,
            run_id=run_id,
            technique_id=card.technique_id,
            branch_scope=card.target_ref,
        ):
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "active_avoid_hint", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:avoid-hint",
            )
            return
        run = await self._required_run_row(session, run_id)
        challenge = await session.get(ChallengeRow, run.challenge_id)
        if challenge is None:
            raise ValueError("challenge_not_found")
        evidence_ids = tuple(item.id for item in observations)
        fingerprint = self._scheduler_attempt_fingerprint(
            tool_id="scheduler.master_fallback",
            challenge_digest=challenge.digest,
            branch_scope=card.target_ref,
            canonical_input={
                "template_id": card.template_id,
                "template_version": card.template_version,
                "technique_id": card.technique_id,
                "directive": card.directive,
                "role": role.value,
                "evidence_ids": list(evidence_ids),
            },
        )
        if (
            await session.scalar(
                select(WorkerTaskRow.id).where(
                    WorkerTaskRow.run_id == run_id,
                    WorkerTaskRow.attempt_fingerprint == fingerprint,
                )
            )
            is not None
        ):
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "attempt_fingerprint_exists", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:duplicate-attempt",
            )
            return
        now = utc_now()
        source_deadline = _stored_utc(source_task.deadline_at)
        deadline = min(source_deadline, now + timedelta(minutes=15))
        if deadline <= now:
            await self._append_event_row(
                session,
                run_id,
                "scheduler.fallback.deferred",
                {"reason": "source_deadline_expired", "source_task_id": source_task.id},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"fallback:{source_task.id}:deadline",
            )
            return
        task_id = new_id("task")
        context_id = new_id("ctx")
        branch_id = new_id("branch")
        objective = (
            f"Review sealed preflight evidence for the reviewed technique {card.technique_id}. "
            "Record one bounded control or contradiction using only reviewed tools and evidence."
        )
        context = ContextManifest.issue(
            id=context_id,
            run_id=run_id,
            task_id=task_id,
            challenge_digest=challenge.digest,
            role=role.value,
            objective=objective,
            allowed_tool_ids=agent_role_tool_ids(role),
            evidence_refs=tuple(
                ContextEvidenceRef(
                    observation_id=item.id,
                    artifact_id=item.artifact_id,
                    digest=item.digest,
                )
                for item in observations
            ),
            hypothesis_refs=(),
            active_hint_refs=await self._active_hint_refs(
                session,
                run_id=run_id,
                technique_id=card.technique_id,
                branch_scope=card.target_ref,
            ),
            attempt_fingerprints=(fingerprint,),
            budget_slice=ContextBudgetSlice(
                tool_calls=min(4, int(run.budget.get("max_tool_calls", 4))),
                input_tokens=6_000,
                output_tokens=1_200,
            ),
            created_at=now,
            expires_at=deadline,
        )
        encoded_context = canonical_json(context.model_dump(mode="json", by_alias=True))
        if len(encoded_context) > _MAX_CONTEXT_MANIFEST_BYTES:
            raise ValueError("context_manifest_too_large")
        session.add(
            ContextManifestRow(
                id=context.id,
                run_id=context.run_id,
                task_id=context.task_id,
                document=encoded_context.decode("utf-8"),
                digest=context.digest,
                size_bytes=len(encoded_context),
                expires_at=context.expires_at,
                created_at=context.created_at,
            )
        )
        session.add(
            RunBranchRow(
                id=branch_id,
                run_id=run_id,
                family=f"m4-fallback-{role.value}-{fingerprint[:24]}",
                state="active",
                technique_id=card.technique_id,
                branch_scope=card.target_ref,
                priority=card.priority / 5.0,
                novelty=1.0,
                evidence_strength=min(1.0, len(observations) / 4.0),
                expected_value=0.7,
                normalized_cost=0.5 if role is AgentRole.HTTP_TESTER else 0.25,
                repetition_penalty=0.0,
                consecutive_no_observation=0,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            WorkerTaskRow(
                id=task_id,
                run_id=run_id,
                branch_id=branch_id,
                role=role.value,
                objective=objective,
                required_evidence=list(evidence_ids),
                context_manifest_id=context.id,
                technique_id=card.technique_id,
                branch_scope=card.target_ref,
                attempt_fingerprint=fingerprint,
                state="queued",
                lease_owner=None,
                lease_version=0,
                lease_expires_at=None,
                attempts=0,
                deadline_at=deadline,
                created_at=now,
                updated_at=now,
            )
        )
        start_job = await self._enqueue_agent_job_row(
            session,
            run_id=run_id,
            kind=AgentJobKind.START_SESSION.value,
            payload_ref=f"context:{context.id}",
            payload_digest=context.digest,
            idempotency_key=f"pi-session:{task_id}:v1",
            deadline_at=deadline,
            actor={"kind": "system", "id": "scheduler"},
        )
        await self._append_event_row(
            session,
            run_id,
            "branch.created",
            {
                "branch_id": branch_id,
                "family": f"m4-fallback-{role.value}-{fingerprint[:24]}",
                "technique_id": card.technique_id,
                "hint_id": card.id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"branch:{branch_id}:created",
        )
        await self._append_event_row(
            session,
            run_id,
            "task.queued",
            {
                "task_id": task_id,
                "branch_id": branch_id,
                "context_manifest_id": context.id,
                "attempt_fingerprint": fingerprint,
                "hint_id": card.id,
                "session_job_id": start_job.id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"task:{task_id}:queued",
        )
        await self._append_event_row(
            session,
            run_id,
            "scheduler.fallback.queued",
            {
                "source_task_id": source_task.id,
                "hint_id": card.id,
                "role": role.value,
                "task_id": task_id,
                "branch_id": branch_id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"fallback:{source_task.id}:queued",
        )

    async def _resolve_active_hints_from_evidence(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        technique_id: str,
        branch_scope: str,
        outcome: HintOutcome,
        evidence_refs: tuple[str, ...],
        actor_id: str,
    ) -> None:
        """Move only a card lifecycle after a sealed worker observation.

        This deliberately does not create a fact or change run status. The
        event tells the operator which sealed evidence made the human
        hypothesis fulfilled or contradicted, while verification remains a
        separate M5 concern.
        """

        cards = (
            await session.scalars(
                select(HintCardRow)
                .where(
                    HintCardRow.run_id == run_id,
                    HintCardRow.technique_id == technique_id,
                    HintCardRow.status == HintStatus.ACTIVE.value,
                    HintCardRow.target_ref.in_(["run:all", branch_scope]),
                )
                .with_for_update()
            )
        ).all()
        for card in cards:
            card.status = outcome.value
            card.evidence_refs = list(evidence_refs)
            card.updated_at = utc_now()
            payload = self._hint_event_payload(card, action=f"evidence_{outcome.value}")
            await self._append_event_row(
                session,
                run_id,
                "hint.card.evidence_status_changed",
                payload,
                actor={"kind": "worker", "id": actor_id},
                idempotency_key=f"hint:{card.id}:evidence:{outcome.value}:{payload['request_digest'][:16]}",
            )

    async def _has_conflicting_finding(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        technique_id: str,
        disposition: str,
        exclude_finding_id: str,
    ) -> bool:
        """Detect opposite high-level observations without parsing model prose."""

        if disposition not in {"supports", "contradicts"}:
            return False
        opposite = "contradicts" if disposition == "supports" else "supports"
        events = (
            await session.scalars(
                select(EventRow)
                .where(EventRow.run_id == run_id, EventRow.event_type == "finding.submitted")
                .order_by(EventRow.sequence.desc())
                .limit(128)
            )
        ).all()
        return any(
            event.payload.get("finding_id") != exclude_finding_id
            and event.payload.get("technique_id") == technique_id
            and event.payload.get("disposition") == opposite
            for event in events
        )

    async def _required_run_row(self, session: AsyncSession, run_id: str) -> RunRow:
        """Load the locked run row for a scheduler side effect."""

        run = await session.get(RunRow, run_id, with_for_update=True)
        if run is None:
            raise ValueError("run_not_found")
        return run

    async def _enqueue_falsifier_for_finding(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        source_task: WorkerTaskRow,
        source_context: ContextManifest,
        evidence_ids: tuple[str, ...],
        finding_id: str,
        trigger: str,
    ) -> None:
        """Queue one independent falsifier after a high-impact worker claim.

        The falsifier receives only sealed evidence references and a static
        objective; it never receives the worker's prose as a prompt. That is
        enough to make the conflicting-observation path auditable without
        accidentally creating a free-form cross-agent instruction channel.
        """

        if source_task.technique_id == "general.review":
            return
        if await self._has_active_avoid_hint(
            session,
            run_id=run.id,
            technique_id=source_task.technique_id,
            branch_scope=source_task.branch_scope,
        ):
            return
        active_tasks = (
            await session.scalars(
                select(WorkerTaskRow)
                .where(
                    WorkerTaskRow.run_id == run.id,
                    WorkerTaskRow.role != AgentRole.MASTER.value,
                    WorkerTaskRow.state.in_(["queued", "leased"]),
                )
                .with_for_update()
            )
        ).all()
        if len(active_tasks) >= _MAX_ACTIVE_WORKER_BRANCHES or any(
            task.role == AgentRole.FALSIFIER.value and task.technique_id == source_task.technique_id
            for task in active_tasks
        ):
            await self._append_event_row(
                session,
                run.id,
                "scheduler.falsifier.deferred",
                {"finding_id": finding_id, "reason": "worker_capacity_or_existing_falsifier"},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"falsifier:{finding_id}:deferred",
            )
            return
        selected_evidence = tuple(
            item
            for item in source_context.evidence_refs
            if item.observation_id in set(evidence_ids)
        )
        if not selected_evidence:
            raise ValueError("falsifier_evidence_not_in_context")
        fingerprint = self._scheduler_attempt_fingerprint(
            tool_id="scheduler.falsifier",
            challenge_digest=source_context.challenge_digest,
            branch_scope=source_task.branch_scope,
            canonical_input={
                "source_task_id": source_task.id,
                "technique_id": source_task.technique_id,
                "evidence_ids": list(evidence_ids),
                "trigger": trigger,
            },
        )
        existing = await session.scalar(
            select(WorkerTaskRow).where(
                WorkerTaskRow.run_id == run.id,
                WorkerTaskRow.attempt_fingerprint == fingerprint,
            )
        )
        if existing is not None:
            return
        now = utc_now()
        deadline = min(_stored_utc(source_task.deadline_at), source_context.expires_at)
        if deadline <= now:
            await self._append_event_row(
                session,
                run.id,
                "scheduler.falsifier.deferred",
                {"finding_id": finding_id, "reason": "context_deadline_expired"},
                actor={"kind": "system", "id": "scheduler"},
                idempotency_key=f"falsifier:{finding_id}:deadline",
            )
            return
        task_id = new_id("task")
        context_id = new_id("ctx")
        branch_id = new_id("branch")
        objective = (
            "Attempt to falsify one high-confidence unverified observation using only the "
            "sealed evidence IDs. Identify a missing control or contradiction; do not claim a flag."
        )
        context = ContextManifest.issue(
            id=context_id,
            run_id=run.id,
            task_id=task_id,
            challenge_digest=source_context.challenge_digest,
            role=AgentRole.FALSIFIER.value,
            objective=objective,
            allowed_tool_ids=agent_role_tool_ids(AgentRole.FALSIFIER),
            evidence_refs=selected_evidence,
            hypothesis_refs=(),
            active_hint_refs=await self._active_hint_refs(
                session,
                run_id=run.id,
                technique_id=source_task.technique_id,
                branch_scope=source_task.branch_scope,
            ),
            attempt_fingerprints=(fingerprint,),
            budget_slice=ContextBudgetSlice(
                tool_calls=min(2, source_context.budget_slice.tool_calls),
                input_tokens=min(4_000, source_context.budget_slice.input_tokens),
                output_tokens=min(1_000, source_context.budget_slice.output_tokens),
            ),
            created_at=now,
            expires_at=deadline,
        )
        encoded_context = canonical_json(context.model_dump(mode="json", by_alias=True))
        if len(encoded_context) > _MAX_CONTEXT_MANIFEST_BYTES:
            raise ValueError("context_manifest_too_large")
        family = f"m4-falsifier-{fingerprint[:24]}"
        session.add(
            ContextManifestRow(
                id=context.id,
                run_id=context.run_id,
                task_id=context.task_id,
                document=encoded_context.decode("utf-8"),
                digest=context.digest,
                size_bytes=len(encoded_context),
                expires_at=context.expires_at,
                created_at=context.created_at,
            )
        )
        session.add(
            RunBranchRow(
                id=branch_id,
                run_id=run.id,
                family=family,
                state="active",
                technique_id=source_task.technique_id,
                branch_scope=source_task.branch_scope,
                priority=1.0,
                novelty=0.9,
                evidence_strength=0.8,
                expected_value=0.9,
                normalized_cost=0.2,
                repetition_penalty=0.0,
                consecutive_no_observation=0,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            WorkerTaskRow(
                id=task_id,
                run_id=run.id,
                branch_id=branch_id,
                role=AgentRole.FALSIFIER.value,
                objective=objective,
                required_evidence=list(evidence_ids),
                context_manifest_id=context.id,
                technique_id=source_task.technique_id,
                branch_scope=source_task.branch_scope,
                attempt_fingerprint=fingerprint,
                state="queued",
                lease_owner=None,
                lease_version=0,
                lease_expires_at=None,
                attempts=0,
                deadline_at=deadline,
                created_at=now,
                updated_at=now,
            )
        )
        start_job = await self._enqueue_agent_job_row(
            session,
            run_id=run.id,
            kind=AgentJobKind.START_SESSION.value,
            payload_ref=f"context:{context.id}",
            payload_digest=context.digest,
            idempotency_key=f"pi-session:{task_id}:v1",
            deadline_at=deadline,
            actor={"kind": "system", "id": "scheduler"},
        )
        await self._append_event_row(
            session,
            run.id,
            "branch.created",
            {
                "branch_id": branch_id,
                "family": family,
                "technique_id": source_task.technique_id,
                "trigger": trigger,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"branch:{branch_id}:created",
        )
        await self._append_event_row(
            session,
            run.id,
            "task.queued",
            {
                "task_id": task_id,
                "branch_id": branch_id,
                "context_manifest_id": context.id,
                "attempt_fingerprint": fingerprint,
                "falsifier_for_finding_id": finding_id,
                "session_job_id": start_job.id,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"task:{task_id}:queued",
        )
        await self._append_event_row(
            session,
            run.id,
            "scheduler.falsifier.queued",
            {
                "finding_id": finding_id,
                "task_id": task_id,
                "branch_id": branch_id,
                "session_job_id": start_job.id,
                "trigger": trigger,
            },
            actor={"kind": "system", "id": "scheduler"},
            idempotency_key=f"falsifier:{finding_id}:queued",
        )

    async def enqueue_agent_job(
        self,
        run_id: str,
        *,
        kind: str,
        payload_ref: str | None,
        payload_digest: str | None,
        idempotency_key: str,
        deadline_at: datetime | None = None,
        actor: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Durably enqueue a non-executing control-plane job exactly once."""

        _validate_idempotency_key(idempotency_key)
        if deadline_at is not None:
            deadline_at = _require_aware_utc(deadline_at)
        async with self._run_locks[run_id]:
            try:
                async with self.database.sessions() as session, session.begin():
                    if await session.get(RunRow, run_id) is None:
                        raise ValueError("run_not_found")
                    row = await self._enqueue_agent_job_row(
                        session,
                        run_id=run_id,
                        kind=kind,
                        payload_ref=payload_ref,
                        payload_digest=payload_digest,
                        idempotency_key=idempotency_key,
                        deadline_at=deadline_at,
                        actor=actor or {"kind": "system", "id": "run-engine"},
                    )
                return self._agent_job(row)
            except IntegrityError:
                async with self.database.sessions() as session:
                    row = await session.scalar(
                        select(AgentJobRow).where(
                            AgentJobRow.run_id == run_id,
                            AgentJobRow.idempotency_key == idempotency_key,
                        )
                    )
                    if row is None:
                        raise
                    return self._agent_job(row)

    async def _enqueue_agent_job_row(
        self,
        session: AsyncSession,
        *,
        run_id: str,
        kind: str,
        payload_ref: str | None,
        payload_digest: str | None,
        idempotency_key: str,
        deadline_at: datetime | None,
        actor: dict[str, str],
    ) -> AgentJobRow:
        if kind not in _RUNTIME_JOB_KINDS:
            raise ValueError("invalid_agent_job_kind")
        _validate_idempotency_key(idempotency_key)
        if payload_ref is not None and (not payload_ref.strip() or len(payload_ref) > 500):
            raise ValueError("invalid_job_payload_ref")
        if payload_digest is not None and not _SHA256.fullmatch(payload_digest):
            raise ValueError("invalid_job_payload_digest")
        if deadline_at is not None:
            deadline_at = _require_aware_utc(deadline_at)
        existing = await session.scalar(
            select(AgentJobRow).where(
                AgentJobRow.run_id == run_id,
                AgentJobRow.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if (
                existing.kind != kind
                or existing.payload_ref != payload_ref
                or existing.payload_digest != payload_digest
                or (
                    existing.deadline_at is not None
                    and deadline_at is not None
                    and _stored_utc(existing.deadline_at) != deadline_at
                )
                or (existing.deadline_at is None) != (deadline_at is None)
            ):
                raise ValueError("idempotency_conflict")
            return existing
        now = utc_now()
        row = AgentJobRow(
            id=new_id("job"),
            run_id=run_id,
            kind=kind,
            payload_ref=payload_ref,
            payload_digest=payload_digest,
            state="queued",
            idempotency_key=idempotency_key,
            lease_owner=None,
            lease_version=0,
            lease_expires_at=None,
            attempts=0,
            deadline_at=deadline_at,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        await self._append_event_row(
            session,
            run_id,
            "agent.job.queued",
            {"job_id": row.id, "kind": kind},
            actor=actor,
            idempotency_key=f"job:{row.id}:queued",
        )
        return row

    async def list_agent_jobs(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(AgentJobRow)
                    .where(AgentJobRow.run_id == run_id)
                    .order_by(AgentJobRow.created_at, AgentJobRow.id)
                )
            ).all()
            return [self._agent_job(row) for row in rows]

    async def claim_agent_job(
        self,
        *,
        worker_id: str,
        lease_seconds: int = 30,
        kinds: tuple[str, ...] | None = None,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Claim one queued/expired job with a versioned lease.

        PostgreSQL receives ``FOR UPDATE SKIP LOCKED`` plus a lease-version
        compare-and-swap. The small local lock only makes SQLite test behavior
        deterministic; it is not the cross-process authority.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= _MAX_LEASE_SECONDS:
            raise ValueError("invalid_lease_seconds")
        if kinds is not None and (
            not kinds or any(kind not in _RUNTIME_JOB_KINDS for kind in kinds)
        ):
            raise ValueError("invalid_agent_job_kind")
        if run_id is not None and _ACTOR_ID.fullmatch(run_id) is None:
            raise ValueError("invalid_run_id")
        claimed_at = utc_now() if now is None else _require_aware_utc(now)
        expires_at = claimed_at + timedelta(seconds=lease_seconds)
        leaseable = or_(
            AgentJobRow.state == "queued",
            (AgentJobRow.state == "leased") & (AgentJobRow.lease_expires_at < claimed_at),
        )
        # A pause never destroys the audit queue, but it must stop a runner
        # from starting another Pi session/turn/steer.  Cancellation is
        # stricter: only abort/dispose jobs remain claimable, so an in-flight
        # runner can clean up while every new target-facing action is denied.
        run_is_runnable_for_job = or_(
            # A verifier worker must never begin while a candidate is merely
            # queued or while a run is paused/cancelled. Legacy kernel jobs
            # retain their existing lifecycle semantics below.
            and_(AgentJobRow.kind == AgentJobKind.VERIFY.value, RunRow.status == "verifying"),
            AgentJobRow.kind.not_in(_PI_AGENT_JOB_KINDS | {AgentJobKind.VERIFY.value}),
            and_(
                AgentJobRow.kind.in_(_PI_START_OR_TURN_JOB_KINDS),
                RunRow.status == "running",
            ),
            and_(
                AgentJobRow.kind.in_(_PI_TEARDOWN_JOB_KINDS),
                RunRow.status == "cancelled",
            ),
            # Power sessions have their own workspace lifecycle.  A verified
            # flag changes the run to solved before sibling abort jobs are
            # claimed, so teardown remains runnable in both terminal states.
            and_(
                AgentJobRow.kind.in_(_POWER_PI_RUNNABLE_JOB_KINDS),
                RunRow.status == "running",
            ),
            and_(
                AgentJobRow.kind.in_(_POWER_PI_TEARDOWN_JOB_KINDS),
                RunRow.status.in_(["cancelled", "solved"]),
            ),
        )
        async with self._job_claim_lock:
            async with self.database.sessions() as session, session.begin():
                query = (
                    select(AgentJobRow)
                    .join(RunRow, AgentJobRow.run_id == RunRow.id)
                    .where(leaseable, run_is_runnable_for_job)
                    .order_by(AgentJobRow.created_at, AgentJobRow.id)
                    .limit(1)
                    # The run join is a status predicate, not a mutation.
                    # Locking it here inverted the Power lifecycle's canonical
                    # run -> job order and deadlocked concurrent racer starts.
                    .with_for_update(of=AgentJobRow, skip_locked=True)
                )
                if kinds is not None:
                    query = query.where(AgentJobRow.kind.in_(kinds))
                if run_id is not None:
                    # This filter is part of the locked selection query rather
                    # than a post-claim check. A scoped diagnostic worker can
                    # therefore never disturb another run's lease/event log.
                    query = query.where(AgentJobRow.run_id == run_id)
                candidate = await session.scalar(query)
                if candidate is None:
                    return None
                next_version = candidate.lease_version + 1
                updated = cast(
                    CursorResult[Any],
                    await session.execute(
                        update(AgentJobRow)
                        .where(
                            AgentJobRow.id == candidate.id,
                            AgentJobRow.lease_version == candidate.lease_version,
                            leaseable,
                        )
                        .values(
                            state="leased",
                            lease_owner=worker_id,
                            lease_version=next_version,
                            lease_expires_at=expires_at,
                            attempts=candidate.attempts + 1,
                            updated_at=claimed_at,
                        )
                    ),
                )
                if updated.rowcount != 1:
                    return None
                await session.refresh(candidate)
                await self._append_event_row(
                    session,
                    candidate.run_id,
                    "agent.job.leased",
                    {
                        "job_id": candidate.id,
                        "kind": candidate.kind,
                        "lease_version": candidate.lease_version,
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"job:{candidate.id}:lease:{candidate.lease_version}",
                )
                return self._agent_job(candidate)

    async def complete_agent_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        result_ref: str,
    ) -> dict[str, Any]:
        """Complete only the exact lease holder's job; stale workers are denied."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not result_ref.strip() or len(result_ref) > 500:
            raise ValueError("invalid_job_result_ref")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            row = await session.get(AgentJobRow, job_id, with_for_update=True)
            if row is None:
                raise ValueError("agent_job_not_found")
            if (
                row.state != "leased"
                or row.lease_owner != worker_id
                or row.lease_version != lease_version
            ):
                raise ValueError("agent_job_lease_lost")
            if row.lease_expires_at is None or _stored_utc(row.lease_expires_at) <= now:
                raise ValueError("agent_job_lease_expired")
            row.state = "completed"
            row.lease_owner = None
            row.lease_expires_at = None
            row.updated_at = now
            await self._append_event_row(
                session,
                row.run_id,
                "agent.job.completed",
                {"job_id": row.id, "kind": row.kind, "result_ref": result_ref},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{row.id}:complete:{lease_version}",
            )
        return self._agent_job(row)

    async def fail_agent_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        reason: str,
    ) -> dict[str, Any]:
        """Persist one safe failure outcome for the exact active job lease.

        This is intentionally not a retry mechanism. A scheduler can decide
        whether a new, explicitly idempotent job is appropriate later; an
        ambiguous preflight failure never silently retries source I/O.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        _validate_runtime_failure_code(reason)
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            row = await session.get(AgentJobRow, job_id, with_for_update=True)
            if row is None:
                raise ValueError("agent_job_not_found")
            if (
                row.state != "leased"
                or row.lease_owner != worker_id
                or row.lease_version != lease_version
            ):
                raise ValueError("agent_job_lease_lost")
            if row.lease_expires_at is None or _stored_utc(row.lease_expires_at) <= now:
                raise ValueError("agent_job_lease_expired")
            run = await session.get(RunRow, row.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            row.state = "failed"
            row.lease_owner = None
            row.lease_expires_at = None
            row.updated_at = now
            if row.kind == "preflight" and run.status == "preparing":
                previous_status = run.status
                run.status = "failed"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run.id,
                    "run.state.changed",
                    {
                        "previous_status": previous_status,
                        "status": "failed",
                        "reason": f"preflight_failed:{reason}",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"run:{run.id}:preflight-failed:{lease_version}",
                )
            await self._append_event_row(
                session,
                row.run_id,
                "agent.job.failed",
                {"job_id": row.id, "kind": row.kind, "reason": reason},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{row.id}:failed:{lease_version}",
            )
        return self._agent_job(row)

    async def fail_pi_agent_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        reason: str,
    ) -> dict[str, Any]:
        """Fail closed when an isolated Pi job cannot finish safely.

        Unlike legacy/fake jobs, a Pi job may own a session and worker-task
        lease. Marking only the queue row would let stale work look runnable
        after a runner failure. This transaction records a secret-free reason,
        stops the active run, and retains all prior append-only evidence.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        _validate_runtime_failure_code(reason)
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=None,
                now=now,
            )
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")

            agent_session: AgentSessionRow | None = None
            task: WorkerTaskRow | None = None
            steer: AgentSteerRow | None = None
            if job.kind == AgentJobKind.START_SESSION.value:
                context_id = _parse_runtime_reference(
                    job.payload_ref,
                    _CONTEXT_REF,
                    "pi_failure_context_ref_invalid",
                )
                context_row = await session.get(ContextManifestRow, context_id)
                if context_row is None or context_row.run_id != job.run_id:
                    raise ValueError("pi_failure_context_missing")
                context = self._context_manifest_from_row(context_row)
                task = await session.get(WorkerTaskRow, context.task_id, with_for_update=True)
                agent_session = await session.scalar(
                    select(AgentSessionRow)
                    .where(AgentSessionRow.start_job_id == job.id)
                    .with_for_update()
                )
            elif job.kind == AgentJobKind.STEER.value:
                steer_id = _parse_runtime_reference(
                    job.payload_ref,
                    _STEER_REF,
                    "pi_failure_steer_ref_invalid",
                )
                steer = await session.get(AgentSteerRow, steer_id, with_for_update=True)
                if steer is None or steer.run_id != job.run_id:
                    raise ValueError("pi_failure_steer_missing")
                agent_session = await session.get(
                    AgentSessionRow, steer.session_id, with_for_update=True
                )
                if agent_session is not None:
                    task = await session.get(
                        WorkerTaskRow, agent_session.task_id, with_for_update=True
                    )
            else:
                session_id = _parse_runtime_reference(
                    job.payload_ref,
                    _SESSION_REF,
                    "pi_failure_session_ref_invalid",
                )
                agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
                if agent_session is not None:
                    task = await session.get(
                        WorkerTaskRow, agent_session.task_id, with_for_update=True
                    )

            if task is None or task.run_id != job.run_id:
                raise ValueError("pi_failure_task_missing")
            if agent_session is not None:
                if agent_session.run_id != job.run_id:
                    raise ValueError("pi_failure_session_missing")
                agent_session.state = AgentSessionState.FAILED.value
                agent_session.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "agent.session.failed",
                    {"session_id": agent_session.id, "reason": reason},
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"session:{agent_session.id}:failed:{job.id}:{lease_version}",
                )
            if task.state in {"queued", "leased"}:
                task.state = "failed"
                task.lease_owner = None
                task.lease_expires_at = None
                task.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "task.failed",
                    {"task_id": task.id, "reason": reason},
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"task:{task.id}:pi-failed:{job.id}:{lease_version}",
                )
            if steer is not None and steer.state == "queued":
                # The message was never delivered. Keep its digest/audit row
                # but make it ineligible for accidental later injection.
                steer.state = "failed"

            job.state = "failed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            if run.status in {"preparing", "running", "paused", "verifying"}:
                previous_status = run.status
                run.status = "failed"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run.id,
                    "run.state.changed",
                    {
                        "previous_status": previous_status,
                        "status": "failed",
                        "reason": f"pi_job_failed:{reason}",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"run:{run.id}:pi-failed:{job.id}:{lease_version}",
                )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.failed",
                {"job_id": job.id, "kind": job.kind, "reason": reason},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:failed:{lease_version}",
            )
        return self._agent_job(job)

    async def complete_preflight_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        branch_family: str,
        artifacts: tuple[RuntimeArtifact, ...],
        observations: tuple[PreflightObservation, ...],
        context_manifest: ContextManifest,
        task: RuntimeTask,
        enqueue_pi_session: bool = False,
    ) -> dict[str, Any]:
        """Commit preflight evidence, sealed context, task, state, and outbox atomically."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not branch_family.strip() or len(branch_family) > 100:
            raise ValueError("invalid_branch_family")
        if not artifacts or not observations:
            raise ValueError("preflight_evidence_required")
        artifact_ids = tuple(item.id for item in artifacts)
        observation_ids = tuple(item.id for item in observations)
        observation_kinds = tuple(item.kind.value for item in observations)
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("duplicate_runtime_artifact")
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("duplicate_preflight_observation")
        if len(observation_kinds) != len(set(observation_kinds)):
            raise ValueError("duplicate_preflight_observation_kind")
        if task.context_manifest_id != context_manifest.id or task.id != context_manifest.task_id:
            raise ValueError("context_task_mismatch")
        if task.run_id != context_manifest.run_id or task.branch_id == "":
            raise ValueError("context_task_run_mismatch")
        artifact_by_id = {item.id: item for item in artifacts}
        for observation in observations:
            artifact = artifact_by_id.get(observation.artifact_id)
            if artifact is None or artifact.sha256 != observation.digest:
                raise ValueError("preflight_observation_artifact_mismatch")
        observation_by_id = {item.id: item for item in observations}
        context_observation_ids = {
            evidence.observation_id for evidence in context_manifest.evidence_refs
        }
        for evidence in context_manifest.evidence_refs:
            observation = observation_by_id.get(evidence.observation_id)
            if (
                observation is None
                or observation.artifact_id != evidence.artifact_id
                or observation.digest != evidence.digest
            ):
                raise ValueError("context_manifest_unknown_evidence")
        if not set(task.required_evidence).issubset(context_observation_ids):
            raise ValueError("task_requires_unknown_context_evidence")

        now = utc_now()
        pi_session_job: AgentJobRow | None = None
        async with self._run_locks[context_manifest.run_id]:
            async with self.database.sessions() as session, session.begin():
                job = await session.get(AgentJobRow, job_id, with_for_update=True)
                if job is None or job.kind != "preflight":
                    raise ValueError("preflight_job_not_found")
                if (
                    job.run_id != context_manifest.run_id
                    or job.state != "leased"
                    or job.lease_owner != worker_id
                    or job.lease_version != lease_version
                    or job.lease_expires_at is None
                    or _stored_utc(job.lease_expires_at) <= now
                ):
                    raise ValueError("preflight_job_lease_lost")
                run = await session.get(RunRow, job.run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status != "preparing":
                    raise ValueError("run_not_preparing")
                challenge = await session.get(ChallengeRow, run.challenge_id)
                if challenge is None:
                    raise ValueError("challenge_not_found")
                if context_manifest.challenge_digest != challenge.digest:
                    raise ValueError("context_manifest_challenge_mismatch")

                for artifact in artifacts:
                    if artifact.run_id != run.id:
                        raise ValueError("runtime_artifact_cross_run")
                    existing = await session.get(ArtifactRow, artifact.id)
                    if existing is not None:
                        if (
                            existing.run_id != artifact.run_id
                            or existing.sha256 != artifact.sha256
                            or existing.locator != artifact.locator
                        ):
                            raise ValueError("runtime_artifact_id_conflict")
                        continue
                    session.add(
                        ArtifactRow(
                            id=artifact.id,
                            run_id=artifact.run_id,
                            sha256=artifact.sha256,
                            name=artifact.name,
                            media_type=artifact.media_type,
                            size_bytes=artifact.size_bytes,
                            classification=artifact.classification,
                            producer=artifact.producer,
                            locator=artifact.locator,
                            created_at=artifact.created_at,
                        )
                    )
                await session.flush()

                for observation in observations:
                    if observation.run_id != run.id:
                        raise ValueError("preflight_observation_cross_run")
                    session.add(
                        PreflightObservationRow(
                            id=observation.id,
                            run_id=observation.run_id,
                            kind=observation.kind.value,
                            artifact_id=observation.artifact_id,
                            digest=observation.digest,
                            summary=_redact_text(observation.summary),
                            created_at=observation.created_at,
                        )
                    )

                context_payload = context_manifest.model_dump(mode="json", by_alias=True)
                encoded_context = canonical_json(context_payload)
                if len(encoded_context) > _MAX_CONTEXT_MANIFEST_BYTES:
                    raise ValueError("context_manifest_too_large")
                session.add(
                    ContextManifestRow(
                        id=context_manifest.id,
                        run_id=context_manifest.run_id,
                        task_id=context_manifest.task_id,
                        document=encoded_context.decode("utf-8"),
                        digest=context_manifest.digest,
                        size_bytes=len(encoded_context),
                        expires_at=context_manifest.expires_at,
                        created_at=context_manifest.created_at,
                    )
                )
                branch = RunBranchRow(
                    id=task.branch_id,
                    run_id=run.id,
                    family=branch_family,
                    state="active",
                    priority=1.0,
                    novelty=1.0,
                    created_at=now,
                    updated_at=now,
                )
                session.add(branch)
                session.add(
                    WorkerTaskRow(
                        id=task.id,
                        run_id=task.run_id,
                        branch_id=task.branch_id,
                        role=task.role,
                        objective=task.objective,
                        required_evidence=list(task.required_evidence),
                        context_manifest_id=task.context_manifest_id,
                        state="queued",
                        lease_owner=None,
                        lease_version=task.lease_version,
                        lease_expires_at=None,
                        attempts=0,
                        deadline_at=task.deadline_at,
                        created_at=now,
                        updated_at=now,
                    )
                )
                # The M2 runner start is committed with the preflight task so
                # a process restart cannot leave a runnable task without a
                # corresponding durable consumer job. The legacy fake harness
                # explicitly opts out and remains test/dev-only.
                if enqueue_pi_session:
                    pi_session_job = await self._enqueue_agent_job_row(
                        session,
                        run_id=run.id,
                        kind=AgentJobKind.START_SESSION.value,
                        payload_ref=f"context:{context_manifest.id}",
                        payload_digest=context_manifest.digest,
                        idempotency_key=f"pi-session:{task.id}:v1",
                        deadline_at=task.deadline_at,
                        actor={"kind": "service", "id": worker_id},
                    )
                job.state = "completed"
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = now
                previous_status = run.status
                run.status = "running"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run.id,
                    "task.queued",
                    {
                        "task_id": task.id,
                        "branch_id": task.branch_id,
                        "context_manifest_id": context_manifest.id,
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"task:{task.id}:queued",
                )
                await self._append_event_row(
                    session,
                    run.id,
                    "run.preflight.completed",
                    {
                        "context_manifest_id": context_manifest.id,
                        "context_manifest_digest": context_manifest.digest,
                        "observation_count": len(observations),
                        "task_id": task.id,
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"job:{job.id}:preflight:{lease_version}",
                )
                await self._append_event_row(
                    session,
                    run.id,
                    "run.state.changed",
                    {
                        "previous_status": previous_status,
                        "status": "running",
                        "reason": "preflight_evidence_committed",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"run:{run.id}:preflight-running:{lease_version}",
                )
                await self._append_event_row(
                    session,
                    run.id,
                    "agent.job.completed",
                    {
                        "job_id": job.id,
                        "kind": job.kind,
                        "result_ref": f"context:{context_manifest.id}",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"job:{job.id}:complete:{lease_version}",
                )
        return {
            "run": self._run(run),
            "job": self._agent_job(job),
            "task": self._worker_task(task),
            "context_manifest": context_manifest.model_dump(mode="json", by_alias=True),
            "pi_session_job": None if pi_session_job is None else self._agent_job(pi_session_job),
        }

    async def get_context_manifest(self, context_manifest_id: str) -> ContextManifest | None:
        """Load and revalidate a sealed context before a harness can consume it."""

        async with self.database.sessions() as session:
            row = await session.get(ContextManifestRow, context_manifest_id)
            if row is None:
                return None
            manifest = self._context_manifest_from_row(row)
            if manifest.digest != row.digest or manifest.run_id != row.run_id:
                raise ValueError("stored_context_manifest_mismatch")
            return manifest

    async def list_agent_sessions(self, run_id: str) -> list[dict[str, Any]]:
        """Return lifecycle metadata only; Pi transcripts remain runner-local."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(AgentSessionRow)
                    .where(AgentSessionRow.run_id == run_id)
                    .order_by(AgentSessionRow.created_at, AgentSessionRow.id)
                )
            ).all()
            return [self._agent_session(row) for row in rows]

    async def get_agent_session(self, session_id: str) -> dict[str, Any] | None:
        async with self.database.sessions() as session:
            row = await session.get(AgentSessionRow, session_id)
            return None if row is None else self._agent_session(row)

    async def reserve_pi_session(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Reserve one durable session identity before the runner creates Pi.

        A retried delivery always receives the same session/store identity. The
        current worker can reopen that exact append-only session file; it can
        never create a second one for the same start job.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.START_SESSION,
                now=now,
            )
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "running":
                raise ValueError("pi_session_run_not_active")
            context_id = _parse_runtime_reference(
                job.payload_ref,
                _CONTEXT_REF,
                "pi_session_context_ref_invalid",
            )
            context_row = await session.get(ContextManifestRow, context_id, with_for_update=True)
            if context_row is None or context_row.run_id != job.run_id:
                raise ValueError("pi_session_context_missing")
            context = self._context_manifest_from_row(context_row)
            if context.digest != context_row.digest or context.digest != job.payload_digest:
                raise ValueError("pi_session_context_mismatch")
            if context.expires_at <= now:
                raise ValueError("pi_session_context_expired")
            task = await session.get(WorkerTaskRow, context.task_id, with_for_update=True)
            if (
                task is None
                or task.run_id != job.run_id
                or task.context_manifest_id != context_id
                or task.role != context.role
            ):
                raise ValueError("pi_session_task_mismatch")
            try:
                role = AgentRole(task.role)
            except ValueError as exc:
                raise ValueError("pi_session_role_invalid") from exc
            if tuple(context.allowed_tool_ids) != agent_role_tool_ids(role):
                raise ValueError("pi_session_context_tool_policy_mismatch")

            existing = await session.scalar(
                select(AgentSessionRow)
                .where(AgentSessionRow.start_job_id == job.id)
                .with_for_update()
            )
            if existing is None:
                if task.state == "queued":
                    task.state = "leased"
                    task.lease_owner = worker_id
                    task.lease_version += 1
                    task.lease_expires_at = job.lease_expires_at
                    task.attempts += 1
                    task.updated_at = now
                    await self._append_event_row(
                        session,
                        job.run_id,
                        "task.leased",
                        {"task_id": task.id, "lease_version": task.lease_version},
                        actor={"kind": "worker", "id": worker_id},
                        idempotency_key=f"task:{task.id}:pi-session:{job.lease_version}",
                    )
                elif task.state != "leased":
                    raise ValueError("pi_session_task_not_leaseable")
                elif task.lease_owner != worker_id:
                    # A different worker may hold a manually claimed task.
                    # Holding the start-job lease is not enough to steal that
                    # task and construct a second execution authority.
                    raise ValueError("pi_session_task_lease_lost")
                session_id = new_id("session")
                existing = AgentSessionRow(
                    id=session_id,
                    run_id=job.run_id,
                    start_job_id=job.id,
                    task_id=task.id,
                    context_manifest_id=context_id,
                    role=role.value,
                    state=AgentSessionState.STARTING.value,
                    runner_id=worker_id,
                    session_store_key=f"pi_{session_id}",
                    created_at=now,
                    updated_at=now,
                )
                session.add(existing)
                await self._append_event_row(
                    session,
                    job.run_id,
                    "agent.session.reserved",
                    {
                        "session_id": existing.id,
                        "task_id": task.id,
                        "role": role.value,
                        "context_manifest_id": context_id,
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"session:{existing.id}:reserved",
                )
            else:
                if (
                    existing.run_id != job.run_id
                    or existing.task_id != task.id
                    or existing.context_manifest_id != context_id
                    or existing.role != role.value
                    or existing.state
                    in {AgentSessionState.DISPOSED.value, AgentSessionState.FAILED.value}
                ):
                    raise ValueError("pi_session_reservation_conflict")
                # A start-job lease can expire while Pi is booting. The durable
                # identity remains the same but the new holder becomes the only
                # runner allowed to continue it.
                existing.runner_id = worker_id
                existing.updated_at = now
                if task.lease_owner != worker_id:
                    if (
                        task.lease_expires_at is not None
                        and _stored_utc(task.lease_expires_at) > now
                    ):
                        raise ValueError("pi_session_task_lease_lost")
                    # The start-job delivery was reclaimed after the paired
                    # task lease expired. Rebind the *same* session identity,
                    # never create a new one.
                    task.lease_owner = worker_id
                    task.lease_version += 1
                    task.lease_expires_at = job.lease_expires_at
                    task.attempts += 1
                    task.updated_at = now
                    await self._append_event_row(
                        session,
                        job.run_id,
                        "task.leased",
                        {"task_id": task.id, "lease_version": task.lease_version},
                        actor={"kind": "worker", "id": worker_id},
                        idempotency_key=f"task:{task.id}:pi-reclaim:{job.lease_version}",
                    )
        return {
            "session": self._agent_session(existing),
            "task": self._worker_task(task),
            "context_manifest": context.model_dump(mode="json", by_alias=True),
        }

    async def activate_pi_session(
        self,
        job_id: str,
        *,
        session_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Mark a reserved Pi session ready and atomically queue its first turn."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if job is None or agent_session is None:
                raise ValueError("pi_session_or_job_not_found")
            if agent_session.start_job_id != job_id:
                raise ValueError("pi_session_start_job_mismatch")
            # Completion responses are retry-safe after a client-side timeout.
            if job.state == "completed" and job.lease_version == lease_version:
                return self._agent_session(agent_session)
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.START_SESSION,
                now=now,
            )
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "running":
                raise ValueError("pi_session_run_not_active")
            if agent_session.state != AgentSessionState.STARTING.value:
                raise ValueError("pi_session_not_starting")
            context_row = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            if context_row is None:
                raise ValueError("pi_session_context_missing")
            context = self._context_manifest_from_row(context_row)
            agent_session.state = AgentSessionState.READY.value
            agent_session.runner_id = worker_id
            agent_session.updated_at = now
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            await self._append_event_row(
                session,
                job.run_id,
                "agent.session.ready",
                {"session_id": agent_session.id, "role": agent_session.role},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"session:{agent_session.id}:ready",
            )
            await self._enqueue_agent_job_row(
                session,
                run_id=job.run_id,
                kind=AgentJobKind.RUN_TURN.value,
                payload_ref=f"session:{agent_session.id}",
                payload_digest=context.digest,
                idempotency_key=f"pi-turn:{agent_session.id}:initial",
                # SQLite returns timezone-naive datetimes even for a UTC
                # column. `_enqueue_agent_job_row` correctly requires aware
                # inputs, so normalize the already-validated stored value.
                deadline_at=None if job.deadline_at is None else _stored_utc(job.deadline_at),
                actor={"kind": "service", "id": worker_id},
            )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.completed",
                {
                    "job_id": job.id,
                    "kind": job.kind,
                    "result_ref": f"session:{agent_session.id}",
                },
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
        return self._agent_session(agent_session)

    async def get_pi_agent_job_work(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Resolve one active Pi job into typed, target-free runner work.

        The runner receives a sealed context and opaque session metadata only.
        It never receives a filesystem location, challenge archive, endpoint,
        provider key, or database credential through this protocol.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=None,
                now=now,
            )
            if job.deadline_at is not None and _stored_utc(job.deadline_at) <= now:
                raise ValueError("agent_job_deadline_expired")
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            # Recheck lifecycle after a job was leased: pause/cancel can race
            # a runner claim, and no stale lease may construct a new session,
            # execute a turn, or deliver a steer after that boundary.
            if job.kind in _PI_START_OR_TURN_JOB_KINDS and run.status != "running":
                raise ValueError("pi_job_run_not_active")
            if job.kind in _PI_TEARDOWN_JOB_KINDS and run.status != "cancelled":
                raise ValueError("pi_teardown_run_not_cancelled")

            if job.kind == AgentJobKind.START_SESSION.value:
                context_id = _parse_runtime_reference(
                    job.payload_ref,
                    _CONTEXT_REF,
                    "pi_session_context_ref_invalid",
                )
                context_row = await session.get(ContextManifestRow, context_id)
                if context_row is None or context_row.run_id != job.run_id:
                    raise ValueError("pi_session_context_missing")
                context = self._context_manifest_from_row(context_row)
                task = await session.get(WorkerTaskRow, context.task_id)
                if task is None or task.run_id != job.run_id or task.role != context.role:
                    raise ValueError("pi_session_task_mismatch")
                return {
                    "job": self._agent_job(job),
                    "task": self._worker_task(task),
                    "context_manifest": context.model_dump(mode="json", by_alias=True),
                }

            session_id = _parse_runtime_reference(
                job.payload_ref,
                _SESSION_REF if job.kind != AgentJobKind.STEER.value else _STEER_REF,
                "pi_agent_job_payload_ref_invalid",
            )
            if job.kind == AgentJobKind.STEER.value:
                steer = await session.get(AgentSteerRow, session_id, with_for_update=True)
                if steer is None or steer.run_id != job.run_id or steer.state != "queued":
                    raise ValueError("agent_steer_not_available")
                agent_session = await session.get(
                    AgentSessionRow, steer.session_id, with_for_update=True
                )
                if agent_session is None or agent_session.state != AgentSessionState.READY.value:
                    raise ValueError("agent_steer_not_at_safe_boundary")
                if agent_session.runner_id != worker_id:
                    raise ValueError("agent_session_runner_mismatch")
                context_row = await session.get(
                    ContextManifestRow,
                    agent_session.context_manifest_id,
                )
                if context_row is None or context_row.run_id != job.run_id:
                    raise ValueError("agent_steer_context_missing")
                context = self._context_manifest_from_row(context_row)
                if (
                    context.id != agent_session.context_manifest_id
                    or context.role != agent_session.role
                    or context.task_id != agent_session.task_id
                ):
                    raise ValueError("agent_steer_context_mismatch")
                return {
                    "job": self._agent_job(job),
                    "session": self._agent_session(agent_session),
                    "steer": self._agent_steer(steer),
                    "context_manifest": context.model_dump(mode="json", by_alias=True),
                }

            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if agent_session is None or agent_session.run_id != job.run_id:
                raise ValueError("agent_session_not_found")
            if job.kind == AgentJobKind.RUN_TURN.value:
                if agent_session.state == AgentSessionState.READY.value:
                    agent_session.state = AgentSessionState.RUNNING.value
                    agent_session.runner_id = worker_id
                    agent_session.updated_at = now
                    await self._append_event_row(
                        session,
                        job.run_id,
                        "agent.turn.claimed",
                        {"job_id": job.id, "session_id": agent_session.id},
                        actor={"kind": "service", "id": worker_id},
                        idempotency_key=f"job:{job.id}:turn-claimed:{lease_version}",
                    )
                elif (
                    agent_session.state != AgentSessionState.RUNNING.value
                    or agent_session.runner_id != worker_id
                ):
                    # Do not start a second turn after a stolen/expired lease.
                    # M2 has no target tool, but preserving this deny path keeps
                    # the invariant ready for M3 side effects.
                    raise ValueError("agent_turn_not_reclaimable")
                task = await session.get(
                    WorkerTaskRow,
                    agent_session.task_id,
                    with_for_update=True,
                )
                context_row = await session.get(
                    ContextManifestRow, agent_session.context_manifest_id
                )
                if task is None or context_row is None:
                    raise ValueError("agent_turn_context_missing")
                if task.state == "leased" and task.lease_owner != worker_id:
                    raise ValueError("agent_turn_task_lease_lost")
                if task.state not in {"leased", "completed"}:
                    raise ValueError("agent_turn_task_not_runnable")
                branch = await session.get(RunBranchRow, task.branch_id, with_for_update=True)
                if branch is None or branch.run_id != job.run_id:
                    raise ValueError("agent_turn_branch_missing")
                # A queued turn may have raced an operator avoid/suspend
                # request.  Refuse before Pi constructs a prompt or opens its
                # authority gate; already-started turns are independently
                # denied at the tool reservation boundary below.
                if branch.state != "active":
                    if task.state == "leased":
                        task.state = "cancelled"
                        task.lease_owner = None
                        task.lease_expires_at = None
                        task.updated_at = now
                        await self._append_event_row(
                            session,
                            job.run_id,
                            "task.cancelled",
                            {"task_id": task.id, "reason": "branch_not_active"},
                            actor={"kind": "system", "id": "scheduler"},
                            idempotency_key=f"task:{task.id}:branch-not-active",
                        )
                    # The job was leased before the scheduler state changed.
                    # Close that stale lease transactionally instead of
                    # letting a consumer retry it forever or treating it as a
                    # model failure that could fail the entire run.
                    agent_session.state = AgentSessionState.READY.value
                    agent_session.updated_at = now
                    job.state = "cancelled"
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.updated_at = now
                    await self._append_event_row(
                        session,
                        job.run_id,
                        "agent.job.cancelled",
                        {"job_id": job.id, "kind": job.kind, "reason": "branch_not_active"},
                        actor={"kind": "system", "id": "scheduler"},
                        idempotency_key=f"job:{job.id}:branch-not-active",
                    )
                    raise ValueError("agent_turn_branch_not_active")
                if task.state == "leased":
                    # A task is first leased while the session starts. Extend
                    # that paired lease to the active turn before M3 can
                    # reserve a side-effecting tool call under it.
                    if job.lease_expires_at is None:
                        raise ValueError("agent_turn_job_lease_missing")
                    task.lease_expires_at = job.lease_expires_at
                    task.updated_at = now
                context = self._context_manifest_from_row(context_row)
                return {
                    "job": self._agent_job(job),
                    "session": self._agent_session(agent_session),
                    "task": self._worker_task(task),
                    "context_manifest": context.model_dump(mode="json", by_alias=True),
                }

            if job.kind == AgentJobKind.ABORT.value:
                if agent_session.state not in {
                    AgentSessionState.STARTING.value,
                    AgentSessionState.READY.value,
                    AgentSessionState.RUNNING.value,
                    AgentSessionState.ABORTING.value,
                }:
                    raise ValueError("agent_abort_session_not_active")
                agent_session.state = AgentSessionState.ABORTING.value
                agent_session.runner_id = worker_id
                agent_session.updated_at = now
                return {"job": self._agent_job(job), "session": self._agent_session(agent_session)}

            if job.kind == AgentJobKind.DISPOSE.value:
                if agent_session.state == AgentSessionState.DISPOSED.value:
                    raise ValueError("agent_session_already_disposed")
                agent_session.runner_id = worker_id
                agent_session.updated_at = now
                return {"job": self._agent_job(job), "session": self._agent_session(agent_session)}

            raise ValueError("invalid_pi_agent_job_kind")

    async def get_pi_tool_execution_authority(
        self,
        job_id: str,
        *,
        session_id: str,
        worker_id: str,
        lease_version: int,
    ) -> ToolExecutionAuthority:
        """Return server-derived authority for one active Pi turn only.

        The result is intended for the internal tool gateway, never the Pi
        process.  It deliberately binds an eventual dispatch to the same
        session, task, and lease that owns the current turn.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            authority, _, _, _ = await self._pi_tool_authority_from_job(
                session,
                job=job,
                session_id=session_id,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
            )
        return authority

    async def reserve_pi_tool_invocation(
        self,
        request: ToolInvocationRequest,
        *,
        job_id: str,
        session_id: str,
        worker_id: str,
        lease_version: int,
        policy_decision: Literal["allow", "deny"],
        policy_reason: str,
    ) -> ToolInvocation:
        """Persist idempotency and budget before gateway dispatch.

        A successful reservation represents a possible side effect.  It is
        intentionally not retried if the dispatcher later disappears: a
        duplicate gets the same durable ``reserved`` record rather than an
        opportunity to run the tool a second time.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if policy_decision not in {"allow", "deny"}:
            raise ValueError("invalid_tool_policy_decision")
        if not _RUNTIME_FAILURE_CODE.fullmatch(policy_reason):
            raise ValueError("invalid_tool_policy_reason")

        # This is the SQLite-safe half of the reservation lock. PostgreSQL
        # additionally serializes writers with the locked run row below.
        async with self._tool_reservation_lock:
            now = utc_now()
            async with self.database.sessions() as session, session.begin():
                job = await session.get(AgentJobRow, job_id, with_for_update=True)
                if job is None:
                    raise ValueError("agent_job_not_found")
                authority, run, _, task = await self._pi_tool_authority_from_job(
                    session,
                    job=job,
                    session_id=session_id,
                    worker_id=worker_id,
                    lease_version=lease_version,
                    now=now,
                )
                scope = self._tool_idempotency_scope(authority.task_id)
                existing_record = await session.scalar(
                    select(IdempotencyRecordRow).where(
                        IdempotencyRecordRow.run_id == authority.run_id,
                        IdempotencyRecordRow.scope == scope,
                        IdempotencyRecordRow.key == request.idempotency_key,
                    )
                )
                if existing_record is not None:
                    if existing_record.payload_digest != request.input_digest:
                        raise ValueError("idempotency_conflict")
                    invocation_id = _parse_runtime_reference(
                        existing_record.result_ref,
                        _TOOL_INVOCATION_REF,
                        "tool_idempotency_result_invalid",
                    )
                    existing = await session.get(ToolInvocationRow, invocation_id)
                    if existing is None:
                        raise ValueError("tool_idempotency_result_missing")
                    self._validate_duplicate_tool_invocation(existing, request, authority)
                    return self._tool_invocation(existing)

                existing_call = await session.scalar(
                    select(ToolInvocationRow).where(
                        ToolInvocationRow.run_id == authority.run_id,
                        ToolInvocationRow.session_id == authority.session_id,
                        ToolInvocationRow.tool_call_id == request.tool_call_id,
                    )
                )
                if existing_call is not None:
                    raise ValueError("tool_call_id_conflict")

                # The database repeats the allowlist check rather than trusting
                # a policy result supplied by another process.
                effective_decision = policy_decision
                effective_reason = policy_reason
                if request.tool_name != "finding.submit" and await self._has_active_avoid_hint(
                    session,
                    run_id=authority.run_id,
                    technique_id=task.technique_id,
                    branch_scope=task.branch_scope,
                ):
                    # An avoid card is a scheduler/policy gate, not a model
                    # instruction. Deny even a task that was leased before
                    # the card arrived, and retain the normal audit record.
                    effective_decision = "deny"
                    effective_reason = "hint_avoid_blocks_tool"
                if (
                    request.tool_name not in authority.context_manifest.allowed_tool_ids
                    or request.tool_name not in agent_role_tool_ids(authority.role)
                ):
                    effective_decision = "deny"
                    effective_reason = "tool_not_allowed"

                if effective_decision == "allow":
                    budget_reason = await self._tool_budget_reason(
                        session,
                        run=run,
                        tool_name=request.tool_name,
                    )
                    if budget_reason is not None:
                        effective_decision = "deny"
                        effective_reason = budget_reason

                invocation = ToolInvocationRow(
                    id=new_id("tool"),
                    run_id=authority.run_id,
                    agent_job_id=authority.agent_job_id,
                    session_id=authority.session_id,
                    task_id=authority.task_id,
                    branch_id=authority.branch_id,
                    tool_call_id=request.tool_call_id,
                    tool_name=request.tool_name,
                    tool_version=request.tool_version,
                    idempotency_key=request.idempotency_key,
                    input_digest=request.input_digest,
                    policy_decision=effective_decision,
                    policy_reason=effective_reason,
                    state=(
                        ToolInvocationState.RESERVED.value
                        if effective_decision == "allow"
                        else ToolInvocationState.DENIED.value
                    ),
                    tool_budget_ledger_id=None,
                    http_budget_ledger_id=None,
                    result_artifact_id=None,
                    result_digest=None,
                    result_summary=None,
                    error_code=None,
                    created_at=now,
                    completed_at=None if effective_decision == "allow" else now,
                )
                session.add(invocation)
                session.add(
                    IdempotencyRecordRow(
                        id=new_id("idem"),
                        run_id=authority.run_id,
                        scope=scope,
                        key=request.idempotency_key,
                        payload_digest=request.input_digest,
                        result_ref=f"tool:{invocation.id}",
                        created_at=now,
                    )
                )

                if effective_decision == "deny":
                    await self._append_event_row(
                        session,
                        authority.run_id,
                        "tool.policy_denied",
                        {
                            "invocation_id": invocation.id,
                            "tool_name": request.tool_name,
                            "tool_version": request.tool_version,
                            "input_digest": request.input_digest,
                            "reason": effective_reason,
                        },
                        actor={"kind": "service", "id": "tool-gateway"},
                        idempotency_key=f"tool:{invocation.id}:denied",
                    )
                    return self._tool_invocation(invocation)

                tool_ledger = await self._reserve_tool_budget_row(
                    session,
                    run=run,
                    dimension="max_tool_calls",
                    idempotency_key=f"tool:{invocation.id}:calls",
                    now=now,
                )
                invocation.tool_budget_ledger_id = tool_ledger.id
                await self._append_budget_debit_event(session, tool_ledger)
                if request.tool_name == "http.request":
                    http_ledger = await self._reserve_tool_budget_row(
                        session,
                        run=run,
                        dimension="max_http_requests",
                        idempotency_key=f"tool:{invocation.id}:http",
                        now=now,
                    )
                    invocation.http_budget_ledger_id = http_ledger.id
                    await self._append_budget_debit_event(session, http_ledger)
                await self._append_event_row(
                    session,
                    authority.run_id,
                    "tool.requested",
                    {
                        "invocation_id": invocation.id,
                        "tool_name": request.tool_name,
                        "tool_version": request.tool_version,
                        "input_digest": request.input_digest,
                        "tool_budget_ledger_id": invocation.tool_budget_ledger_id,
                        "http_budget_ledger_id": invocation.http_budget_ledger_id,
                    },
                    actor={"kind": "service", "id": "tool-gateway"},
                    idempotency_key=f"tool:{invocation.id}:requested",
                )
            return self._tool_invocation(invocation)

    async def complete_tool_invocation(
        self,
        invocation_id: str,
        *,
        artifact: RuntimeArtifact,
        result_summary: str,
    ) -> ToolInvocation:
        """Attach one normalized immutable artifact to a reserved invocation."""

        if _contains_plaintext_secret(result_summary):
            raise ValueError("tool_result_summary_contains_secret")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            invocation = await session.get(ToolInvocationRow, invocation_id, with_for_update=True)
            if invocation is None:
                raise ValueError("tool_invocation_not_found")
            if invocation.state == ToolInvocationState.COMPLETED.value:
                if (
                    invocation.result_artifact_id != artifact.id
                    or invocation.result_digest != artifact.sha256
                    or invocation.result_summary != result_summary
                ):
                    raise ValueError("tool_invocation_completion_conflict")
                return self._tool_invocation(invocation)
            if invocation.state != ToolInvocationState.RESERVED.value:
                raise ValueError("tool_invocation_not_reservable")
            if (
                artifact.run_id != invocation.run_id
                or artifact.classification != "internal"
                or artifact.producer != "tool-gateway"
                or artifact.locator != f"sha256:{artifact.sha256}"
            ):
                raise ValueError("tool_result_artifact_invalid")
            existing_artifact = await session.get(ArtifactRow, artifact.id)
            if existing_artifact is None:
                session.add(
                    ArtifactRow(
                        id=artifact.id,
                        run_id=artifact.run_id,
                        sha256=artifact.sha256,
                        name=artifact.name,
                        media_type=artifact.media_type,
                        size_bytes=artifact.size_bytes,
                        classification=artifact.classification,
                        producer=artifact.producer,
                        locator=artifact.locator,
                        created_at=artifact.created_at,
                    )
                )
            elif (
                existing_artifact.run_id != artifact.run_id
                or existing_artifact.sha256 != artifact.sha256
                or existing_artifact.locator != artifact.locator
            ):
                raise ValueError("tool_result_artifact_conflict")
            invocation.state = ToolInvocationState.COMPLETED.value
            invocation.result_artifact_id = artifact.id
            invocation.result_digest = artifact.sha256
            invocation.result_summary = _redact_text(result_summary)
            invocation.completed_at = now
            await self._append_event_row(
                session,
                invocation.run_id,
                "tool.completed",
                {
                    "invocation_id": invocation.id,
                    "tool_name": invocation.tool_name,
                    "artifact_id": artifact.id,
                    "digest": artifact.sha256,
                    "summary": invocation.result_summary,
                },
                actor={"kind": "service", "id": "tool-gateway"},
                idempotency_key=f"tool:{invocation.id}:completed",
            )
            await self._append_event_row(
                session,
                invocation.run_id,
                "evidence.recorded",
                {
                    "invocation_id": invocation.id,
                    "artifact_id": artifact.id,
                    "digest": artifact.sha256,
                    "source": "typed-tool-result",
                },
                actor={"kind": "tool", "id": "tool-gateway"},
                idempotency_key=f"tool:{invocation.id}:evidence",
            )
        return self._tool_invocation(invocation)

    async def fail_tool_invocation(self, invocation_id: str, *, error_code: str) -> ToolInvocation:
        """Close an uncertain reserved invocation without retrying its tool action."""

        _validate_runtime_failure_code(error_code)
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            invocation = await session.get(ToolInvocationRow, invocation_id, with_for_update=True)
            if invocation is None:
                raise ValueError("tool_invocation_not_found")
            if invocation.state == ToolInvocationState.FAILED.value:
                if invocation.error_code != error_code:
                    raise ValueError("tool_invocation_failure_conflict")
                return self._tool_invocation(invocation)
            if invocation.state != ToolInvocationState.RESERVED.value:
                raise ValueError("tool_invocation_not_reservable")
            invocation.state = ToolInvocationState.FAILED.value
            invocation.error_code = error_code
            invocation.completed_at = now
            await self._append_event_row(
                session,
                invocation.run_id,
                "tool.failed",
                {
                    "invocation_id": invocation.id,
                    "tool_name": invocation.tool_name,
                    "error_code": error_code,
                },
                actor={"kind": "service", "id": "tool-gateway"},
                idempotency_key=f"tool:{invocation.id}:failed",
            )
        return self._tool_invocation(invocation)

    async def get_tool_invocation(self, invocation_id: str) -> ToolInvocation | None:
        """Load a body-free invocation record for durable retry handling."""

        async with self.database.sessions() as session:
            row = await session.get(ToolInvocationRow, invocation_id)
            return None if row is None else self._tool_invocation(row)

    async def list_tool_invocations(self, run_id: str) -> tuple[ToolInvocation, ...]:
        """Expose auditable metadata without rehydrating normalized artifacts."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(ToolInvocationRow)
                    .where(ToolInvocationRow.run_id == run_id)
                    .order_by(ToolInvocationRow.created_at, ToolInvocationRow.id)
                )
            ).all()
            return tuple(self._tool_invocation(row) for row in rows)

    async def _pi_tool_authority_from_job(
        self,
        session: AsyncSession,
        *,
        job: AgentJobRow,
        session_id: str,
        worker_id: str,
        lease_version: int,
        now: datetime,
        allow_verifying: bool = False,
    ) -> tuple[ToolExecutionAuthority, RunRow, AgentSessionRow, WorkerTaskRow]:
        """Load all authoritative rows while the caller holds the job lock."""

        self._require_pi_job_lease(
            job,
            worker_id=worker_id,
            lease_version=lease_version,
            expected_kind=AgentJobKind.RUN_TURN,
            now=now,
        )
        if job.deadline_at is not None and _stored_utc(job.deadline_at) <= now:
            raise ValueError("agent_job_deadline_expired")
        if job.lease_expires_at is None:
            raise ValueError("agent_job_lease_missing")
        stored_session_id = _parse_runtime_reference(
            job.payload_ref,
            _SESSION_REF,
            "pi_tool_session_ref_invalid",
        )
        if stored_session_id != session_id:
            raise ValueError("pi_tool_session_mismatch")
        agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
        if (
            agent_session is None
            or agent_session.run_id != job.run_id
            or agent_session.runner_id != worker_id
            or agent_session.state != AgentSessionState.RUNNING.value
        ):
            raise ValueError("pi_tool_session_lease_lost")
        task = await session.get(WorkerTaskRow, agent_session.task_id, with_for_update=True)
        if (
            task is None
            or task.run_id != job.run_id
            or task.state != "leased"
            or task.lease_owner != worker_id
            or task.lease_expires_at is None
            or _stored_utc(task.lease_expires_at) <= now
        ):
            raise ValueError("pi_tool_task_lease_lost")
        context_row = await session.get(
            ContextManifestRow,
            agent_session.context_manifest_id,
            with_for_update=True,
        )
        if context_row is None or context_row.run_id != job.run_id:
            raise ValueError("pi_tool_context_missing")
        context = self._context_manifest_from_row(context_row)
        if context.expires_at <= now:
            raise ValueError("pi_tool_context_expired")
        try:
            role = AgentRole(agent_session.role)
        except ValueError as exc:
            raise ValueError("pi_tool_role_invalid") from exc
        if (
            task.role != role.value
            or context.role != role.value
            or context.task_id != task.id
            or context.id != agent_session.context_manifest_id
            or tuple(context.allowed_tool_ids) != agent_role_tool_ids(role)
        ):
            raise ValueError("pi_tool_context_mismatch")
        run = await session.get(RunRow, job.run_id, with_for_update=True)
        if run is None:
            raise ValueError("run_not_found")
        # A submitted candidate moves the run to ``verifying`` before the Pi
        # turn is acknowledged. Its exact idempotent retry may still need to
        # inspect the same sealed authority, but ordinary target-facing tools
        # remain strictly limited to a running run.
        if run.status not in ({"running", "verifying"} if allow_verifying else {"running"}):
            raise ValueError("pi_tool_run_not_active")
        challenge = await session.get(ChallengeRow, run.challenge_id, with_for_update=True)
        if challenge is None:
            raise ValueError("challenge_not_found")
        try:
            manifest = ChallengeManifest.model_validate(challenge.manifest)
        except (TypeError, ValueError) as exc:
            raise ValueError("stored_challenge_manifest_invalid") from exc
        if context.challenge_digest != challenge.digest or manifest.spec.mode.value != run.mode:
            raise ValueError("pi_tool_challenge_mismatch")
        return (
            ToolExecutionAuthority(
                run_id=run.id,
                challenge_id=challenge.id,
                agent_job_id=job.id,
                session_id=agent_session.id,
                task_id=task.id,
                branch_id=task.branch_id,
                role=role,
                context_manifest=context,
                challenge_manifest=manifest,
                lease_expires_at=_stored_utc(job.lease_expires_at),
            ),
            run,
            agent_session,
            task,
        )

    async def _tool_budget_reason(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        tool_name: str,
    ) -> str | None:
        dimensions = ["max_tool_calls"]
        if tool_name == "http.request":
            dimensions.append("max_http_requests")
        for dimension in dimensions:
            remaining = await self._remaining_budget_in_session(session, run, dimension)
            if remaining < 1:
                return "budget_exhausted"
        return None

    async def _reserve_tool_budget_row(
        self,
        session: AsyncSession,
        *,
        run: RunRow,
        dimension: str,
        idempotency_key: str,
        now: datetime,
    ) -> BudgetLedgerRow:
        """Record a one-unit pre-dispatch debit inside the invocation transaction."""

        remaining = await self._remaining_budget_in_session(session, run, dimension)
        if remaining < 1:
            # This should be unreachable because ``_tool_budget_reason`` was
            # evaluated while the same run row was locked. Keep fail-closed
            # behavior if future changes alter that ordering.
            raise ValueError("tool_budget_reservation_race")
        row = BudgetLedgerRow(
            id=new_id("ledger"),
            run_id=run.id,
            dimension=dimension,
            debit=1.0,
            remaining_after=remaining - 1.0,
            idempotency_key=idempotency_key,
            created_at=now,
        )
        session.add(row)
        return row

    async def _remaining_budget_in_session(
        self,
        session: AsyncSession,
        run: RunRow,
        dimension: str,
    ) -> float:
        limit = run.budget.get(dimension)
        if isinstance(limit, bool) or not isinstance(limit, int | float):
            raise ValueError("run_budget_dimension_missing")
        used = await session.scalar(
            select(func.coalesce(func.sum(BudgetLedgerRow.debit), 0.0)).where(
                BudgetLedgerRow.run_id == run.id,
                BudgetLedgerRow.dimension == dimension,
            )
        )
        return max(0.0, float(limit) - float(used or 0.0))

    async def _append_budget_debit_event(
        self,
        session: AsyncSession,
        ledger: BudgetLedgerRow,
    ) -> None:
        await self._append_event_row(
            session,
            ledger.run_id,
            "budget.debited",
            {
                "ledger_id": ledger.id,
                "dimension": ledger.dimension,
                "debit": ledger.debit,
                "remaining": ledger.remaining_after,
            },
            actor={"kind": "system", "id": "tool-gateway"},
            idempotency_key=f"budget:{ledger.id}",
        )

    @staticmethod
    def _tool_idempotency_scope(task_id: str) -> str:
        """Bound a task-scoped idempotency namespace to the schema limit."""

        return f"tool:{hashlib.sha256(task_id.encode('utf-8')).hexdigest()}"

    @staticmethod
    def _validate_duplicate_tool_invocation(
        existing: ToolInvocationRow,
        request: ToolInvocationRequest,
        authority: ToolExecutionAuthority,
    ) -> None:
        if (
            existing.run_id != authority.run_id
            or existing.agent_job_id != authority.agent_job_id
            or existing.session_id != authority.session_id
            or existing.task_id != authority.task_id
            or existing.tool_call_id != request.tool_call_id
            or existing.tool_name != request.tool_name
            or existing.tool_version != request.tool_version
            or existing.idempotency_key != request.idempotency_key
            or existing.input_digest != request.input_digest
        ):
            raise ValueError("idempotency_conflict")

    async def append_pi_agent_events(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        events: tuple[AgentBridgeEvent, ...],
    ) -> list[dict[str, Any]]:
        """Append a bounded typed Pi event batch under the exact job lease."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not events or len(events) > 128:
            raise ValueError("invalid_agent_event_batch_size")
        sequences = tuple(event.sequence for event in events)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(set(sequences)):
            raise ValueError("agent_event_sequences_must_be_unique_and_sorted")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=None,
                now=now,
            )
            session_id = events[0].session_id
            if any(event.session_id != session_id for event in events):
                raise ValueError("agent_event_batch_session_mismatch")
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if (
                agent_session is None
                or agent_session.run_id != job.run_id
                or agent_session.runner_id != worker_id
            ):
                raise ValueError("agent_event_session_lease_lost")
            rows: list[EventRow] = []
            for event in events:
                event_payload = event.model_dump(mode="json", exclude_none=True)
                event_payload.pop("type")
                event_payload.pop("sequence")
                # The DB event timestamp remains authoritative. The remote
                # runner's time is preserved as a validated reported field.
                event_payload["reported_at"] = event_payload.pop("occurred_at")
                rows.append(
                    await self._append_event_row(
                        session,
                        job.run_id,
                        event.type.value,
                        event_payload,
                        actor={"kind": "service", "id": worker_id},
                        idempotency_key=f"agent-event:{job.id}:{lease_version}:{event.sequence}",
                    )
                )
            agent_session.updated_at = now
        return [self._event(row) for row in rows]

    async def complete_pi_turn(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        result_ref: str,
    ) -> dict[str, Any]:
        """Complete a turn at a safe boundary and release its session/task lease."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not re.fullmatch(
            r"(?:candidate|finding|agent):[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", result_ref
        ):
            raise ValueError("invalid_pi_turn_result_ref")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            if job.state == "completed" and job.lease_version == lease_version:
                return self._agent_job(job)
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.RUN_TURN,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _SESSION_REF, "pi_turn_session_ref_invalid"
            )
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if (
                agent_session is None
                or agent_session.runner_id != worker_id
                or agent_session.state != AgentSessionState.RUNNING.value
            ):
                raise ValueError("pi_turn_session_lease_lost")
            task = await session.get(WorkerTaskRow, agent_session.task_id, with_for_update=True)
            if task is None or task.run_id != job.run_id:
                raise ValueError("pi_turn_task_missing")
            # A prose-only turn is an observation-free scheduler outcome, not
            # a fact.  Keep the existing branch visible and advance its stall
            # counter only for this explicit inconclusive result.  Findings
            # update the branch in ``submit_pi_finding`` before completion.
            if result_ref == "agent:inconclusive":
                await self._complete_branch_from_task(
                    session,
                    task=task,
                    confidence=0.0,
                    observed=False,
                )
            if task.state == "leased":
                if task.lease_owner != worker_id:
                    raise ValueError("pi_turn_task_lease_lost")
                task.state = "completed"
                task.lease_owner = None
                task.lease_expires_at = None
                task.updated_at = now
                await self._append_event_row(
                    session,
                    job.run_id,
                    "task.completed",
                    {"task_id": task.id, "result_ref": result_ref},
                    actor={"kind": "worker", "id": worker_id},
                    idempotency_key=f"task:{task.id}:pi-complete:{job.lease_version}",
                )
            elif task.state != "completed":
                raise ValueError("pi_turn_task_not_completable")
            agent_session.state = AgentSessionState.READY.value
            agent_session.updated_at = now
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.completed",
                {"job_id": job.id, "kind": job.kind, "result_ref": result_ref},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
            await self._enqueue_pending_agent_steers(
                session,
                agent_session=agent_session,
                actor={"kind": "service", "id": worker_id},
            )
            if result_ref == "agent:inconclusive" and task.role == AgentRole.MASTER.value:
                await self._advance_master_stall(
                    session,
                    run_id=job.run_id,
                    agent_session=agent_session,
                    task=task,
                )
        return self._agent_job(job)

    async def submit_pi_candidate(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        submission: ExploitCandidateSubmission,
        plan: ExploitPlanV1,
        plan_artifact: RuntimeArtifact,
    ) -> dict[str, Any]:
        """Accept one replayable plan from a leased exploit-builder turn.

        The plan bytes are already content-addressed by the API composition
        root. This transaction is nevertheless the authority for binding that
        immutable blob to the exact Pi turn, sealed context evidence, task
        technique, run state, candidate, verification job, and audit events.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if submission.tool_call_id != submission.idempotency_key:
            raise ValueError("candidate_idempotency_key_must_match_tool_call")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            authority, run, agent_session, task = await self._pi_tool_authority_from_job(
                session,
                job=job,
                session_id=submission.session_id,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
                allow_verifying=True,
            )
            if authority.role is not AgentRole.EXPLOIT_BUILDER:
                raise ValueError("candidate_role_not_allowed")
            if "candidate.submit" not in authority.context_manifest.allowed_tool_ids:
                raise ValueError("candidate_capability_not_allowed")

            # A repeated Pi custom-tool call is harmless only when it binds to
            # the same canonical plan. This branch intentionally runs before
            # the active-run check because the first successful call already
            # moved the run to ``verifying``.
            existing = await session.scalar(
                select(ExploitCandidateRow)
                .where(
                    ExploitCandidateRow.run_id == run.id,
                    ExploitCandidateRow.session_id == agent_session.id,
                    ExploitCandidateRow.tool_call_id == submission.tool_call_id,
                )
                .with_for_update()
            )
            if existing is not None:
                self._validate_existing_candidate(existing, submission, plan, plan_artifact)
                verification_job = (
                    None
                    if existing.verification_job_id is None
                    else await session.get(AgentJobRow, existing.verification_job_id)
                )
                return {
                    "candidate": self._exploit_candidate(existing),
                    "verification_job": None
                    if verification_job is None
                    else self._agent_job(verification_job),
                }

            if run.status != "running":
                raise ValueError("candidate_run_not_active")
            if plan.challenge_digest != authority.context_manifest.challenge_digest:
                raise ValueError("candidate_challenge_digest_mismatch")
            if not _candidate_technique_is_reviewed(
                authority.challenge_manifest,
                task_technique_id=task.technique_id,
                plan_technique_id=plan.technique_id,
            ):
                raise ValueError("candidate_technique_not_reviewed")
            plan.validate_for_flag_patterns(tuple(authority.challenge_manifest.spec.flag.patterns))
            allowed_evidence = {
                reference.observation_id for reference in authority.context_manifest.evidence_refs
            }
            if not set(plan.evidence_refs).issubset(allowed_evidence):
                raise ValueError("candidate_evidence_not_in_context")
            self._validate_candidate_plan_artifact(plan, plan_artifact, run_id=run.id)

            artifact = await session.get(ArtifactRow, plan_artifact.id, with_for_update=True)
            if artifact is None:
                artifact = ArtifactRow(
                    id=plan_artifact.id,
                    run_id=plan_artifact.run_id,
                    sha256=plan_artifact.sha256,
                    name=plan_artifact.name,
                    media_type=plan_artifact.media_type,
                    size_bytes=plan_artifact.size_bytes,
                    classification=plan_artifact.classification,
                    producer=plan_artifact.producer,
                    locator=plan_artifact.locator,
                    created_at=now,
                )
                session.add(artifact)
                await self._append_event_row(
                    session,
                    run.id,
                    "artifact.created",
                    {
                        "artifact_id": artifact.id,
                        "sha256": artifact.sha256,
                        "name": artifact.name,
                        "classification": artifact.classification,
                    },
                    actor={"kind": "service", "id": artifact.producer},
                    idempotency_key=f"artifact:{artifact.id}",
                )
            elif not self._runtime_artifact_matches_row(plan_artifact, artifact):
                raise ValueError("artifact_id_conflict")

            candidate = ExploitCandidateRow(
                id=new_id("candidate"),
                run_id=run.id,
                branch_id=task.branch_id,
                task_id=task.id,
                session_id=agent_session.id,
                tool_call_id=submission.tool_call_id,
                idempotency_key=submission.idempotency_key,
                challenge_digest=plan.challenge_digest,
                technique_id=plan.technique_id,
                plan_artifact_id=plan_artifact.id,
                plan_artifact_digest=plan_artifact.sha256,
                plan_semantic_digest=plan.digest,
                evidence_refs=list(plan.evidence_refs),
                status="verifying",
                verification_job_id=None,
                verification_id=None,
                failure_code=None,
                created_at=now,
                updated_at=now,
            )
            session.add(candidate)
            verification_job = await self._enqueue_agent_job_row(
                session,
                run_id=run.id,
                kind=AgentJobKind.VERIFY.value,
                payload_ref=f"candidate:{candidate.id}",
                payload_digest=plan_artifact.sha256,
                idempotency_key=f"verify:{candidate.id}:v1",
                deadline_at=None,
                actor={"kind": "system", "id": "candidate-kernel"},
            )
            candidate.verification_job_id = verification_job.id
            previous_status = run.status
            run.status = "verifying"
            run.updated_at = now
            await self._append_event_row(
                session,
                run.id,
                "candidate.submitted",
                {
                    "candidate_id": candidate.id,
                    "task_id": task.id,
                    "branch_id": task.branch_id,
                    "technique_id": candidate.technique_id,
                    "plan_artifact_id": candidate.plan_artifact_id,
                    "plan_artifact_digest": candidate.plan_artifact_digest,
                    "evidence_refs": candidate.evidence_refs,
                    "verification_job_id": verification_job.id,
                },
                actor={"kind": "worker", "id": worker_id},
                idempotency_key=f"candidate:{candidate.id}:submitted",
            )
            await self._append_event_row(
                session,
                run.id,
                "run.state.changed",
                {
                    "previous_status": previous_status,
                    "status": "verifying",
                    "reason": "candidate_submitted_for_independent_replay",
                },
                actor={"kind": "system", "id": "candidate-kernel"},
                idempotency_key=f"run:{run.id}:candidate:{candidate.id}:verifying",
            )
        return {
            "candidate": self._exploit_candidate(candidate),
            "verification_job": self._agent_job(verification_job),
        }

    async def get_pi_candidate_submission_scope(
        self,
        job_id: str,
        *,
        session_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, str]:
        """Return only the run ID needed to content-address a candidate plan.

        This small pre-write check avoids trusting a caller-supplied run ID
        while keeping immutable artifact creation outside the database
        transaction. The final ``submit_pi_candidate`` call validates every
        authority condition again before it changes any durable state.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            authority, _, agent_session, _ = await self._pi_tool_authority_from_job(
                session,
                job=job,
                session_id=session_id,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
                allow_verifying=True,
            )
            if (
                authority.role is not AgentRole.EXPLOIT_BUILDER
                or "candidate.submit" not in authority.context_manifest.allowed_tool_ids
            ):
                raise ValueError("candidate_capability_not_allowed")
            return {"run_id": authority.run_id, "session_id": agent_session.id}

    async def get_verification_job_work(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Resolve one verifier lease into the minimal replay work envelope.

        This method deliberately returns no Pi transcript, hint note, raw
        finding prose, target URL, provider credential, or flag. The verifier
        derives the fixed internal origin from its code-owned
        technique-to-lab mapping, never from this row.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_verification_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
            )
            candidate_id = _parse_runtime_reference(
                job.payload_ref, _CANDIDATE_REF, "verification_job_candidate_ref_invalid"
            )
            candidate = await session.get(ExploitCandidateRow, candidate_id, with_for_update=True)
            if (
                candidate is None
                or candidate.run_id != job.run_id
                or candidate.verification_job_id != job.id
                or candidate.status != "verifying"
            ):
                raise ValueError("verification_candidate_not_available")
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "verifying":
                raise ValueError("verification_run_not_active")
            challenge = await session.get(ChallengeRow, run.challenge_id)
            if challenge is None:
                raise ValueError("challenge_not_found")
            try:
                manifest = ChallengeManifest.model_validate(challenge.manifest)
            except (TypeError, ValueError) as exc:
                raise ValueError("stored_challenge_manifest_invalid") from exc
            profile = _verification_manifest_profile(manifest, candidate.technique_id)
            if candidate.challenge_digest != challenge.digest or profile is None:
                raise ValueError("verification_lab_manifest_not_supported")
            plan_artifact = await session.get(ArtifactRow, candidate.plan_artifact_id)
            if (
                plan_artifact is None
                or plan_artifact.run_id != run.id
                or plan_artifact.sha256 != candidate.plan_artifact_digest
                or plan_artifact.classification != "internal"
            ):
                raise ValueError("verification_plan_artifact_unavailable")
            work = {
                "job": self._agent_job(job),
                "candidate": {
                    "id": candidate.id,
                    "run_id": candidate.run_id,
                    "plan_artifact_digest": candidate.plan_artifact_digest,
                    "evidence_refs": list(candidate.evidence_refs),
                },
                "manifest_digest": challenge.digest,
            }
            if profile == "m6-ui":
                work["replay_target"] = {
                    "kind": "exact_remote_origin_v1",
                    "origin": manifest.spec.target.target_aliases["target"],
                }
            return work

    async def complete_verification_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        completion: VerifierCompletionV1,
        proof_artifact: RuntimeArtifact | None,
    ) -> dict[str, Any]:
        """Apply an independent replay conclusion and the sole SOLVED transition."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            candidate_id = _parse_runtime_reference(
                job.payload_ref, _CANDIDATE_REF, "verification_job_candidate_ref_invalid"
            )
            candidate = await session.get(ExploitCandidateRow, candidate_id, with_for_update=True)
            if candidate is None or candidate.run_id != job.run_id:
                raise ValueError("verification_candidate_not_found")
            if completion.candidate_id != candidate.id:
                raise ValueError("verification_completion_candidate_mismatch")
            if job.state == "completed":
                if candidate.verification_id is None:
                    raise ValueError("verification_completion_missing_projection")
                existing = await session.get(VerificationRow, candidate.verification_id)
                if existing is None:
                    raise ValueError("verification_completion_missing_projection")
                return {
                    "verification": self._verification(existing),
                    "candidate": self._exploit_candidate(candidate),
                }
            self._require_verification_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
            )
            if candidate.verification_job_id != job.id or candidate.status != "verifying":
                raise ValueError("verification_candidate_not_available")
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "verifying":
                raise ValueError("verification_run_not_active")
            challenge = await session.get(ChallengeRow, run.challenge_id)
            if challenge is None:
                raise ValueError("challenge_not_found")
            try:
                manifest = ChallengeManifest.model_validate(challenge.manifest)
            except (TypeError, ValueError) as exc:
                raise ValueError("stored_challenge_manifest_invalid") from exc
            profile = _verification_manifest_profile(manifest, candidate.technique_id)
            if profile is None:
                raise ValueError("verification_lab_manifest_not_supported")
            if len(completion.replay_results) != manifest.spec.flag.replay_count:
                raise ValueError("verification_replay_count_mismatch")
            expected_target_digest = (
                _M5_LAB_TARGET_DIGESTS.get(manifest.metadata.name)
                if profile == "m5"
                else _m6_remote_origin_digest(manifest.spec.target.target_aliases["target"])
            )
            if completion.environment_digest != expected_target_digest:
                raise ValueError("verification_target_profile_mismatch")
            if len({replay.reset_id for replay in completion.replay_results}) != _M5_REPLAY_COUNT:
                raise ValueError("verification_reset_reuse_detected")
            if profile == "m5":
                if any(
                    replay.remote_origin_sha256 is not None for replay in completion.replay_results
                ):
                    raise ValueError("verification_remote_proof_not_allowed")
            elif any(
                replay.remote_origin_sha256 != expected_target_digest
                or replay.remote_response_sha256 is None
                or replay.controller_lab_id is not None
                for replay in completion.replay_results
            ):
                raise ValueError("verification_remote_proof_invalid")

            replay_results = [
                replay.model_dump(mode="json", exclude_none=True)
                for replay in completion.replay_results
            ]
            verification_proof_ref: str | None = None
            if completion.verified:
                proof = completion.proof
                assert proof is not None  # validated by VerifierCompletionV1
                if (
                    proof.run_id != run.id
                    or proof.candidate_id != candidate.id
                    or proof.challenge_digest != candidate.challenge_digest
                    or proof.plan_artifact_digest != candidate.plan_artifact_digest
                    or proof.target_image_digest != completion.environment_digest
                    or tuple(proof.replays) != tuple(completion.replay_results)
                ):
                    raise ValueError("verification_proof_binding_mismatch")
                if proof_artifact is None:
                    raise ValueError("verification_proof_artifact_required")
                self._validate_verification_proof_artifact(
                    proof_artifact,
                    proof_bytes=proof.canonical_bytes(),
                    run_id=run.id,
                )
                artifact = await session.get(ArtifactRow, proof_artifact.id, with_for_update=True)
                if artifact is None:
                    artifact = ArtifactRow(
                        id=proof_artifact.id,
                        run_id=proof_artifact.run_id,
                        sha256=proof_artifact.sha256,
                        name=proof_artifact.name,
                        media_type=proof_artifact.media_type,
                        size_bytes=proof_artifact.size_bytes,
                        classification=proof_artifact.classification,
                        producer=proof_artifact.producer,
                        locator=proof_artifact.locator,
                        created_at=now,
                    )
                    session.add(artifact)
                    await self._append_event_row(
                        session,
                        run.id,
                        "artifact.created",
                        {
                            "artifact_id": artifact.id,
                            "sha256": artifact.sha256,
                            "name": artifact.name,
                            "classification": artifact.classification,
                        },
                        actor={"kind": "service", "id": artifact.producer},
                        idempotency_key=f"artifact:{artifact.id}",
                    )
                elif not self._runtime_artifact_matches_row(proof_artifact, artifact):
                    raise ValueError("artifact_id_conflict")
                verification_proof_ref = proof_artifact.id
            elif proof_artifact is not None:
                raise ValueError("rejected_verification_cannot_store_proof")

            verification = VerificationRow(
                id=new_id("verify"),
                run_id=run.id,
                verified=completion.verified,
                exploit_digest=candidate.plan_artifact_digest,
                environment_digest=completion.environment_digest,
                # Each reset intentionally uses a different flag. The hashes
                # stay attached to per-attempt evidence; no raw flag or
                # misleading single canonical hash is persisted here.
                flag_sha256=None,
                masked_flag=None,
                replay_results=replay_results,
                provenance={
                    "source": "fresh_target_response" if completion.verified else "replay_rejected",
                    "runner_profile": (
                        "m5-declarative-replay-v1"
                        if profile == "m5"
                        else "m6-exact-remote-replay-v1"
                    ),
                    "candidate_id": candidate.id,
                    "plan_semantic_digest": candidate.plan_semantic_digest,
                    "replay_count_required": manifest.spec.flag.replay_count,
                },
                verification_proof_ref=verification_proof_ref,
                created_at=now,
            )
            session.add(verification)
            for replay in completion.replay_results:
                session.add(
                    VerificationAttemptRow(
                        id=new_id("verify_attempt"),
                        candidate_id=candidate.id,
                        run_id=run.id,
                        verification_id=verification.id,
                        attempt=replay.attempt,
                        reset_id=replay.reset_id,
                        target_generation=replay.target_generation,
                        passed=replay.passed,
                        started_from_clean_reset=replay.started_from_clean_reset,
                        flag_sha256=replay.flag_sha256,
                        controller_lab_id=replay.controller_lab_id,
                        controller_issued_at=replay.controller_issued_at,
                        controller_proof_id=replay.controller_proof_id,
                        controller_signature=replay.controller_signature,
                        failure_code=replay.failure_code,
                        created_at=now,
                    )
                )

            candidate.verification_id = verification.id
            candidate.status = "verified" if completion.verified else "rejected"
            candidate.failure_code = completion.failure_code
            candidate.updated_at = now
            previous_status = run.status
            run.status = "solved" if completion.verified else "running"
            run.updated_at = now
            run.result = (
                {
                    "verification_id": verification.id,
                    "verified": True,
                    "masked_flag": None,
                }
                if completion.verified
                else None
            )
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            outcome_event = (
                "verification.completed" if completion.verified else "verification.rejected"
            )
            await self._append_event_row(
                session,
                run.id,
                outcome_event,
                {
                    "verification_id": verification.id,
                    "candidate_id": candidate.id,
                    "verified": completion.verified,
                    "verification_proof_ref": verification_proof_ref,
                    "replay_count": len(replay_results),
                    "failure_code": completion.failure_code,
                },
                actor={"kind": "verifier", "id": worker_id},
                idempotency_key=f"verification:{verification.id}:completed",
            )
            await self._append_event_row(
                session,
                run.id,
                "run.state.changed",
                {
                    "previous_status": previous_status,
                    "status": run.status,
                    "reason": "independent_verifier_passed"
                    if completion.verified
                    else "independent_verifier_rejected_candidate",
                },
                actor={"kind": "verifier", "id": worker_id},
                idempotency_key=f"run:{run.id}:verification:{verification.id}:state",
            )
            await self._append_event_row(
                session,
                run.id,
                "agent.job.completed",
                {
                    "job_id": job.id,
                    "kind": job.kind,
                    "result_ref": f"verification:{verification.id}",
                },
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{job.lease_version}",
            )
        return {
            "verification": self._verification(verification),
            "candidate": self._exploit_candidate(candidate),
        }

    async def fail_verification_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
        reason: str,
    ) -> dict[str, Any]:
        """Fail a verifier worker without granting a synthetic solve/reject outcome.

        A controller outage or artifact-read failure leaves the run in
        ``verifying``. An operator can inspect the durable failure and decide
        whether to cancel or retry through a later explicit workflow.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        _validate_runtime_failure_code(reason)
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_verification_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                now=now,
            )
            candidate_id = _parse_runtime_reference(
                job.payload_ref, _CANDIDATE_REF, "verification_job_candidate_ref_invalid"
            )
            candidate = await session.get(ExploitCandidateRow, candidate_id, with_for_update=True)
            if candidate is None or candidate.run_id != job.run_id:
                raise ValueError("verification_candidate_not_found")
            if candidate.status != "verifying":
                raise ValueError("verification_candidate_not_available")
            candidate.status = "unavailable"
            candidate.failure_code = reason
            candidate.updated_at = now
            job.state = "failed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            await self._append_event_row(
                session,
                job.run_id,
                "verification.unavailable",
                {"candidate_id": candidate.id, "job_id": job.id, "reason": reason},
                actor={"kind": "verifier", "id": worker_id},
                idempotency_key=f"verification:{candidate.id}:unavailable:{job.lease_version}",
            )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.failed",
                {"job_id": job.id, "kind": job.kind, "reason": reason},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:failed:{job.lease_version}",
            )
        return {"job": self._agent_job(job), "candidate": self._exploit_candidate(candidate)}

    async def queue_agent_steer(
        self,
        run_id: str,
        *,
        message: str,
        idempotency_key: str,
        requested_by: str,
    ) -> dict[str, Any]:
        """Persist a sanitized operator steer without injecting it mid-turn.

        If the session is busy, this method records the request only. A turn
        completion atomically exposes it as a `steer` job, which is the safe
        boundary Pi Runner is allowed to consume.
        """

        _validate_idempotency_key(idempotency_key)
        _validate_lease_owner(requested_by)
        if not message.strip() or len(message) > 2_000:
            raise ValueError("invalid_agent_steer_message")
        if _contains_plaintext_secret(message):
            raise ValueError("agent_steer_contains_secret")
        safe_message = _redact_text(message.strip())
        message_digest = hashlib.sha256(safe_message.encode("utf-8")).hexdigest()
        now = utc_now()
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status not in {"running", "paused"}:
                    raise ValueError("agent_steer_run_not_active")
                existing = await session.scalar(
                    select(AgentSteerRow).where(
                        AgentSteerRow.run_id == run_id,
                        AgentSteerRow.idempotency_key == idempotency_key,
                    )
                )
                if existing is not None:
                    if existing.message_digest != message_digest:
                        raise ValueError("idempotency_conflict")
                    return self._agent_steer(existing)
                agent_session = await session.scalar(
                    select(AgentSessionRow)
                    .where(
                        AgentSessionRow.run_id == run_id,
                        AgentSessionRow.state.in_(
                            [AgentSessionState.READY.value, AgentSessionState.RUNNING.value]
                        ),
                    )
                    .order_by(AgentSessionRow.created_at.desc())
                    .limit(1)
                    .with_for_update()
                )
                if agent_session is None:
                    raise ValueError("agent_session_not_available")
                steer = AgentSteerRow(
                    id=new_id("steer"),
                    run_id=run_id,
                    session_id=agent_session.id,
                    message=safe_message,
                    message_digest=message_digest,
                    state="queued",
                    idempotency_key=idempotency_key,
                    requested_by=requested_by,
                    created_at=now,
                    applied_at=None,
                )
                session.add(steer)
                await self._append_event_row(
                    session,
                    run_id,
                    "human.steering.added",
                    {
                        "steer_id": steer.id,
                        "session_id": agent_session.id,
                        "message_sha256": message_digest,
                    },
                    actor={"kind": "human", "id": requested_by},
                    idempotency_key=f"steer:{steer.id}:requested",
                )
                await self._enqueue_pending_agent_steers(
                    session,
                    agent_session=agent_session,
                    actor={"kind": "system", "id": "run-engine"},
                )
        return self._agent_steer(steer)

    async def complete_pi_steer(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Acknowledge queued steer delivery and schedule the next safe turn."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.STEER,
                now=now,
            )
            steer_id = _parse_runtime_reference(
                job.payload_ref, _STEER_REF, "agent_steer_ref_invalid"
            )
            steer = await session.get(AgentSteerRow, steer_id, with_for_update=True)
            if steer is None or steer.run_id != job.run_id or steer.state != "queued":
                raise ValueError("agent_steer_not_available")
            agent_session = await session.get(
                AgentSessionRow, steer.session_id, with_for_update=True
            )
            if (
                agent_session is None
                or agent_session.runner_id != worker_id
                or agent_session.state != AgentSessionState.READY.value
            ):
                raise ValueError("agent_steer_not_at_safe_boundary")
            context_row = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            if context_row is None:
                raise ValueError("agent_steer_context_missing")
            context = self._context_manifest_from_row(context_row)
            steer.state = "applied"
            steer.applied_at = now
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            await self._append_event_row(
                session,
                job.run_id,
                "agent.steer.applied",
                {"steer_id": steer.id, "session_id": agent_session.id},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"steer:{steer.id}:applied",
            )
            await self._enqueue_agent_job_row(
                session,
                run_id=job.run_id,
                kind=AgentJobKind.RUN_TURN.value,
                payload_ref=f"session:{agent_session.id}",
                payload_digest=context.digest,
                idempotency_key=f"pi-turn:{agent_session.id}:steer:{steer.id}",
                deadline_at=None,
                actor={"kind": "service", "id": worker_id},
            )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.completed",
                {"job_id": job.id, "kind": job.kind, "result_ref": f"steer:{steer.id}"},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
        return self._agent_steer(steer)

    async def request_pi_abort(
        self,
        run_id: str,
        *,
        idempotency_key: str,
        requested_by: str,
    ) -> list[dict[str, Any]]:
        """Cancel a run and enqueue aborts for every active Pi session.

        The state transition happens before an abort worker is claimed.  This
        immediately denies newly reserved tool calls, starts, turns, and
        steers, while the only remaining Pi jobs are non-target-facing abort
        and dispose work required to release local session resources.
        """

        _validate_idempotency_key(idempotency_key)
        _validate_lease_owner(requested_by)
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status == "cancelled":
                    rows = (
                        await session.scalars(
                            select(AgentJobRow)
                            .where(
                                AgentJobRow.run_id == run_id,
                                AgentJobRow.kind == AgentJobKind.ABORT.value,
                            )
                            .order_by(AgentJobRow.created_at, AgentJobRow.id)
                        )
                    ).all()
                    return [self._agent_job(row) for row in rows]
                if run.status not in {"created", "preparing", "running", "paused", "verifying"}:
                    raise ValueError("invalid_run_transition")
                now = utc_now()
                queued_jobs = (
                    await session.scalars(
                        select(AgentJobRow)
                        .where(
                            AgentJobRow.run_id == run_id,
                            AgentJobRow.kind.in_(_PI_START_OR_TURN_JOB_KINDS),
                            AgentJobRow.state == "queued",
                        )
                        .with_for_update()
                    )
                ).all()
                for queued_job in queued_jobs:
                    queued_job.state = "cancelled"
                    queued_job.updated_at = now
                    await self._append_event_row(
                        session,
                        run_id,
                        "agent.job.cancelled",
                        {
                            "job_id": queued_job.id,
                            "kind": queued_job.kind,
                            "reason": "run_cancelled",
                        },
                        actor={"kind": "human", "id": requested_by},
                        idempotency_key=f"job:{queued_job.id}:cancelled",
                    )
                queued_tasks = (
                    await session.scalars(
                        select(WorkerTaskRow)
                        .where(WorkerTaskRow.run_id == run_id, WorkerTaskRow.state == "queued")
                        .with_for_update()
                    )
                ).all()
                for task in queued_tasks:
                    task.state = "cancelled"
                    task.updated_at = now
                    await self._append_event_row(
                        session,
                        run_id,
                        "task.cancelled",
                        {"task_id": task.id, "reason": "run_cancelled"},
                        actor={"kind": "human", "id": requested_by},
                        idempotency_key=f"task:{task.id}:cancelled",
                    )
                await session.execute(
                    update(AgentSteerRow)
                    .where(AgentSteerRow.run_id == run_id, AgentSteerRow.state == "queued")
                    .values(state="cancelled")
                )
                previous_status = run.status
                run.status = "cancelled"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run_id,
                    "run.state.changed",
                    {
                        "previous_status": previous_status,
                        "status": "cancelled",
                        "reason": "human_cancel_requested",
                    },
                    actor={"kind": "human", "id": requested_by},
                    idempotency_key=f"run:{run_id}:cancel:{idempotency_key}",
                )
                agent_sessions = (
                    await session.scalars(
                        select(AgentSessionRow)
                        .where(
                            AgentSessionRow.run_id == run_id,
                            AgentSessionRow.state.in_(
                                [
                                    AgentSessionState.STARTING.value,
                                    AgentSessionState.READY.value,
                                    AgentSessionState.RUNNING.value,
                                    AgentSessionState.ABORTING.value,
                                ]
                            ),
                        )
                        .order_by(AgentSessionRow.created_at, AgentSessionRow.id)
                        .with_for_update()
                    )
                ).all()
                abort_jobs: list[AgentJobRow] = []
                for agent_session in agent_sessions:
                    context_row = await session.get(
                        ContextManifestRow,
                        agent_session.context_manifest_id,
                    )
                    if context_row is None:
                        raise ValueError("agent_abort_context_missing")
                    context = self._context_manifest_from_row(context_row)
                    agent_session.state = AgentSessionState.ABORTING.value
                    agent_session.updated_at = now
                    abort_key = (
                        "pi-abort:"
                        + hashlib.sha256(
                            f"{idempotency_key}:{agent_session.id}".encode()
                        ).hexdigest()[:48]
                    )
                    job = await self._enqueue_agent_job_row(
                        session,
                        run_id=run_id,
                        kind=AgentJobKind.ABORT.value,
                        payload_ref=f"session:{agent_session.id}",
                        payload_digest=context.digest,
                        idempotency_key=abort_key,
                        deadline_at=None,
                        actor={"kind": "human", "id": requested_by},
                    )
                    abort_jobs.append(job)
                    await self._append_event_row(
                        session,
                        run_id,
                        "agent.abort.requested",
                        {"session_id": agent_session.id, "job_id": job.id},
                        actor={"kind": "human", "id": requested_by},
                        idempotency_key=f"session:{agent_session.id}:abort-requested",
                    )
        return [self._agent_job(job) for job in abort_jobs]

    async def complete_pi_abort(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Record Pi abort acknowledgement, cancel the run, then queue disposal."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.ABORT,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _SESSION_REF, "agent_abort_ref_invalid"
            )
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            run = await session.get(RunRow, job.run_id, with_for_update=True)
            if agent_session is None or run is None or agent_session.run_id != run.id:
                raise ValueError("agent_abort_session_missing")
            if agent_session.runner_id != worker_id:
                raise ValueError("agent_session_runner_mismatch")
            context_row = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            if context_row is None:
                raise ValueError("agent_abort_context_missing")
            context = self._context_manifest_from_row(context_row)
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            if run.status in {"preparing", "running", "paused", "verifying"}:
                previous_status = run.status
                run.status = "cancelled"
                run.updated_at = now
                await self._append_event_row(
                    session,
                    run.id,
                    "run.state.changed",
                    {
                        "previous_status": previous_status,
                        "status": "cancelled",
                        "reason": "pi_abort_acknowledged",
                    },
                    actor={"kind": "service", "id": worker_id},
                    idempotency_key=f"run:{run.id}:pi-abort-cancelled",
                )
            await self._enqueue_agent_job_row(
                session,
                run_id=run.id,
                kind=AgentJobKind.DISPOSE.value,
                payload_ref=f"session:{agent_session.id}",
                payload_digest=context.digest,
                idempotency_key=f"pi-dispose:{agent_session.id}:v1",
                deadline_at=None,
                actor={"kind": "service", "id": worker_id},
            )
            await self._append_event_row(
                session,
                run.id,
                "agent.job.completed",
                {"job_id": job.id, "kind": job.kind, "result_ref": f"session:{agent_session.id}"},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
        return self._agent_job(job)

    async def complete_pi_dispose(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Close the durable session lifecycle after Pi releases local resources."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.DISPOSE,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _SESSION_REF, "agent_dispose_ref_invalid"
            )
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if agent_session is None or agent_session.run_id != job.run_id:
                raise ValueError("agent_dispose_session_missing")
            agent_session.state = AgentSessionState.DISPOSED.value
            agent_session.runner_id = worker_id
            agent_session.updated_at = now
            job.state = "completed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = now
            await self._append_event_row(
                session,
                job.run_id,
                "agent.session.disposed",
                {"session_id": agent_session.id},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"session:{agent_session.id}:disposed",
            )
            await self._append_event_row(
                session,
                job.run_id,
                "agent.job.completed",
                {"job_id": job.id, "kind": job.kind, "result_ref": f"session:{agent_session.id}"},
                actor={"kind": "service", "id": worker_id},
                idempotency_key=f"job:{job.id}:complete:{lease_version}",
            )
        return self._agent_job(job)

    async def submit_pi_finding(
        self,
        submission: FindingSubmission,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Accept a worker finding only when evidence is in its sealed context."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if _contains_plaintext_secret(submission.statement):
            raise ValueError("finding_contains_secret")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            job = await session.get(AgentJobRow, job_id, with_for_update=True)
            if job is None:
                raise ValueError("agent_job_not_found")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.RUN_TURN,
                now=now,
            )
            session_id = _parse_runtime_reference(
                job.payload_ref, _SESSION_REF, "finding_session_ref_invalid"
            )
            if session_id != submission.session_id:
                raise ValueError("finding_session_mismatch")
            agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
            if (
                agent_session is None
                or agent_session.run_id != job.run_id
                or agent_session.runner_id != worker_id
                or agent_session.state != AgentSessionState.RUNNING.value
            ):
                raise ValueError("finding_session_not_running")
            try:
                role = AgentRole(agent_session.role)
            except ValueError as exc:
                raise ValueError("finding_role_invalid") from exc
            if "finding.submit" not in agent_role_tool_ids(role):
                raise ValueError("finding_role_not_authorized")
            context_row = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            task = await session.get(WorkerTaskRow, agent_session.task_id, with_for_update=True)
            if context_row is None or task is None:
                raise ValueError("finding_context_or_task_missing")
            context = self._context_manifest_from_row(context_row)
            permitted_evidence = {reference.observation_id for reference in context.evidence_refs}
            if not set(submission.evidence_ids).issubset(permitted_evidence):
                raise ValueError("finding_evidence_not_in_context")
            if task.state != "leased" or task.lease_owner != worker_id:
                raise ValueError("finding_task_lease_lost")
            finding_digest = hashlib.sha256(
                f"{job.id}:{submission.tool_call_id}".encode()
            ).hexdigest()
            finding_id = f"finding_{finding_digest[:32]}"
            event = await self._append_event_row(
                session,
                job.run_id,
                "finding.submitted",
                {
                    "finding_id": finding_id,
                    "session_id": agent_session.id,
                    "task_id": task.id,
                    "technique_id": task.technique_id,
                    "statement": submission.statement,
                    "confidence": submission.confidence,
                    "disposition": submission.disposition,
                    "evidence_ids": list(submission.evidence_ids),
                },
                actor={"kind": "worker", "id": worker_id},
                idempotency_key=f"finding:{finding_digest}",
            )
            task.state = "completed"
            task.lease_owner = None
            task.lease_expires_at = None
            task.updated_at = now
            await self._complete_branch_from_task(
                session,
                task=task,
                confidence=submission.confidence,
                observed=submission.disposition != "inconclusive",
            )
            await self._append_event_row(
                session,
                job.run_id,
                "task.completed",
                {"task_id": task.id, "result_ref": f"finding:{finding_id}"},
                actor={"kind": "worker", "id": worker_id},
                idempotency_key=f"task:{task.id}:finding:{finding_digest[:24]}",
            )
            if submission.disposition != "inconclusive" and task.technique_id != "general.review":
                outcome = (
                    HintOutcome.FULFILLED
                    if submission.disposition == "supports"
                    else HintOutcome.CONTRADICTED
                )
                await self._resolve_active_hints_from_evidence(
                    session,
                    run_id=job.run_id,
                    technique_id=task.technique_id,
                    branch_scope=task.branch_scope,
                    outcome=outcome,
                    evidence_refs=tuple(submission.evidence_ids),
                    actor_id=worker_id,
                )
            if (
                role is not AgentRole.FALSIFIER
                and submission.disposition != "inconclusive"
                and submission.confidence >= 0.8
            ):
                trigger = (
                    "conflicting_findings"
                    if await self._has_conflicting_finding(
                        session,
                        run_id=job.run_id,
                        technique_id=task.technique_id,
                        disposition=submission.disposition,
                        exclude_finding_id=finding_id,
                    )
                    else "high_confidence_unverified_finding"
                )
                await self._enqueue_falsifier_for_finding(
                    session,
                    run=await self._required_run_row(session, job.run_id),
                    source_task=task,
                    source_context=context,
                    evidence_ids=tuple(submission.evidence_ids),
                    finding_id=finding_id,
                    trigger=trigger,
                )
        return {"finding_id": finding_id, "event": self._event(event)}

    async def delegate_pi_task(
        self,
        delegation: TaskDelegationRequest,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Let a master request one bounded worker task through the kernel.

        The tool call supplies only a reviewed role, short objective, and
        evidence IDs already visible to the master.  The kernel owns every
        durable identity, context digest, lease, branch, budget slice, and Pi
        start job; no model response is ever copied into those authority fields.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if _contains_plaintext_secret(delegation.objective):
            raise ValueError("delegated_task_contains_secret")
        now = utc_now()
        # Serialise duplicate delivery of this one master tool call locally;
        # the database job lease remains the cross-process authority.
        async with self._run_locks[job_id]:
            async with self.database.sessions() as session, session.begin():
                job = await session.get(AgentJobRow, job_id, with_for_update=True)
                if job is None:
                    raise ValueError("agent_job_not_found")
                self._require_pi_job_lease(
                    job,
                    worker_id=worker_id,
                    lease_version=lease_version,
                    expected_kind=AgentJobKind.RUN_TURN,
                    now=now,
                )
                session_id = _parse_runtime_reference(
                    job.payload_ref,
                    _SESSION_REF,
                    "delegation_session_ref_invalid",
                )
                agent_session = await session.get(AgentSessionRow, session_id, with_for_update=True)
                if (
                    agent_session is None
                    or agent_session.run_id != job.run_id
                    or agent_session.runner_id != worker_id
                    or agent_session.role != AgentRole.MASTER.value
                    or agent_session.state != AgentSessionState.RUNNING.value
                ):
                    raise ValueError("delegation_master_session_not_running")
                parent_task = await session.get(
                    WorkerTaskRow, agent_session.task_id, with_for_update=True
                )
                context_row = await session.get(
                    ContextManifestRow,
                    agent_session.context_manifest_id,
                    with_for_update=True,
                )
                if parent_task is None or context_row is None or parent_task.run_id != job.run_id:
                    raise ValueError("delegation_parent_context_missing")
                if parent_task.state != "leased" or parent_task.lease_owner != worker_id:
                    raise ValueError("delegation_parent_task_lease_lost")
                context = self._context_manifest_from_row(context_row)
                if context.role != AgentRole.MASTER.value or context.expires_at <= now:
                    raise ValueError("delegation_master_context_invalid")
                if _stored_utc(parent_task.deadline_at) <= now:
                    raise ValueError("delegation_parent_task_expired")

                active_hint = await session.scalar(
                    select(HintCardRow)
                    .where(
                        HintCardRow.run_id == job.run_id,
                        HintCardRow.technique_id == delegation.technique_id,
                        HintCardRow.status == HintStatus.ACTIVE.value,
                    )
                    .order_by(HintCardRow.priority.desc(), HintCardRow.created_at, HintCardRow.id)
                    .limit(1)
                )
                if delegation.technique_id != "general.review" and active_hint is None:
                    # A master may choose the neutral review path, or a
                    # technique an operator has attached from the reviewed
                    # catalog. It cannot invent a new attack category.
                    raise ValueError("delegation_technique_not_active")
                branch_scope = "run:all" if active_hint is None else active_hint.target_ref
                if await self._has_active_avoid_hint(
                    session,
                    run_id=job.run_id,
                    technique_id=delegation.technique_id,
                    branch_scope=branch_scope,
                ):
                    raise ValueError("hint_avoid_blocks_task")

                allowed_by_id = {
                    evidence.observation_id: evidence for evidence in context.evidence_refs
                }
                if not set(delegation.evidence_ids).issubset(allowed_by_id):
                    raise ValueError("delegation_evidence_not_in_context")

                # The tool-call ID gives retry-safe deterministic records
                # without trusting the model to mint an ID or idempotency key.
                delegation_digest = hashlib.sha256(
                    f"{job.id}:{delegation.tool_call_id}".encode()
                ).hexdigest()
                child_task_id = f"task_{delegation_digest[:32]}"
                child_context_id = f"ctx_{delegation_digest[:32]}"
                child_branch_id = f"branch_{delegation_digest[:32]}"
                existing_task = await session.get(
                    WorkerTaskRow, child_task_id, with_for_update=True
                )
                if existing_task is not None:
                    if (
                        existing_task.run_id != job.run_id
                        or existing_task.role != delegation.role.value
                        or existing_task.technique_id != delegation.technique_id
                        or existing_task.objective != delegation.objective
                        or tuple(existing_task.required_evidence) != tuple(delegation.evidence_ids)
                        or existing_task.context_manifest_id != child_context_id
                    ):
                        raise ValueError("delegation_idempotency_conflict")
                    start_job = await session.scalar(
                        select(AgentJobRow).where(
                            AgentJobRow.run_id == job.run_id,
                            AgentJobRow.idempotency_key == f"pi-session:{child_task_id}:v1",
                        )
                    )
                    if start_job is None:
                        raise ValueError("delegation_start_job_missing")
                    return {
                        "task": self._worker_task(existing_task),
                        "session_job": self._agent_job(start_job),
                    }

                # M4 replaces M2's one-child proof cap with a stable two
                # worker portfolio. A second worker must differ by role, so a
                # weak model cannot spend both slots repeating one approach.
                active_workers = (
                    await session.scalars(
                        select(WorkerTaskRow)
                        .where(
                            WorkerTaskRow.run_id == job.run_id,
                            WorkerTaskRow.role != AgentRole.MASTER.value,
                            WorkerTaskRow.state.in_(["queued", "leased"]),
                        )
                        .with_for_update()
                    )
                ).all()
                if len(active_workers) >= _MAX_ACTIVE_WORKER_BRANCHES:
                    raise ValueError("worker_capacity_reached")
                if any(worker.role == delegation.role.value for worker in active_workers):
                    raise ValueError("worker_role_diversity_required")

                selected_evidence = tuple(
                    allowed_by_id[evidence_id] for evidence_id in delegation.evidence_ids
                )
                attempt_fingerprint = self._scheduler_attempt_fingerprint(
                    tool_id="task.delegate",
                    challenge_digest=context.challenge_digest,
                    branch_scope=branch_scope,
                    canonical_input={
                        "technique_id": delegation.technique_id,
                        "role": delegation.role.value,
                        "objective": delegation.objective,
                        "evidence_ids": list(delegation.evidence_ids),
                    },
                )
                prior_attempt = await session.scalar(
                    select(WorkerTaskRow).where(
                        WorkerTaskRow.run_id == job.run_id,
                        WorkerTaskRow.attempt_fingerprint == attempt_fingerprint,
                    )
                )
                if prior_attempt is not None:
                    raise ValueError("attempt_fingerprint_exists")
                child_deadline = min(_stored_utc(parent_task.deadline_at), context.expires_at)
                child_context = ContextManifest.issue(
                    id=child_context_id,
                    run_id=job.run_id,
                    task_id=child_task_id,
                    challenge_digest=context.challenge_digest,
                    role=delegation.role.value,
                    objective=delegation.objective,
                    allowed_tool_ids=agent_role_tool_ids(delegation.role),
                    evidence_refs=tuple(
                        ContextEvidenceRef(
                            observation_id=evidence.observation_id,
                            artifact_id=evidence.artifact_id,
                            digest=evidence.digest,
                        )
                        for evidence in selected_evidence
                    ),
                    hypothesis_refs=(),
                    active_hint_refs=await self._active_hint_refs(
                        session,
                        run_id=job.run_id,
                        technique_id=delegation.technique_id,
                        branch_scope=branch_scope,
                    ),
                    attempt_fingerprints=(attempt_fingerprint,),
                    budget_slice=ContextBudgetSlice(
                        tool_calls=min(4, context.budget_slice.tool_calls),
                        input_tokens=min(6_000, context.budget_slice.input_tokens),
                        output_tokens=min(1_200, context.budget_slice.output_tokens),
                    ),
                    created_at=now,
                    expires_at=child_deadline,
                )
                child_task = RuntimeTask(
                    id=child_task_id,
                    run_id=job.run_id,
                    branch_id=child_branch_id,
                    role=delegation.role.value,
                    objective=delegation.objective,
                    required_evidence=tuple(delegation.evidence_ids),
                    context_manifest_id=child_context.id,
                    lease_version=0,
                    deadline_at=child_deadline,
                )
                encoded_context = canonical_json(
                    child_context.model_dump(mode="json", by_alias=True)
                )
                if len(encoded_context) > _MAX_CONTEXT_MANIFEST_BYTES:
                    raise ValueError("context_manifest_too_large")
                session.add(
                    ContextManifestRow(
                        id=child_context.id,
                        run_id=child_context.run_id,
                        task_id=child_context.task_id,
                        document=encoded_context.decode("utf-8"),
                        digest=child_context.digest,
                        size_bytes=len(encoded_context),
                        expires_at=child_context.expires_at,
                        created_at=child_context.created_at,
                    )
                )
                session.add(
                    RunBranchRow(
                        id=child_task.branch_id,
                        run_id=child_task.run_id,
                        family=f"m4-delegated-{delegation.role.value}-{attempt_fingerprint[:16]}",
                        state="active",
                        technique_id=delegation.technique_id,
                        branch_scope=branch_scope,
                        priority=1.0,
                        novelty=1.0,
                        evidence_strength=min(1.0, len(selected_evidence) / 4.0),
                        expected_value=0.6,
                        normalized_cost=0.5 if delegation.role is AgentRole.HTTP_TESTER else 0.25,
                        repetition_penalty=0.0,
                        consecutive_no_observation=0,
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.add(
                    WorkerTaskRow(
                        id=child_task.id,
                        run_id=child_task.run_id,
                        branch_id=child_task.branch_id,
                        role=child_task.role,
                        objective=child_task.objective,
                        required_evidence=list(child_task.required_evidence),
                        context_manifest_id=child_task.context_manifest_id,
                        technique_id=delegation.technique_id,
                        branch_scope=branch_scope,
                        attempt_fingerprint=attempt_fingerprint,
                        state="queued",
                        lease_owner=None,
                        lease_version=child_task.lease_version,
                        lease_expires_at=None,
                        attempts=0,
                        deadline_at=child_task.deadline_at,
                        created_at=now,
                        updated_at=now,
                    )
                )
                start_job = await self._enqueue_agent_job_row(
                    session,
                    run_id=job.run_id,
                    kind=AgentJobKind.START_SESSION.value,
                    payload_ref=f"context:{child_context.id}",
                    payload_digest=child_context.digest,
                    idempotency_key=f"pi-session:{child_task.id}:v1",
                    deadline_at=child_task.deadline_at,
                    actor={"kind": "worker", "id": worker_id},
                )
                await self._append_event_row(
                    session,
                    job.run_id,
                    "branch.created",
                    {
                        "branch_id": child_task.branch_id,
                        "family": (
                            f"m4-delegated-{delegation.role.value}-{attempt_fingerprint[:16]}"
                        ),
                        "technique_id": delegation.technique_id,
                    },
                    actor={"kind": "worker", "id": worker_id},
                    idempotency_key=f"branch:{child_task.branch_id}:created",
                )
                await self._append_event_row(
                    session,
                    job.run_id,
                    "task.queued",
                    {
                        "task_id": child_task.id,
                        "branch_id": child_task.branch_id,
                        "context_manifest_id": child_context.id,
                        "attempt_fingerprint": attempt_fingerprint,
                    },
                    actor={"kind": "worker", "id": worker_id},
                    idempotency_key=f"task:{child_task.id}:queued",
                )
                await self._append_event_row(
                    session,
                    job.run_id,
                    "agent.task.delegated",
                    {
                        "parent_session_id": agent_session.id,
                        "task_id": child_task.id,
                        "role": delegation.role.value,
                        "technique_id": delegation.technique_id,
                        "evidence_count": len(delegation.evidence_ids),
                    },
                    actor={"kind": "worker", "id": worker_id},
                    idempotency_key=f"delegation:{delegation_digest}",
                )
        return {"task": self._worker_task(child_task), "session_job": self._agent_job(start_job)}

    async def pi_run_state_view(
        self,
        session_id: str,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, Any]:
        """Return compact, target-free state for reviewed Pi control tools.

        This common state view intentionally excludes target/source details,
        operator secrets, and builder-only capture configuration.  A worker
        receives any narrower capability through its own typed control route.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session:
            job = await session.get(AgentJobRow, job_id)
            agent_session = await session.get(AgentSessionRow, session_id)
            if job is None or agent_session is None or agent_session.runner_id != worker_id:
                raise ValueError("agent_session_not_available")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.RUN_TURN,
                now=now,
            )
            if (
                _parse_runtime_reference(job.payload_ref, _SESSION_REF, "state_session_ref_invalid")
                != session_id
            ):
                raise ValueError("state_session_mismatch")
            run = await session.get(RunRow, agent_session.run_id)
            task = await session.get(WorkerTaskRow, agent_session.task_id)
            context = await session.get(ContextManifestRow, agent_session.context_manifest_id)
            if run is None or task is None or context is None:
                raise ValueError("agent_session_state_incomplete")
            hint_rows = (
                await session.scalars(
                    select(HintCardRow)
                    .where(
                        HintCardRow.run_id == run.id,
                        HintCardRow.status == HintStatus.ACTIVE.value,
                    )
                    .order_by(HintCardRow.priority.desc(), HintCardRow.created_at, HintCardRow.id)
                    .limit(32)
                )
            ).all()
            branch_rows = (
                await session.scalars(
                    select(RunBranchRow)
                    .where(RunBranchRow.run_id == run.id)
                    .order_by(RunBranchRow.updated_at.desc(), RunBranchRow.id)
                    .limit(16)
                )
            ).all()
            return {
                "run_id": run.id,
                "run_status": run.status,
                "session_id": agent_session.id,
                "session_state": agent_session.state,
                "task_id": task.id,
                "task_state": task.state,
                "context_manifest_digest": context.digest,
                "budget": {
                    "max_tool_calls": run.budget.get("max_tool_calls"),
                    "max_cost_usd": run.budget.get("max_cost_usd"),
                },
                # This fixed structure crosses only through state.get. It is
                # not concatenated into a system prompt, and the note remains
                # explicitly untrusted data that must be tested with tools.
                "operator_hints": [
                    {
                        "id": hint.id,
                        "technique_id": hint.technique_id,
                        "directive": hint.directive,
                        "scope": hint.target_ref,
                        "status": hint.status,
                        "note_data": hint.note,
                    }
                    for hint in hint_rows
                ],
                "branch_portfolio": [
                    {
                        "id": branch.id,
                        "technique_id": branch.technique_id,
                        "scope": branch.branch_scope,
                        "state": branch.state,
                        "score": round(
                            0.35 * branch.evidence_strength
                            + 0.25 * branch.novelty
                            + 0.20 * branch.priority
                            + 0.15 * branch.expected_value
                            - 0.20 * branch.normalized_cost
                            - branch.repetition_penalty,
                            6,
                        ),
                    }
                    for branch in branch_rows
                ],
            }

    async def pi_flag_capture_patterns_view(
        self,
        session_id: str,
        *,
        job_id: str,
        worker_id: str,
        lease_version: int,
    ) -> dict[str, tuple[str, ...]]:
        """Return the builder-only manifest capture projection for one active turn.

        This is deliberately not a convenience wrapper around ``state.get``.
        The extra role check makes the least-privilege rule enforceable at the
        control-plane boundary even if an untrusted transcript attempts to call
        the internal HTTP route directly.
        """

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        now = utc_now()
        async with self.database.sessions() as session:
            job = await session.get(AgentJobRow, job_id)
            agent_session = await session.get(AgentSessionRow, session_id)
            if job is None or agent_session is None or agent_session.runner_id != worker_id:
                raise ValueError("agent_session_not_available")
            self._require_pi_job_lease(
                job,
                worker_id=worker_id,
                lease_version=lease_version,
                expected_kind=AgentJobKind.RUN_TURN,
                now=now,
            )
            if (
                _parse_runtime_reference(job.payload_ref, _SESSION_REF, "state_session_ref_invalid")
                != session_id
            ):
                raise ValueError("state_session_mismatch")
            task = await session.get(WorkerTaskRow, agent_session.task_id)
            if task is None:
                raise ValueError("agent_session_state_incomplete")
            if task.role != AgentRole.EXPLOIT_BUILDER.value:
                raise ValueError("flag_capture_role_not_allowed")
            # Keep the run lookup explicit; it avoids accepting a session whose
            # foreign key was damaged or whose challenge record disappeared.
            run = await session.get(RunRow, agent_session.run_id)
            if run is None:
                raise ValueError("agent_session_state_incomplete")
            challenge = await session.get(ChallengeRow, run.challenge_id)
            if challenge is None:
                raise ValueError("challenge_not_found")
            try:
                manifest = ChallengeManifest.model_validate(challenge.manifest)
            except (TypeError, ValueError) as exc:
                raise ValueError("stored_challenge_manifest_invalid") from exc
            return {"flag_capture_patterns": manifest.spec.flag.patterns}

    async def list_preflight_observations(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(PreflightObservationRow)
                    .where(PreflightObservationRow.run_id == run_id)
                    .order_by(PreflightObservationRow.created_at, PreflightObservationRow.id)
                )
            ).all()
            return [self._preflight_observation(row) for row in rows]

    async def list_worker_tasks(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(WorkerTaskRow)
                    .where(WorkerTaskRow.run_id == run_id)
                    .order_by(WorkerTaskRow.created_at, WorkerTaskRow.id)
                )
            ).all()
            return [self._worker_task(row) for row in rows]

    async def claim_worker_task(
        self,
        run_id: str,
        *,
        worker_id: str,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Lease one task using the same CAS discipline as agent jobs."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= _MAX_LEASE_SECONDS:
            raise ValueError("invalid_lease_seconds")
        claimed_at = utc_now() if now is None else _require_aware_utc(now)
        expires_at = claimed_at + timedelta(seconds=lease_seconds)
        leaseable = or_(
            WorkerTaskRow.state == "queued",
            (WorkerTaskRow.state == "leased") & (WorkerTaskRow.lease_expires_at < claimed_at),
        )
        async with self._task_claim_lock:
            async with self.database.sessions() as session, session.begin():
                candidate = await session.scalar(
                    select(WorkerTaskRow)
                    .join(RunRow, WorkerTaskRow.run_id == RunRow.id)
                    .where(
                        WorkerTaskRow.run_id == run_id,
                        RunRow.status == "running",
                        leaseable,
                    )
                    .order_by(WorkerTaskRow.created_at, WorkerTaskRow.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if candidate is None:
                    return None
                next_version = candidate.lease_version + 1
                updated = cast(
                    CursorResult[Any],
                    await session.execute(
                        update(WorkerTaskRow)
                        .where(
                            WorkerTaskRow.id == candidate.id,
                            WorkerTaskRow.lease_version == candidate.lease_version,
                            leaseable,
                        )
                        .values(
                            state="leased",
                            lease_owner=worker_id,
                            lease_version=next_version,
                            lease_expires_at=expires_at,
                            attempts=candidate.attempts + 1,
                            updated_at=claimed_at,
                        )
                    ),
                )
                if updated.rowcount != 1:
                    return None
                await session.refresh(candidate)
                await self._append_event_row(
                    session,
                    run_id,
                    "task.leased",
                    {"task_id": candidate.id, "lease_version": candidate.lease_version},
                    actor={"kind": "worker", "id": worker_id},
                    idempotency_key=f"task:{candidate.id}:lease:{candidate.lease_version}",
                )
                return self._worker_task(candidate)

    async def complete_worker_task(
        self,
        task_id: str,
        *,
        worker_id: str,
        lease_version: int,
        result_ref: str,
    ) -> dict[str, Any]:
        """Close a task only when the caller owns its active lease."""

        _validate_lease_owner(worker_id)
        if isinstance(lease_version, bool) or lease_version < 1:
            raise ValueError("invalid_lease_version")
        if not result_ref.strip() or len(result_ref) > 500:
            raise ValueError("invalid_task_result_ref")
        now = utc_now()
        async with self.database.sessions() as session, session.begin():
            row = await session.get(WorkerTaskRow, task_id, with_for_update=True)
            if row is None:
                raise ValueError("worker_task_not_found")
            if (
                row.state != "leased"
                or row.lease_owner != worker_id
                or row.lease_version != lease_version
            ):
                raise ValueError("worker_task_lease_lost")
            if row.lease_expires_at is None or _stored_utc(row.lease_expires_at) <= now:
                raise ValueError("worker_task_lease_expired")
            row.state = "completed"
            row.lease_owner = None
            row.lease_expires_at = None
            row.updated_at = now
            await self._append_event_row(
                session,
                row.run_id,
                "task.completed",
                {"task_id": row.id, "result_ref": result_ref},
                actor={"kind": "worker", "id": worker_id},
                idempotency_key=f"task:{row.id}:complete:{lease_version}",
            )
        return self._worker_task(row)

    async def debit_power_wall_time(self, run_id: str) -> dict[str, Any]:
        """Debit elapsed wall time so a long race can exhaust its own cap.

        ``wall_time_seconds`` was a declared budget dimension that nothing ever
        debited, so the configured minute cap could not end a run: the console
        rendered an elapsed figure while the ledger stayed at zero.

        Time is charged in fixed buckets rather than as "seconds since the last
        debit". Several racers report usage concurrently, and a delta computed
        from the wall clock differs for each of them; keyed by the same second
        that produced ``idempotency_conflict`` and failed the caller's session.
        A whole bucket always carries the same amount, so two callers racing on
        one bucket replay a single idempotent debit instead of colliding.

        This bounds an *active* race only. A race whose sessions have all gone
        idle stops reporting usage, so nothing calls this and the cap cannot
        fire: an idle Power run is designed to wait for an operator steer or
        cancel, and ending it automatically would break that resume path.
        """

        async with self.database.sessions() as session:
            run = await session.get(RunRow, run_id)
            if run is None:
                raise ValueError("run_not_found")
            if run.status != "running":
                return {"accepted": True, "remaining": None, "ledger_id": None}
            limit = run.budget.get("wall_time_seconds")
            if isinstance(limit, bool) or not isinstance(limit, int | float):
                return {"accepted": True, "remaining": None, "ledger_id": None}
            recorded = await session.scalar(
                select(func.coalesce(func.sum(BudgetLedgerRow.debit), 0.0)).where(
                    BudgetLedgerRow.run_id == run_id,
                    BudgetLedgerRow.dimension == "wall_time_seconds",
                )
            )
            elapsed = (utc_now() - _stored_utc(run.created_at)).total_seconds()

        settled = int(float(recorded or 0.0) // _WALL_TIME_BUCKET_SECONDS)
        reached = int(elapsed // _WALL_TIME_BUCKET_SECONDS)
        outcome: dict[str, Any] = {"accepted": True, "remaining": None, "ledger_id": None}
        # A sparse reporter can leave several buckets unpaid; the ceiling keeps
        # one call bounded while still letting the next call catch up.
        for bucket in range(settled, min(reached, settled + _WALL_TIME_MAX_BUCKETS_PER_CALL)):
            outcome = await self.debit_budget(
                run_id,
                dimension="wall_time_seconds",
                amount=_WALL_TIME_BUCKET_SECONDS,
                idempotency_key=f"power-wall-time:{run_id}:{bucket}",
            )
            if not outcome["accepted"]:
                break
        return outcome

    async def debit_budget(
        self,
        run_id: str,
        *,
        dimension: str,
        amount: int | float,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Atomically reserve one bounded budget dimension before side effects.

        Repeating the same key returns the original ledger outcome. A rejected
        debit can transition an active run to ``budget_exhausted`` but never
        manufactures a tool result or retries a side effect.
        """

        if dimension not in _BUDGET_DIMENSIONS:
            raise ValueError("invalid_budget_dimension")
        if isinstance(amount, bool) or not isinstance(amount, int | float):
            raise ValueError("invalid_budget_amount")
        debit = float(amount)
        if not math.isfinite(debit) or debit <= 0:
            raise ValueError("invalid_budget_amount")
        _validate_idempotency_key(idempotency_key)
        payload_digest = digest_json({"dimension": dimension, "amount": debit})
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                existing = await session.scalar(
                    select(IdempotencyRecordRow).where(
                        IdempotencyRecordRow.run_id == run_id,
                        IdempotencyRecordRow.scope == "budget.debit",
                        IdempotencyRecordRow.key == idempotency_key,
                    )
                )
                if existing is not None:
                    if existing.payload_digest != payload_digest:
                        raise ValueError("idempotency_conflict")
                    if existing.result_ref == "budget:exhausted":
                        return {"accepted": False, "remaining": 0.0, "ledger_id": None}
                    ledger = await session.get(
                        BudgetLedgerRow, existing.result_ref.removeprefix("ledger:")
                    )
                    if ledger is None:
                        raise ValueError("idempotency_result_missing")
                    return {
                        "accepted": True,
                        "remaining": ledger.remaining_after,
                        "ledger_id": ledger.id,
                    }

                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                limit = run.budget.get(dimension)
                if isinstance(limit, bool) or not isinstance(limit, int | float):
                    raise ValueError("run_budget_dimension_missing")
                used = await session.scalar(
                    select(func.coalesce(func.sum(BudgetLedgerRow.debit), 0.0)).where(
                        BudgetLedgerRow.run_id == run_id,
                        BudgetLedgerRow.dimension == dimension,
                    )
                )
                remaining_before = max(0.0, float(limit) - float(used or 0.0))
                if debit > remaining_before + 1e-9:
                    session.add(
                        IdempotencyRecordRow(
                            id=new_id("idem"),
                            run_id=run_id,
                            scope="budget.debit",
                            key=idempotency_key,
                            payload_digest=payload_digest,
                            result_ref="budget:exhausted",
                            created_at=utc_now(),
                        )
                    )
                    if run.status == "running":
                        previous_status = run.status
                        run.status = "budget_exhausted"
                        run.updated_at = utc_now()
                        await self._append_event_row(
                            session,
                            run_id,
                            "run.state.changed",
                            {
                                "previous_status": previous_status,
                                "status": "budget_exhausted",
                                "reason": f"budget_exhausted:{dimension}",
                            },
                            actor={"kind": "system", "id": "run-engine"},
                            idempotency_key=f"run:{run_id}:budget-exhausted:{dimension}",
                        )
                    return {"accepted": False, "remaining": remaining_before, "ledger_id": None}

                remaining_after = max(0.0, remaining_before - debit)
                row = BudgetLedgerRow(
                    id=new_id("ledger"),
                    run_id=run_id,
                    dimension=dimension,
                    debit=debit,
                    remaining_after=remaining_after,
                    idempotency_key=idempotency_key,
                    created_at=utc_now(),
                )
                session.add(row)
                session.add(
                    IdempotencyRecordRow(
                        id=new_id("idem"),
                        run_id=run_id,
                        scope="budget.debit",
                        key=idempotency_key,
                        payload_digest=payload_digest,
                        result_ref=f"ledger:{row.id}",
                        created_at=utc_now(),
                    )
                )
                await self._append_event_row(
                    session,
                    run_id,
                    "budget.debited",
                    {
                        "ledger_id": row.id,
                        "dimension": dimension,
                        "debit": debit,
                        "remaining": remaining_after,
                    },
                    actor={"kind": "system", "id": "run-engine"},
                    idempotency_key=f"budget:{row.id}",
                )
                return {"accepted": True, "remaining": remaining_after, "ledger_id": row.id}

    async def list_budget_ledger(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(BudgetLedgerRow)
                    .where(BudgetLedgerRow.run_id == run_id)
                    .order_by(BudgetLedgerRow.created_at, BudgetLedgerRow.id)
                )
            ).all()
            return [self._budget_ledger(row) for row in rows]

    async def list_outbox(self, run_id: str, *, pending_only: bool = False) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            query = select(OutboxRow).where(OutboxRow.run_id == run_id)
            if pending_only:
                query = query.where(OutboxRow.published_at.is_(None))
            rows = (await session.scalars(query.order_by(OutboxRow.created_at, OutboxRow.id))).all()
            return [self._outbox(row) for row in rows]

    async def mark_outbox_published(self, outbox_id: str) -> dict[str, Any]:
        """Record a retry-safe publication acknowledgement without rewriting events."""

        async with self.database.sessions() as session, session.begin():
            row = await session.get(OutboxRow, outbox_id, with_for_update=True)
            if row is None:
                raise ValueError("outbox_not_found")
            if row.published_at is None:
                row.published_at = utc_now()
                row.attempts += 1
        return self._outbox(row)

    async def add_fact(self, fact: dict[str, Any]) -> dict[str, Any]:
        evidence = fact.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise ValueError("invalid_evidence")
        status = str(fact.get("status", "proposed"))
        actor_kind = str(fact.get("actor_kind", "worker"))
        if status not in {"proposed", "confirmed", "contradicted", "retracted"}:
            raise ValueError("invalid_fact_status")
        if actor_kind not in {"human", "worker", "system", "tool", "verifier"}:
            raise ValueError("invalid_actor_kind")
        if status == "confirmed" and not evidence and actor_kind != "human":
            raise ValueError("confirmed_fact_requires_evidence")
        if any(not _SHA256.fullmatch(str(item.get("digest", ""))) for item in evidence):
            raise ValueError("evidence_digest_required")
        raw_confidence = fact["confidence"]
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, int | float):
            raise ValueError("invalid_confidence")
        confidence = float(raw_confidence)
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid_confidence")
        safe_evidence = redact_event_payload(evidence)
        assert isinstance(safe_evidence, list)
        row = FactRow(
            id=str(fact.get("id") or new_id("fact")),
            run_id=str(fact["run_id"]),
            branch_id=fact.get("branch_id"),
            statement=_redact_text(str(fact["statement"])),
            confidence=confidence,
            status=status,
            evidence=safe_evidence,
            created_by=str(fact["created_by"]),
            created_at=utc_now(),
        )
        async with self._run_locks[row.run_id]:
            async with self.database.sessions() as session, session.begin():
                if await session.get(RunRow, row.run_id) is None:
                    raise ValueError("run_not_found")
                existing = await session.get(FactRow, row.id)
                if existing is not None:
                    if (
                        existing.run_id != row.run_id
                        or existing.branch_id != row.branch_id
                        or existing.statement != row.statement
                        or existing.confidence != row.confidence
                        or existing.status != row.status
                        or existing.evidence != row.evidence
                        or existing.created_by != row.created_by
                    ):
                        raise ValueError("fact_id_conflict")
                    return self._fact(existing)
                session.add(row)
                await self._append_event_row(
                    session,
                    row.run_id,
                    "blackboard.fact.added",
                    {"fact_id": row.id, "statement": row.statement, "status": row.status},
                    actor={"kind": actor_kind, "id": row.created_by},
                    idempotency_key=f"fact:{row.id}",
                )
        return self._fact(row)

    async def add_hypothesis(self, hypothesis: dict[str, Any]) -> dict[str, Any]:
        raw_confidence = hypothesis["confidence"]
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, int | float):
            raise ValueError("invalid_confidence")
        confidence = float(raw_confidence)
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid_confidence")
        status = str(hypothesis.get("status", "open"))
        if status not in {"open", "testing", "supported", "rejected", "merged", "suspended"}:
            raise ValueError("invalid_hypothesis_status")
        falsifiers = list(hypothesis.get("falsifiers", []))
        if not falsifiers or any(
            not isinstance(value, str) or not value.strip() for value in falsifiers
        ):
            raise ValueError("hypothesis_falsifier_required")
        row = HypothesisRow(
            id=str(hypothesis.get("id") or new_id("hyp")),
            run_id=str(hypothesis["run_id"]),
            branch_id=str(hypothesis["branch_id"]),
            family=str(hypothesis["family"]),
            statement=_redact_text(str(hypothesis["statement"])),
            confidence=confidence,
            status=status,
            supporting_fact_ids=list(hypothesis.get("supporting_fact_ids", [])),
            contradicting_fact_ids=list(hypothesis.get("contradicting_fact_ids", [])),
            falsifiers=falsifiers,
            next_experiment_id=hypothesis.get("next_experiment_id"),
        )
        async with self._run_locks[row.run_id]:
            async with self.database.sessions() as session, session.begin():
                if await session.get(RunRow, row.run_id) is None:
                    raise ValueError("run_not_found")
                for fact_id in row.supporting_fact_ids + row.contradicting_fact_ids:
                    fact = await session.get(FactRow, fact_id)
                    if fact is None or fact.run_id != row.run_id:
                        raise ValueError("cross_run_or_missing_fact_reference")
                existing = await session.get(HypothesisRow, row.id)
                if existing is not None:
                    if (
                        existing.run_id != row.run_id
                        or existing.branch_id != row.branch_id
                        or existing.family != row.family
                        or existing.statement != row.statement
                        or existing.confidence != row.confidence
                        or existing.status != row.status
                        or existing.supporting_fact_ids != row.supporting_fact_ids
                        or existing.contradicting_fact_ids != row.contradicting_fact_ids
                        or existing.falsifiers != row.falsifiers
                        or existing.next_experiment_id != row.next_experiment_id
                    ):
                        raise ValueError("hypothesis_id_conflict")
                    return self._hypothesis(existing)
                session.add(row)
                await self._append_event_row(
                    session,
                    row.run_id,
                    "blackboard.hypothesis.proposed",
                    {"hypothesis_id": row.id, "statement": row.statement},
                    actor={"kind": "worker", "id": "fake-strategist"},
                    idempotency_key=f"hypothesis:{row.id}",
                )
        return self._hypothesis(row)

    async def transition_hypothesis(
        self,
        run_id: str,
        hypothesis_id: str,
        *,
        status: str,
        actor: dict[str, str],
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Append a causal status transition for a persisted hypothesis.

        Council critics and adjudicators may only resolve an existing proposal;
        they cannot mutate its statement, evidence links, or falsifier.  The
        append-only event explains why a branch changed state.
        """

        if status not in {"testing", "supported", "rejected", "suspended", "merged"}:
            raise ValueError("invalid_hypothesis_status")
        if not reason.strip():
            raise ValueError("hypothesis_transition_reason_required")
        if not idempotency_key.strip() or len(idempotency_key) > 200:
            raise ValueError("invalid_idempotency_key")
        _validate_actor(actor)
        allowed = {
            "open": {"testing", "supported", "rejected", "suspended", "merged"},
            "testing": {"supported", "rejected", "suspended", "merged"},
            "supported": set(),
            "rejected": set(),
            "suspended": set(),
            "merged": set(),
        }
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                row = await session.get(HypothesisRow, hypothesis_id, with_for_update=True)
                if row is None or row.run_id != run_id:
                    raise ValueError("hypothesis_not_found")
                previous_event = await session.scalar(
                    select(EventRow).where(
                        EventRow.run_id == run_id,
                        EventRow.idempotency_key == idempotency_key,
                    )
                )
                if previous_event is not None:
                    if previous_event.event_type != "blackboard.hypothesis.status_changed":
                        raise ValueError("idempotency_conflict")
                    return self._hypothesis(row)
                if status not in allowed.get(row.status, set()):
                    raise ValueError(f"invalid_hypothesis_transition:{row.status}:{status}")
                previous = row.status
                row.status = status
                await self._append_event_row(
                    session,
                    run_id,
                    "blackboard.hypothesis.status_changed",
                    {
                        "hypothesis_id": hypothesis_id,
                        "previous_status": previous,
                        "status": status,
                        "reason": reason,
                    },
                    actor=actor,
                    idempotency_key=idempotency_key,
                )
        return self._hypothesis(row)

    async def add_experiment(self, experiment: dict[str, Any]) -> dict[str, Any]:
        tool_input = dict(experiment["tool_input"])
        if _contains_plaintext_secret(tool_input):
            raise ValueError("experiment_tool_input_contains_secret")
        status = str(experiment.get("status", "scheduled"))
        if status != "scheduled":
            raise ValueError("invalid_experiment_status")
        row = ExperimentRow(
            id=str(experiment.get("id") or new_id("exp")),
            run_id=str(experiment["run_id"]),
            hypothesis_id=str(experiment["hypothesis_id"]),
            objective=_redact_text(str(experiment["objective"])),
            tool_name=str(experiment["tool_name"]),
            tool_input=tool_input,
            status=status,
            result=experiment.get("result"),
        )
        async with self._run_locks[row.run_id]:
            async with self.database.sessions() as session, session.begin():
                hypothesis = await session.get(HypothesisRow, row.hypothesis_id)
                if hypothesis is None or hypothesis.run_id != row.run_id:
                    raise ValueError("cross_run_or_missing_hypothesis_reference")
                existing = await session.get(ExperimentRow, row.id)
                if existing is not None:
                    if (
                        existing.run_id != row.run_id
                        or existing.hypothesis_id != row.hypothesis_id
                        or existing.objective != row.objective
                        or existing.tool_name != row.tool_name
                        or existing.tool_input != row.tool_input
                        or existing.status != row.status
                    ):
                        raise ValueError("experiment_id_conflict")
                    return self._experiment(existing)
                session.add(row)
                await self._append_event_row(
                    session,
                    row.run_id,
                    "blackboard.experiment.scheduled",
                    {"experiment_id": row.id, "tool_name": row.tool_name},
                    actor={"kind": "worker", "id": "fake-strategist"},
                    idempotency_key=f"experiment:{row.id}",
                )
        return self._experiment(row)

    async def complete_experiment(
        self, run_id: str, experiment_id: str, result: dict[str, Any]
    ) -> dict[str, Any]:
        safe_result = redact_event_payload(result)
        if not isinstance(safe_result, dict):
            raise ValueError("experiment_result_must_be_object")
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                row = await session.get(ExperimentRow, experiment_id, with_for_update=True)
                if row is None or row.run_id != run_id:
                    raise ValueError("experiment_not_found")
                if row.status == "completed":
                    if row.result != safe_result:
                        raise ValueError("experiment_completion_conflict")
                    return self._experiment(row)
                if row.status != "scheduled":
                    raise ValueError("invalid_experiment_transition")
                row.status = "completed"
                row.result = safe_result
                await self._append_event_row(
                    session,
                    run_id,
                    "blackboard.experiment.completed",
                    {"experiment_id": experiment_id, "result_summary": safe_result},
                    actor={
                        "kind": "tool",
                        "id": str(safe_result.get("tool_name", "tool-runtime")),
                    },
                    idempotency_key=f"experiment:{experiment_id}:completed",
                )
        return self._experiment(row)

    async def add_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        sha256 = str(artifact["sha256"])
        if not _SHA256.fullmatch(sha256):
            raise ValueError("invalid_artifact_digest")
        size_bytes = artifact["size_bytes"]
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            raise ValueError("invalid_artifact_size")
        classification = str(artifact.get("classification", "internal"))
        if classification not in {"public", "internal", "secret", "flag"}:
            raise ValueError("invalid_artifact_classification")
        row = ArtifactRow(
            id=str(artifact["id"]),
            run_id=str(artifact["run_id"]),
            sha256=sha256,
            name=str(artifact["name"]),
            media_type=str(artifact["media_type"]),
            size_bytes=size_bytes,
            classification=classification,
            producer=str(artifact["producer"]),
            locator=str(artifact["locator"]),
            created_at=utc_now(),
        )
        async with self._run_locks[row.run_id]:
            async with self.database.sessions() as session, session.begin():
                if await session.get(RunRow, row.run_id) is None:
                    raise ValueError("run_not_found")
                existing = await session.get(ArtifactRow, row.id)
                if existing is not None:
                    if (
                        existing.run_id != row.run_id
                        or existing.sha256 != row.sha256
                        or existing.name != row.name
                        or existing.media_type != row.media_type
                        or existing.size_bytes != row.size_bytes
                        or existing.classification != row.classification
                        or existing.producer != row.producer
                        or existing.locator != row.locator
                    ):
                        raise ValueError("artifact_id_conflict")
                    return self._artifact(existing)
                session.add(row)
                await self._append_event_row(
                    session,
                    row.run_id,
                    "artifact.created",
                    {
                        "artifact_id": row.id,
                        "sha256": row.sha256,
                        "name": row.name,
                        "classification": row.classification,
                    },
                    actor={"kind": "service", "id": row.producer},
                    idempotency_key=f"artifact:{row.id}",
                )
        return self._artifact(row)

    async def record_verification(self, verification: dict[str, Any]) -> dict[str, Any]:
        run_id = str(verification["run_id"])
        verified = verification["verified"]
        if not isinstance(verified, bool):
            raise ValueError("verification_verified_must_be_boolean")
        exploit_digest = str(verification["exploit_digest"])
        environment_digest = str(verification["environment_digest"])
        if not _SHA256.fullmatch(exploit_digest) or not _SHA256.fullmatch(environment_digest):
            raise ValueError("invalid_verification_digest")
        flag_sha256 = verification.get("flag_sha256")
        if flag_sha256 is not None and not _SHA256.fullmatch(str(flag_sha256)):
            raise ValueError("invalid_flag_digest")
        raw_proof_ref = verification.get("verification_proof_ref")
        if raw_proof_ref is not None and (
            not isinstance(raw_proof_ref, str) or not _ACTOR_ID.fullmatch(raw_proof_ref)
        ):
            raise ValueError("invalid_verification_proof_ref")
        verification_proof_ref = raw_proof_ref
        if verified and verification_proof_ref is None:
            raise ValueError("verification_proof_ref_required")
        masked_flag = verification.get("masked_flag")
        if isinstance(masked_flag, str) and _RAW_FLAG.search(masked_flag):
            raise ValueError("masked_flag_contains_raw_flag")
        replay_results = verification["replay_results"]
        if not isinstance(replay_results, list) or any(
            not isinstance(item, dict) for item in replay_results
        ):
            raise ValueError("invalid_replay_results")
        row = VerificationRow(
            id=str(verification.get("id") or new_id("verify")),
            run_id=run_id,
            verified=verified,
            exploit_digest=exploit_digest,
            environment_digest=environment_digest,
            flag_sha256=None if flag_sha256 is None else str(flag_sha256),
            masked_flag=None if masked_flag is None else str(masked_flag),
            replay_results=replay_results,
            provenance=dict(verification["provenance"]),
            verification_proof_ref=verification_proof_ref,
            created_at=utc_now(),
        )
        async with self._run_locks[run_id]:
            async with self.database.sessions() as session, session.begin():
                run = await session.get(RunRow, run_id, with_for_update=True)
                if run is None:
                    raise ValueError("run_not_found")
                if run.status != "verifying":
                    raise ValueError("run_not_verifying")
                challenge = await session.get(ChallengeRow, run.challenge_id)
                if challenge is None:
                    raise ValueError("challenge_not_found")
                replay_count = (
                    challenge.manifest.get("spec", {}).get("flag", {}).get("replay_count", 1)
                )
                if row.verified and (
                    len(row.replay_results) < replay_count
                    or any(
                        item.get("passed") is not True
                        or item.get("started_from_clean_reset") is not True
                        for item in row.replay_results
                    )
                ):
                    raise ValueError("verified_replay_requirements_not_met")
                if row.verified:
                    assert row.verification_proof_ref is not None
                    proof = await session.get(ArtifactRow, row.verification_proof_ref)
                    if (
                        proof is None
                        or proof.run_id != run_id
                        or proof.producer != "independent-verifier"
                        or proof.classification not in {"internal", "secret"}
                    ):
                        raise ValueError("verification_proof_not_authoritative")
                session.add(row)
                run.status = "solved" if row.verified else "failed"
                run.updated_at = utc_now()
                run.result = {
                    "verification_id": row.id,
                    "verified": row.verified,
                    "masked_flag": row.masked_flag,
                }
                await self._append_event_row(
                    session,
                    run_id,
                    "verification.completed" if row.verified else "verification.failed",
                    {
                        "verification_id": row.id,
                        "verified": row.verified,
                        "verification_proof_ref": row.verification_proof_ref,
                        "replay_count": len(row.replay_results),
                        "flag_sha256": row.flag_sha256,
                        "masked_flag": row.masked_flag,
                    },
                    actor={"kind": "verifier", "id": "independent-verifier"},
                    idempotency_key=f"verification:{row.id}",
                )
        return self._verification(row)

    async def list_events(
        self, run_id: str, *, after: int = 0, limit: int = 200
    ) -> list[dict[str, Any]]:
        if after < 0:
            raise ValueError("event_cursor_cannot_be_negative")
        if limit < 1:
            raise ValueError("limit_must_be_positive")
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(EventRow)
                    .where(EventRow.run_id == run_id, EventRow.sequence > after)
                    .order_by(EventRow.sequence)
                    .limit(min(limit, 1000))
                )
            ).all()
            return [self._event(row) for row in rows]

    async def blackboard(self, run_id: str) -> dict[str, Any]:
        async with self.database.sessions() as session:
            facts = (await session.scalars(select(FactRow).where(FactRow.run_id == run_id))).all()
            hypotheses = (
                await session.scalars(select(HypothesisRow).where(HypothesisRow.run_id == run_id))
            ).all()
            experiments = (
                await session.scalars(select(ExperimentRow).where(ExperimentRow.run_id == run_id))
            ).all()
            return {
                "facts": [self._fact(row) for row in facts],
                "hypotheses": [self._hypothesis(row) for row in hypotheses],
                "experiments": [self._experiment(row) for row in experiments],
            }

    async def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(select(ArtifactRow).where(ArtifactRow.run_id == run_id))
            ).all()
            return [self._artifact(row) for row in rows]

    async def list_verifications(self, run_id: str) -> list[dict[str, Any]]:
        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(VerificationRow).where(VerificationRow.run_id == run_id)
                )
            ).all()
            return [self._verification(row) for row in rows]

    async def list_exploit_candidates(self, run_id: str) -> list[dict[str, Any]]:
        """Expose candidate lifecycle metadata without returning plan bytes or flags."""

        async with self.database.sessions() as session:
            rows = (
                await session.scalars(
                    select(ExploitCandidateRow)
                    .where(ExploitCandidateRow.run_id == run_id)
                    .order_by(ExploitCandidateRow.created_at, ExploitCandidateRow.id)
                )
            ).all()
            return [self._exploit_candidate(row) for row in rows]

    async def _enqueue_pending_agent_steers(
        self,
        session: AsyncSession,
        *,
        agent_session: AgentSessionRow,
        actor: dict[str, str],
    ) -> None:
        """Expose at most one steer after an idle boundary.

        Serializing steers prevents a second operator message from being
        delivered between `steer` acknowledgement and the resulting turn.
        """

        if agent_session.state != AgentSessionState.READY.value:
            return
        # A queued or active turn is not an idle boundary, even if the durable
        # session state is still READY before the runner claims it. Holding a
        # steer until that turn completes prevents an operator message from
        # being delivered ahead of the task it was meant to steer.
        active_turn_job = await session.scalar(
            select(AgentJobRow)
            .where(
                AgentJobRow.run_id == agent_session.run_id,
                AgentJobRow.kind == AgentJobKind.RUN_TURN.value,
                AgentJobRow.payload_ref == f"session:{agent_session.id}",
                AgentJobRow.state.in_(["queued", "leased"]),
            )
            .limit(1)
        )
        if active_turn_job is not None:
            return
        active_steer_job = await session.scalar(
            select(AgentJobRow)
            .where(
                AgentJobRow.run_id == agent_session.run_id,
                AgentJobRow.kind == AgentJobKind.STEER.value,
                AgentJobRow.state.in_(["queued", "leased"]),
            )
            .limit(1)
        )
        if active_steer_job is not None:
            return
        steer = await session.scalar(
            select(AgentSteerRow)
            .where(
                AgentSteerRow.session_id == agent_session.id,
                AgentSteerRow.state == "queued",
            )
            .order_by(AgentSteerRow.created_at, AgentSteerRow.id)
            .limit(1)
        )
        if steer is None:
            return
        job = await self._enqueue_agent_job_row(
            session,
            run_id=agent_session.run_id,
            kind=AgentJobKind.STEER.value,
            payload_ref=f"steer:{steer.id}",
            payload_digest=steer.message_digest,
            idempotency_key=f"pi-steer:{steer.id}:v1",
            deadline_at=None,
            actor=actor,
        )
        await self._append_event_row(
            session,
            agent_session.run_id,
            "agent.steer.queued",
            {"steer_id": steer.id, "session_id": agent_session.id, "job_id": job.id},
            actor=actor,
            idempotency_key=f"steer:{steer.id}:queued",
        )

    @staticmethod
    def _require_verification_job_lease(
        job: AgentJobRow,
        *,
        worker_id: str,
        lease_version: int,
        now: datetime,
    ) -> None:
        """Check the verifier-only queue lease without accepting Pi jobs."""

        if job.kind != AgentJobKind.VERIFY.value:
            raise ValueError("unexpected_verification_job_kind")
        if (
            job.state != "leased"
            or job.lease_owner != worker_id
            or job.lease_version != lease_version
        ):
            raise ValueError("agent_job_lease_lost")
        if job.lease_expires_at is None or _stored_utc(job.lease_expires_at) <= now:
            raise ValueError("agent_job_lease_expired")

    @staticmethod
    def _runtime_artifact_matches_row(artifact: RuntimeArtifact, row: ArtifactRow) -> bool:
        """Compare immutable artifact metadata without trusting a caller's ID alone."""

        return (
            row.run_id == artifact.run_id
            and row.sha256 == artifact.sha256
            and row.name == artifact.name
            and row.media_type == artifact.media_type
            and row.size_bytes == artifact.size_bytes
            and row.classification == artifact.classification
            and row.producer == artifact.producer
            and row.locator == artifact.locator
        )

    @staticmethod
    def _validate_candidate_plan_artifact(
        plan: ExploitPlanV1,
        artifact: RuntimeArtifact,
        *,
        run_id: str,
    ) -> None:
        """Bind a candidate row to exact canonical plan bytes and provenance."""

        expected_bytes = plan.canonical_bytes()
        expected_digest = plan.artifact_digest()
        if (
            artifact.run_id != run_id
            or artifact.sha256 != expected_digest
            or artifact.size_bytes != len(expected_bytes)
            or artifact.name != "candidate/exploit-plan-v1.json"
            or artifact.media_type != "application/json"
            or artifact.classification != "internal"
            or artifact.producer != "candidate-kernel"
            or artifact.locator != f"sha256:{expected_digest}"
        ):
            raise ValueError("candidate_plan_artifact_mismatch")

    @staticmethod
    def _validate_verification_proof_artifact(
        artifact: RuntimeArtifact,
        *,
        proof_bytes: bytes,
        run_id: str,
    ) -> None:
        """Ensure only the verifier's canonical opaque proof can authorize SOLVED."""

        expected_digest = hashlib.sha256(proof_bytes).hexdigest()
        if (
            artifact.run_id != run_id
            or artifact.sha256 != expected_digest
            or artifact.size_bytes != len(proof_bytes)
            or artifact.name != "verification/m5-replay-proof-v1.json"
            or artifact.media_type != "application/json"
            or artifact.classification not in {"internal", "secret"}
            or artifact.producer != "independent-verifier"
            or artifact.locator != f"sha256:{expected_digest}"
        ):
            raise ValueError("verification_proof_artifact_mismatch")

    @classmethod
    def _validate_existing_candidate(
        cls,
        existing: ExploitCandidateRow,
        submission: ExploitCandidateSubmission,
        plan: ExploitPlanV1,
        plan_artifact: RuntimeArtifact,
    ) -> None:
        """Make retries idempotent but reject any divergent candidate payload."""

        cls._validate_candidate_plan_artifact(
            plan,
            plan_artifact,
            run_id=existing.run_id,
        )
        if (
            existing.tool_call_id != submission.tool_call_id
            or existing.idempotency_key != submission.idempotency_key
            or existing.challenge_digest != plan.challenge_digest
            or existing.technique_id != plan.technique_id
            or existing.plan_artifact_id != plan_artifact.id
            or existing.plan_artifact_digest != plan_artifact.sha256
            or existing.plan_semantic_digest != plan.digest
            or existing.evidence_refs != list(plan.evidence_refs)
        ):
            raise ValueError("idempotency_conflict")

    @staticmethod
    def _require_pi_job_lease(
        job: AgentJobRow,
        *,
        worker_id: str,
        lease_version: int,
        expected_kind: AgentJobKind | None,
        now: datetime,
    ) -> None:
        if job.kind not in _PI_AGENT_JOB_KINDS:
            raise ValueError("invalid_pi_agent_job_kind")
        if expected_kind is not None and job.kind != expected_kind.value:
            raise ValueError("unexpected_pi_agent_job_kind")
        if (
            job.state != "leased"
            or job.lease_owner != worker_id
            or job.lease_version != lease_version
        ):
            raise ValueError("agent_job_lease_lost")
        if job.lease_expires_at is None or _stored_utc(job.lease_expires_at) <= now:
            raise ValueError("agent_job_lease_expired")

    @staticmethod
    def _require_power_pi_job_lease(
        job: AgentJobRow,
        *,
        worker_id: str,
        lease_version: int,
        now: datetime,
        expected_kind: AgentJobKind | None = None,
    ) -> None:
        """Check a Power job without admitting it to the generic Pi kernel."""

        if job.kind not in _POWER_PI_JOB_KINDS:
            raise ValueError("invalid_power_pi_job_kind")
        if expected_kind is not None and job.kind != expected_kind.value:
            raise ValueError("unexpected_power_pi_job_kind")
        if (
            job.state != "leased"
            or job.lease_owner != worker_id
            or job.lease_version != lease_version
        ):
            raise ValueError("power_pi_job_lease_lost")
        if job.lease_expires_at is None or _stored_utc(job.lease_expires_at) <= now:
            raise ValueError("power_pi_job_lease_expired")

    @staticmethod
    def _complete_power_pi_job_row(job: AgentJobRow, *, now: datetime) -> None:
        job.state = "completed"
        job.lease_owner = None
        job.lease_expires_at = None
        job.updated_at = now

    @staticmethod
    def _context_manifest_from_row(row: ContextManifestRow) -> ContextManifest:
        try:
            payload = json.loads(row.document)
            manifest = ContextManifest.model_validate(payload)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("stored_context_manifest_invalid") from exc
        if manifest.digest != row.digest or manifest.run_id != row.run_id:
            raise ValueError("stored_context_manifest_mismatch")
        return manifest

    @staticmethod
    def _agent_session(row: AgentSessionRow) -> dict[str, Any]:
        # ORM values are persisted strings, while the public domain contract
        # deliberately exposes closed enums. Parse explicitly here so a bad
        # database row cannot silently cross the infrastructure boundary.
        try:
            role = AgentRole(row.role)
            state = AgentSessionState(row.state)
        except ValueError as exc:
            raise ValueError("stored_agent_session_invalid") from exc
        return AgentSession(
            id=row.id,
            run_id=row.run_id,
            start_job_id=row.start_job_id,
            task_id=row.task_id,
            context_manifest_id=row.context_manifest_id,
            role=role,
            state=state,
            session_store_key=row.session_store_key,
            runner_id=row.runner_id,
            created_at=_stored_utc(row.created_at),
            updated_at=_stored_utc(row.updated_at),
        ).model_dump(mode="json")

    @staticmethod
    def _power_pi_session(row: PowerPiSessionRow) -> dict[str, Any]:
        """Return the runner-only Power session envelope with no credentials."""

        if (
            row.role not in _POWER_PI_ROLES
            or row.provider not in _POWER_PI_PROVIDERS
            or row.state not in _POWER_PI_SESSION_STATES
            or _POWER_PI_MODEL.fullmatch(row.model) is None
            or not math.isfinite(row.temperature)
            or not 0 <= row.temperature <= 2
            or not _SHA256.fullmatch(row.archive_digest)
            or not 1 <= len(row.brief) <= 4_000
            or row.workspace_id is None
            or _POWER_PI_WORKSPACE_ID.fullmatch(row.workspace_id) is None
            or (row.target_host is None) != (row.target_port is None)
            or (row.target_port is not None and not 1 <= row.target_port <= 65_535)
        ):
            raise ValueError("stored_power_pi_session_invalid")
        return {
            "id": row.id,
            "run_id": row.run_id,
            "start_job_id": row.start_job_id,
            "label": row.label,
            "role": row.role,
            "provider": row.provider,
            "model": row.model,
            "temperature": row.temperature,
            "archive_digest": row.archive_digest,
            "brief": row.brief,
            "target_host": row.target_host,
            "target_port": row.target_port,
            "workspace_id": row.workspace_id,
            "state": row.state,
            "runner_id": row.runner_id,
            "session_store_key": row.session_store_key,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    @staticmethod
    def _power_pi_steer(row: PowerPiSteerRow) -> dict[str, Any]:
        if row.state not in {"queued", "applied"} or not _SHA256.fullmatch(row.message_digest):
            raise ValueError("stored_power_pi_steer_invalid")
        return {
            "id": row.id,
            "run_id": row.run_id,
            "session_id": row.session_id,
            "job_id": row.job_id,
            "message": row.message,
            "message_digest": row.message_digest,
            "state": row.state,
            "created_at": _iso(row.created_at),
            "applied_at": None if row.applied_at is None else _iso(row.applied_at),
        }

    @staticmethod
    def _tool_invocation(row: ToolInvocationRow) -> ToolInvocation:
        """Parse ORM strings back through the strict, body-free domain view."""

        try:
            return ToolInvocation(
                id=row.id,
                run_id=row.run_id,
                agent_job_id=row.agent_job_id,
                session_id=row.session_id,
                task_id=row.task_id,
                branch_id=row.branch_id,
                tool_call_id=row.tool_call_id,
                tool_name=row.tool_name,
                tool_version=row.tool_version,
                idempotency_key=row.idempotency_key,
                input_digest=row.input_digest,
                policy_decision=cast(Literal["allow", "deny"], row.policy_decision),
                policy_reason=row.policy_reason,
                state=ToolInvocationState(row.state),
                tool_budget_ledger_id=row.tool_budget_ledger_id,
                http_budget_ledger_id=row.http_budget_ledger_id,
                result_artifact_id=row.result_artifact_id,
                result_digest=row.result_digest,
                result_summary=row.result_summary,
                error_code=row.error_code,
                created_at=_stored_utc(row.created_at),
                completed_at=None if row.completed_at is None else _stored_utc(row.completed_at),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("stored_tool_invocation_invalid") from exc

    @staticmethod
    def _agent_steer(row: AgentSteerRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "session_id": row.session_id,
            # This sanitized text is returned solely to the authenticated
            # control-plane runner. Public APIs/events expose only its digest.
            "message": row.message,
            "message_digest": row.message_digest,
            "state": row.state,
            "created_at": _iso(row.created_at),
            "applied_at": None if row.applied_at is None else _iso(row.applied_at),
        }

    @staticmethod
    def _hint_card_model(row: HintCardRow) -> HintCard:
        """Revalidate persisted card data before it crosses a repository boundary."""

        try:
            if row.epistemic_status != "human_hypothesis":
                raise ValueError("stored_hint_card_epistemic_status_invalid")
            return HintCard(
                id=row.id,
                run_id=row.run_id,
                template_id=row.template_id,
                template_version=row.template_version,
                technique_id=row.technique_id,
                category=HintCategory(row.category),
                directive=HintDirective(row.directive),
                target_ref=row.target_ref,
                priority=row.priority,
                note=row.note,
                epistemic_status="human_hypothesis",
                status=HintStatus(row.status),
                evidence_refs=tuple(row.evidence_refs),
                actor_id=row.actor_id,
                created_at=_stored_utc(row.created_at),
                updated_at=_stored_utc(row.updated_at),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("stored_hint_card_invalid") from exc

    @classmethod
    def _hint_card(cls, row: HintCardRow) -> dict[str, Any]:
        """Expose local UI data with its human-hypothesis status intact."""

        return cls._hint_card_model(row).model_dump(mode="json")

    @staticmethod
    def _run_branch(row: RunBranchRow) -> dict[str, Any]:
        """Project transparent M4 score inputs without model/private content."""

        score = round(
            0.35 * row.evidence_strength
            + 0.25 * row.novelty
            + 0.20 * row.priority
            + 0.15 * row.expected_value
            - 0.20 * row.normalized_cost
            - row.repetition_penalty,
            6,
        )
        return {
            "id": row.id,
            "run_id": row.run_id,
            "family": row.family,
            "state": row.state,
            "technique_id": row.technique_id,
            "branch_scope": row.branch_scope,
            "priority": row.priority,
            "novelty": row.novelty,
            "evidence_strength": row.evidence_strength,
            "expected_value": row.expected_value,
            "normalized_cost": row.normalized_cost,
            "repetition_penalty": row.repetition_penalty,
            "consecutive_no_observation": row.consecutive_no_observation,
            "score": score,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    @staticmethod
    def _challenge(row: ChallengeRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "manifest": row.manifest,
            "digest": row.digest,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _run(row: RunRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "challenge_id": row.challenge_id,
            "status": row.status,
            "mode": row.mode,
            "provider": row.provider,
            "budget": row.budget,
            "result": row.result,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    @staticmethod
    def _agent_job(row: AgentJobRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "kind": row.kind,
            "payload_ref": row.payload_ref,
            "payload_digest": row.payload_digest,
            "state": row.state,
            "lease_owner": row.lease_owner,
            "lease_version": row.lease_version,
            "lease_expires_at": None
            if row.lease_expires_at is None
            else _iso(row.lease_expires_at),
            "attempts": row.attempts,
            "deadline_at": None if row.deadline_at is None else _iso(row.deadline_at),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    @staticmethod
    def _worker_task(row: RuntimeTask | WorkerTaskRow) -> dict[str, Any]:
        if isinstance(row, RuntimeTask):
            return row.model_dump(mode="json")
        return {
            "id": row.id,
            "run_id": row.run_id,
            "branch_id": row.branch_id,
            "role": row.role,
            "objective": row.objective,
            "required_evidence": row.required_evidence,
            "context_manifest_id": row.context_manifest_id,
            "state": row.state,
            "lease_owner": row.lease_owner,
            "lease_version": row.lease_version,
            "lease_expires_at": None
            if row.lease_expires_at is None
            else _iso(row.lease_expires_at),
            "attempts": row.attempts,
            "deadline_at": _iso(row.deadline_at),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    @staticmethod
    def _preflight_observation(row: PreflightObservationRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "kind": row.kind,
            "artifact_id": row.artifact_id,
            "digest": row.digest,
            "summary": row.summary,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _budget_ledger(row: BudgetLedgerRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "dimension": row.dimension,
            "debit": row.debit,
            "remaining_after": row.remaining_after,
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _outbox(row: OutboxRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "event_id": row.event_id,
            "event_type": row.event_type,
            "payload_ref": row.payload_ref,
            "payload_digest": row.payload_digest,
            "published_at": None if row.published_at is None else _iso(row.published_at),
            "attempts": row.attempts,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _event(row: EventRow) -> dict[str, Any]:
        return {
            "event_id": row.event_id,
            "run_id": row.run_id,
            "sequence": row.sequence,
            "type": row.event_type,
            "schema_version": row.schema_version,
            "actor": row.actor,
            "correlation_id": row.correlation_id,
            "causation_id": row.causation_id,
            "created_at": _iso(row.created_at),
            "payload": row.payload,
            "integrity": {
                "payload_sha256": row.payload_sha256,
                "prev_hash": row.prev_hash,
                "event_hash": row.event_hash,
            },
        }

    @staticmethod
    def _fact(row: FactRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "branch_id": row.branch_id,
            "statement": row.statement,
            "confidence": row.confidence,
            "status": row.status,
            "evidence": row.evidence,
            "created_by": row.created_by,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _hypothesis(row: HypothesisRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "branch_id": row.branch_id,
            "family": row.family,
            "statement": row.statement,
            "confidence": row.confidence,
            "status": row.status,
            "supporting_fact_ids": row.supporting_fact_ids,
            "contradicting_fact_ids": row.contradicting_fact_ids,
            "falsifiers": row.falsifiers,
            "next_experiment_id": row.next_experiment_id,
        }

    @staticmethod
    def _experiment(row: ExperimentRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "hypothesis_id": row.hypothesis_id,
            "objective": row.objective,
            "tool_name": row.tool_name,
            "tool_input": row.tool_input,
            "status": row.status,
            "result": row.result,
        }

    @staticmethod
    def _artifact(row: ArtifactRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "sha256": row.sha256,
            "name": row.name,
            "media_type": row.media_type,
            "size_bytes": row.size_bytes,
            "classification": row.classification,
            "producer": row.producer,
            "locator": row.locator,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _verification(row: VerificationRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "verified": row.verified,
            "exploit_digest": row.exploit_digest,
            "environment_digest": row.environment_digest,
            "flag_sha256": row.flag_sha256,
            "masked_flag": row.masked_flag,
            "replay_results": row.replay_results,
            "provenance": row.provenance,
            "verification_proof_ref": row.verification_proof_ref,
            "created_at": _iso(row.created_at),
        }

    @staticmethod
    def _exploit_candidate(row: ExploitCandidateRow) -> dict[str, Any]:
        """Return auditable candidate metadata while keeping the plan body private."""

        return {
            "id": row.id,
            "run_id": row.run_id,
            "branch_id": row.branch_id,
            "task_id": row.task_id,
            "session_id": row.session_id,
            "tool_call_id": row.tool_call_id,
            "challenge_digest": row.challenge_digest,
            "technique_id": row.technique_id,
            "plan_artifact_id": row.plan_artifact_id,
            "plan_artifact_digest": row.plan_artifact_digest,
            "plan_semantic_digest": row.plan_semantic_digest,
            "evidence_refs": list(row.evidence_refs),
            "status": row.status,
            "verification_job_id": row.verification_job_id,
            "verification_id": row.verification_id,
            "failure_code": row.failure_code,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }
