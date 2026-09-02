"""Relational models for the local control plane.

The event table is intentionally append-only: no repository API exposes update
or delete operations for historical events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utc_column() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False)


class ChallengeRow(Base):
    __tablename__ = "challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = utc_column()


class RunRow(Base):
    __tablename__ = "runs"
    __table_args__ = (UniqueConstraint("start_idempotency_key", name="uq_runs_start_idempotency"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    mode: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(64), default="operator-pending")
    budget: Mapped[dict[str, Any]] = mapped_column(JSON)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    start_idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    start_request_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class RunSequenceRow(Base):
    __tablename__ = "run_sequences"

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), primary_key=True)
    current: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class EventRow(Base):
    __tablename__ = "run_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_run_event_sequence"),
        UniqueConstraint("run_id", "idempotency_key", name="uq_run_event_idempotency"),
        Index("ix_run_events_type", "event_type"),
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    actor: Mapped[dict[str, Any]] = mapped_column(JSON)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    causation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = utc_column()


class RunBranchRow(Base):
    __tablename__ = "run_branches"
    __table_args__ = (
        Index("ix_run_branches_run_state", "run_id", "state"),
        UniqueConstraint("run_id", "family", "state", name="uq_run_branch_family_state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    family: Mapped[str] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(32))
    # M4 records only scheduler metadata here.  It does not store a model
    # transcript, source path, tool input, or a free-form operator note.
    technique_id: Mapped[str] = mapped_column(String(160), nullable=False, default="general.review")
    branch_scope: Mapped[str] = mapped_column(String(160), nullable=False, default="run:all")
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    novelty: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence_strength: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expected_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    normalized_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    repetition_penalty: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    consecutive_no_observation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class ContextManifestRow(Base):
    __tablename__ = "context_manifests"
    __table_args__ = (Index("ix_context_manifests_run", "run_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    task_id: Mapped[str] = mapped_column(String(64), unique=True)
    document: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = utc_column()
    created_at: Mapped[datetime] = utc_column()


class WorkerTaskRow(Base):
    __tablename__ = "worker_tasks"
    __table_args__ = (
        Index("ix_worker_tasks_run_state", "run_id", "state"),
        Index("ix_worker_tasks_lease", "state", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    branch_id: Mapped[str] = mapped_column(ForeignKey("run_branches.id"), index=True)
    role: Mapped[str] = mapped_column(String(160))
    objective: Mapped[str] = mapped_column(Text)
    required_evidence: Mapped[list[str]] = mapped_column(JSON)
    context_manifest_id: Mapped[str] = mapped_column(ForeignKey("context_manifests.id"))
    # This hash represents the reviewed task intent.  It is deliberately
    # independent of opaque Pi prose and gives the scheduler a durable way to
    # prevent two active workers from receiving the same attempt.
    technique_id: Mapped[str] = mapped_column(String(160), nullable=False, default="general.review")
    branch_scope: Mapped[str] = mapped_column(String(160), nullable=False, default="run:all")
    attempt_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)
    state: Mapped[str] = mapped_column(String(32), index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deadline_at: Mapped[datetime] = utc_column()
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class HintCardRow(Base):
    """Durable operator hint data separate from append-only public events.

    The note remains available to the local UI as explicitly untrusted data.
    Event payloads only retain the card metadata/digest, so replay/audit logs
    cannot turn operator prose into a prompt or a secret-bearing transcript.
    """

    __tablename__ = "hint_cards"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_hint_cards_idempotency"),
        Index("ix_hint_cards_run_status", "run_id", "status"),
        Index("ix_hint_cards_run_technique", "run_id", "technique_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    template_id: Mapped[str] = mapped_column(String(160), nullable=False)
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    technique_id: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    directive: Mapped[str] = mapped_column(String(32), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    epistemic_status: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class AgentJobRow(Base):
    __tablename__ = "agent_jobs"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_agent_job_idempotency"),
        Index("ix_agent_jobs_claim", "state", "lease_expires_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class AgentSessionRow(Base):
    """Durable lifecycle metadata for a Pi session.

    The append-only Pi transcript lives in the runner's dedicated session
    volume. This table deliberately stores only the opaque store key and
    audit/lifecycle metadata; it never stores model messages or credentials.
    """

    __tablename__ = "agent_sessions"
    __table_args__ = (
        UniqueConstraint("start_job_id", name="uq_agent_sessions_start_job"),
        UniqueConstraint("session_store_key", name="uq_agent_sessions_store_key"),
        Index("ix_agent_sessions_run_state", "run_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    start_job_id: Mapped[str] = mapped_column(ForeignKey("agent_jobs.id"), nullable=False)
    task_id: Mapped[str] = mapped_column(ForeignKey("worker_tasks.id"), nullable=False)
    context_manifest_id: Mapped[str] = mapped_column(ForeignKey("context_manifests.id"))
    role: Mapped[str] = mapped_column(String(160), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="starting")
    runner_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_store_key: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class PowerPiSessionRow(Base):
    """Durable, credential-free metadata for one Power Pi session.

    Power sessions deliberately do not reuse ``AgentSessionRow``: its sealed
    source-slot ContextManifest and generic role contracts would be the wrong
    authority for a disposable sandboxd workspace.  The row records only
    trusted orchestration choices and opaque lifecycle references; provider
    API keys, transcripts, tool inputs/outputs, and flags are absent.
    """

    __tablename__ = "power_pi_sessions"
    __table_args__ = (
        UniqueConstraint("start_job_id", name="uq_power_pi_sessions_start_job"),
        UniqueConstraint("session_store_key", name="uq_power_pi_sessions_store_key"),
        Index("ix_power_pi_sessions_run_state", "run_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    start_job_id: Mapped[str] = mapped_column(ForeignKey("agent_jobs.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(32), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    temperature: Mapped[float] = mapped_column(Float, nullable=False)
    archive_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    brief: Mapped[str] = mapped_column(Text, nullable=False)
    target_host: Mapped[str | None] = mapped_column(String(253), nullable=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="starting")
    runner_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_store_key: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class PowerPiSteerRow(Base):
    """One bounded operator/coordinator steer for an idle Power session."""

    __tablename__ = "power_pi_steers"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_power_pi_steers_idempotency"),
        UniqueConstraint("job_id", name="uq_power_pi_steers_job"),
        Index("ix_power_pi_steers_session_state", "session_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("power_pi_sessions.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("agent_jobs.id"), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    message_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = utc_column()
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentSteerRow(Base):
    """A sanitized operator steering request delivered only at a safe boundary."""

    __tablename__ = "agent_steers"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_agent_steers_idempotency"),
        Index("ix_agent_steers_session_state", "session_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    message_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = utc_column()
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PreflightObservationRow(Base):
    __tablename__ = "preflight_observations"
    __table_args__ = (
        UniqueConstraint("run_id", "kind", name="uq_preflight_observation_kind"),
        Index("ix_preflight_observations_run", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = utc_column()


class IdempotencyRecordRow(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint("run_id", "scope", "key", name="uq_idempotency_record"),
        Index("ix_idempotency_records_run", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    scope: Mapped[str] = mapped_column(String(80), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = utc_column()


class BudgetLedgerRow(Base):
    __tablename__ = "budget_ledger"
    __table_args__ = (Index("ix_budget_ledger_run_dimension", "run_id", "dimension"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    dimension: Mapped[str] = mapped_column(String(64), nullable=False)
    debit: Mapped[float] = mapped_column(Float, nullable=False)
    remaining_after: Mapped[float] = mapped_column(Float, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = utc_column()


class ToolInvocationRow(Base):
    """Durable tool-boundary record without raw request or response bodies.

    The normalized result itself is stored as a content-addressed artifact.
    Keeping only digests and references here prevents the control database
    from becoming a transcript, cookie jar, or flag store.
    """

    __tablename__ = "tool_invocations"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "task_id",
            "tool_name",
            "idempotency_key",
            name="uq_tool_invocation_idempotency",
        ),
        UniqueConstraint(
            "run_id",
            "session_id",
            "tool_call_id",
            name="uq_tool_invocation_call",
        ),
        Index("ix_tool_invocations_run_state", "run_id", "state"),
        Index("ix_tool_invocations_session", "session_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    agent_job_id: Mapped[str] = mapped_column(ForeignKey("agent_jobs.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("worker_tasks.id"), index=True)
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("run_branches.id"), nullable=True)
    tool_call_id: Mapped[str] = mapped_column(String(160), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_reason: Mapped[str] = mapped_column(String(160), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_budget_ledger_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    http_budget_ledger_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id"), nullable=True
    )
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = utc_column()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OutboxRow(Base):
    __tablename__ = "outbox"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_outbox_event"),
        Index("ix_outbox_pending", "published_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("run_events.event_id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    payload_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = utc_column()


class FactRow(Base):
    __tablename__ = "facts"
    __table_args__ = (Index("ix_facts_run_status", "run_id", "status"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    branch_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float]
    status: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = utc_column()


class HypothesisRow(Base):
    __tablename__ = "hypotheses"
    __table_args__ = (Index("ix_hypotheses_run_branch_status", "run_id", "branch_id", "status"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    branch_id: Mapped[str] = mapped_column(String(64))
    family: Mapped[str] = mapped_column(String(100))
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float]
    status: Mapped[str] = mapped_column(String(32))
    supporting_fact_ids: Mapped[list[str]] = mapped_column(JSON)
    contradicting_fact_ids: Mapped[list[str]] = mapped_column(JSON)
    falsifiers: Mapped[list[str]] = mapped_column(JSON)
    next_experiment_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ExperimentRow(Base):
    __tablename__ = "experiments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id"))
    objective: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(String(120))
    tool_input: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class ArtifactRow(Base):
    __tablename__ = "artifacts"
    __table_args__ = (Index("ix_artifacts_run_sha", "run_id", "sha256"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    sha256: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(240))
    media_type: Mapped[str] = mapped_column(String(160))
    size_bytes: Mapped[int] = mapped_column(Integer)
    classification: Mapped[str] = mapped_column(String(40))
    producer: Mapped[str] = mapped_column(String(120))
    locator: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = utc_column()


class VerificationRow(Base):
    __tablename__ = "verifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    verified: Mapped[bool]
    exploit_digest: Mapped[str] = mapped_column(String(64))
    environment_digest: Mapped[str] = mapped_column(String(64))
    flag_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    masked_flag: Mapped[str | None] = mapped_column(String(160), nullable=True)
    replay_results: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON)
    verification_proof_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = utc_column()


class ExploitCandidateRow(Base):
    """A typed plan proposed by a leased exploit-builder turn.

    The candidate never stores a raw flag, model transcript, request body, or
    target URL. Its plan is a separate immutable content-addressed artifact.
    """

    __tablename__ = "exploit_candidates"
    __table_args__ = (
        UniqueConstraint(
            "run_id", "session_id", "tool_call_id", name="uq_exploit_candidate_tool_call"
        ),
        UniqueConstraint(
            "run_id", "task_id", "idempotency_key", name="uq_exploit_candidate_idempotency"
        ),
        Index("ix_exploit_candidates_run_status", "run_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    branch_id: Mapped[str] = mapped_column(ForeignKey("run_branches.id"), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("worker_tasks.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    tool_call_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    challenge_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(160), nullable=False)
    plan_artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), nullable=False)
    plan_artifact_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_semantic_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="submitted")
    verification_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_id: Mapped[str | None] = mapped_column(
        ForeignKey("verifications.id"), nullable=True
    )
    failure_code: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = utc_column()
    updated_at: Mapped[datetime] = utc_column()


class VerificationAttemptRow(Base):
    """One secret-free outcome of a verifier-owned fresh-reset replay."""

    __tablename__ = "verification_attempts"
    __table_args__ = (
        UniqueConstraint("candidate_id", "attempt", name="uq_verification_attempt_index"),
        Index("ix_verification_attempts_run_candidate", "run_id", "candidate_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("exploit_candidates.id"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    verification_id: Mapped[str] = mapped_column(ForeignKey("verifications.id"), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    reset_id: Mapped[str] = mapped_column(String(160), nullable=False)
    target_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    passed: Mapped[bool] = mapped_column(nullable=False)
    started_from_clean_reset: Mapped[bool] = mapped_column(nullable=False)
    flag_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    controller_lab_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    # Preserve the exact `Z`-suffixed text signed by the controller instead of
    # normalizing it through a database datetime serializer. Auditors need the
    # original bytes to reconstruct and verify the Ed25519 proof later.
    controller_issued_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    controller_proof_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    controller_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = utc_column()
