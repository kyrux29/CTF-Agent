"""Versioned immutable run-event envelope."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, Any

from ctfmesh_domain import (
    ActorKind,
    ContractModel,
    Identifier,
    Sha256Digest,
    UtcDatetime,
)
from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

EventType = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
]


def payload_digest(payload: dict[str, JsonValue]) -> str:
    """Return a deterministic SHA-256 over the canonical JSON payload."""

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class EventActor(ContractModel):
    kind: ActorKind
    id: Identifier

    @field_validator("kind", mode="before")
    @classmethod
    def _parse_kind(cls, value: Any) -> Any:
        return ActorKind(value) if isinstance(value, str) else value


class EventIntegrity(ContractModel):
    payload_sha256: Sha256Digest


class EventEnvelope(ContractModel):
    """Self-validating immutable event boundary model."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        populate_by_name=True,
        allow_inf_nan=False,
    )

    event_id: Identifier
    run_id: Identifier
    sequence: int = Field(ge=1)
    type: EventType
    schema_version: int = Field(ge=1)
    actor: EventActor
    created_at: UtcDatetime
    payload: dict[str, JsonValue]
    integrity: EventIntegrity
    correlation_id: Identifier | None = None
    causation_id: Identifier | None = None

    @model_validator(mode="after")
    def _verify_payload_digest(self) -> EventEnvelope:
        expected = payload_digest(self.payload)
        if self.integrity.payload_sha256 != expected:
            raise ValueError("integrity.payload_sha256 does not match payload")
        return self

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        run_id: str,
        sequence: int,
        type: str,
        actor: EventActor,
        payload: dict[str, JsonValue],
        schema_version: int = 1,
        correlation_id: str | None = None,
        causation_id: str | None = None,
        created_at: datetime | None = None,
    ) -> EventEnvelope:
        timestamp = created_at or datetime.now(UTC)
        return cls(
            event_id=event_id,
            run_id=run_id,
            sequence=sequence,
            type=type,
            schema_version=schema_version,
            actor=actor,
            correlation_id=correlation_id,
            causation_id=causation_id,
            created_at=timestamp,
            payload=payload,
            integrity=EventIntegrity(payload_sha256=payload_digest(payload)),
        )
