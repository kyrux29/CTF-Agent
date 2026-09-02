"""Thread-safe in-memory append-only event stream used by tests and local development."""

from __future__ import annotations

from collections import defaultdict
from threading import RLock

from .models import EventEnvelope


class EventStreamError(RuntimeError):
    """Base error for event stream contract violations."""


class SequenceConflictError(EventStreamError):
    """Raised when an append would break per-run monotonic sequencing."""


class DuplicateEventError(EventStreamError):
    """Raised when an event ID is reused for different content."""


class IdempotencyConflictError(EventStreamError):
    """Raised when an idempotency key is reused for a different event."""


def _same_event(left: EventEnvelope, right: EventEnvelope) -> bool:
    return left.model_dump(mode="json") == right.model_dump(mode="json")


class EventStream:
    """Small reference implementation with no mutation/deletion API.

    The class deep-copies models at its boundary so mutable nested payload values
    cannot rewrite stored history after append or through replay results.
    """

    def __init__(self) -> None:
        self._events: dict[str, list[EventEnvelope]] = defaultdict(list)
        self._event_ids: dict[str, EventEnvelope] = {}
        self._idempotency: dict[tuple[str, str], EventEnvelope] = {}
        self._lock = RLock()

    def append(
        self,
        event: EventEnvelope,
        *,
        idempotency_key: str | None = None,
    ) -> EventEnvelope:
        """Append exactly once and return the canonical stored event."""

        if idempotency_key is not None and not idempotency_key.strip():
            raise ValueError("idempotency_key cannot be blank")

        # Revalidate because a frozen Pydantic model can still contain a mutable
        # JSON payload. This prevents a caller from changing payload bytes after
        # construction while retaining the old integrity digest.
        candidate = EventEnvelope.model_validate(event.model_dump())

        with self._lock:
            if idempotency_key is not None:
                key = (candidate.run_id, idempotency_key)
                previous = self._idempotency.get(key)
                if previous is not None:
                    if not _same_event(previous, candidate):
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different event"
                        )
                    return previous.model_copy(deep=True)

            duplicate = self._event_ids.get(candidate.event_id)
            if duplicate is not None:
                if not _same_event(duplicate, candidate):
                    raise DuplicateEventError("event_id was already used for different content")
                if idempotency_key is not None:
                    self._idempotency[(candidate.run_id, idempotency_key)] = duplicate
                return duplicate.model_copy(deep=True)

            expected = len(self._events[candidate.run_id]) + 1
            if candidate.sequence != expected:
                raise SequenceConflictError(
                    f"expected sequence {expected} for run {candidate.run_id}, "
                    f"got {candidate.sequence}"
                )

            stored = candidate.model_copy(deep=True)
            self._events[candidate.run_id].append(stored)
            self._event_ids[candidate.event_id] = stored
            if idempotency_key is not None:
                self._idempotency[(candidate.run_id, idempotency_key)] = stored
            return stored.model_copy(deep=True)

    def replay(self, run_id: str, *, after_sequence: int = 0) -> tuple[EventEnvelope, ...]:
        """Return an ordered immutable snapshot after the supplied cursor."""

        if after_sequence < 0:
            raise ValueError("after_sequence cannot be negative")
        with self._lock:
            return tuple(
                event.model_copy(deep=True)
                for event in self._events.get(run_id, ())
                if event.sequence > after_sequence
            )

    def last_sequence(self, run_id: str) -> int:
        with self._lock:
            events = self._events.get(run_id)
            return events[-1].sequence if events else 0

    def __len__(self) -> int:
        with self._lock:
            return sum(len(events) for events in self._events.values())
