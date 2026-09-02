from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctfmesh_domain import ActorKind
from ctfmesh_events import (
    EventActor,
    EventEnvelope,
    EventIntegrity,
    EventStream,
    IdempotencyConflictError,
    SequenceConflictError,
    payload_digest,
)
from pydantic import JsonValue, ValidationError


def make_event(
    sequence: int,
    *,
    event_id: str | None = None,
    payload: dict[str, JsonValue] | None = None,
) -> EventEnvelope:
    return EventEnvelope.create(
        event_id=event_id or f"event-{sequence}",
        run_id="run-1",
        sequence=sequence,
        type="fact.proposed",
        actor=EventActor(kind=ActorKind.WORKER, id="worker-1"),
        payload=payload or {"fact_id": f"fact-{sequence}"},
        created_at=datetime(2026, 7, 18, tzinfo=UTC),
    )


class EventEnvelopeTests(unittest.TestCase):
    def test_digest_is_canonical_across_key_order(self) -> None:
        self.assertEqual(payload_digest({"b": 2, "a": 1}), payload_digest({"a": 1, "b": 2}))

    def test_mismatched_digest_is_rejected(self) -> None:
        payload: dict[str, JsonValue] = {"fact_id": "fact-1"}
        with self.assertRaisesRegex(ValidationError, "does not match payload"):
            EventEnvelope(
                event_id="event-1",
                run_id="run-1",
                sequence=1,
                type="fact.proposed",
                schema_version=1,
                actor=EventActor(kind=ActorKind.WORKER, id="worker-1"),
                created_at=datetime.now(UTC),
                payload=payload,
                integrity=EventIntegrity(payload_sha256="0" * 64),
            )

    def test_naive_datetime_and_unknown_fields_are_rejected(self) -> None:
        data = make_event(1).model_dump()
        data["created_at"] = datetime(2026, 7, 18)
        with self.assertRaisesRegex(ValidationError, "timezone-aware"):
            EventEnvelope.model_validate(data)

        data = make_event(1).model_dump()
        data["unknown"] = True
        with self.assertRaises(ValidationError):
            EventEnvelope.model_validate(data)


class EventStreamTests(unittest.TestCase):
    def test_append_is_monotonic_and_replay_is_ordered(self) -> None:
        stream = EventStream()
        stream.append(make_event(1))
        stream.append(make_event(2))

        self.assertEqual(stream.last_sequence("run-1"), 2)
        self.assertEqual([event.sequence for event in stream.replay("run-1")], [1, 2])
        self.assertEqual(
            [event.sequence for event in stream.replay("run-1", after_sequence=1)], [2]
        )

    def test_sequence_gap_is_rejected_without_mutating_stream(self) -> None:
        stream = EventStream()
        with self.assertRaises(SequenceConflictError):
            stream.append(make_event(2))
        self.assertEqual(stream.last_sequence("run-1"), 0)

    def test_same_idempotency_key_returns_original_event(self) -> None:
        stream = EventStream()
        event = make_event(1)
        first = stream.append(event, idempotency_key="command-1")
        second = stream.append(event, idempotency_key="command-1")
        self.assertEqual(first, second)
        self.assertEqual(len(stream), 1)

    def test_idempotency_key_reuse_for_different_event_is_rejected(self) -> None:
        stream = EventStream()
        stream.append(make_event(1), idempotency_key="command-1")
        with self.assertRaises(IdempotencyConflictError):
            stream.append(make_event(1, event_id="event-other"), idempotency_key="command-1")
        self.assertEqual(len(stream), 1)

    def test_payload_mutation_cannot_rewrite_history(self) -> None:
        stream = EventStream()
        original = make_event(1, payload={"nested": {"value": "original"}})
        returned = stream.append(original)
        returned.payload["nested"]["value"] = "tampered"  # type: ignore[index]

        replayed = stream.replay("run-1")[0]
        self.assertEqual(replayed.payload, {"nested": {"value": "original"}})
        self.assertFalse(hasattr(stream, "update"))
        self.assertFalse(hasattr(stream, "delete"))

    def test_payload_changed_after_envelope_validation_is_rejected_on_append(self) -> None:
        stream = EventStream()
        event = make_event(1, payload={"value": "original"})
        event.payload["value"] = "changed"
        with self.assertRaisesRegex(ValidationError, "does not match payload"):
            stream.append(event)


if __name__ == "__main__":
    unittest.main()
