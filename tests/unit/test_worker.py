from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

import ctfmesh_provider_base
import pytest
from ctfmesh_provider_base import (
    FakeWorkerBackend,
    WorkerEvent,
    WorkerPolicy,
    WorkerTask,
)
from ctfmesh_provider_base.worker import redact
from pydantic import ValidationError


def test_public_provider_surface_excludes_legacy_host_execution_backends() -> None:
    for name in (
        "CODEX_EXEC_BACKEND_LIFECYCLE",
        "CodexExecBackend",
        "SCRIPTED_COUNCIL_BACKEND_LIFECYCLE",
        "ScriptedCouncilBackend",
    ):
        assert not hasattr(ctfmesh_provider_base, name)


def worker_task(workspace: Path, **overrides: object) -> WorkerTask:
    data: dict[str, object] = {
        "id": "task-1",
        "run_id": "run-1",
        "role": "source-auditor",
        "objective": "Inspect the authorized fixture only.",
        "context": {"source": "app.py"},
        "allowed_tools": ["files.read_text_range"],
        "workspace": workspace,
        "budget": {"turns": 2},
        "expected_output_schema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
            "additionalProperties": False,
        },
    }
    data.update(overrides)
    return WorkerTask.model_validate(data)


async def collect(stream: AsyncIterator[WorkerEvent]) -> list[WorkerEvent]:
    return [event async for event in stream]


def test_worker_contracts_are_strict_and_require_aware_time(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        worker_task(tmp_path, unknown=True)
    with pytest.raises(ValidationError, match="timezone-aware"):
        WorkerEvent(
            type="worker.started",
            worker_session_id="session-1",
            sequence=1,
            payload={},
            created_at=datetime(2026, 7, 18),
        )
    with pytest.raises(ValidationError, match="finite and non-negative"):
        worker_task(tmp_path, budget={"turns": float("inf")})


@pytest.mark.asyncio
async def test_fake_worker_has_contiguous_deterministic_lifecycle(tmp_path: Path) -> None:
    backend = FakeWorkerBackend([{"summary": "one"}, {"summary": "two"}])
    events = await collect(backend.start(worker_task(tmp_path), policy=WorkerPolicy()))
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    assert events[0].type == "worker.started"
    assert events[-1].type == "worker.completed"


def test_redaction_covers_keys_and_embedded_secret_values() -> None:
    redacted = redact(
        {
            "access_token": "top-secret",
            "message": "Authorization: Bearer abcdefghijklmnop CTF{raw_flag}",
        }
    )
    encoded = json.dumps(redacted)
    assert "top-secret" not in encoded
    assert "abcdefghijklmnop" not in encoded
    assert "CTF{raw_flag}" not in encoded
