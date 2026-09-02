from __future__ import annotations

import io
import json
import os
import stat
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from ctfmesh_api.archive_intake import ArchiveIntakeError, ArchiveIntakeService
from ctfmesh_provider_openai_responses import (
    TriageCompletion,
    TriageFact,
    TriageHypothesis,
    TriageNextAction,
    TriageRequest,
    TriageResult,
)


def archive_bytes(member_name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(member_name, payload)
    return buffer.getvalue()


async def chunk_once(payload: bytes) -> AsyncIterator[bytes]:
    yield payload


class RecordingBackend:
    """Fake provider that proves exactly what may cross the local AI boundary."""

    name = "recording"

    def __init__(self) -> None:
        self.request: TriageRequest | None = None
        self.api_key: str | None = None
        self.timeout_seconds: float | None = None
        self.call_count = 0

    async def triage(
        self,
        request: TriageRequest,
        *,
        api_key: str,
        timeout_seconds: float = 30.0,
    ) -> TriageCompletion:
        self.call_count += 1
        self.request = request
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        return TriageCompletion(
            response_id="response_operator_test",
            result=TriageResult(
                category="forensics",
                summary="A direct CTF{model_must_not_repeat_this} string is unverified input.",
                facts=(
                    TriageFact(
                        statement="The archive contains a text observation.",
                        confidence=0.8,
                        evidence_ids=("file-001",),
                    ),
                ),
                hypotheses=(
                    TriageHypothesis(
                        statement="The artifact merits offline forensics review.",
                        confidence=0.5,
                        evidence_ids=("archive-context",),
                    ),
                ),
                next_actions=(
                    TriageNextAction(
                        statement="Choose a bounded static follow-up after operator review.",
                        evidence_ids=("file-001",),
                    ),
                ),
            ),
        )


@pytest.mark.asyncio
async def test_archive_triage_receives_redacted_evidence_and_persists_only_redacted_proposal(
    tmp_path: Path,
) -> None:
    candidate = "CTF{archive_input_must_stay_redacted}"
    uncommon_flag = "HTB{slash/plus+equals=must-not-egress}"
    jwt_like_token = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
    path_secret = "HTB{filename-secret}.txt"
    service = ArchiveIntakeService(tmp_path / "artifacts")
    intake = await service.ingest_stream(
        chunk_once(
            archive_bytes(
                path_secret,
                (
                    f"notes: {candidate}\n{uncommon_flag}\n{jwt_like_token}\n"
                    "import hashlib\nAES.new(key, mode)"
                ).encode(),
            )
        ),
        original_name="operator.zip",
        declared_size=None,
    )
    backend = RecordingBackend()
    api_key = "sk-unit-triage-key-must-not-persist"

    triaged = await service.run_triage(
        intake["intake_id"],
        backend=backend,
        api_key=api_key,
        model="operator-model",
        provider="gemini-openai-compat",
        output_contract="json_validated",
    )

    assert backend.request is not None
    assert backend.api_key == api_key
    assert backend.timeout_seconds == 30.0
    # A provider may try to repeat untrusted input. The persisted proposal must
    # still apply the same redaction used for the receipt and prompt evidence.
    provider_evidence = "\n".join(item.content for item in backend.request.evidence)
    assert candidate not in provider_evidence
    assert uncommon_flag not in provider_evidence
    assert jwt_like_token not in provider_evidence
    assert path_secret not in provider_evidence
    assert "text_excerpt" not in provider_evidence
    assert "text_profile" in provider_evidence
    assert '"ctf_topic_markers":["crypto"]' in provider_evidence
    assert triaged["analysis"]["ai"]["status"] == "completed"
    assert triaged["analysis"]["ai"]["provider"] == "gemini-openai-compat"
    assert triaged["analysis"]["ai"]["output_contract"] == "json_validated"
    assert triaged["boundary"]["target_network"] == "not authorized (0 requests)"
    assert triaged["boundary"]["provider_egress"] == "1 metadata-only evidence request"
    assert triaged["analysis"]["ai"]["execution"] == "none"
    assert "[REDACTED_FLAG]" in triaged["analysis"]["ai"]["summary"]

    report = tmp_path / "artifacts" / "archive-intakes" / intake["intake_id"] / "report.json"
    persisted = report.read_text(encoding="utf-8")
    assert candidate not in persisted
    assert api_key not in persisted
    assert json.loads(persisted)["analysis"]["ai"]["verification"] == "not_attempted"

    with pytest.raises(ArchiveIntakeError, match="archive_triage_already_requested"):
        await service.run_triage(
            intake["intake_id"],
            backend=backend,
            api_key="sk-second-request-must-not-leave",
            model="operator-model",
            provider="gemini-openai-compat",
            output_contract="json_validated",
        )
    assert backend.call_count == 1


@pytest.mark.asyncio
async def test_unreferenced_archive_intake_can_be_permanently_removed(tmp_path: Path) -> None:
    service = ArchiveIntakeService(tmp_path / "artifacts")
    intake = await service.ingest_stream(
        chunk_once(archive_bytes("notes/readme.txt", b"remove this receipt\n")),
        original_name="finished.zip",
        declared_size=None,
    )
    intake_id = intake["intake_id"]
    intake_root = tmp_path / "artifacts" / "archive-intakes" / intake_id

    removed = await service.remove_intake(intake_id)

    assert removed == {"removed": True, "intake_id": intake_id}
    assert not intake_root.exists()
    assert await service.list_intakes() == []
    with pytest.raises(ArchiveIntakeError, match="archive_intake_not_found"):
        await service.get_intake(intake_id)


@pytest.mark.asyncio
async def test_validated_archive_is_materialized_only_into_a_fixed_source_slot(
    tmp_path: Path,
) -> None:
    """The source slot receives a read-only copy plus trusted outer metadata."""

    service = ArchiveIntakeService(tmp_path / "artifacts")
    intake = await service.ingest_stream(
        chunk_once(archive_bytes("web/app.py", b"print('source only')\n")),
        original_name="source.zip",
        declared_size=None,
    )
    slot_root = tmp_path / "source-slot-1"
    slot_root.mkdir()

    result = await service.materialize_source_slot(
        intake["intake_id"],
        slot_root=slot_root,
        slot_id="source-slot-1",
        challenge_id="challenge_ui_exact_instance",
    )

    assert result == {
        "intake_id": intake["intake_id"],
        "slot_id": "source-slot-1",
        "challenge_id": "challenge_ui_exact_instance",
    }
    assert (slot_root / "challenge" / "web" / "app.py").read_bytes() == b"print('source only')\n"
    assignment = json.loads((slot_root / "assignment.json").read_text(encoding="utf-8"))
    assert assignment == {
        "challenge_id": "challenge_ui_exact_instance",
        "intake_id": intake["intake_id"],
        "schema_version": 1,
        "slot_id": "source-slot-1",
    }
    assert stat.S_IMODE((slot_root / "challenge").stat().st_mode) == 0o555
    assert stat.S_IMODE((slot_root / "challenge" / "web" / "app.py").stat().st_mode) == 0o444
    assert stat.S_IMODE((slot_root / "assignment.json").stat().st_mode) == 0o444


@pytest.mark.asyncio
async def test_source_slot_materializer_freezes_source_after_publish_before_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dynamic slot never gets an assignment before its source is read-only."""

    service = ArchiveIntakeService(tmp_path / "artifacts")
    intake = await service.ingest_stream(
        chunk_once(archive_bytes("web/app.py", b"print('source only')\n")),
        original_name="source.zip",
        declared_size=None,
    )
    slot_root = tmp_path / "source-slot-1"
    slot_root.mkdir()
    real_replace = os.replace
    observed_source_mode: list[int] = []

    def checked_replace(source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        if destination_path == slot_root / "challenge":
            observed_source_mode.append(stat.S_IMODE(source_path.stat().st_mode))
        if destination_path == slot_root / "assignment.json":
            assert stat.S_IMODE((slot_root / "challenge").stat().st_mode) == 0o555
        real_replace(source, destination)

    monkeypatch.setattr("ctfmesh_api.archive_intake.os.replace", checked_replace)
    await service.materialize_source_slot(
        intake["intake_id"],
        slot_root=slot_root,
        slot_id="source-slot-1",
        challenge_id="challenge_ui_exact_instance",
    )

    assert observed_source_mode and observed_source_mode[0] & stat.S_IWUSR


@pytest.mark.asyncio
async def test_source_slot_materializer_detects_a_changed_extracted_file(tmp_path: Path) -> None:
    """A workspace mutation cannot be silently copied into an active source slot."""

    service = ArchiveIntakeService(tmp_path / "artifacts")
    intake = await service.ingest_stream(
        chunk_once(archive_bytes("app.py", b"print('original')\n")),
        original_name="source.zip",
        declared_size=None,
    )
    workspace_file = (
        tmp_path / "artifacts" / "archive-intakes" / intake["intake_id"] / "workspace" / "app.py"
    )
    workspace_file.write_bytes(b"changed source with a different size\n")
    slot_root = tmp_path / "source-slot-1"
    slot_root.mkdir()

    with pytest.raises(ArchiveIntakeError, match="archive_entry_changed"):
        await service.materialize_source_slot(
            intake["intake_id"],
            slot_root=slot_root,
            slot_id="source-slot-1",
            challenge_id="challenge_ui_exact_instance",
        )
    assert not (slot_root / "challenge").exists()
    assert not (slot_root / "assignment.json").exists()


@pytest.mark.asyncio
async def test_source_slot_materializer_replaces_read_only_previous_archive_cleanly(
    tmp_path: Path,
) -> None:
    """A finished run's read-only tree cannot leave stale source in a reused slot."""

    service = ArchiveIntakeService(tmp_path / "artifacts")
    first = await service.ingest_stream(
        chunk_once(archive_bytes("app.py", b"print('first')\n")),
        original_name="first.zip",
        declared_size=None,
    )
    second = await service.ingest_stream(
        chunk_once(archive_bytes("app.py", b"print('second')\n")),
        original_name="second.zip",
        declared_size=None,
    )
    slot_root = tmp_path / "source-slot-1"
    slot_root.mkdir()

    await service.materialize_source_slot(
        first["intake_id"],
        slot_root=slot_root,
        slot_id="source-slot-1",
        challenge_id="challenge-first",
    )
    await service.materialize_source_slot(
        second["intake_id"],
        slot_root=slot_root,
        slot_id="source-slot-1",
        challenge_id="challenge-second",
    )

    assert (slot_root / "challenge" / "app.py").read_bytes() == b"print('second')\n"
    assert json.loads((slot_root / "assignment.json").read_text(encoding="utf-8"))[
        "challenge_id"
    ] == ("challenge-second")
    assert not tuple(slot_root.glob(".challenge.previous.*"))
    assert not tuple(slot_root.glob(".assignment.previous.*"))
