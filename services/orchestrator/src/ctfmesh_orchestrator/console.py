"""Projection-to-UI adapter. The database remains the source of truth."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
_EVENT_REFERENCE_KEYS = (
    "hint_id",
    "branch_id",
    "task_id",
    "finding_id",
    "context_manifest_id",
    "session_id",
    "invocation_id",
    "falsifier_for_finding_id",
)

_POWER_PI_FAILURE_DETAILS = {
    "power_pi_provider_authentication_failed": "Provider rejected the saved API key.",
    "power_pi_provider_rate_limited": "Provider rate limit reached.",
    "power_pi_provider_quota_exhausted": "Provider account quota is unavailable.",
    "power_pi_provider_model_unavailable": "Selected model is unavailable.",
    "power_pi_provider_tool_schema_rejected": "Provider rejected the model tool schema.",
    "power_pi_provider_transport_failed": "Provider connection failed.",
    "power_pi_provider_unavailable": "Provider is temporarily unavailable.",
    "power_pi_model_turn_missing": "Provider ended the turn before work began.",
    "power_pi_model_turn_aborted": "Provider model turn was aborted.",
    "power_pi_model_turn_failed": "Provider did not complete a usable model turn.",
}
_POWER_TRANSCRIPT_RAW_FLAG = re.compile(r"(?i)\b[A-Z][A-Z0-9_]{0,31}\{[^\s{}]{1,512}\}")
_POWER_TRANSCRIPT_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_POWER_TRANSCRIPT_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{16,})\b")
_POWER_TRANSCRIPT_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+"
)


def _kind(event_type: str) -> str:
    if event_type.startswith("verification"):
        return "verifier"
    if event_type.startswith("artifact"):
        return "artifact"
    if event_type.startswith("tool") or event_type.startswith("blackboard.experiment"):
        return "tool"
    if event_type.startswith("policy"):
        return "policy"
    return "worker"


def _event_title(event_type: str) -> str:
    return event_type.replace(".", " ").replace("_", " ").capitalize()


# A run in one of these statuses can still accumulate wall time; every other
# status is settled, so its recorded ``updated_at`` is the true end.
_ACTIVE_RUN_STATUSES = frozenset({"created", "preparing", "running", "paused", "verifying"})


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _nonnegative_int(value: Any) -> int | None:
    """Accept only JSON-safe non-negative counters from trusted receipts."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _nonnegative_float(value: Any) -> float | None:
    """Accept a finite, non-negative usage/cost value from a stored receipt."""

    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return float(value)


def _latest_power_budget(events: list[dict[str, Any]]) -> tuple[float, float] | None:
    """Return the latest conservative Power reservation without provider data.

    Power reserves a configured upper bound *before* every model request. It
    is intentionally not a provider-reported invoice, so the console labels
    it as a reservation and never mistakes it for a zero-cost run.
    """

    event = next(
        (item for item in reversed(events) if item.get("type") == "power.budget.progress"),
        None,
    )
    payload = _mapping(event.get("payload") if event is not None else None)
    reserved = _nonnegative_int(payload.get("reserved_cost_microusd"))
    maximum = _nonnegative_int(payload.get("max_cost_microusd"))
    if reserved is None or maximum is None or maximum <= 0 or reserved > maximum:
        return None
    return reserved / 1_000_000, maximum / 1_000_000


def _latest_power_pi_usage(events: list[dict[str, Any]]) -> float | None:
    """Sum post-turn Pi cost receipts without treating them as a credit path."""

    total = 0.0
    seen: set[int] = set()
    for event in events:
        if event.get("type") != "power.pi.usage":
            continue
        sequence = _nonnegative_int(event.get("sequence"))
        if sequence is None or sequence in seen:
            continue
        amount = _nonnegative_float(_mapping(event.get("payload")).get("cost_usd"))
        if amount is None:
            continue
        seen.add(sequence)
        total += amount
    return total if seen else None


def _observed_tool_call_count(events: list[dict[str, Any]]) -> int:
    """Count each completed call once, including older repeated Power snapshots."""

    count = sum(1 for event in events if event.get("type") == "tool.invocation.completed")
    power_actions: set[tuple[str, int, str]] = set()
    for event in events:
        if event.get("type") != "power.command.observed":
            continue
        payload = _mapping(event.get("payload"))
        action = payload.get("action_type")
        if not isinstance(action, str) or not action:
            continue
        racer_id = payload.get("racer_id")
        racer = racer_id if isinstance(racer_id, str) and racer_id else "legacy"
        turn_count = _nonnegative_int(payload.get("turn_count"))
        # Pre-P8.1 receipts have no turn counter. Their event sequence remains
        # a safe unique fallback, while current receipts deduplicate any old
        # repeated snapshot rows for the same racer/action/turn.
        sequence = turn_count if turn_count is not None and turn_count > 0 else event["sequence"]
        power_actions.add((racer, sequence, action))
    return count + len(power_actions)


def _public_detail(label: str, value: str) -> dict[str, Any]:
    """Build one UI field whose value has passed fixed local validation."""

    return {"label": label, "content": {"value": value, "classification": "public"}}


def _redacted_transcript_text(value: Any, *, maximum: int) -> str:
    """Defend the console projection if an old/malformed event bypasses API.

    The API redacts Power terminal entries before appending them. Repeating the
    transform here makes the display safe even when an operator inspects a
    database restored from an earlier build or a deliberately hostile fixture.
    """

    if not isinstance(value, str):
        return ""
    safe = _POWER_TRANSCRIPT_RAW_FLAG.sub("[REDACTED_FLAG]", value)
    safe = _POWER_TRANSCRIPT_BEARER.sub("Bearer [REDACTED]", safe)
    safe = _POWER_TRANSCRIPT_API_KEY.sub("[REDACTED_API_KEY]", safe)
    safe = _POWER_TRANSCRIPT_SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", safe)
    return _bounded_text(safe, fallback="", maximum=maximum)


def _power_trace_details(event_type: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Project Power events into bounded, operator-useful trace metadata.

    Pi assistant prose and completed custom-tool terminal records are visible
    only after the runner and API redact them. Private thought, credentials,
    raw flags, and full artifact bodies never become public details.
    """

    if event_type == "power.pi.session.failed":
        # The runner emits only a fixed local reason code. Project a closed
        # operator-facing sentence and drop every unknown value so provider
        # response text can never become a public transcript by accident.
        reason = payload.get("reason")
        failure = _POWER_PI_FAILURE_DETAILS.get(reason) if isinstance(reason, str) else None
        return [_public_detail("Failure", failure)] if failure is not None else []
    if event_type == "power.command.observed":
        details: list[dict[str, Any]] = []
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        state = _bounded_text(payload.get("state"), fallback="unknown", maximum=24)
        details.extend([_public_detail("Racer", racer), _public_detail("State", state)])
        turn_count = _nonnegative_int(payload.get("turn_count"))
        if turn_count is not None:
            details.append(_public_detail("Turn", str(turn_count)))
        action = _bounded_text(payload.get("action_type"), fallback="Waiting", maximum=64)
        details.append(_public_detail("Action", action))
        activity = _bounded_text(
            payload.get("action_summary"), fallback="Awaiting the next model action.", maximum=160
        )
        details.append(_public_detail("Activity", activity))
        observation_received = payload.get("observation_received")
        if isinstance(observation_received, bool):
            details.append(
                _public_detail(
                    "Evidence",
                    "Captured immutable observation."
                    if observation_received
                    else "No observation returned.",
                )
            )
        observation_count = _nonnegative_int(payload.get("observation_count"))
        if observation_count is not None:
            details.append(_public_detail("Evidence count", str(observation_count)))
        fingerprint = payload.get("recon_fingerprint")
        if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            # A one-way identifier lets the operator recognize converging
            # reconnaissance without revealing the archive path to the trace.
            details.append(_public_detail("Fingerprint", fingerprint[:12]))
        if payload.get("duplicate_recon") is True:
            details.append(_public_detail("Coordination", "Duplicate file read; racer redirected."))
        return details
    if event_type == "power.recon.duplicate":
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        return [
            _public_detail("Racer", racer),
            _public_detail("Coordination", "Duplicate file read; racer redirected."),
        ]
    if event_type == "power.candidate.review.confirmed":
        # The API writes this fixed racer label only after it has bound the
        # browser selection to one observation. It lets the solved console
        # identify the winning lane without persisting the candidate itself.
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        return [_public_detail("Racer", racer)]
    if event_type == "power.pi.tool_transcript":
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        tool = payload.get("tool")
        if not isinstance(tool, str) or re.fullmatch(r"ctf_[a-z0-9_]{2,59}", tool) is None:
            return []
        command = _redacted_transcript_text(payload.get("command"), maximum=2_000)
        output = _redacted_transcript_text(payload.get("output"), maximum=6_000)
        if not command or not output:
            return []
        exit_code = payload.get("exit_code")
        if isinstance(exit_code, bool) or (
            exit_code is not None and not isinstance(exit_code, int)
        ):
            return []
        if isinstance(exit_code, int) and not -255 <= exit_code <= 255:
            return []
        timed_out = payload.get("timed_out")
        output_truncated = payload.get("output_truncated")
        if not isinstance(timed_out, bool) or not isinstance(output_truncated, bool):
            return []
        return [
            _public_detail("Racer", racer),
            _public_detail("Tool", tool),
            _public_detail("Command", command),
            _public_detail("Output", output),
            _public_detail("Exit code", "n/a" if exit_code is None else str(exit_code)),
            _public_detail("Timed out", "yes" if timed_out else "no"),
            _public_detail("Output capped", "yes" if output_truncated else "no"),
        ]
    if event_type == "power.pi.activity":
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        message_kind = payload.get("message_kind")
        content = payload.get("content")
        if message_kind not in {"prompt", "response"} or not isinstance(content, str):
            return []
        # The API owns both redaction and the 2k cap. Re-check the display
        # shape here so an unrelated event cannot masquerade as Pi output.
        safe = _bounded_text(content, fallback="", maximum=2_000)
        if not safe:
            return []
        return [
            _public_detail("Racer", racer),
            _public_detail("Message kind", message_kind),
            _public_detail("Message", safe),
        ]
    if event_type == "power.pi.usage":
        racer = _bounded_text(payload.get("label"), fallback="Unknown", maximum=8)
        input_tokens = _nonnegative_int(payload.get("input_tokens"))
        output_tokens = _nonnegative_int(payload.get("output_tokens"))
        compacted = _nonnegative_int(payload.get("compacted"))
        details = [
            _public_detail("Racer", racer),
            _public_detail("Input", str(input_tokens if input_tokens is not None else 0)),
            _public_detail("Output", str(output_tokens if output_tokens is not None else 0)),
        ]
        if compacted:
            details.append(_public_detail("Context", f"Compacted {compacted} time(s)"))
        return details
    if event_type == "power.autoprompter.progress":
        turns = _nonnegative_int(payload.get("turn_count"))
        action = _bounded_text(payload.get("last_action_type"), fallback="Waiting", maximum=64)
        return [
            _public_detail("Stage", "Reconnaissance"),
            _public_detail("Turns", str(turns if turns is not None else 0)),
            _public_detail("Last action", action),
        ]
    if event_type == "power.swarm.progress":
        return [
            _public_detail(
                "Stage", _bounded_text(payload.get("state"), fallback="unknown", maximum=32)
            ),
            _public_detail(
                "Category pack",
                _bounded_text(payload.get("category"), fallback="unknown", maximum=64),
            ),
            _public_detail(
                "Local knowledge",
                _bounded_text(payload.get("knowledge_mode"), fallback="disabled", maximum=32),
            ),
        ]
    if event_type == "power.budget.progress":
        reserved = _nonnegative_int(payload.get("reserved_cost_microusd"))
        maximum = _nonnegative_int(payload.get("max_cost_microusd"))
        reservations = _nonnegative_int(payload.get("reservation_count"))
        if reserved is None or maximum is None:
            return []
        return [
            _public_detail("Reserved", f"${reserved / 1_000_000:.2f} / ${maximum / 1_000_000:.2f}"),
            _public_detail(
                "Model calls reserved", str(reservations if reservations is not None else 0)
            ),
        ]
    return []


def _bounded_text(value: Any, *, fallback: str, maximum: int = 160) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip()
    return normalized[:maximum] if normalized else fallback


def _target_scope(target: dict[str, Any]) -> tuple[str, str]:
    target_type = _bounded_text(target.get("type"), fallback="unknown", maximum=32)
    if target_type == "artifact_bundle":
        return "artifact://declared-bundle", target_type

    endpoints = target.get("allowed_endpoints")
    if isinstance(endpoints, list):
        for item in endpoints:
            endpoint = _mapping(item)
            host = _bounded_text(endpoint.get("host"), fallback="", maximum=253)
            protocols = endpoint.get("protocols")
            ports = endpoint.get("ports")
            protocol = protocols[0] if isinstance(protocols, list) and protocols else None
            port = ports[0] if isinstance(ports, list) and ports else None
            if (
                host
                and isinstance(protocol, str)
                and protocol in {"http", "https", "tcp"}
                and isinstance(port, int)
                and not isinstance(port, bool)
            ):
                return f"{protocol}://{host}:{port}", target_type

    if target_type == "docker_compose":
        service = _bounded_text(target.get("service"), fallback="", maximum=160)
        if service:
            return f"compose://{service}", target_type
    return "manifest://declared-scope", target_type


def _triage_metadata(events: list[dict[str, Any]], has_verification: bool) -> dict[str, Any]:
    proposal_event = next(
        (event for event in reversed(events) if event.get("type") == "triage.proposal.received"),
        None,
    )
    payload = _mapping(proposal_event.get("payload") if proposal_event else None)
    raw_skills = payload.get("selected_skill_ids")
    skill_ids = (
        tuple(item.strip() for item in raw_skills if isinstance(item, str) and item.strip())[:32]
        if isinstance(raw_skills, list)
        else ()
    )
    raw_actions = payload.get("actions_executed", 0)
    actions_executed = (
        raw_actions
        if isinstance(raw_actions, int) and not isinstance(raw_actions, bool) and raw_actions >= 0
        else 0
    )
    return {
        "read_only": proposal_event is not None,
        "actions_executed": actions_executed,
        "verification_attempted": has_verification,
        "selected_skill_ids": list(skill_ids),
    }


def _provider_label(provider: Any, *, read_only_triage: bool) -> str:
    label = _bounded_text(provider, fallback="unknown-provider", maximum=64)
    return f"{label} · read-only triage" if read_only_triage else label


def _current_stage(run_status: str, *, read_only_triage: bool, has_verification: bool) -> str:
    if run_status == "solved" or has_verification or run_status == "verifying":
        return "replay"
    if read_only_triage:
        return "triage"
    return "hypothesis"


def _fact_state(status: Any) -> str:
    return {
        "proposed": "proposed",
        "confirmed": "accepted",
        "contradicted": "disputed",
        "retracted": "retracted",
    }.get(status, "proposed")


def _hypothesis_status(status: Any) -> str:
    valid_statuses = {"open", "testing", "supported", "rejected", "merged", "suspended"}
    return status if status in valid_statuses else "open"


def _event_related_refs(payload: dict[str, Any]) -> list[str]:
    """Return only identifier-shaped links from an already sanitized event.

    Hint notes and arbitrary event text never become a navigation reference.
    This keeps the UI's evidence links useful without turning the trace into a
    second unbounded data-exposure channel.
    """

    values: list[Any] = [payload.get(key) for key in _EVENT_REFERENCE_KEYS]
    for key in ("evidence_refs", "evidence_ids", "artifact_refs"):
        collection = payload.get(key)
        if isinstance(collection, list):
            values.extend(collection)
    references: list[str] = []
    for value in values:
        if isinstance(value, str) and _SAFE_REFERENCE.fullmatch(value) and value not in references:
            references.append(value)
    return references[:64]


async def build_console_snapshot(
    repository: Any,
    run_id: str,
    *,
    sealed_artifacts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    run = await repository.get_run(run_id)
    if run is None:
        raise ValueError("run_not_found")
    challenge = await repository.get_challenge(run["challenge_id"])
    blackboard = await repository.blackboard(run_id)
    raw_events = await repository.list_events(run_id, limit=1000)
    # Two generations seal evidence differently. The v0.1 flows write a
    # control-plane artifact row; Power seals straight into the content store
    # and writes no row, so a Power run's evidence was absent from this
    # projection entirely and the console listed nothing for it. Rows win on a
    # collision because they carry the richer name and media type.
    artifacts = await repository.list_artifacts(run_id)
    known = {item["id"] for item in artifacts}
    artifacts = [*artifacts, *(dict(item) for item in sealed_artifacts if item["id"] not in known)]
    verifications = await repository.list_verifications(run_id)
    # Hint Cards and branch scoring are separate projections so the console
    # can explain scheduler effects without exposing Pi transcripts.
    hint_cards = await repository.list_hint_cards(run_id)
    branches = await repository.list_run_branches(run_id)
    verification = verifications[-1] if verifications else None
    manifest = _mapping(challenge.get("manifest") if challenge else None)
    metadata = _mapping(manifest.get("metadata"))
    spec = _mapping(manifest.get("spec"))
    target_scope, scope_kind = _target_scope(_mapping(spec.get("target")))
    category = _bounded_text(metadata.get("category"), fallback="unknown", maximum=64)
    triage = _triage_metadata(raw_events, has_verification=verification is not None)
    started = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    # ``updated_at`` only moves on a status transition, so an active run kept
    # reporting an elapsed time of zero and its wall-time budget looked
    # untouched no matter how long the race had been going.  Measure a live
    # run against the wall clock and a settled one against its final update.
    ended = (
        datetime.now(UTC)
        if run["status"] in _ACTIVE_RUN_STATUSES
        else datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
    )
    elapsed = max(0, int((ended.astimezone(UTC) - started.astimezone(UTC)).total_seconds()))
    status_map = {"created": "queued", "preparing": "queued"}
    ui_status = status_map.get(run["status"], run["status"])
    event_views = []
    for event in raw_events:
        safe_payload = {
            key: value
            for key, value in event["payload"].items()
            if key not in {"flag", "raw_flag", "body", "authorization", "cookie"}
        }
        event_views.append(
            {
                "sequence": event["sequence"],
                "id": event["event_id"],
                "occurred_at": event["created_at"],
                "kind": _kind(event["type"]),
                "title": _event_title(event["type"]),
                "summary": str(
                    safe_payload.get("summary") or safe_payload.get("statement") or event["type"]
                ),
                "tool_name": safe_payload.get("tool_name") or safe_payload.get("action_type"),
                "duration_ms": safe_payload.get("elapsed_ms"),
                "policy_decision": safe_payload.get("policy_decision", "not_applicable"),
                "details": _power_trace_details(event["type"], safe_payload),
                "artifact_refs": [
                    value
                    for key, value in safe_payload.items()
                    if key.endswith("artifact_id") and isinstance(value, str)
                ]
                + [
                    value
                    for value in safe_payload.get("evidence_refs", [])
                    if isinstance(value, str)
                ],
                "related_refs": _event_related_refs(safe_payload),
            }
        )
    facts = [
        {
            "id": item["id"],
            "statement": item["statement"],
            "state": _fact_state(item["status"]),
            "observed_at": item["created_at"],
            "confidence": item["confidence"],
            "evidence_refs": [evidence["artifact_id"] for evidence in item["evidence"]],
        }
        for item in blackboard["facts"]
    ]
    hypotheses = [
        {
            "id": item["id"],
            "statement": item["statement"],
            "status": _hypothesis_status(item["status"]),
            "confidence": item["confidence"],
            "rationale": "Evidence-backed hypothesis; inspect custody links for provenance.",
            "evidence_refs": item["supporting_fact_ids"],
        }
        for item in blackboard["hypotheses"]
    ]
    experiments = [
        {
            "id": item["id"],
            "objective": item["objective"],
            "status": "passed" if item["status"] == "completed" else "queued",
            "risk": "target_interaction" if item["tool_name"].startswith("http.") else "read_only",
            "outcome": None if item["result"] is None else item["result"].get("summary"),
            "evidence_refs": []
            if item["result"] is None
            else item["result"].get("artifact_refs", []),
        }
        for item in blackboard["experiments"]
    ]
    artifact_views = [
        {
            "id": item["id"],
            "name": item["name"],
            "media_type": item["media_type"],
            "digest": f"sha256:{item['sha256']}",
            "size_bytes": item["size_bytes"],
            "classification": "secret"
            if item["classification"] in {"flag", "secret"}
            else "sensitive",
        }
        for item in artifacts
        if item["classification"] != "flag"
    ]
    replay_views = []
    if verification:
        replay_views = [
            {
                "attempt": item["attempt"],
                "status": "passed" if item["passed"] else "failed",
                "started_from_clean_reset": item["started_from_clean_reset"],
                "artifact_digest_match": item.get("artifact_digest_match", True),
                "duration_ms": item.get("duration_ms"),
                "evidence_ref": item.get("evidence_ref"),
            }
            for item in verification["replay_results"]
        ]
    flag = _mapping(spec.get("flag"))
    replay_required = flag.get("replay_count", 1)
    if (
        not isinstance(replay_required, int)
        or isinstance(replay_required, bool)
        or replay_required < 1
    ):
        replay_required = 1
    verification_view = {
        "status": "verified" if verification and verification["verified"] else "pending",
        "summary": (
            "Independent verifier reproduced the exploit "
            f"{replay_required} times from clean target state."
            if verification and verification["verified"]
            else (
                "No verification was attempted in this read-only triage stage."
                if triage["read_only"]
                else "Awaiting independent replay."
            )
        ),
        "exploit_digest": None
        if verification is None
        else f"sha256:{verification['exploit_digest']}",
        "environment_digest": None
        if verification is None
        else f"sha256:{verification['environment_digest']}",
        "flag": None
        if verification is None
        else {"value": "", "classification": "secret", "masked_label": verification["masked_flag"]},
        "replay_required": replay_required,
        "replay_passed": sum(1 for item in replay_views if item["status"] == "passed"),
        "flaky": bool(replay_views)
        and not all(item["status"] == "passed" for item in replay_views),
        "replays": replay_views,
    }
    custody: list[dict[str, Any]] = []
    for index, fact in enumerate(facts, start=1):
        fact_state = fact["state"]
        custody.append(
            {
                "id": f"custody-fact-{index}",
                "kind": "fact",
                "label": fact["statement"][:48],
                "ref_id": fact["id"],
                "digest": None,
                "event_sequence": min(len(raw_events), index + 2),
                "state": (
                    "observed"
                    if fact_state == "accepted"
                    else "derived"
                    if fact_state == "proposed"
                    else "missing"
                ),
                "related_refs": [fact["id"], *fact["evidence_refs"]],
                "target_view": "blackboard",
            }
        )
    for item in artifact_views:
        if item["media_type"] in {"text/x-python", "text/x-shellscript"}:
            custody.append(
                {
                    "id": "custody-reproduction-artifact",
                    "kind": "artifact",
                    "label": "Reproduction artifact",
                    "ref_id": item["id"],
                    "digest": item["digest"],
                    "event_sequence": max(1, len(raw_events) - 1),
                    "state": "derived",
                    "related_refs": [item["id"], *[fact["id"] for fact in facts]],
                    "target_view": "verification",
                }
            )
    if verification:
        custody.append(
            {
                "id": "custody-verification",
                "kind": "verification",
                "label": "Clean replay 2 of 2",
                "ref_id": verification["id"],
                "digest": f"sha256:{verification['environment_digest']}",
                "event_sequence": len(raw_events),
                "state": "verified" if verification["verified"] else "missing",
                "related_refs": [verification["id"], *[item["id"] for item in artifact_views]],
                "target_view": "verification",
            }
        )
    budget = run["budget"]
    is_power_run = run.get("provider") == "power-swarm"
    reserved_power_cost = _latest_power_budget(raw_events) if is_power_run else None
    observed_power_cost = _latest_power_pi_usage(raw_events) if is_power_run else None
    tool_calls_used = _observed_tool_call_count(raw_events)
    return {
        "schema_version": "1",
        "run": {
            "id": run["id"],
            "challenge_name": challenge["name"] if challenge else "unknown",
            "category": category,
            "status": ui_status,
            "started_at": run["created_at"],
            "elapsed_seconds": elapsed,
            "current_stage": _current_stage(
                run["status"],
                read_only_triage=bool(triage["read_only"]),
                has_verification=verification is not None,
            ),
            "event_sequence": raw_events[-1]["sequence"] if raw_events else 0,
            "target_scope": target_scope,
            "scope_kind": scope_kind,
            "execution_mode": "read_only_triage" if triage["read_only"] else "standard",
            "provider_label": _provider_label(
                run.get("provider"), read_only_triage=bool(triage["read_only"])
            ),
            "triage": triage,
        },
        "budgets": [
            {
                "id": "cost",
                "label": (
                    "Reserved cost"
                    if reserved_power_cost is not None
                    else "Observed cost"
                    if observed_power_cost is not None
                    else "Cost"
                ),
                "used": (
                    reserved_power_cost[0]
                    if reserved_power_cost is not None
                    else observed_power_cost
                    if observed_power_cost is not None
                    else 0
                ),
                "limit": (
                    reserved_power_cost[1]
                    if reserved_power_cost is not None
                    else budget.get("max_cost_usd", 1)
                ),
                "unit": "USD",
            },
            {
                "id": "tool_calls",
                "label": "Tool calls",
                "used": tool_calls_used,
                "limit": budget.get("max_tool_calls", 50),
                "unit": "requests",
            },
            {
                "id": "time",
                "label": "Wall time",
                "used": elapsed,
                "limit": budget.get("wall_time_seconds", 300),
                "unit": "seconds",
            },
        ],
        "facts": facts,
        "hypotheses": hypotheses,
        "experiments": experiments,
        "events": event_views,
        "artifacts": artifact_views,
        "verification": verification_view,
        "custody": custody,
        "hints": hint_cards,
        "branches": branches,
    }


__all__ = ["build_console_snapshot"]
