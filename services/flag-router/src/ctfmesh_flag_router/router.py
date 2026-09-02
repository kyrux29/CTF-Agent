"""Verify a candidate against an immutable sandbox observation before completion."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Protocol

import httpx
from ctfmesh_domain import ActorKind
from ctfmesh_tools import LocalArtifactStore
from pydantic import SecretStr

_DEFAULT_FLAG_PATTERN = r"(?i)\b(?:FLAG|HTB|CTF)\{[A-Za-z0-9_:-]{1,512}\}"


class FlagRouterError(RuntimeError):
    """Stable failure code that never renders a raw candidate."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PowerRunCompleter(Protocol):
    """The sole durable state transition used by this independent component."""

    async def complete_power_flag(
        self,
        *,
        run_id: str,
        flag: SecretStr,
        flag_sha256: str,
        masked_flag: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool: ...


class PowerFlagPatternResolver(Protocol):
    """Resolve the durable, per-run capture rule for an independent check."""

    async def patterns_for_run(self, *, run_id: str) -> tuple[str, ...]: ...


class ControlApiPowerRunCompleter:
    """Send a verified flag through the private, memory-only reveal hand-off."""

    def __init__(self, *, base_url: str, token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token

    async def complete_power_flag(
        self,
        *,
        run_id: str,
        flag: SecretStr,
        flag_sha256: str,
        masked_flag: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(5.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    "/internal/power/flag-completions",
                    headers={"X-CTFMesh-Flag-Router-Token": self._token},
                    json={
                        "run_id": run_id,
                        # The API accepts this field only to issue a
                        # process-memory, one-time reveal lease after the
                        # digest-bound durable transition succeeds. It is
                        # never appended to an event or database record.
                        "flag": flag.get_secret_value(),
                        "flag_sha256": flag_sha256,
                        "masked_flag": masked_flag,
                        "observation_artifact_id": observation_artifact_id,
                        "observation_sha256": observation_sha256,
                    },
                )
        except httpx.HTTPError as exc:
            raise FlagRouterError("flag_completion_unavailable") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlagRouterError("flag_completion_invalid_response") from exc
        if response.status_code != 200 or payload != {"accepted": True}:
            raise FlagRouterError("flag_completion_rejected")
        return True


class ControlApiPowerFlagPatternResolver:
    """Read only manifest-owned Power patterns over the router's own identity.

    Candidate submission reaches the flag router through the Control API, but
    this separate read prevents that caller from choosing the regex used to
    accept its own candidate.  The returned values are still length-checked
    and compiled locally by :class:`PowerFlagRouter` before use.
    """

    def __init__(self, *, base_url: str, token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token

    async def patterns_for_run(self, *, run_id: str) -> tuple[str, ...]:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(5.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(
                    f"/internal/power/runs/{run_id}/flag-patterns",
                    headers={"X-CTFMesh-Flag-Router-Token": self._token},
                )
        except httpx.HTTPError as exc:
            raise FlagRouterError("flag_pattern_resolution_unavailable") from exc
        if response.status_code != 200:
            raise FlagRouterError("flag_pattern_resolution_rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlagRouterError("flag_pattern_resolution_invalid_response") from exc
        if not isinstance(payload, dict) or set(payload) != {"patterns"}:
            raise FlagRouterError("flag_pattern_resolution_invalid_response")
        raw_patterns = payload["patterns"]
        if (
            not isinstance(raw_patterns, list)
            or not 1 <= len(raw_patterns) <= 8
            or not all(isinstance(pattern, str) for pattern in raw_patterns)
        ):
            raise FlagRouterError("flag_pattern_resolution_invalid_response")
        return tuple(raw_patterns)


class PowerFlagRouter:
    """Read the CAS independently instead of trusting model or solver output."""

    def __init__(
        self,
        *,
        artifact_root: Path,
        completer: PowerRunCompleter,
        patterns: tuple[str, ...] | None = None,
        pattern_resolver: PowerFlagPatternResolver | None = None,
    ) -> None:
        if patterns is not None and pattern_resolver is not None:
            raise ValueError("flag_router_pattern_source_conflict")
        self._patterns = (
            None
            if pattern_resolver is not None
            else self._compile_patterns(patterns or (_DEFAULT_FLAG_PATTERN,))
        )
        self._pattern_resolver = pattern_resolver
        self._store = LocalArtifactStore(
            artifact_root,
            max_artifact_bytes=64 * 1024,
            read_only=True,
        )
        self._completer = completer

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        """Return true only after CAS provenance, pattern and durable completion agree."""

        if not 1 <= len(candidate) <= 1024:
            return False
        expected_digest = observation_artifact_id.removeprefix("sha256:")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            or observation_sha256 != expected_digest
        ):
            return False
        try:
            metadata = await self._store.iter_metadata(observation_artifact_id)
            payload = await self._store.get_bytes(observation_artifact_id)
        except (OSError, RuntimeError) as exc:
            raise FlagRouterError("flag_observation_unavailable") from exc
        if hashlib.sha256(payload).hexdigest() != observation_sha256:
            return False
        if not any(
            item.run_id == run_id
            and item.sha256 == observation_sha256
            and item.producer.kind is ActorKind.TOOL
            and item.producer.id == "sandboxd"
            for item in metadata
        ):
            return False
        patterns = await self._patterns_for_run(run_id)
        if not any(pattern.fullmatch(candidate) for pattern in patterns):
            return False
        if candidate.encode("utf-8") not in payload:
            return False
        return await self._completer.complete_power_flag(
            run_id=run_id,
            flag=SecretStr(candidate),
            flag_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
            masked_flag=_mask_flag(candidate),
            observation_artifact_id=observation_artifact_id,
            observation_sha256=observation_sha256,
        )

    async def _patterns_for_run(self, run_id: str) -> tuple[re.Pattern[str], ...]:
        """Choose a static test rule or resolve the persisted Power rule."""

        if self._pattern_resolver is None:
            if self._patterns is None:  # defensive invariant for static type checkers
                raise FlagRouterError("flag_pattern_resolution_unavailable")
            return self._patterns
        patterns = await self._pattern_resolver.patterns_for_run(run_id=run_id)
        try:
            return self._compile_patterns(patterns)
        except ValueError as exc:
            raise FlagRouterError("flag_pattern_resolution_invalid_response") from exc

    @staticmethod
    def _compile_patterns(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
        if (
            not patterns
            or len(patterns) > 8
            or any(not 1 <= len(pattern) <= 512 for pattern in patterns)
        ):
            raise ValueError("flag_router_patterns_invalid")
        try:
            return tuple(re.compile(pattern) for pattern in patterns)
        except re.error as exc:
            raise ValueError("flag_router_patterns_invalid") from exc


def _mask_flag(value: str) -> str:
    """Preserve a brief operator confirmation without persisting the raw flag."""

    if len(value) < 8:
        return "[masked]"
    return f"{value[:4]}…{value[-2:]}"


__all__ = [
    "ControlApiPowerRunCompleter",
    "ControlApiPowerFlagPatternResolver",
    "FlagRouterError",
    "PowerFlagPatternResolver",
    "PowerFlagRouter",
    "PowerRunCompleter",
]
