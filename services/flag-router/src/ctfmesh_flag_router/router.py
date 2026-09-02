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


class PowerFlagRouter:
    """Read the CAS independently instead of trusting model or solver output."""

    def __init__(
        self,
        *,
        artifact_root: Path,
        completer: PowerRunCompleter,
        patterns: tuple[str, ...] = (_DEFAULT_FLAG_PATTERN,),
    ) -> None:
        if not patterns or len(patterns) > 8:
            raise ValueError("flag_router_patterns_invalid")
        try:
            self._patterns = tuple(re.compile(pattern) for pattern in patterns)
        except re.error as exc:
            raise ValueError("flag_router_patterns_invalid") from exc
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
        if not any(pattern.fullmatch(candidate) for pattern in self._patterns):
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


def _mask_flag(value: str) -> str:
    """Preserve a brief operator confirmation without persisting the raw flag."""

    if len(value) < 8:
        return "[masked]"
    return f"{value[:4]}…{value[-2:]}"


__all__ = [
    "ControlApiPowerRunCompleter",
    "FlagRouterError",
    "PowerFlagRouter",
    "PowerRunCompleter",
]
