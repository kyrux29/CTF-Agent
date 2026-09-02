"""Typed client for the private P2 flag-router service."""

from __future__ import annotations

import httpx


class HttpFlagRouterClientError(RuntimeError):
    """Stable error that never includes a candidate or response body."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HttpFlagRouterClient:
    """Forward a transient candidate to the independently deployed router."""

    def __init__(self, *, base_url: str, token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token

    async def submit(
        self,
        *,
        run_id: str,
        candidate: str,
        observation_artifact_id: str,
        observation_sha256: str,
    ) -> bool:
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(10.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    "/v1/flags/submit",
                    headers={"X-CTFMesh-Flag-Router-Token": self._token},
                    json={
                        "run_id": run_id,
                        "candidate": candidate,
                        "observation_artifact_id": observation_artifact_id,
                        "observation_sha256": observation_sha256,
                    },
                )
        except httpx.HTTPError as exc:
            raise HttpFlagRouterClientError("flag_router_unavailable") from exc
        if response.status_code != 200:
            raise HttpFlagRouterClientError("flag_router_rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            raise HttpFlagRouterClientError("flag_router_protocol_invalid") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("accepted"), bool):
            raise HttpFlagRouterClientError("flag_router_protocol_invalid")
        return payload["accepted"]


__all__ = ["HttpFlagRouterClient", "HttpFlagRouterClientError"]
