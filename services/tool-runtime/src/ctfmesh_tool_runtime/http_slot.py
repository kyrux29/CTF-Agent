"""Fixed-slot wrapper for M3's exact-target HTTP observation tool.

The generic tool package already implements bounded HTTP streaming and cookie
isolation.  This adapter removes its absolute-URL input from the worker-facing
contract: only a manifest-declared alias plus a relative path reaches the
slot, which materializes the URL itself.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from ctfmesh_domain import ChallengeManifest
from ctfmesh_tools import (
    HttpRequestInput,
    HttpRequestTool,
    HttpResponseOutput,
    ToolDeniedError,
    ToolInvocationContext,
    ToolRisk,
    ToolSpec,
)

from .contracts import HttpObservationOutput, HttpRequestCallInput


class TargetHttpScopeError(ValueError):
    """Stable alias-resolution failure used before a network call is made."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def resolve_target_url(manifest: ChallengeManifest, request: HttpRequestCallInput) -> str:
    """Build one URL from a reviewed origin alias and typed relative fields."""

    base_url = manifest.spec.target.target_aliases.get(request.target_alias)
    if base_url is None:
        raise TargetHttpScopeError("http_target_alias_unavailable")
    try:
        base = urlsplit(base_url)
        port = base.port
    except ValueError as exc:  # pragma: no cover - manifest validation is authoritative.
        raise TargetHttpScopeError("http_target_alias_invalid") from exc
    if (
        base.scheme not in {"http", "https"}
        or base.hostname is None
        or base.username is not None
        or base.password is not None
        or base.path not in {"", "/"}
        or base.query
        or base.fragment
        or port is None
    ):
        raise TargetHttpScopeError("http_target_alias_invalid")
    # ``urlunsplit`` receives its netloc from the signed manifest and its path
    # from an input contract that forbids query, fragment, backslash, control
    # characters, and network-path references. It is never `urljoin`ed with
    # model text, avoiding a common authority-smuggling bug.
    query = urlencode(
        tuple(request.query.items()),
        doseq=False,
        encoding="utf-8",
        errors="strict",
    )
    return urlunsplit((base.scheme, base.netloc, request.path, query, ""))


class FixedHttpRequestTool:
    """A typed wrapper that binds HTTP session state to the task branch."""

    input_model: ClassVar[type[HttpRequestCallInput]] = HttpRequestCallInput
    output_model: ClassVar[type[HttpObservationOutput]] = HttpObservationOutput
    spec: ClassVar[ToolSpec] = ToolSpec.from_models(
        name="http.request",
        version="1.0.0",
        description="Send a bounded request to a manifest-declared alias and relative path.",
        risk=ToolRisk.TARGET_INTERACTION,
        idempotency="key_required",
        input_model=HttpRequestCallInput,
        output_model=HttpObservationOutput,
        required_capabilities=("target_http",),
        default_timeout_seconds=20,
        max_output_bytes=512 * 1024,
    )

    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        if transport is None:
            raise ValueError("fixed_http_transport_required")
        self._http = HttpRequestTool(transport)

    def requested_url(
        self,
        request: HttpRequestCallInput,
    ) -> None:
        """Keep the raw tool-runtime hook URL-free for alias-only input."""

        del request
        return None

    def requested_url_with_context(
        self,
        request: HttpRequestCallInput,
        context: ToolInvocationContext,
    ) -> str:
        """Resolve the actual destination only while policy has sealed context."""

        try:
            return resolve_target_url(context.manifest, request)
        except TargetHttpScopeError as exc:
            raise ToolDeniedError(exc.code) from exc

    def requested_path(
        self,
        request: HttpRequestCallInput,
        context: ToolInvocationContext,
    ) -> None:
        del request, context
        return None

    async def invoke(
        self,
        request: HttpRequestCallInput,
        context: ToolInvocationContext,
    ) -> HttpObservationOutput:
        """Delegate bounded I/O after reconstructing the hidden absolute URL."""

        try:
            url = resolve_target_url(context.manifest, request)
        except TargetHttpScopeError as exc:
            raise ToolDeniedError(exc.code) from exc
        if context.branch_id is None:
            raise ToolDeniedError("http_branch_session_required")
        response = await self._http.invoke(
            HttpRequestInput(
                # Cookie state is deliberately keyed by run + branch, not by a
                # model-controlled call field or an arbitrary target origin.
                session_id=context.branch_id,
                method=request.method,
                url=url,
                headers=request.headers,
                json_body=request.json_body,
                content=request.content,
                follow_redirects=False,
                timeout_seconds=request.timeout_seconds,
                max_response_bytes=request.max_response_bytes,
            ),
            context,
        )
        return _observation(request, response)

    async def aclose(self) -> None:
        """Release only the slot-local cookie clients at controlled shutdown."""

        await self._http.aclose()


def _observation(
    request: HttpRequestCallInput,
    response: HttpResponseOutput,
) -> HttpObservationOutput:
    """Drop the absolute origin while retaining bounded, typed HTTP evidence."""

    body = response.body_text.encode("utf-8")
    after_cookie_count = response.cookie_delta.get("after", 0)
    return HttpObservationOutput(
        target_alias=request.target_alias,
        method=request.method,
        path=request.path,
        status=response.status,
        headers=response.headers,
        body_text=response.body_text,
        body_text_sha256=hashlib.sha256(body).hexdigest(),
        body_text_size_bytes=len(body),
        content_type=response.content_type,
        elapsed_ms=response.elapsed_ms,
        cookie_count=after_cookie_count,
        # The connector may truncate upstream data before it reaches the
        # generic HTTP tool. Preserve that evidence instead of presenting a
        # complete-looking observation to Pi or the verifier.
        truncated=response.truncated
        or response.headers.get("x-ctfmesh-truncated", "").lower() == "true",
    )


__all__ = ["FixedHttpRequestTool", "TargetHttpScopeError", "resolve_target_url"]
