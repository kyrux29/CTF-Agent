"""Internal ASGI service for M3's durable tool gateway.

Only the control API may reach this process on the internal control network.
The route accepts a versioned envelope, independently checks the durable Pi
lease inside :class:`ToolGateway`, then sends source-only work to one fixed
slot. It never exposes a public operator route or a general proxy endpoint.
"""

from __future__ import annotations

import asyncio
import hmac
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from time import monotonic
from typing import Any

from ctfmesh_db import Database, Repository
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .contracts import GatewayInvocationEnvelope, RejectedToolResult
from .dispatch import ToolGateway
from .remote import HttpSourceSlotClient
from .settings import ToolGatewaySettings
from .slots import SourceSlotClient
from .target_capability import TargetCapabilitySigner

SourceSlotFactory = Callable[[ToolGatewaySettings], tuple[SourceSlotClient, ...]]


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _require_control_api(request: Request) -> None:
    """Authenticate the API relay without exposing the shared token."""

    configured = request.app.state.settings.tool_gateway_token.get_secret_value()
    supplied = request.headers.get("x-ctfmesh-tool-gateway-token")
    if (
        supplied is None
        or len(supplied) > 512
        or not hmac.compare_digest(supplied.encode("utf-8"), configured.encode("utf-8"))
    ):
        raise _error(401, "tool_gateway_unauthorized", "Tool gateway authentication failed.")


def configured_source_slots(settings: ToolGatewaySettings) -> tuple[SourceSlotClient, ...]:
    """Build reviewed static or backend-assigned source-slot clients.

    A dynamic client still names a fixed internal service URL.  The only
    changing association lives in that slot's read-only, backend-written
    assignment file; neither Pi nor the gateway receives an archive path.
    """

    token = settings.source_slot_token.get_secret_value()
    candidates = (
        (
            "source-slot-1",
            settings.source_slot_1_challenge_id,
            settings.source_slot_1_url,
            settings.source_slot_1_dynamic_assignment,
        ),
        (
            "source-slot-2",
            settings.source_slot_2_challenge_id,
            settings.source_slot_2_url,
            settings.source_slot_2_dynamic_assignment,
        ),
    )
    slots: list[SourceSlotClient] = []
    for slot_id, challenge_id, base_url, dynamic_assignment in candidates:
        if base_url is None:
            continue
        slots.append(
            HttpSourceSlotClient(
                slot_id=slot_id,
                challenge_id=challenge_id,
                base_url=base_url,
                token=token,
                workspace_root=(
                    settings.source_slot_dynamic_workspace_root
                    if dynamic_assignment
                    else settings.source_slot_workspace_root
                ),
                dynamic_assignment=dynamic_assignment,
            )
        )
    return tuple(slots)


def create_gateway_app(
    settings: ToolGatewaySettings | None = None,
    *,
    source_slot_factory: SourceSlotFactory | None = None,
) -> FastAPI:
    """Compose the gateway without granting it a public or provider surface."""

    configuration = settings or ToolGatewaySettings.from_environment()
    slot_factory = source_slot_factory or configured_source_slots
    started_at = monotonic()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        artifact_root = configuration.artifact_root.resolve()
        await asyncio.to_thread((artifact_root / "tool-gateway").mkdir, parents=True, exist_ok=True)
        database = Database(configuration.database_dsn)
        # Schema migration is deliberately owned by the API deployment. The
        # gateway only checks that the configured DB is reachable, then relies
        # on its typed repository methods for every durable decision.
        await database.ping()
        repository = Repository(database)
        slots = slot_factory(configuration)
        app.state.settings = configuration
        app.state.database = database
        app.state.gateway = ToolGateway(
            repository=repository,
            artifact_root=artifact_root,
            source_slots=slots,
            max_dispatch_seconds=configuration.dispatch_timeout_seconds,
            target_capability_signer=(
                TargetCapabilitySigner(configuration.target_capability_key.get_secret_value())
                if configuration.target_capability_key is not None
                else None
            ),
        )
        try:
            yield
        finally:
            await database.close()

    app = FastAPI(
        title="CTFMesh Tool Gateway",
        version="0.1.0",
        description="Internal, typed dispatch to fixed CTF source slots.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Input bodies can contain untrusted source search literals. Never echo
        # invalid values back across the internal trust boundary.
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "tool_gateway_request_invalid",
                    "message": "Tool gateway request validation failed.",
                }
            },
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ctfmesh-tool-gateway",
            "uptime_seconds": round(monotonic() - started_at, 3),
        }

    @app.post("/internal/tool-invocations")
    async def invoke_tool(
        envelope: GatewayInvocationEnvelope,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        """Dispatch one authenticated, closed-world worker call.

        Even a gateway execution failure becomes an ordinary rejected tool
        response, so Pi cannot learn database, network, or source-path error
        details and cannot retry a potentially side-effecting action blindly.
        """

        del response
        _require_control_api(request)
        try:
            result = await request.app.state.gateway.invoke(
                envelope.request,
                job_id=envelope.job_id,
                worker_id=envelope.worker_id,
                lease_version=envelope.lease_version,
            )
        except Exception:
            result = RejectedToolResult(
                tool_call_id=envelope.request.call.tool_call_id,
                tool_name=envelope.request.call.tool_name,
                code="tool_gateway_execution_failed",
            )
        return result.model_dump(mode="json")

    return app


__all__ = ["SourceSlotFactory", "configured_source_slots", "create_gateway_app"]
