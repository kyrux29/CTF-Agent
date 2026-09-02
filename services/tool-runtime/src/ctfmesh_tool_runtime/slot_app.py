"""Internal ASGI process for one fixed, read-only M3 source slot."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import monotonic
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .contracts import ToolGatewayContractError, parse_source_slot_invocation
from .settings import SourceSlotSettings
from .slots import InProcessSourceSlot, SourceSlotError
from .target_connector import TargetConnectorTransport


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _require_gateway(request: Request) -> None:
    """Only tool-gateway can invoke the slot; Pi has no slot network route."""

    configured = request.app.state.settings.source_slot_token.get_secret_value()
    supplied = request.headers.get("x-ctfmesh-tool-gateway-token")
    if (
        supplied is None
        or len(supplied) > 512
        or not hmac.compare_digest(supplied.encode("utf-8"), configured.encode("utf-8"))
    ):
        raise _error(401, "source_slot_unauthorized", "Source slot authentication failed.")


def create_source_slot_app(
    settings: SourceSlotSettings | None = None,
    *,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Construct a fixed source/HTTP slot with no generic execution endpoint."""

    configuration = settings or SourceSlotSettings.from_environment()
    started_at = monotonic()
    slot = InProcessSourceSlot(
        slot_id=configuration.source_slot_id,
        challenge_id=configuration.source_slot_challenge_id,
        source_root=configuration.source_slot_root,
        assignment_path=(
            configuration.source_slot_assignment_path
            if configuration.source_slot_dynamic_assignment
            else None
        ),
        # Archive-backed slots never receive a raw public transport. Their
        # typed HTTP calls require a gateway-signed one-use capability and go
        # through the connector; curated M3 slots retain local-lab behavior.
        http_transport=(
            http_transport
            if http_transport is not None
            else (
                TargetConnectorTransport(configuration.target_connector_url)
                if configuration.target_connector_url is not None
                else httpx.AsyncHTTPTransport(retries=0)
            )
        ),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await slot.aclose()

    app = FastAPI(
        title="CTFMesh Source Slot",
        version="0.1.0",
        description="Internal fixed source and exact-target HTTP observation slot.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = configuration
    app.state.slot = slot

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "source_slot_request_invalid",
                    "message": "Source slot request validation failed.",
                }
            },
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ctfmesh-source-slot",
            "slot_id": configuration.source_slot_id,
            "uptime_seconds": round(monotonic() - started_at, 3),
        }

    @app.post("/internal/slot-invocations")
    async def invoke_source_slot(
        invocation: dict[str, Any],
        request: Request,
    ) -> dict[str, Any]:
        """Execute one typed invocation authenticated by the gateway."""

        _require_gateway(request)
        try:
            parsed = parse_source_slot_invocation(invocation)
            response = await request.app.state.slot.invoke(parsed)
        except ToolGatewayContractError as exc:
            raise _error(
                422,
                "source_slot_request_invalid",
                "Source slot request validation failed.",
            ) from exc
        except SourceSlotError as exc:
            # The code is intentionally not echoed: an upstream gateway turns
            # slot availability into a stable, secret-free terminal outcome.
            raise _error(
                409,
                "source_slot_rejected",
                "Source slot rejected the invocation.",
            ) from exc
        return response.model_dump(mode="json")

    return app


__all__ = ["create_source_slot_app"]
