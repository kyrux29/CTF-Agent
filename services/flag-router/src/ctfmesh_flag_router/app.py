"""Private HTTP boundary for independently checked Power flag submissions."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .router import (
    ControlApiPowerFlagPatternResolver,
    ControlApiPowerRunCompleter,
    FlagRouterError,
    PowerFlagRouter,
)
from .settings import FlagRouterSettings


class FlagSubmissionRequest(BaseModel):
    """Raw candidate is transient and excluded from all responses."""

    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    candidate: SecretStr = Field(min_length=1, max_length=1024)
    observation_artifact_id: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71
    )
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)


def create_flag_router_app(
    settings: FlagRouterSettings | None = None,
    *,
    router: PowerFlagRouter | None = None,
) -> FastAPI:
    """Create a private service with a dedicated solver-facing capability."""

    configuration = settings or FlagRouterSettings()  # type: ignore[call-arg]
    active_router = router or PowerFlagRouter(
        artifact_root=configuration.artifact_root,
        completer=ControlApiPowerRunCompleter(
            base_url=configuration.control_api_url,
            token=configuration.control_api_token.get_secret_value(),
        ),
        pattern_resolver=ControlApiPowerFlagPatternResolver(
            base_url=configuration.control_api_url,
            token=configuration.control_api_token.get_secret_value(),
        ),
    )
    app = FastAPI(title="CTFMesh Power flag router", version="0.1.0")

    async def require_solver_token(
        supplied: Annotated[
            str | None,
            Header(alias="X-CTFMesh-Flag-Router-Token"),
        ] = None,
    ) -> None:
        expected = configuration.router_token.get_secret_value()
        if supplied is None or not secrets.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "flag_router_unauthorized"},
            )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "profile": "power", "service": "flag-router"}

    @app.post("/v1/flags/submit")
    async def submit(
        body: FlagSubmissionRequest,
        _: None = Depends(require_solver_token),
    ) -> dict[str, bool]:
        try:
            accepted = await active_router.submit(
                run_id=body.run_id,
                candidate=body.candidate.get_secret_value(),
                observation_artifact_id=body.observation_artifact_id,
                observation_sha256=body.observation_sha256,
            )
        except FlagRouterError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": exc.code},
            ) from exc
        return {"accepted": accepted}

    app.state.settings = configuration
    app.state.router = active_router
    return app


__all__ = ["FlagSubmissionRequest", "create_flag_router_app"]
