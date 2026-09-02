"""Private Power workspace RPC served only on the control bridge."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, status

from .contracts import (
    PtyReadReceipt,
    PtyReadRequest,
    PtyReceipt,
    PtySendRequest,
    TubeConnectRequest,
    TubeReceipt,
    TubeRecvReceipt,
    TubeRecvUntilRequest,
    TubeSendRequest,
    WorkspaceCreateRequest,
    WorkspaceDestroyReceipt,
    WorkspaceExecReceipt,
    WorkspaceExecRequest,
    WorkspacePtyStartRequest,
    WorkspaceReceipt,
)
from .service import WorkspaceService, WorkspaceServiceError
from .settings import SandboxdSettings

_WORKSPACE_ID_PATTERN = r"^ws_[0-9a-f]{32}$"
_PTY_ID_PATTERN = r"^pty_[0-9a-f]{32}$"
_TUBE_ID_PATTERN = r"^tube_[0-9a-f]{32}$"
WorkspaceId = Annotated[str, Path(pattern=_WORKSPACE_ID_PATTERN)]
PtyId = Annotated[str, Path(pattern=_PTY_ID_PATTERN)]
TubeId = Annotated[str, Path(pattern=_TUBE_ID_PATTERN)]


def create_sandboxd_app(
    settings: SandboxdSettings | None = None,
    workspace_service: WorkspaceService | None = None,
) -> FastAPI:
    """Create the Power service after the explicit feature gate.

    Docker access stays behind an unexported service object. All RPC routes
    require a deployment capability token and have no published host port.
    """

    configuration = (settings or SandboxdSettings()).require_power_enabled()
    app = FastAPI(title="CTFMesh Power sandboxd", version="0.1.0")
    manager = workspace_service or WorkspaceService.from_settings(configuration)

    async def require_capability(
        supplied_token: Annotated[
            str | None,
            Header(alias="X-CTFMesh-Sandboxd-Token"),
        ] = None,
    ) -> None:
        """Require a separate internal capability without retaining it in state."""

        configured_token = configuration.sandboxd_token
        if configured_token is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "sandboxd_capability_not_configured"},
            )
        expected_token = configured_token.get_secret_value()
        if supplied_token is None or not secrets.compare_digest(supplied_token, expected_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "sandboxd_capability_invalid"},
            )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "profile": "power", "service": "sandboxd"}

    @app.post(
        "/v1/workspaces",
        response_model=WorkspaceReceipt,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_workspace(
        body: WorkspaceCreateRequest,
        _: None = Depends(require_capability),
    ) -> WorkspaceReceipt:
        return await _workspace_call(manager.create, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/exec",
        response_model=WorkspaceExecReceipt,
    )
    async def exec_workspace(
        workspace_id: WorkspaceId,
        body: WorkspaceExecRequest,
        _: None = Depends(require_capability),
    ) -> WorkspaceExecReceipt:
        return await _workspace_call(manager.exec, workspace_id, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/pty",
        response_model=PtyReceipt,
        status_code=status.HTTP_201_CREATED,
    )
    async def start_pty(
        workspace_id: WorkspaceId,
        body: WorkspacePtyStartRequest,
        _: None = Depends(require_capability),
    ) -> PtyReceipt:
        return await _workspace_call(manager.pty_start, workspace_id, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/pty/{pty_id}/send",
        response_model=PtyReceipt,
    )
    async def send_pty(
        workspace_id: WorkspaceId,
        pty_id: PtyId,
        body: PtySendRequest,
        _: None = Depends(require_capability),
    ) -> PtyReceipt:
        return await _workspace_call(manager.pty_send, workspace_id, pty_id, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/pty/{pty_id}/read",
        response_model=PtyReadReceipt,
    )
    async def read_pty(
        workspace_id: WorkspaceId,
        pty_id: PtyId,
        body: PtyReadRequest,
        _: None = Depends(require_capability),
    ) -> PtyReadReceipt:
        return await _workspace_call(manager.pty_read, workspace_id, pty_id, body)

    @app.delete(
        "/v1/workspaces/{workspace_id}/pty/{pty_id}",
        response_model=PtyReceipt,
    )
    async def close_pty(
        workspace_id: WorkspaceId,
        pty_id: PtyId,
        _: None = Depends(require_capability),
    ) -> PtyReceipt:
        return await _workspace_call(manager.pty_close, workspace_id, pty_id)

    @app.post(
        "/v1/workspaces/{workspace_id}/tubes",
        response_model=TubeReceipt,
        status_code=status.HTTP_201_CREATED,
    )
    async def connect_tube(
        workspace_id: WorkspaceId,
        body: TubeConnectRequest,
        _: None = Depends(require_capability),
    ) -> TubeReceipt:
        return await _workspace_call(manager.tube_connect, workspace_id, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/tubes/{tube_id}/send",
        response_model=TubeReceipt,
    )
    async def send_tube(
        workspace_id: WorkspaceId,
        tube_id: TubeId,
        body: TubeSendRequest,
        _: None = Depends(require_capability),
    ) -> TubeReceipt:
        return await _workspace_call(manager.tube_send, workspace_id, tube_id, body)

    @app.post(
        "/v1/workspaces/{workspace_id}/tubes/{tube_id}/recv-until",
        response_model=TubeRecvReceipt,
    )
    async def recv_tube(
        workspace_id: WorkspaceId,
        tube_id: TubeId,
        body: TubeRecvUntilRequest,
        _: None = Depends(require_capability),
    ) -> TubeRecvReceipt:
        return await _workspace_call(manager.tube_recv_until, workspace_id, tube_id, body)

    @app.delete(
        "/v1/workspaces/{workspace_id}/tubes/{tube_id}",
        response_model=TubeReceipt,
    )
    async def close_tube(
        workspace_id: WorkspaceId,
        tube_id: TubeId,
        _: None = Depends(require_capability),
    ) -> TubeReceipt:
        return await _workspace_call(manager.tube_close, workspace_id, tube_id)

    @app.delete(
        "/v1/workspaces/{workspace_id}",
        response_model=WorkspaceDestroyReceipt,
    )
    async def destroy_workspace(
        workspace_id: WorkspaceId,
        _: None = Depends(require_capability),
    ) -> WorkspaceDestroyReceipt:
        return await _workspace_call(manager.destroy, workspace_id)

    # Retain only the service object. Configuration contains a SecretStr and
    # is neither returned nor serialized by any RPC response.
    app.state.settings = configuration
    app.state.workspace_service = manager
    return app


async def _workspace_call[WorkspaceResult](
    function: Callable[..., Awaitable[WorkspaceResult]],
    *arguments: object,
) -> WorkspaceResult:
    """Translate expected manager codes without exposing daemon/source details."""

    try:
        return await function(*arguments)
    except WorkspaceServiceError as exc:
        status_code = (
            status.HTTP_404_NOT_FOUND
            if exc.code
            in {
                "archive_digest_not_found",
                "workspace_not_found",
                "pty_not_found",
                "tube_not_found",
            }
            else status.HTTP_503_SERVICE_UNAVAILABLE
        )
        raise HTTPException(status_code=status_code, detail={"code": exc.code}) from exc


__all__ = ["create_sandboxd_app"]
