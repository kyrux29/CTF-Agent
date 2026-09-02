"""Uvicorn entry point for the internal M3 tool gateway."""

from __future__ import annotations

import uvicorn

from .gateway_app import create_gateway_app
from .settings import ToolGatewaySettings


def main() -> None:
    settings = ToolGatewaySettings.from_environment()
    uvicorn.run(create_gateway_app(settings), host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":  # pragma: no cover - exercised by the container entry point.
    main()
