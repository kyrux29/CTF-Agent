"""Entrypoint for the internal-only Power flag-router service."""

from __future__ import annotations

import uvicorn

from .app import create_flag_router_app
from .settings import FlagRouterSettings


def main() -> None:
    """Run the service on its Compose-private control network interface."""

    settings = FlagRouterSettings()  # type: ignore[call-arg]
    uvicorn.run(create_flag_router_app(settings), host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()
