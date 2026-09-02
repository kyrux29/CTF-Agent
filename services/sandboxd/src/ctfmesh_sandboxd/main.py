"""Console entry point for the Power-profile sandboxd skeleton."""

from __future__ import annotations

import uvicorn

from .app import create_sandboxd_app
from .settings import SandboxdSettings


def main() -> None:
    """Serve only the P0 health endpoint on the private control bridge."""

    settings = SandboxdSettings().require_power_enabled()
    uvicorn.run(create_sandboxd_app(settings), host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()
