"""Uvicorn entry point for the internal M6.a target connector."""

from __future__ import annotations

import uvicorn

from .target_connector import TargetConnectorSettings, create_target_connector_app


def main() -> None:
    settings = TargetConnectorSettings.from_environment()
    uvicorn.run(
        create_target_connector_app(settings),
        host=settings.target_connector_host,
        port=settings.target_connector_port,
    )


if __name__ == "__main__":  # pragma: no cover - container entry point.
    main()
