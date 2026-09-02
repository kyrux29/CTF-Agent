"""Uvicorn entry point for one internal fixed M3 source slot."""

from __future__ import annotations

import uvicorn

from .settings import SourceSlotSettings
from .slot_app import create_source_slot_app


def main() -> None:
    settings = SourceSlotSettings.from_environment()
    uvicorn.run(create_source_slot_app(settings), host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":  # pragma: no cover - exercised by the container entry point.
    main()
