"""Sandbox/verification contracts; legacy Python model code is test-only."""

from typing import Any

from .flag_router import HttpFlagRouterClient, HttpFlagRouterClientError
from .runner import (
    CoordinatorHintProvider,
    FlagRouter,
    ModelBackend,
    ReActSolver,
    Sandbox,
    SandboxObservation,
    SolverContext,
    SolverObservation,
    SolverResult,
    SolverTurn,
    SolverTurnTelemetry,
    TurnTelemetryListener,
)
from .sandboxd import HttpSandboxdClient, SandboxdClientError

_LEGACY_MODEL_EXPORTS = frozenset(
    {"OpenAICompatibleSolverBackend", "SolverModelError", "SolverProvider"}
)


def __getattr__(name: str) -> Any:
    """Load legacy provider code only for isolated fixture compatibility.

    The Power Compose path imports sandboxd/flag-router directly. Keeping the
    old model adapter lazy lets its unit tests remain useful without making an
    import of this package instantiate Python's LLM-client dependency path.
    """

    if name in _LEGACY_MODEL_EXPORTS:
        from . import model

        return getattr(model, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "FlagRouter",
    "CoordinatorHintProvider",
    "HttpFlagRouterClient",
    "HttpFlagRouterClientError",
    "HttpSandboxdClient",
    "ModelBackend",
    "ReActSolver",
    "Sandbox",
    "SandboxObservation",
    "SandboxdClientError",
    "SolverContext",
    "SolverObservation",
    "SolverResult",
    "SolverTurn",
    "SolverTurnTelemetry",
    "TurnTelemetryListener",
]
