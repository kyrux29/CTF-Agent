"""OpenAI Responses provider adapter for evidence-first CTF triage.

The package deliberately has no environment-variable credential lookup. Callers
must pass an API key for each request through a trusted secret boundary.
"""

from .triage import (
    AsyncResponsesTransport,
    HttpxResponsesTransport,
    MissingOpenAIAPIKeyError,
    OpenAIResponsesError,
    OpenAIResponsesHTTPError,
    OpenAIResponsesProtocolError,
    OpenAIResponsesTimeoutError,
    OpenAIResponsesTransportError,
    OpenAIResponsesTriageClient,
    ResponsesHTTPResponse,
    TriageCategory,
    TriageCompletion,
    TriageEvidence,
    TriageFact,
    TriageHypothesis,
    TriageNextAction,
    TriageRequest,
    TriageResult,
    build_triage_request,
)

__all__ = [
    "AsyncResponsesTransport",
    "HttpxResponsesTransport",
    "MissingOpenAIAPIKeyError",
    "OpenAIResponsesError",
    "OpenAIResponsesHTTPError",
    "OpenAIResponsesProtocolError",
    "OpenAIResponsesTimeoutError",
    "OpenAIResponsesTransportError",
    "OpenAIResponsesTriageClient",
    "ResponsesHTTPResponse",
    "TriageCategory",
    "TriageCompletion",
    "TriageEvidence",
    "TriageFact",
    "TriageHypothesis",
    "TriageNextAction",
    "TriageRequest",
    "TriageResult",
    "build_triage_request",
]
