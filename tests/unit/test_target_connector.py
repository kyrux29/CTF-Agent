"""Focused deny-path tests for M6.a's sole public target connector."""

from __future__ import annotations

import base64

import pytest
from ctfmesh_tool_runtime import target_connector
from ctfmesh_tool_runtime.target_capability import TargetCapabilitySigner
from ctfmesh_tool_runtime.target_connector import (
    ConnectorHeader,
    TargetConnector,
    TargetConnectorError,
    TargetConnectorRequest,
)

_CAPABILITY_KEY = "m6-target-capability-test-key-material-0001"
_URL = "https://challenge.example/api/score"
_BODY = b'{"probe":"one"}'


def _request(*, capability: str, body: bytes = _BODY) -> TargetConnectorRequest:
    """Build a typed connector request without a target-side connection."""

    return TargetConnectorRequest(
        capability=capability,
        method="POST",
        url=_URL,
        headers=[ConnectorHeader(name="accept", value="application/json")],
        body_base64=base64.b64encode(body).decode("ascii"),
    )


@pytest.mark.asyncio
async def test_connector_forwards_one_exact_capability_and_rejects_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied capability cannot cause a second target-side request."""

    signer = TargetCapabilitySigner(_CAPABILITY_KEY)
    capability = signer.issue(
        invocation_id="invocation-connector-one",
        run_id="run-connector-one",
        challenge_id="challenge-connector-one",
        method="POST",
        url=_URL,
        body=_BODY,
        ttl_seconds=30,
    )
    seen: list[tuple[str, bytes]] = []

    async def pinned(
        request: TargetConnectorRequest, body: bytes
    ) -> target_connector._TargetResponse:
        seen.append((request.url, body))
        return target_connector._TargetResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=b"{}",
            truncated=False,
        )

    monkeypatch.setattr(target_connector, "_request_pinned", pinned)
    connector = TargetConnector(signer)

    response = await connector.forward(_request(capability=capability))

    assert response.status == 200
    assert seen == [(_URL, _BODY)]
    with pytest.raises(TargetConnectorError, match="target_capability_replayed"):
        await connector.forward(_request(capability=capability))
    assert seen == [(_URL, _BODY)]


@pytest.mark.asyncio
async def test_connector_rejects_a_changed_body_before_any_target_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slot cannot reuse a capability for a different request payload."""

    signer = TargetCapabilitySigner(_CAPABILITY_KEY)
    capability = signer.issue(
        invocation_id="invocation-connector-two",
        run_id="run-connector-two",
        challenge_id="challenge-connector-two",
        method="POST",
        url=_URL,
        body=_BODY,
        ttl_seconds=30,
    )
    called = False

    async def pinned(
        _request: TargetConnectorRequest, _body: bytes
    ) -> target_connector._TargetResponse:
        nonlocal called
        called = True
        raise AssertionError("mismatched capabilities must not reach a target socket")

    monkeypatch.setattr(target_connector, "_request_pinned", pinned)

    with pytest.raises(TargetConnectorError, match="target_capability_request_mismatch"):
        await TargetConnector(signer).forward(
            _request(capability=capability, body=b'{"probe":"two"}')
        )
    assert called is False


@pytest.mark.asyncio
async def test_connector_denies_private_dns_answers_without_opening_a_socket() -> None:
    """A signed request still cannot turn the connector into an SSRF path."""

    request = TargetConnectorRequest(
        capability="opaque",
        method="GET",
        url="http://127.0.0.1/",
        headers=[],
        body_base64="",
    )

    with pytest.raises(TargetConnectorError, match="target_connector_private_address_denied"):
        await target_connector._request_pinned(request, b"")
