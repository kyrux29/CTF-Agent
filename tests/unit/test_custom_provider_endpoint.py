"""An operator may point Power at any OpenAI-compatible model server.

Three providers were hardcoded, so Claude, OpenRouter, a self-hosted gateway
and a model running on the operator's own machine were all unreachable - not
because the SDK could not talk to them, but because CTFMesh named only three.
Opening that up means a provider credential can now be sent somewhere this
codebase does not know, so the endpoint and the provider that uses it have to
agree, in both directions.
"""

from __future__ import annotations

import pytest
from ctfmesh_api.app import PowerRunRequest, _normalize_custom_base_url
from ctfmesh_api.power_runs import _custom_base_url
from ctfmesh_orchestrator import PowerRaceProvider
from pydantic import SecretStr, ValidationError


def _budget() -> dict[str, float]:
    return {"wall_time_seconds": 600, "max_cost_usd": 1.0, "max_turn_cost_usd": 0.5}


def _racers() -> list[dict[str, object]]:
    return [
        {"label": label, "provider": "custom-openai", "model": "local-model", "temperature": 0.2}
        for label in ("A", "B", "C")
    ]


def test_the_endpoint_and_the_provider_that_uses_it_must_agree() -> None:
    # A URL beside a provider Pi already has an endpoint for would silently
    # redirect that provider's key somewhere the operator did not choose.
    with pytest.raises(ValidationError, match="power_custom_base_url_mismatched"):
        PowerRunRequest.model_validate(
            {
                "racers": _racers(),
                "provider_keys": {"openai-responses": SecretStr("k" * 20)},
                "budget": _budget(),
                "custom_base_url": "http://192.168.1.50:11434/v1",
            }
        )

    # And the custom provider without one has nowhere to go at all.
    with pytest.raises(ValidationError, match="power_custom_base_url_mismatched"):
        PowerRunRequest.model_validate(
            {
                "racers": _racers(),
                "provider_keys": {"custom-openai": SecretStr("k" * 20)},
                "budget": _budget(),
            }
        )

    # Together they are accepted, and the endpoint survives normalization.
    accepted = PowerRunRequest.model_validate(
        {
            "racers": _racers(),
            "provider_keys": {"custom-openai": SecretStr("k" * 20)},
            "budget": _budget(),
            "custom_base_url": "http://192.168.1.50:11434/v1/",
        }
    )
    assert accepted.custom_base_url == "http://192.168.1.50:11434/v1"


def test_the_lease_only_carries_an_endpoint_for_the_provider_that_needs_one() -> None:
    assert _custom_base_url(PowerRaceProvider.ANTHROPIC, None) is None
    # Even configured, a built-in provider's key never travels to it.
    assert _custom_base_url(PowerRaceProvider.ANTHROPIC, "http://192.168.1.50:11434") is None
    assert (
        _custom_base_url(PowerRaceProvider.CUSTOM_OPENAI, "http://192.168.1.50:11434")
        == "http://192.168.1.50:11434"
    )
    with pytest.raises(ValueError, match="power_custom_base_url_missing"):
        _custom_base_url(PowerRaceProvider.CUSTOM_OPENAI, None)


def test_the_endpoint_is_held_to_a_plain_shape() -> None:
    """This is the only URL a provider credential is ever sent to."""

    assert _normalize_custom_base_url("  http://192.168.1.50:11434/v1/  ") == (
        "http://192.168.1.50:11434/v1"
    )
    assert _normalize_custom_base_url("https://gateway.example.test/openai") == (
        "https://gateway.example.test/openai"
    )
    assert _normalize_custom_base_url("   ") is None

    for invalid in (
        "ftp://gateway.example.test",
        "file:///etc/passwd",
        # Embedded credentials, a query or a fragment all mean the operator is
        # describing something other than an endpoint.
        "http://user:secret@gateway.example.test",
        "https://gateway.example.test/v1?key=leak",
        "https://gateway.example.test/v1#frag",
        "not-a-url",
    ):
        with pytest.raises(ValueError, match="power_custom_base_url_invalid"):
            _normalize_custom_base_url(invalid)


def test_every_pi_provider_is_reachable_and_mapped() -> None:
    """A provider CTFMesh names must be one the runner can actually resolve."""

    from ctfmesh_api.power_runs import _PI_PROVIDER_BY_POWER_PROVIDER
    from ctfmesh_orchestrator.power_race import POWER_PROVIDER_HOSTS

    assert set(_PI_PROVIDER_BY_POWER_PROVIDER) == set(PowerRaceProvider)
    # Every provider except the custom one has a known host, so a deployment
    # can allow exactly the endpoints it uses on the provider proxy.
    assert set(POWER_PROVIDER_HOSTS) == set(PowerRaceProvider) - {PowerRaceProvider.CUSTOM_OPENAI}
