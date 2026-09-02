# Archive Receipt + Scope Ledger frontend

The Web UI is an operator-facing archive receipt and manifest ledger, not a
chat transcript or fixture launcher. It uses:

- `POST /v1/archive-intakes` to stream one local archive into a bounded receipt;
- `GET /v1/archive-intakes/{id}` to reload a redacted receipt;
- `POST /v1/archive-intakes/{id}/candidate-flags/reveal` only after an explicit
  operator click; and
- `POST /v1/runs/{id}/candidate-flags/reveal` only after an explicit operator
  click to rescan Power observations for unverified runtime candidates; and
- `POST /v1/archive-intakes/{id}/triage` for one selected-provider call over
  metadata-only static evidence only; and
- `GET /v1/archive-triage/providers` to inspect the fixed non-secret provider
  allowlist;
- `GET /v1/challenges` to load imported manifests;
- `POST /v1/challenges/validate` to validate JSON manifest input;
- `POST /v1/challenges` to import a validated manifest;
- `POST /v1/runs` to create a bounded run record; and
- `GET /v1/runs/{id}/console` to display an evidence projection.

The page intentionally starts empty. It can upload only bounded supported
archives, never a host path. The credential bay exposes only the fixed
OpenAI/Gemini/DeepSeek provider IDs, an exact model field, a password field,
and an explicit one-time evidence-egress acknowledgement. It never accepts a
base URL, custom header, arbitrary provider ID, or multiple active keys. Under
the local single-operator profile, Settings keeps the provider-key map in the
same browser profile's `localStorage` (ADR 0011); a selected request still uses
only its selected provider key. Changing provider or replacing the archive
clears the pane model/acknowledgement, because consent is scoped to that
evidence boundary.
The user-facing copy must distinguish target-network requests from provider
egress, and keep the boundary clear: receipt creation, direct input candidates,
and a triage proposal are not execution, verification, or a solved state.

The visual direction is a lightweight evidence ledger: a drafting-grid
background, blueprint-blue scope markers, and an amber three-stage receipt rail
(`receive → inspect → propose`). The signature element is the dashed scope
stamp beside the empty workspace thesis; the archive rail turns a missing
challenge into a bounded, actionable intake rather than a generic upload box.

Run projections remain evidence-centric. Sensitive values are masked before
they reach the DOM, untrusted text is rendered as escaped React text, and the
layout preserves keyboard focus, reduced-motion behavior, and a single-column
mobile mode.
