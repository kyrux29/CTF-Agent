# ADR 0010: Power model turns use the Pi harness

- Status: accepted
- Date: 2026-09-01

## Context

The existing Power prototype owns a second provider loop in Python. It repeats
tool-schema and conversation management already supplied by the pinned Pi SDK,
and it gives CTFMesh two production paths with different compaction, tool-call,
usage, and cancellation behavior.

Pi is already the reviewed CTFMesh session harness. It is not a policy engine,
sandbox, or verifier. Power therefore needs one model-facing implementation
without moving any security authority into Pi.

## Decision

Pi SDK is the only production model harness for Power. Every AutoPrompter and
racer turn will be sent by a Pi `AgentSession`. The Python coordinator retains
race composition, budget admission, duplicate detection, and first-winner
cancellation, but production Power must not instantiate or call a provider
client directly.

Pi sessions use an empty trusted CWD, reviewed resources only, and
`noTools: "all"` with an explicit custom-tool allowlist. Pi built-in host tools
remain disabled. Custom tools cross a typed control boundary to `sandboxd`;
only `sandboxd` owns disposable Docker workspaces. Flag candidates cross the
flag-router boundary, and only its evidence-bound decision may solve a run.

Provider credentials remain short-lived Pi-runner memory leases. They never
enter a workspace, transcript, event, artifact, database record, command
environment, or challenge mount.

The SDK is pinned to npm package `@earendil-works/pi-coding-agent@0.84.4`,
upstream tag `v0.84.4`, commit
`b79e4cc834970cca69daebffab7df1da7d1e52c4`. Runtime installation from Git or
challenge-local Pi resources is prohibited.

## Consequences

- `services/solver-runtime/model.py` may remain temporarily as an offline test
  fixture, but it must leave the production Power Compose path before M-PI-2 is
  complete.
- Power gains Pi-native tool calling, compaction, session persistence, steering,
  cancellation, and usage events through one reviewed SDK surface.
- Pi compromise cannot grant host execution, widen target scope, or claim a
  verified flag because those authorities remain outside the runner.
- Each migration milestone requires deny-path tests before the next production
  edge is enabled.
