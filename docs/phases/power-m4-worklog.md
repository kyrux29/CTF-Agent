# Power P4 worklog — AutoPrompter and three-racer coordinator

**Status:** completed
**Started:** 2026-09-01
**Completed:** 2026-09-01

## Invariant

- The coordinator has no tool, Docker, target-network, or flag-verification authority. It only constructs isolated P2/P3 solver loops through injected interfaces.
- AutoPrompter runs for at most ten turns. Its shared brief contains only action/evidence receipt metadata, never raw tool output or a flag.
- Each racer owns a separately-created sandbox workspace. A process-local gate lets only the first candidate call the independent flag router; the coordinator then gives siblings five seconds to stop cleanly before cancelling their tasks.
- Progress is an immutable, secret-free read model: it exposes racer state, action type, command fingerprint prefix, and counts—not raw commands, outputs, API keys, or flags.

## Delivered slice

1. Extended the P2 ReAct runtime with cooperative cancellation, a bounded coordinator hint, and post-action telemetry containing only action type, observation presence, and a SHA-256 shell-command fingerprint. The telemetry does not carry command text, output, thought, credentials, or flags.
2. Added `AutoPrompter`, limited to ten typed-action turns and explicitly unable to call flag-router. Its shared brief includes action types and immutable receipt IDs only; raw tool output is neither copied nor made durable by the coordinator.
3. Added `PowerSwarmCoordinator`, which accepts exactly three A/B/C racer specifications, creates a new sandbox through an injected factory for each racer, and exposes an immutable `PowerSwarmSnapshot` read model for P8. The snapshot shows state, last action type, fingerprint prefix, and counts—not raw commands or transcripts.
4. Added a serialized first-winner gate in front of the existing flag-router. Only its first candidate can reach independent verification. A verified result signals sibling cancellation, waits up to the production five-second grace period for cleanup, then cancels only still-pending solver tasks.
5. Added duplicate-command diversity bumps and a five-consecutive-no-observation stall bump. Both are bounded coordinator hints; they do not add tools, network targets, Docker access, or completion authority.
6. Added unit fixtures and a real Docker smoke. The Docker proof materializes a local intake archive, creates one reconnaissance and three isolated racer workspaces, verifies the observed flag through the real P2 router, cancels both siblings, and verifies manager-owned container cleanup.

## Commands and results

- Focused Power unit proof: `8 passed in 1.51s` (`test_power_swarm.py` plus the existing ReAct regression fixture).
- P4 real Docker smoke (`CTFMESH_RUN_POWER_DOCKER_SMOKE=1`): `1 passed in 17.07s`. It used no provider/API key and no external target; the generated image was removed in `finally`.
- Full Python suite in the pinned `python:3.12.4-slim-bookworm` image: `333 passed, 13 skipped, 1 warning, 24 subtests passed in 267.58s`.
- `ruff check .` and `ruff format --check .` using locked Ruff `0.16.0`: passed.
- `pyright` `1.1.390`: `0 errors, 0 warnings, 0 informations`.
- `pnpm --filter @ctfmesh/web check`: TypeScript check, `33` web tests, and production Vite build passed.
- `docker compose config --quiet`, `docker compose --profile power config --quiet`, and `uv 0.5.26 lock --check`: passed.

## Remaining risks

- P4 intentionally provides an in-process coordinator and safe progress contract, not an operator-start API or browser control. P8 must compose it with validated archive/target scope, credential leases, durable event projection, and the Power UI.
- P5 must provide the reviewed category packs and reproducible toolkit image. Until then P4 uses the deliberately minimal P3 workspace image.
