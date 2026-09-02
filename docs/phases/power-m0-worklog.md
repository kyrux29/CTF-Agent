# Power P0 worklog — ADR and profile skeleton

**Status:** complete — accepted 2026-08-31
**Canonical plan:** [CTFMesh Power ExecPlan](../CTFMesh-power-execplan.md)

## Invariant

Power is opt-in. The only Docker socket mount belongs to trusted `sandboxd` in
the `power` profile. No solver/runtime service, default profile or `m6-ui`
profile receives it; P0 exposes no command/workspace API and cannot mark a run
solved.

## Planned slice

- Record ADR 0009 and the explicit Power exception in `AGENTS.md`.
- Add the `CTFMESH_POWER_ENABLED` feature setting and a health-only `sandboxd`.
- Add `power` Compose skeleton with no idle solver replicas.
- Prove topology and disabled/default behavior before P1.

## Commands and results

- `docker compose --env-file /dev/null config --quiet` — passed; the default
  topology contains neither Power service nor a Docker socket mount.
- `CTFMESH_POWER_ENABLED=true docker compose --env-file /dev/null --profile power config --quiet`
  — passed; `sandboxd` is the sole socket owner and `solver-runtime` resolves
  to zero replicas with `network_mode: none`.
- `CTFMESH_POWER_ENABLED=true docker compose --profile power build sandboxd` —
  passed with the frozen workspace lock.
- `CTFMESH_POWER_ENABLED=true docker compose --profile power up -d --no-deps sandboxd`
  followed by the internal `/health` request — passed and returned the reviewed
  Power service receipt. The test container was then stopped and removed.
- Isolated Python gate (`ruff check`, `ruff format --check`, `pyright`, and
  `pytest -q`) — passed with exit code 0. The Compose topology tests skip only
  when the isolated runner intentionally has no Docker CLI; the topology was
  exercised separately by the two Compose commands above.
- Web check on Node 22.19 — passed: 33 tests, TypeScript and production build.
- Pi runner check on Node 22.22 — passed: 28 tests and TypeScript. The runner's
  declared Node floor is now 22.21 because Node 22.19 does not implement the
  required `--use-env-proxy` safety flag; deployed Docker and CI already use
  Node 22.23.
- `git diff --check` — passed.

## Remaining risks and next step

Docker socket authority is intentionally host-equivalent and confined to the
reviewed `sandboxd` process. The next unchecked milestone is P1; it must add
the versioned workspace lifecycle, path jail, limits, artifact handling,
cancellation and deny-path tests before exposing any command API.
