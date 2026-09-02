# Power P3 worklog — IAT gdb/tube

**Status:** completed
**Started:** 2026-08-31
**Completed:** 2026-09-01

## Invariant

- Interactive sessions are owned by `sandboxd`, not by a model or solver container.
- A tube may connect only to an exact host and port declared in the workspace request.
- GDB, PTY, and tube bytes are persisted as immutable observations before they reach the next solver turn.
- Closing a session is idempotent; destroying a workspace closes every remaining session.

## Delivered slice

1. Added strict discriminated ACI actions for `shell.pty_*`, `gdb.start/cmd/close`, and binary-safe `tube.*`. GDB only accepts a normalized file path inside `/challenge`.
2. Extended the private `sandboxd` RPC with PTY CAS receipts and tube connect/send/recv-until/close. A tube is stored per workspace and only opens when its canonical `(host, port)` is in `WorkspaceCreate.tube_targets`.
3. The solver retains only IDs returned in real observations and refuses cross-kind or unknown session IDs. It starts GDB with `--quiet --nx`; aged GDB context keeps a bounded selection of backtrace frames.
4. Fixed the Docker PTY close path and made each PTY read wait a bounded caller-selected interval. Destroying a workspace closes its PTYs and tubes.
5. Added only P3 prerequisites to the workspace image: `gdb`, `python3`, and a C compiler for the hermetic hello-pwn proof. The broad category toolkit remains P5.
6. Added a test-only Compose internal echo network. Its proof container has no Docker socket, API key, challenge mount, or host-published port. The random hello-pwn flag exists only during the Docker smoke.

## Commands and results

- Focused P3 unit tests in the pinned `python:3.12.4-slim-bookworm` image: `12 passed` (the test run includes original P1/P2 coverage).
- Real Docker smoke (`CTFMESH_RUN_POWER_DOCKER_SMOKE=1`): `1 passed in 17.91s`. It compiled a generated hello binary, used GDB `break main` → `run` → `continue`, observed the random flag, kept a Python REPL live, ran `shell.exec` concurrently, and stored tube echo bytes in CAS.
- Test-only Compose tube proof: `1 passed in 1.28s`; `ctfmesh-p3-smoke` containers and network were removed after the run.
- Full Python suite in the pinned image: `329 passed, 12 skipped, 1 warning, 24 subtests passed in 280.30s`.
- `ruff check .` and `ruff format --check .` (locked Ruff 0.16.0): passed.
- `pyright`: `0 errors, 0 warnings, 0 informations`.
- `pnpm --filter @ctfmesh/web check`: `33 passed`; production build passed.
- `docker compose config --quiet` and `docker compose --profile power config --quiet`: passed.

## Remaining risks

- P3 accepts tube targets only on the private `sandboxd` create contract. P4 must bind that input to the validated run/manifest path before the UI can start a Power run.
- The tube manager deliberately does not expose arbitrary DNS, network configuration, egress, or raw socket authority to the model. P4 must preserve this boundary when it materializes racer scopes.
