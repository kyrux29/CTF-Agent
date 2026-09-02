# Power P1 worklog — disposable workspace and controlled shell

**Status:** complete — 2026-08-31
**Canonical plan:** [CTFMesh Power ExecPlan](../CTFMesh-power-execplan.md)

## Invariant

Only trusted `sandboxd` can use the Docker socket. Every workspace is a
separate non-root, read-only-rootfs container with no Docker socket, no host
bind mount, no published port and no network. It receives a copied, validated
archive intake under `/challenge`; commands are argv passed to Docker, never a
host shell. Output is bounded and stored as a content-addressed artifact.

## Planned slice

- Implemented token-gated create, exec, minimal PTY and idempotent destroy
  endpoints on `sandboxd` only. Missing capability configuration fails closed.
- The archive locator finds an API-produced intake by SHA-256, rejects links
  and special files, then makes a bounded deterministic tar from regular files.
- A named Docker volume is generated per workspace. A short-lived non-root,
  no-network init container copies the tar into that volume and is immediately
  removed. The actual workspace has a read-only rootfs; it sees the named
  volume as `/challenge`, never an arbitrary host path.
- Exec uses a fixed in-container timeout wrapper and argv only; `/challenge`
  and `/work` are the sole accepted working directories. The concrete profile
  fixes user, network, capability set, no-new-privileges, memory, CPU, PID and
  tmpfs limits while allowing only `SYS_PTRACE`.
- stdout/stderr are independently bounded to 64 KiB and recorded as immutable
  local CAS artifacts. Provider keys and the Docker socket are not passed to a
  workspace.
- Unit/integration coverage includes `echo hi`, `id`, JSON argv decoding,
  deny-path, tampered-link, two-workspace isolation, PTY ownership,
  idempotent destroy, Compose topology and actual Docker cleanup.

## Commands and results

- Focused P1 checks (isolated Python environment): Ruff + formatting clean;
  `11 passed, 2 skipped` for P0/P1 profile, workspace and Compose tests.
- Real Docker smoke (`CTFMESH_RUN_POWER_DOCKER_SMOKE=1`): `1 passed`.
  It built the workspace image, copied a receipt into `/challenge`, executed
  `ls -1` and `id` as `uid=1000(ctf)`, then proved no labelled container or
  named challenge volume remained.
- Full Python gates: `uv lock --check`, Ruff, formatting, Pyright (`0 errors`)
  and `pytest -q`: `317 passed, 9 skipped` in 254.34s.
- Compose: default and `CTFMESH_POWER_ENABLED=true --profile power` models
  validated; `power-workspace-image` and `sandboxd` built successfully.
- Web gate: `pnpm --filter @ctfmesh/web check`: `33 passed`, production Vite
  build succeeded. Pi runner gate: `28 passed`.

## Remaining risks and next step

The P1 PTY surface is lifecycle-only; P3 must add the user-facing interactive
session tools and `gdb`/tube wrappers. P2 now needs to bind observations to the
solver ledger and independent flag checking; P1 itself cannot transition a run
to `solved`.
