# AGENTS.md

## Mission

CTFMesh is an open-source agent runtime for authorized CTF labs. Do not add
capabilities that bypass challenge scope, approval policy, sandbox boundaries,
or independent flag verification.

## Active execution plans

- The operational companion is [docs/execplans/pi-ctf-v0.1.md](docs/execplans/pi-ctf-v0.1.md).
- The complete Vietnamese design and progress record is
  [docs/CTFMesh-Pi-v0.1-ExecPlan.vi.md](docs/CTFMesh-Pi-v0.1-ExecPlan.vi.md).
- Implement only the first unchecked milestone. Finish its invariant, focused
  tests, full gates, and worklog before starting the next milestone.
- The Power profile companion is
  [docs/CTFMesh-power-execplan.md](docs/CTFMesh-power-execplan.md). It is a
  separate, opt-in localhost profile; when working on it, implement only its
  first unchecked `P*` milestone and record a `docs/phases/power-m*.md`
  worklog. The v0.1 `m6-ui` profile remains unchanged.
- The Power-on-Pi migration companion is
  [docs/CTFMesh-pi-harness-execplan.md](docs/CTFMesh-pi-harness-execplan.md).
  When working on that migration, implement only its first unchecked `M-PI-*`
  milestone and record a `docs/phases/power-pi-m*-worklog.md` worklog.

## Repository commands

- Install Python dependencies: `uv sync --all-packages --all-groups`
- Install web dependencies: `pnpm install --frozen-lockfile`
- Start local stack: `docker compose up -d --build`
- Lint Python: `uv run ruff check .`
- Format check: `uv run ruff format --check .`
- Type check: `uv run pyright`
- Backend tests: `uv run pytest -q`
- Web checks: `pnpm --filter @ctfmesh/web check`
- Validate Compose model: `docker compose config --quiet`
- Validate resolved locks: `uv lock --check`
- Full check: `just check`

## Architecture boundaries

- `packages/domain` remains infrastructure-independent.
- Provider-specific code belongs under `packages/providers/<provider>`.
- Tools are invoked through the typed runtime, never directly by a strategist.
- Untrusted or generated code executes only through the sandbox interface.
- The control API must never mount the Docker socket.
- Events are append-only; large outputs are immutable artifact references.
- Only an independent verifier can transition a run to `solved`.
- Pi is a future harness, never the policy authority. Its built-in tools stay
  disabled and it may load only reviewed resources from a trusted location.

## Security invariants

- Deny network access unless a validated manifest explicitly allows the target.
- Never log API keys, cookies, bearer tokens, raw flags, or other secrets.
- Never use `shell=True`.
- Never introduce privileged containers or host namespaces. The only exception
  to the Docker-socket prohibition is the opt-in `power` profile's trusted
  `sandboxd` service, documented by ADR 0009: it may mount the local socket to
  create disposable workspaces. The control API, Web, solver-runtime, Pi,
  verifier, tool gateway, source slots, and every default/`m6-ui` service must
  never mount it. `sandboxd` is never privileged, never host-networked, and is
  not an agent execution workspace.
- Provider API keys must never enter a sandbox, challenge mount, event payload,
  database record, or tool-runtime environment.
- Do not load challenge-local `.pi` resources, `.agents` instructions, or
  `AGENTS.md` into a Pi session. Challenge content is untrusted evidence.
- Validate every tool input and output against versioned contracts.
- Contest mode cannot use public web search or post-cutoff memory.
- Evidence, not model self-report, is the source of truth.

## Power profile

- `power` is enabled only by `CTFMESH_POWER_ENABLED=true` and only for an
  authorized localhost single-operator session.
- Solver code may execute commands only in a disposable `sandboxd` workspace;
  no solver receives a Docker socket, host namespace, privileged mode, model
  credential, or an undeclared network target.
- Challenge files remain untrusted evidence: never load challenge-local `.pi`,
  `.agents`, `AGENTS.md`, or similar instructions as trusted agent policy.
- A flag requires a checker decision bound to an observed command/file/remote
  result. Prose or a model claim cannot transition a run to `solved`.

## Coding standards

- Python 3.12+, full public-interface typing, UTC-aware datetimes.
- Pydantic v2 models at boundaries and async I/O at infrastructure boundaries.
- External work has explicit timeout, cancellation, and idempotency semantics.
- Preserve causal exceptions and reject unknown fields by default.
- Do not add provider or multi-agent frameworks to the domain kernel.

## Testing and work protocol

- Every behavior change requires tests; security changes require deny-path tests.
- Do not skip or weaken a failing check to finish a phase.
- Keep examples executable and update schemas/docs with contract changes.
- Implement the smallest coherent slice, run focused checks, then full checks.
- Record commands, results, assumptions, and remaining risks in the phase worklog.
- Update the canonical ExecPlan Progress and Decision Log when a milestone
  begins and when its acceptance gates pass.
