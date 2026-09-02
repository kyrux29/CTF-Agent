# Power Pi M-PI-1 worklog — typed Power custom tools

## Started — 2026-09-01

### Objective

Define Pi-native Power tools that can operate only through a typed
control-runtime seam. The runner must not gain Docker, host-shell, filesystem,
target socket, flag-verification, or provider-key authority. This milestone
does not connect the Power controller to Pi; that is M-PI-2.

### Invariant

- All Pi built-ins remain disabled with `noTools: "all"`.
- Workspace identity is injected by trusted orchestration, never provided by a
  model tool call.
- The tool adapter emits bounded, artifact-referenced observations. Its detail
  object never copies raw tool output or a flag candidate.
- `ctf.flag_submit` is absent from the AutoPrompter surface and can only pass a
  candidate to the independent flag-router seam.

## Completed — 2026-09-01

### Delivered

- Added `services/pi-runner/src/power-tools.ts`, a Pi-native custom-tool
  factory with the sixteen Power operations in the execution plan.
- Kept the runner on a typed `PowerToolControl` seam: it contains no host
  shell, Docker client, target-socket implementation, provider credential, or
  flag-verification decision. M-PI-2 will bind that seam to durable Power
  controller jobs and sandboxd routes.
- Enforced trusted workspace injection, `/challenge` and `/work` path bounds,
  bounded argv/input, channel ownership, and standard-base64 validation before
  calling the control seam.
- Bound every observation passed to Pi to 4,000 characters using head/tail
  preservation. Details retain only artifact metadata and execution metadata;
  they never include raw output, write content, or a flag candidate.
- Excluded `ctf.flag_submit` from the AutoPrompter tool list. The racer route
  sends candidate evidence only to the independent flag-router seam.
- Added a faux Pi provider test that creates a real `AgentSession` with
  `noTools: "all"`, calls `ctf.fs_list`, and checks the resulting artifact
  observation. No real model, API key, sandbox, target, or challenge was used.

### Verification

| Command | Result |
|---|---|
| `pnpm --filter @ctfmesh/pi-runner check` | 7 files, 35 tests passed; TypeScript check passed. |
| `pnpm --filter @ctfmesh/web check` | 16 tests passed; production build passed. |
| `pnpm install --frozen-lockfile --prefer-offline` | Passed. |
| `docker compose --env-file /dev/null config --quiet` | Passed for default and enabled `power` profile. |
| Docker full Python gate (`uv lock`, sync, Ruff, format, Pyright, Pytest) | 381 passed, 14 skipped, 1 existing dependency deprecation warning. |

### Remaining risks and next boundary

- This milestone deliberately exposes only the typed adapter and its fake
  transport tests. It does not start durable Pi sessions or make production
  sandboxd/flag-router calls; that is the explicit scope of M-PI-2.
- The only warning in the full Python gate is Starlette's upstream
  `TestClient`/`httpx` deprecation warning. It did not affect any check.
