# Contributing to CTFMesh

Thank you for improving CTFMesh. The project is a localhost-only runtime for
authorized CTF labs. Please do not submit real flags, challenge attachments,
provider keys, cookies, or third-party targets.

## Read before changing code

1. Start with the [documentation map](docs/README.md).
2. Read [AGENTS.md](AGENTS.md), the relevant architecture decision, and the
   active execution plan.
3. Check the plan's progress section. Work only on its first unchecked
   milestone; do not mark a milestone complete without its stated acceptance
   gates and worklog.
4. For UI changes, also read
   [docs/CTFMesh-ui-design-guide.md](docs/CTFMesh-ui-design-guide.md).

## Local setup

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile
```

Product services run with Docker Compose. See the root [README](README.md) for
the default workbench and optional Power profile. Never commit `.env`,
`challenges/`, `knowledge/writeups/`, generated artifacts, or dependency
directories; `.gitignore` covers them.

## Make a focused change

- Keep `packages/domain` independent of infrastructure.
- Put provider-specific behavior under `packages/providers/`.
- Invoke tools through the typed runtime; a strategist must not invoke a tool
  directly.
- Run untrusted/generated code only through the sandbox interface.
- Preserve append-only events and immutable artifact references.
- Only the independent verifier/flag router may move a run to `solved`.
- Add a focused test for every behavior change. Add deny-path coverage for a
  boundary or security change.

Document a material design decision in an ADR, and record commands, results,
assumptions, and remaining risk in the active phase worklog. Do not use a
worklog as the primary user or contributor guide.

## Verify before opening a pull request

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -q
pnpm --filter @ctfmesh/web check
pnpm --filter @ctfmesh/pi-runner check
docker compose config --quiet
docker compose --profile power config --quiet
```

Your pull request should describe the user-visible behavior, architecture and
security impact, migrations (if any), checks run, and residual risk. Keep the
diff small enough to review; do not silence or weaken a failing check merely to
finish a phase.
