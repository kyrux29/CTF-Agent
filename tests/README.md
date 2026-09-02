# Test suites

All executable test code lives under this directory so `apps/`, `packages/`
and `services/` contain product source only.

- `unit/`, `integration/`, and `e2e/` cover cross-package Python behavior.
- `packages/` owns focused Python package contracts and adapters.
- `web/` owns Web type-check and Vitest configuration.
- `pi-runner/` owns Pi Runner type-check and Vitest configuration.

Run the repository gates from the root with `just check`. Test fixtures must
not contain real provider credentials, raw competition flags, or operator data.
