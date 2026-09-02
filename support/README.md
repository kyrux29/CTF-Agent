# Repository support

This directory contains maintainer/operator material that is not imported or
packaged as CTFMesh product code.

- `scripts/` contains fixed-scope bootstrap, diagnostic, cleanup, and release
  utilities.
- `examples/` contains documentation-only local lab examples.

Production source lives only in `apps/`, `packages/`, and `services/`. Docker
build contexts exclude this support tree; host-side utilities invoke the
product only through documented control or Compose boundaries.
