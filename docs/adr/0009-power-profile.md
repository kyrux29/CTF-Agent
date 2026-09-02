# ADR 0009: Opt-in Power profile with a single trusted Docker manager

**Status:** accepted for Power P0 on 2026-08-31
**Scope:** authorized, single-operator CTF work on the local machine only

## Context

The v0.1/M6 runtime deliberately restricts action space to typed tools and
never mounts a Docker socket. That remains the default because uploaded
challenge material and model output are untrusted. The Power profile requires
disposable shell-capable workspaces to solve non-Web CTF categories, but a
solver with direct Docker access would be equivalent to host control.

## Decision

`power` is a separately selected Compose profile, gated by
`CTFMESH_POWER_ENABLED=true`. Only the trusted `sandboxd` manager mounts the
host Docker socket. It is a local control-plane component, not a solver
workspace and not a public service. It runs without privileged mode, host
network, published ports, or a host namespace. P0 exposes only `/health`; P1
must define versioned workspace/exec contracts, path jail, resources,
artifacts, cancellation, and destroy semantics before Docker actions exist.

`solver-runtime` is reserved at zero replicas in P0. It receives no Docker
socket, host mount, model key, or undeclared network route. API, Web, Pi,
verifier, source slots and typed tool gateway keep their existing no-socket
boundary. The default and `m6-ui` profiles do not include `sandboxd`.

Even in Power, a model claim cannot solve a run: P2+ must bind any flag
candidate to a recorded observation and flag-router/checker decision.

## Consequences

- The operator explicitly accepts that `sandboxd`'s socket access is
  host-equivalent authority; it is limited to one reviewed service and profile.
- P0 gives a deployable topology and fail-closed feature gate, not an execution
  API. A Power deployment is not useful for solving until P1/P2 are complete.
- Compose and regression tests must prove the socket occurs exactly once and
  never reaches the solver/default profile.
