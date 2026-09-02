# ADR 0001: Deliver the verified Web-lab vertical slice first

> **Historical decision — superseded.** The bundled Web-lab fixture and
> observer demo described here were removed for the blank-workspace release.
> The current product boundary is documented in
> [the operator guide](../usage-guide-vi.md).

- Status: accepted
- Date: 2026-07-26

## Context

The blueprint spans thirteen phases from repository bootstrap to distributed
runtime and plugin governance. Its own prioritization says the first public
release should prove one narrow Web workflow whose declarative exploit plan can
be replayed after deterministic state resets, before scale, memory, or
multi-provider breadth.

## Decision

Implement the contracts needed for a complete v0.1 path and a deterministic
demo fixture. Keep infrastructure adapters replaceable. Include a small Web
console only as an observer/control surface for the requested product demo.

## Consequences

The repository demonstrates the core promise without claiming production
multi-tenant isolation. Rootless OCI/gVisor, durable distributed workflows,
portfolio search, and plugins remain separate release gates.
