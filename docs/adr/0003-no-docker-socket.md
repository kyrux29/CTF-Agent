# ADR 0003: Use fixed isolated execution slots, never a Docker socket

- Status: accepted
- Date: 2026-08-28

## Context

Giving the API, orchestrator, or agent a Docker socket effectively grants host
container control. That conflicts with a CTF runtime that processes untrusted
archives and model-generated requests.

## Decision

The Compose topology will declare a small fixed pool of sandbox slots. The
control plane talks to slots only through an authenticated typed RPC contract;
it cannot create containers dynamically. Privileged containers, host-network
mode, host namespaces, Docker-in-Docker, and Docker socket mounts are forbidden.

## Consequences

Concurrency is intentionally bounded by declared slots, which makes resource
and network policy reviewable. Scaling beyond this topology requires a new ADR
and an independently reviewed scheduler boundary, not an agent-side Docker API.
