# ADR 0002: Use the Pi SDK only as a constrained agent harness

- Status: accepted
- Date: 2026-08-28

## Context

CTFMesh needs resumable agent sessions and structured events, but Pi itself is
not a policy engine, permission system, or sandbox. Challenge archives are
untrusted input and can contain prompt-injection-style project instructions.

## Decision

In Milestone 2, CTFMesh will pin a reviewed Pi SDK version and run it only as a
harness behind the Python run kernel. Sessions start from an empty trusted CWD,
use `noTools: "all"`, and receive only reviewed custom tools through the typed
tool runtime. The resource loader will allow only CTFMesh-owned resources;
challenge-local `.pi`, `.agents`, and `AGENTS.md` files are never loaded.

## Consequences

The kernel, not Pi or a model, remains authoritative for state, scope, budget,
and audit decisions. Pi integration requires version/lock provenance plus
denial tests for built-in tools and untrusted resource discovery before any
challenge data or target access is enabled.
