# ADR 0004: Limit Pi v0.1 to local source-available Web CTF labs

- Status: accepted
- Date: 2026-08-28

## Context

The existing product has several historical interfaces, while the new Pi path
must first prove a complete, auditable vertical slice. Expanding immediately to
binary, crypto, forensics, arbitrary shells, or public targets would blur the
security and verification contracts.

## Decision

Pi v0.1 accepts authorized local Web challenges with source material and a
validated manifest that declares HTTP targets. It uses source inspection and
typed HTTP operations only. Public web search, arbitrary code execution,
arbitrary shell access, and unmanifested network targets are out of scope.

## Consequences

The first release can measure deterministic evidence, replay, and verifier
authority without claiming universal CTF coverage. Other categories require
their own manifest, tool, sandbox, and verifier designs in later ADRs.
