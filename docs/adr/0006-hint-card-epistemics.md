# ADR 0006: Treat a Hint Card as an explicit human hypothesis

- Status: accepted
- Date: 2026-08-28

## Context

Operators need a way to guide a run without silently turning an unverified
idea into trusted evidence or injecting raw text into a model prompt.

## Decision

A future Hint Card stores a structured, auditable human hypothesis with
confidence, falsifier, and referenced evidence IDs. It is neither a confirmed
fact nor a direct system prompt. The kernel can turn it into a bounded proposal
only after normal validation and policy checks.

## Consequences

The UI can surface human intuition without poisoning the evidence ledger.
Milestone 0 records this invariant; the schema, UI, and tests arrive only in
the later master/worker evidence milestone.
