# ADR 0005: Reserve `SOLVED` for independent verifier proof

- Status: accepted
- Date: 2026-08-28

## Context

Model self-report, a council decision, or a worker's claimed flag is not
evidence that a challenge was solved. A durable state machine needs one sealed
path to terminal success.

## Decision

Direct run transitions to `solved` are rejected for every actor, including a
spoofed verifier identity. The independent verifier records the proof only
while a run is `verifying`; it must satisfy the manifest replay count with
successful clean-reset replays and digest-pinned provenance. That verifier
record atomically changes the run to `solved` and emits the verifier event.

## Consequences

Raw flags stay out of ordinary events, and a flag claim remains a hypothesis
until replayed. The no-bypass test is an architecture regression gate that
must remain green as the API and Pi Runner are introduced.
