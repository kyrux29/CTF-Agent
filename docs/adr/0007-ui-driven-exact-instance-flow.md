# ADR 0007: UI-driven exact-instance flow for authorized Web CTFs

- Status: accepted
- Date: 2026-08-31

## Context

The original v0.1 profile proved a closed local Web-lab path, but an operator
could not take a validated source archive, declare an authorized instance, and
start a run entirely from the browser. The previous UI exposed archive triage
and manual manifest/run creation as separate actions; it did not create a
solver-capable challenge binding.

The operator has explicitly approved a narrow expansion: archive + exact
instance URL + provider key are supplied from the local UI, while the
backend owns scheduling, tool dispatch, replay verification and lifecycle.

ADR 0011 later supersedes only this document's tab-memory retention UX with an
explicit local-browser provider-key store. The API/Pi request-local handling
and every no-server-secret-persistence boundary below remain unchanged.

## Decision

Add one bounded `ui_exact_instance_v1` path for **assisted, authorized Web
CTFs**:

1. The browser uploads a bounded archive and enters one origin-only HTTP(S)
   instance URL, provider/model, and a one-time API key.
2. The API canonicalizes the URL, creates the immutable challenge manifest and
   run, materializes only the already-validated archive into one fixed
   source-slot volume, and sends the key over an authenticated internal
   memory-only lease to Pi Runner.
3. Pi Runner uses Pi's in-memory credential support for that run only. No key
   is stored in Postgres, an event, an artifact, a session transcript, a slot,
   or environment variable.
4. Source slots keep no public network route. Every remote HTTP request is
   relayed through a target connector that accepts a short-lived,
   gateway-signed capability bound to the exact method, URL and request-body
   digest. It rejects loopback, link-local, multicast, private and otherwise
   non-global resolved addresses; redirects stay disabled.
5. The verifier may independently replay a closed declarative HTTP plan twice
   with fresh cookie jars against the same exact target. A remote target has
   no reset authority, so it produces `verified_remote_replay` only when both
   replays return the same flag-shaped value. A flag is held only in a
   short-lived, one-time local reveal lease after verification; no raw flag is
   persisted or put in an event/proof artifact.

The default scope remains source-available Web CTFs. `contest` mode still
cannot authorize a public target or public web search. The new path is
`assisted` only and is not a general Internet client.

## Non-goals

- Do not execute a Dockerfile, Docker Compose file, binary, script, package
  install, browser automation, or model-authored code from the archive.
- Do not use a Docker socket, privileged container, host network, or direct
  source-slot Internet egress.
- Do not turn arbitrary candidate text into `SOLVED`; two independent verifier
  replays remain required.
- Do not support pwn/reverse/crypto/forensics execution in this v0.1 path.
- Do not promise restart-resume of an unpersisted API key or flag-reveal lease;
  the UI must request a fresh key/re-run after a runner/API restart.

## Consequences

This adds source-slot assignment, target-capability and one-time credential
lease contracts, plus deny-path tests for SSRF, expired/replayed capability,
runner restart, source-slot exhaustion, and no-secret persistence. It keeps
the control API free of a Docker socket and preserves the existing fixed local
lab profile for M3/M5 regressions.
