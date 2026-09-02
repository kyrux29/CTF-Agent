# ADR 0011: Local browser provider-key store for the Power profile

- Status: accepted
- Date: 2026-09-01
- Supersedes: ADR 0008 for the localhost single-operator Power profile

## Context

Power is intentionally operated only through a loopback browser by one local
operator. Re-entering multiple provider credentials for every run prevents the
three-racer workflow from being practical. The operator explicitly chose
durable local persistence over passphrase encryption for this profile.

Provider keys must still never enter Postgres, the append-only event ledger,
artifacts, archive intake, challenge mounts, sandbox workspaces, Pi session
files, tool-runtime environments, Compose configuration, or `.env`.

## Decision

The Web Settings dialog stores a versioned provider-key map as plaintext in the
same browser origin's `localStorage`. It restores that map only in the same
browser profile. Saving a new map removes the legacy encrypted envelope from
ADR 0008 so the two stores cannot disagree.

Each provider call sends only the selected provider's key in its explicit
request. The API passes it only through the in-memory lease used by the Pi
runner; it is not persisted or exposed in the operator activity feed. **Remove
saved keys** clears both the active store and the retired legacy envelope.

## Consequences and limits

- This is a local convenience store, not a general-purpose secret vault.
- It is allowed only for a protected, single-user browser profile served on
  loopback. Do not expose the Web service remotely or use a shared profile.
- Clearing browser site data or using **Remove saved keys** revokes local
  persistence. Runs, receipts, and evidence are not changed.
- Team credential sharing, remote sync, recovery, and production secret
  management remain out of scope until a separate authenticated secret broker
  is designed.
