# ADR 0008: Encrypted local browser vault for provider credentials

- Status: superseded on 2026-09-01 by ADR 0011
- Date: 2026-08-31
- Supersedes: the tab-memory-only retention decision in ADR 0007

## Context

Entering an OpenAI, Gemini or DeepSeek key again after every reload is too slow
for an operator working through several CTF challenges. Copying CLIProxyAPI's
plain auth-file/database persistence is not compatible with CTFMesh: provider
keys must never enter Postgres, the append-only event ledger, artifacts,
challenge mounts, a sandbox, Pi session files or tool-runtime environments.

V0.1 is a loopback, single-operator product. It has no tenant authentication or
shared secret service, so a server-side team vault would claim a security model
that the product does not yet implement.

## Decision

Settings may persist a versioned encrypted envelope in the browser origin's
`localStorage`:

1. The operator explicitly enables **Remember encrypted on this browser** and
   supplies a passphrase of at least 12 characters.
2. Web Crypto derives a non-exportable AES-256-GCM key with PBKDF2-SHA-256,
   a random 16-byte salt and 310,000 iterations. Encryption uses a random
   12-byte IV and the schema version as authenticated additional data.
3. Only algorithm metadata, salt, IV and ciphertext are serialized. The
   passphrase and plaintext provider keys stay in current-tab memory after
   unlock and are never sent to the API as vault-management data.
4. A reload starts locked. An explicit passphrase unlock is required before a
   provider key can be reused or edited. Wrong passphrases and malformed
   envelopes fail closed with no partial credential recovery.
5. **Forget saved keys** deletes only the encrypted envelope and clears the
   in-memory provider map. It does not delete runs, archive receipts or
   workspace preferences.

Each provider call and Pi lease retains ADR 0007's request-local boundary. The
API receives only the selected plaintext key for that explicit operation and
does not persist it.

## Consequences and limits

- Long-term retention survives browser and Docker restarts without putting a
  provider key in `.env`, Compose, Postgres or CTFMesh artifacts.
- Loss of the passphrase makes the envelope unrecoverable. The operator must
  forget it and enter fresh provider keys.
- This protects data at rest, not a compromised browser profile or script
  executing in the origin while the vault is unlocked. CSP, loopback-only
  ingress and no remote UI assets remain required.
- The vault is local to one browser profile. Team credential sharing, remote
  sync, recovery keys and tenant access control remain out of scope until a
  separately authenticated secret broker is designed.
