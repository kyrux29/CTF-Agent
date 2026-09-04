import type { PowerProviderId } from "./api";

/**
 * Keys the operator saved, by provider.
 *
 * Partial because the list of providers is now long enough that most stay
 * empty; an absent entry and an empty one mean the same thing.
 */
export type ProviderCredentialVault = Partial<Record<PowerProviderId, string>>;

const STORAGE_KEY = "ctfmesh.provider-credentials/v2";
const LEGACY_ENCRYPTED_STORAGE_KEY = "ctfmesh.provider-credentials/v1";
const SCHEMA_VERSION = "ctfmesh.browser-credential-store/v2";

interface StoredCredentialEnvelope {
  schema_version: typeof SCHEMA_VERSION;
  credentials: ProviderCredentialVault;
}

function emptyCredentials(): ProviderCredentialVault {
  return {};
}

function parseCredentials(value: unknown): ProviderCredentialVault {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The saved credential store is invalid.");
  }
  const record = value as Record<string, unknown>;
  // Read every string entry rather than three fixed ones. A store written
  // before a provider existed is still valid, and one written after this
  // version knows about more providers must not be rejected wholesale.
  const parsed: ProviderCredentialVault = {};
  for (const [provider, key] of Object.entries(record)) {
    if (typeof key !== "string") {
      throw new Error("The saved credential store is invalid.");
    }
    if (key) parsed[provider as PowerProviderId] = key;
  }
  return parsed;
}

/**
 * Load the operator's local-only provider keys on startup. The value remains
 * in this browser profile and is never sent to the CTFMesh database, event
 * ledger, sandbox, or challenge volume.
 */
export function loadStoredCredentialVault(): ProviderCredentialVault {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === null) return emptyCredentials();
    const parsed: unknown = JSON.parse(stored);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return emptyCredentials();
    }
    const envelope = parsed as Partial<StoredCredentialEnvelope>;
    if (envelope.schema_version !== SCHEMA_VERSION) return emptyCredentials();
    return parseCredentials(envelope.credentials);
  } catch {
    return emptyCredentials();
  }
}

export function hasStoredCredentialVault(): boolean {
  return Object.values(loadStoredCredentialVault()).some((value) => value.length > 0);
}

/** Persist plaintext keys in this browser profile as explicitly requested. */
export function saveStoredCredentialVault(credentials: ProviderCredentialVault): void {
  const envelope: StoredCredentialEnvelope = {
    schema_version: SCHEMA_VERSION,
    credentials: parseCredentials(credentials),
  };
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  // A prior encrypted envelope cannot be used without its passphrase and must
  // not shadow the new local-only store after migration.
  window.localStorage.removeItem(LEGACY_ENCRYPTED_STORAGE_KEY);
}

/** Forget provider keys only; workspace settings and run evidence remain. */
export function clearStoredCredentialVault(): void {
  window.localStorage.removeItem(STORAGE_KEY);
  window.localStorage.removeItem(LEGACY_ENCRYPTED_STORAGE_KEY);
}
