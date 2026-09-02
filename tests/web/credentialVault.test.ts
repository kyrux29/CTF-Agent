import { beforeEach, describe, expect, it } from "vitest";

import {
  clearStoredCredentialVault,
  hasStoredCredentialVault,
  loadStoredCredentialVault,
  saveStoredCredentialVault,
  type ProviderCredentialVault,
} from "../../apps/web/src/credentialVault";

const credentials: ProviderCredentialVault = {
  "openai-responses": "sk-openai-local",
  "gemini-openai-compat": "gemini-local",
  "deepseek-chat": "deepseek-local",
};

describe("local browser credential store", () => {
  beforeEach(() => window.localStorage.clear());

  it("persists plaintext provider keys and loads them without an unlock step", () => {
    saveStoredCredentialVault(credentials);

    const stored = window.localStorage.getItem("ctfmesh.provider-credentials/v2") ?? "";
    expect(stored).toContain("ctfmesh.browser-credential-store/v2");
    expect(stored).toContain(credentials["deepseek-chat"]);
    expect(hasStoredCredentialVault()).toBe(true);
    expect(loadStoredCredentialVault()).toEqual(credentials);
  });

  it("drops malformed or legacy state and supports explicit removal", () => {
    window.localStorage.setItem("ctfmesh.provider-credentials/v2", "not-json");
    expect(loadStoredCredentialVault()).toEqual({
      "openai-responses": "",
      "gemini-openai-compat": "",
      "deepseek-chat": "",
    });

    window.localStorage.setItem("ctfmesh.provider-credentials/v1", "legacy-envelope");
    saveStoredCredentialVault(credentials);
    clearStoredCredentialVault();
    expect(hasStoredCredentialVault()).toBe(false);
    expect(window.localStorage.getItem("ctfmesh.provider-credentials/v1")).toBeNull();
  });
});
