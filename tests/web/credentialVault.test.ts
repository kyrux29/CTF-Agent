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
  it("keeps a store written before or after this build's provider list", () => {
    // The provider list grows; a store saved by another build must not be
    // discarded wholesale, and an absent key means the same as an empty one.
    window.localStorage.setItem(
      "ctfmesh.provider-credentials/v2",
      JSON.stringify({
        schema_version: "ctfmesh.browser-credential-store/v2",
        credentials: { anthropic: "sk-ant-local", "some-future-provider": "later", groq: "" },
      }),
    );

    expect(loadStoredCredentialVault()).toEqual({
      anthropic: "sk-ant-local",
      "some-future-provider": "later",
    });
  });

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
    expect(loadStoredCredentialVault()).toEqual({});

    window.localStorage.setItem("ctfmesh.provider-credentials/v1", "legacy-envelope");
    saveStoredCredentialVault(credentials);
    clearStoredCredentialVault();
    expect(hasStoredCredentialVault()).toBe(false);
    expect(window.localStorage.getItem("ctfmesh.provider-credentials/v1")).toBeNull();
  });
});
