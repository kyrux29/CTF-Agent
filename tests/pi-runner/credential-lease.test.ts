import { afterEach, describe, expect, it } from "vitest";

import { loadRunnerConfig } from "../../services/pi-runner/src/config.js";
import {
  CredentialLeaseBroker,
  CredentialLeaseStore,
  type ActiveCredentialLease,
} from "../../services/pi-runner/src/credential-lease.js";
import { ControlProtocolError } from "../../services/pi-runner/src/contracts.js";
import { configureLeaseBackedModel, createIsolatedPiRuntime } from "../../services/pi-runner/src/session-factory.js";

const TEST_TOKEN = "credential-broker-test-token-1234";
const TEST_KEY = "test-key-value-not-a-real-secret";

const brokers: CredentialLeaseBroker[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map(async (broker) => broker.close()));
});

function lease(overrides: Partial<ActiveCredentialLease> = {}): ActiveCredentialLease {
  return {
    runId: "run-credential-test-1",
    provider: "openai",
    model: "gpt-4.1",
    apiKey: TEST_KEY,
    expiresAtMs: 1_800_000,
    revision: 1,
    ...overrides,
  };
}

async function broker(): Promise<{ readonly broker: CredentialLeaseBroker; readonly store: CredentialLeaseStore; readonly url: string }> {
  const store = new CredentialLeaseStore(120);
  const instance = new CredentialLeaseBroker({
    controlToken: TEST_TOKEN,
    bindHost: "127.0.0.1",
    bindPort: 0,
  }, store);
  brokers.push(instance);
  await instance.start();
  const address = instance.address();
  if (address === undefined) {
    throw new Error("test broker did not expose a TCP address");
  }
  return { broker: instance, store, url: `http://127.0.0.1:${address.port}` };
}

function body(): Record<string, unknown> {
  return {
    run_id: "run-credential-test-1",
    provider: "openai",
    model: "gpt-4.1",
    api_key: TEST_KEY,
    ttl_seconds: 60,
  };
}

describe("CredentialLeaseStore", () => {
  it("expires a lease and invokes runtime-key revokers without serializing its key", async () => {
    let now = 1_000_000;
    const store = new CredentialLeaseStore(60, () => now);
    const receipt = store.put({
      runId: "run-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    const active = store.get("run-credential-test-1");
    expect(active).toMatchObject({ provider: "openai", model: "gpt-4.1" });
    expect(JSON.stringify(receipt)).not.toContain(TEST_KEY);
    expect(receipt).toEqual({ accepted: true, expires_at: "1970-01-01T00:17:40.000Z" });

    let revoked = 0;
    const unsubscribe = store.subscribe(active as ActiveCredentialLease, () => {
      revoked += 1;
    });
    expect(unsubscribe).toBeTypeOf("function");

    now += 60_000;
    expect(store.get("run-credential-test-1")).toBeUndefined();
    expect(revoked).toBe(1);
    store.close();
  });

  it("extends an identical active lease without revoking Pi's runtime key", () => {
    let now = 1_000_000;
    const store = new CredentialLeaseStore(120, () => now);
    store.put({
      runId: "run-credential-test-1",
      sessionId: "power-session-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    const first = store.get("power-session-credential-test-1");
    expect(first).toBeDefined();
    let revoked = 0;
    store.subscribe(first as ActiveCredentialLease, () => {
      revoked += 1;
    });

    now += 30_000;
    const renewal = store.put({
      runId: "run-credential-test-1",
      sessionId: "power-session-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    const renewed = store.get("power-session-credential-test-1");
    expect(revoked).toBe(0);
    expect(renewed).toMatchObject({ revision: first?.revision });
    expect(renewal.expires_at).toBe("1970-01-01T00:18:10.000Z");

    // The old sixty-second deadline has elapsed, but the renewed lease is
    // still usable. Advancing beyond the new deadline invokes its original
    // revoker exactly once.
    now += 31_000;
    expect(store.get("power-session-credential-test-1")).toBeDefined();
    now += 30_000;
    expect(store.get("power-session-credential-test-1")).toBeUndefined();
    expect(revoked).toBe(1);
    store.close();
  });

  it("revokes an elapsed lease before accepting a later identical renewal", () => {
    let now = 1_000_000;
    const store = new CredentialLeaseStore(120, () => now);
    store.put({
      runId: "run-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    const first = store.get("run-credential-test-1");
    let revoked = 0;
    store.subscribe(first as ActiveCredentialLease, () => {
      revoked += 1;
    });

    now += 60_000;
    store.put({
      runId: "run-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    const replacement = store.get("run-credential-test-1");
    expect(revoked).toBe(1);
    expect(replacement?.revision).toBe((first?.revision ?? 0) + 1);
    store.close();
  });

  it("does not let a replaced lease's old expiry revoke the replacement", () => {
    let now = 1_000_000;
    const store = new CredentialLeaseStore(120, () => now);
    store.put({
      runId: "run-credential-test-1",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    now += 1_000;
    store.put({
      runId: "run-credential-test-1",
      provider: "google",
      model: "gemini-2.5-pro",
      apiKey: "replacement-test-key-value",
      ttlSeconds: 120,
    });
    now += 60_000;
    expect(store.get("run-credential-test-1")).toMatchObject({
      provider: "google",
      model: "gemini-2.5-pro",
    });
    store.close();
  });

  it("wakes a pending session start only after the matching run receives a lease", async () => {
    const store = new CredentialLeaseStore(60);
    const pending = store.waitFor("run-credential-test-1", 500);
    store.put({
      runId: "run-credential-test-1",
      provider: "deepseek",
      model: "deepseek-chat",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    });
    await expect(pending).resolves.toMatchObject({ provider: "deepseek", model: "deepseek-chat" });
    store.close();
  });

  it("fails closed when an internal caller tries to retain too many run keys", () => {
    const store = new CredentialLeaseStore(60);
    for (let index = 0; index < 64; index += 1) {
      store.put({
        runId: `run-credential-capacity-${index}`,
        provider: "openai",
        model: "gpt-4.1",
        apiKey: TEST_KEY,
        ttlSeconds: 60,
      });
    }
    expect(() => store.put({
      runId: "run-credential-capacity-overflow",
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
      ttlSeconds: 60,
    })).toThrowError(ControlProtocolError);
    store.close();
  });
});

describe("CredentialLeaseBroker", () => {
  it("accepts the exact authenticated handoff contract and only returns a secret-free receipt", async () => {
    const { store, url } = await broker();
    const response = await fetch(`${url}/internal/credential-leases`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ctfmesh-runner-token": TEST_TOKEN,
      },
      body: JSON.stringify(body()),
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const receipt = await response.json() as Record<string, unknown>;
    expect(receipt).toMatchObject({ accepted: true, expires_at: expect.any(String) });
    expect(JSON.stringify(receipt)).not.toContain(TEST_KEY);
    expect(store.get("run-credential-test-1")).toMatchObject({
      provider: "openai",
      model: "gpt-4.1",
      apiKey: TEST_KEY,
    });
  });

  it("rejects unauthenticated, over-broad, and overlong handoffs without retaining a key", async () => {
    const { store, url } = await broker();
    const missingToken = await fetch(`${url}/internal/credential-leases`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body()),
    });
    expect(missingToken.status).toBe(401);
    expect(await missingToken.json()).toEqual({ accepted: false, code: "credential_lease_unauthorized" });

    const invalid = await fetch(`${url}/internal/credential-leases`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ctfmesh-runner-token": TEST_TOKEN,
      },
      body: JSON.stringify({ ...body(), ttl_seconds: 121, unexpected: TEST_KEY }),
    });
    expect(invalid.status).toBe(400);
    const rejected = await invalid.json() as Record<string, unknown>;
    expect(rejected).toEqual({ accepted: false, code: "credential_lease_request_unknown_field" });
    expect(JSON.stringify(rejected)).not.toContain(TEST_KEY);
    expect(store.get("run-credential-test-1")).toBeUndefined();
  });
});

describe("lease-backed Pi runtime", () => {
  it("uses Pi's runtime-only key overlay with an empty in-memory base store", async () => {
    const runtime = await createIsolatedPiRuntime();
    await runtime.setRuntimeApiKey("openai", TEST_KEY);
    // Pi's public credential listing intentionally exposes metadata only.
    expect(await runtime.listCredentials()).toEqual([{ providerId: "openai", type: "api_key" }]);
    await runtime.removeRuntimeApiKey("openai");
    expect(await runtime.listCredentials()).toEqual([]);
  });

  it("injects the run lease into Pi's runtime overlay before selecting the model", async () => {
    const calls: string[] = [];
    const model = { id: "gpt-4.1", provider: "openai" };
    const runtime = {
      async setRuntimeApiKey(provider: string, apiKey: string): Promise<void> {
        calls.push(`set:${provider}:${apiKey}`);
      },
      async removeRuntimeApiKey(provider: string): Promise<void> {
        calls.push(`remove:${provider}`);
      },
      getModel(provider: string, modelId: string): unknown {
        calls.push(`model:${provider}:${modelId}`);
        return model;
      },
    };

    await expect(configureLeaseBackedModel(runtime as never, lease())).resolves.toBe(model);
    expect(calls).toEqual([
      `set:openai:${TEST_KEY}`,
      "model:openai:gpt-4.1",
    ]);
  });

  it("removes the runtime key when a lease names an unavailable model", async () => {
    const calls: string[] = [];
    const runtime = {
      async setRuntimeApiKey(provider: string): Promise<void> {
        calls.push(`set:${provider}`);
      },
      async removeRuntimeApiKey(provider: string): Promise<void> {
        calls.push(`remove:${provider}`);
      },
      getModel(): undefined {
        return undefined;
      },
    };

    await expect(configureLeaseBackedModel(runtime as never, lease()))
      .rejects.toMatchObject({ code: "leased_pi_model_not_available" });
    expect(calls).toEqual(["set:openai", "remove:openai"]);
  });

  it("removes the runtime key when Pi rejects a key during metadata refresh", async () => {
    const calls: string[] = [];
    const runtime = {
      async setRuntimeApiKey(provider: string): Promise<void> {
        calls.push(`set:${provider}`);
        throw new Error("provider rejected test key");
      },
      async removeRuntimeApiKey(provider: string): Promise<void> {
        calls.push(`remove:${provider}`);
      },
      getModel(): undefined {
        return undefined;
      },
    };

    await expect(configureLeaseBackedModel(runtime as never, lease()))
      .rejects.toMatchObject({ code: "leased_pi_runtime_key_rejected" });
    expect(calls).toEqual(["set:openai", "remove:openai"]);
  });
});

describe("runner credential configuration", () => {
  it("rejects an inherited provider key instead of allowing SDK environment discovery", () => {
    const environment: NodeJS.ProcessEnv = {
      CTFMESH_INTERNAL_RUNNER_TOKEN: TEST_TOKEN,
      OPENAI_API_KEY: TEST_KEY,
    };
    expect(() => loadRunnerConfig(environment)).toThrowError(ControlProtocolError);
    try {
      loadRunnerConfig(environment);
    } catch (error) {
      expect(error).toMatchObject({ code: "provider_api_key_environment_forbidden" });
    }
  });

  it("allows a live runner to start without static model/key environment configuration", () => {
    const config = loadRunnerConfig({
      CTFMESH_INTERNAL_RUNNER_TOKEN: TEST_TOKEN,
      CTFMESH_PI_RUNNER_MODE: "live",
    });
    expect(config.mode).toBe("live");
    expect(config.modelProvider).toBeNull();
    expect(config.modelId).toBeNull();
    expect(config.credentialBrokerBindPort).toBe(8090);
    expect(config.powerProviderRetryAttempts).toBe(5);
    expect(config.powerProviderRetryBaseDelayMs).toBe(1_000);
    expect(config.powerProviderRetryMaxDelayMs).toBe(30_000);
  });

  it("rejects a provider retry ceiling below its initial delay", () => {
    expect(() => loadRunnerConfig({
      CTFMESH_INTERNAL_RUNNER_TOKEN: TEST_TOKEN,
      CTFMESH_PI_POWER_PROVIDER_RETRY_BASE_MS: "5000",
      CTFMESH_PI_POWER_PROVIDER_RETRY_MAX_DELAY_MS: "1000",
    })).toThrowError(ControlProtocolError);
    try {
      loadRunnerConfig({
        CTFMESH_INTERNAL_RUNNER_TOKEN: TEST_TOKEN,
        CTFMESH_PI_POWER_PROVIDER_RETRY_BASE_MS: "5000",
        CTFMESH_PI_POWER_PROVIDER_RETRY_MAX_DELAY_MS: "1000",
      });
    } catch (error) {
      expect(error).toMatchObject({ code: "power_provider_retry_max_delay_ms_invalid" });
    }
  });
});

describe("an endpoint belongs to the provider that has none", () => {
  const base = {
    runId: "run-lease-custom",
    sessionId: "session-lease-custom",
    model: "qwen2.5-coder",
    apiKey: "k".repeat(20),
    ttlSeconds: 60,
  };

  it("refuses a URL beside a provider Pi already has an endpoint for", () => {
    // This is where the session key is sent, so a URL here would quietly
    // redirect that provider's credential somewhere else.
    const store = new CredentialLeaseStore(900);
    expect(() =>
      store.put({ ...base, provider: "anthropic", baseUrl: "http://192.168.1.50:11434" } as never),
    ).toThrow(/credential_lease_base_url_forbidden/);
  });

  it("requires a usable one from the provider that has nowhere else to go", () => {
    const store = new CredentialLeaseStore(900);
    expect(() => store.put({ ...base, provider: "ctfmesh-custom" } as never)).toThrow(
      /credential_lease_base_url_invalid/,
    );
    for (const baseUrl of [
      "ftp://gateway.example.test",
      "http://user:secret@gateway.example.test",
      "https://gateway.example.test/v1?key=leak",
      "not-a-url",
    ]) {
      expect(() =>
        store.put({ ...base, provider: "ctfmesh-custom", baseUrl } as never),
      ).toThrow(/credential_lease_base_url_invalid/);
    }
    expect(
      store.put({
        ...base,
        provider: "ctfmesh-custom",
        baseUrl: "http://192.168.1.50:11434/v1",
      } as never).accepted,
    ).toBe(true);
  });
});
