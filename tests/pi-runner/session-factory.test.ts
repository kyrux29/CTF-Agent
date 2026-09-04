import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  configureLeaseBackedModel,
  ensureDurableSessionFile,
} from "../../services/pi-runner/src/session-factory.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => rm(root, { recursive: true, force: true })),
  );
});

describe("continuing a finished run", () => {
  it("seeds a new transcript from the one its predecessor ended on", async () => {
    // A finished run kept its transcripts and nothing could adopt them, so
    // every continuation started from reconnaissance again. The store key
    // stays unique per session — two live sessions must never write one
    // transcript — so the successor copies rather than shares.
    const root = await mkdtemp(join(tmpdir(), "ctfmesh-resume-"));
    roots.push(root);
    const source = join(root, "power-pi-old.jsonl");
    const target = join(root, "power-pi-new.jsonl");
    await writeFile(source, '{"type":"header"}\n{"role":"assistant"}\n', "utf8");

    await ensureDurableSessionFile(target, source);

    expect(await readFile(target, "utf8")).toBe('{"type":"header"}\n{"role":"assistant"}\n');
    expect(await readFile(source, "utf8")).toBe('{"type":"header"}\n{"role":"assistant"}\n');
  });

  it("never overwrites a transcript this run has already grown", async () => {
    const root = await mkdtemp(join(tmpdir(), "ctfmesh-resume-"));
    roots.push(root);
    const source = join(root, "power-pi-old.jsonl");
    const target = join(root, "power-pi-new.jsonl");
    await writeFile(source, "seed\n", "utf8");
    await writeFile(target, "already grown\n", "utf8");

    await ensureDurableSessionFile(target, source);

    expect(await readFile(target, "utf8")).toBe("already grown\n");
  });

  it("starts a racer fresh when the source transcript is gone", async () => {
    // The runner volume can be reset between runs. A racer starting empty is
    // better than a run that cannot start at all.
    const root = await mkdtemp(join(tmpdir(), "ctfmesh-resume-"));
    roots.push(root);
    const target = join(root, "power-pi-new.jsonl");

    await ensureDurableSessionFile(target, join(root, "power-pi-missing.jsonl"));

    expect(await readFile(target, "utf8")).toBe("");
  });
});

describe("pointing a session at an operator's own model server", () => {
  const lease = (overrides: Record<string, unknown> = {}) => ({
    runId: "run-custom-1",
    sessionId: "session-custom-1",
    provider: "ctfmesh-custom" as const,
    model: "qwen2.5-coder",
    apiKey: "k".repeat(20),
    baseUrl: "http://192.168.1.50:11434/v1",
    expiresAtMs: Date.now() + 60_000,
    revision: 1,
    ...overrides,
  });

  it("declares the endpoint Pi's catalog cannot know", async () => {
    // A local server has no public model index, so the model is declared
    // rather than refreshed; without this the provider resolves to nothing.
    const registered: Array<[string, Record<string, unknown>]> = [];
    const runtime = {
      registerProvider(id: string, config: Record<string, unknown>) {
        registered.push([id, config]);
      },
      async setRuntimeApiKey() {},
      async removeRuntimeApiKey() {},
      getModel: (provider: string, model: string) =>
        provider === "ctfmesh-custom" && model === "qwen2.5-coder"
          ? ({ id: model } as never)
          : undefined,
    };

    const model = await configureLeaseBackedModel(runtime as never, lease() as never);

    expect(model).toEqual({ id: "qwen2.5-coder" });
    expect(registered).toHaveLength(1);
    const [id, config] = registered[0]!;
    expect(id).toBe("ctfmesh-custom");
    expect(config.baseUrl).toBe("http://192.168.1.50:11434/v1");
    expect(config.api).toBe("openai-completions");
  });

  it("never registers a provider whose endpoint Pi already knows", async () => {
    // Registering over a built-in would redirect that provider's key to an
    // endpoint the operator chose for something else.
    const registered: string[] = [];
    const runtime = {
      registerProvider(id: string) {
        registered.push(id);
      },
      async setRuntimeApiKey() {},
      async removeRuntimeApiKey() {},
      getModel: () => ({ id: "claude" }) as never,
    };

    await configureLeaseBackedModel(
      runtime as never,
      lease({ provider: "anthropic", baseUrl: undefined }) as never,
    );

    expect(registered).toEqual([]);
  });
});
