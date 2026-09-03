import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { ensureDurableSessionFile } from "../../services/pi-runner/src/session-factory.js";

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
