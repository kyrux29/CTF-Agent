import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createAgentSession, SessionManager } from "@earendil-works/pi-coding-agent";
import {
  fauxAssistantMessage,
  fauxToolCall,
  registerFauxProvider,
  streamSimple,
} from "@earendil-works/pi-ai/compat";
import { afterEach, describe, expect, it } from "vitest";

import { PowerUsageReporter } from "../../services/pi-runner/src/power-usage.js";
import {
  configurePowerCompaction,
  createReviewedResources,
  POWER_COMPACTION_SETTINGS,
} from "../../services/pi-runner/src/resource-loader.js";
import { createPowerTools, powerToolNames, type PowerToolControl } from "../../services/pi-runner/src/power-tools.js";
import { TurnAuthority } from "../../services/pi-runner/src/tools.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => rm(root, { recursive: true, force: true })));
});

const fixtureWorkspaceId = `ws_${"a".repeat(32)}`;
const fixtureArtifactId = `sha256:${"b".repeat(64)}`;
const fixtureArtifactSha256 = "b".repeat(64);

async function createFixtureSession(withPowerTool = false) {
  const root = await mkdtemp(join(tmpdir(), "ctfmesh-power-pi-compact-"));
  roots.push(root);
  const cwd = join(root, "empty-cwd");
  const agentDir = join(root, "agent");
  await Promise.all([mkdir(cwd), mkdir(agentDir)]);
  const resources = await createReviewedResources(cwd, agentDir, "Power fixture system prompt.");
  configurePowerCompaction(resources.settings);
  const faux = registerFauxProvider();
  const authority = new TurnAuthority();
  // The fake control seam exercises a normal Pi custom-tool result. It never
  // starts a process, contacts a service, or stores the long fixture in the
  // API/event ledger.
  const control = {
    async exec() {
      return {
        artifact: {
          id: fixtureArtifactId,
          sha256: fixtureArtifactSha256,
          sizeBytes: 64 * 1024,
        },
        stdout: `TOOL_HEAD:${"z".repeat(64 * 1024 - 24)}:TOOL_TAIL`,
        stderr: "",
        exitCode: 0,
        timedOut: false,
        outputTruncated: false,
      };
    },
  } as unknown as PowerToolControl;
  const customTools = withPowerTool
    ? createPowerTools({
      role: "racer",
      runId: "run-power-compaction-fixture",
      sessionId: "session-power-compaction-fixture",
      workspaceId: fixtureWorkspaceId,
      authority,
      control,
    })
    : [];
  const { session } = await createAgentSession({
    cwd,
    agentDir,
    model: faux.getModel(),
    // A Pi faux transport gives this fixture a real AgentSession and
    // compaction path without a network request or an actual provider key.
    modelRuntime: {
      hasConfiguredAuth() {
        return true;
      },
      async getAuth() {
        return { auth: { apiKey: "fixture-pi-key" } };
      },
    } as never,
    noTools: "all",
    tools: withPowerTool ? [...powerToolNames("racer")] : [],
    customTools,
    resourceLoader: resources.loader,
    settingsManager: resources.settings,
    sessionManager: SessionManager.inMemory(),
    thinkingLevel: "off",
  });
  session.agent.streamFunction = streamSimple;
  return { authority, faux, resources, session };
}

describe("Power Pi compaction and usage", () => {
  it("uses the reviewed in-memory context window settings", async () => {
    const { faux, resources, session } = await createFixtureSession();
    try {
      // Overrides are intentionally session-effective rather than persisted
      // into the in-memory global settings document.
      expect(resources.settings.getCompactionSettings()).toEqual(POWER_COMPACTION_SETTINGS);
      expect(session.autoCompactionEnabled).toBe(true);
    } finally {
      session.dispose();
      faux.unregister();
    }
  });

  it("compacts long fake tool results and continues with a new prompt", async () => {
    const { authority, faux, session } = await createFixtureSession(true);
    const events: string[] = [];
    const reporter = new PowerUsageReporter(session);
    const unsubscribe = session.subscribe((event) => {
      events.push(event.type);
      reporter.capture(event);
    });
    try {
      faux.setResponses([
        fauxAssistantMessage(
          fauxToolCall("ctf_fs_read", { path: "/challenge/fixture-0.txt", max_bytes: 65_536 }),
          { stopReason: "toolUse" },
        ),
        fauxAssistantMessage("first observed result"),
        fauxAssistantMessage(
          fauxToolCall("ctf_fs_read", { path: "/challenge/fixture-1.txt", max_bytes: 65_536 }),
          { stopReason: "toolUse" },
        ),
        fauxAssistantMessage("second observed result"),
        fauxAssistantMessage(
          fauxToolCall("ctf_fs_read", { path: "/challenge/fixture-2.txt", max_bytes: 65_536 }),
          { stopReason: "toolUse" },
        ),
        fauxAssistantMessage("third observed result"),
        fauxAssistantMessage("summary preserves the investigated evidence"),
        fauxAssistantMessage("continued from the compacted evidence"),
      ]);
      const longEvidence = `offline fixture evidence ${"x".repeat(36_000)}`;
      authority.open({
        jobId: "job-power-compaction-fixture",
        leaseVersion: 1,
        sessionId: "session-power-compaction-fixture",
      });
      for (let index = 0; index < 3; index += 1) {
        await session.prompt(`${longEvidence}\nturn=${index}`, { expandPromptTemplates: false });
        await session.waitForIdle();
      }

      const compacted = await session.compact();
      expect(compacted.tokensBefore).toBeGreaterThan(6_000);
      expect(compacted.summary).toContain("summary preserves");
      expect(events).toContain("compaction_end");
      expect(reporter.pending()).toMatchObject({ compacted: 1 });

      reporter.acknowledge();
      await session.prompt("Continue the same offline investigation.", { expandPromptTemplates: false });
      await session.waitForIdle();
      const resumedContextTokens = session.getContextUsage()?.tokens;
      // Pi reports the newly built context only after the next model turn.
      // This gives the fixture an observable before/after regression guard
      // while retaining the normal turn-boundary safety of compaction.
      expect(resumedContextTokens).not.toBeNull();
      expect(resumedContextTokens).toBeLessThan(compacted.tokensBefore);
      expect(session.messages.at(-1)).toMatchObject({ role: "assistant", stopReason: "stop" });
    } finally {
      authority.close();
      unsubscribe();
      session.dispose();
      faux.unregister();
    }
  });

  it("records a failed compaction as non-solving local state", async () => {
    const { faux, session } = await createFixtureSession();
    let compactionFailed = false;
    let flagSubmissionCalls = 0;
    const unsubscribe = session.subscribe((event) => {
      if (event.type === "compaction_end" && event.result === undefined && !event.aborted) {
        compactionFailed = true;
      }
    });
    try {
      faux.setResponses([
        fauxAssistantMessage("observed result"),
        fauxAssistantMessage("compaction unavailable", { stopReason: "error" }),
      ]);
      await session.prompt(`offline fixture evidence ${"y".repeat(30_000)}`, {
        expandPromptTemplates: false,
      });
      await session.waitForIdle();

      await expect(session.compact()).rejects.toThrow();
      expect(compactionFailed).toBe(true);
      // No Power flag tool exists in this fixture and compaction has no route
      // to the flag-router; a failed summary can therefore never solve a run.
      expect(flagSubmissionCalls).toBe(0);
    } finally {
      unsubscribe();
      session.dispose();
      faux.unregister();
    }
  });
});
