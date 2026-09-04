import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { ControlClient } from "../../services/pi-runner/src/control-client.js";
import type { RunnerConfig } from "../../services/pi-runner/src/config.js";
import type {
  AgentJob,
  AgentSession,
  AgentSteer,
  ContextManifest,
  PowerPiSession,
  PowerSessionWork,
  StartSessionWork,
  SteerWork,
  TurnWork,
  WorkerTask,
} from "../../services/pi-runner/src/contracts.js";
import { ControlProtocolError } from "../../services/pi-runner/src/contracts.js";
import {
  PiRunnerConsumer,
  powerModelTurnFailureCode,
  powerProviderRetryDelayMs,
  RETRYABLE_POWER_MODEL_FAILURES,
} from "../../services/pi-runner/src/task-consumer.js";
import { runRunnerLoop } from "../../services/pi-runner/src/runner.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => rm(root, { recursive: true, force: true })));
});

function timestamps(): Pick<AgentJob, "created_at" | "updated_at"> {
  return { created_at: "2026-08-29T00:00:00Z", updated_at: "2026-08-29T00:00:00Z" };
}

function job(kind: AgentJob["kind"], id: string): AgentJob {
  const payloadRef = kind === "start_session"
    ? "context:ctx-consumer-1"
    : kind === "steer"
      ? "steer:steer-consumer-1"
      : "session:session-consumer-1";
  return {
    id,
    run_id: "run-consumer-1",
    kind,
    payload_ref: payloadRef,
    payload_digest: "a".repeat(64),
    state: "leased",
    lease_owner: "pi-consumer-test",
    lease_version: 1,
    lease_expires_at: "2026-08-29T01:00:00Z",
    attempts: 1,
    deadline_at: "2026-08-29T01:00:00Z",
    ...timestamps(),
  };
}

const context: ContextManifest = {
  schema: "ctfmesh.context-manifest",
  schema_version: 1,
  id: "ctx-consumer-1",
  run_id: "run-consumer-1",
  task_id: "task-consumer-1",
  challenge_digest: "a".repeat(64),
  role: "master",
  objective: "Delegate one sealed evidence-backed task.",
  allowed_tool_ids: ["state.get", "task.delegate", "branch.suspend", "verify.request", "run.stop"],
  evidence_refs: [{ observation_id: "obs-consumer-1", artifact_id: "artifact-consumer-1", digest: "b".repeat(64) }],
  hypothesis_refs: [],
  active_hint_refs: [],
  attempt_fingerprints: [],
  budget_slice: { tool_calls: 1, input_tokens: 100, output_tokens: 100 },
  created_at: "2026-08-29T00:00:00Z",
  expires_at: "2026-08-29T01:00:00Z",
  digest: "c".repeat(64),
};

const task: WorkerTask = {
  id: "task-consumer-1",
  run_id: "run-consumer-1",
  branch_id: "branch-consumer-1",
  role: "master",
  objective: "Delegate one sealed evidence-backed task.",
  required_evidence: ["obs-consumer-1"],
  context_manifest_id: "ctx-consumer-1",
  state: "leased",
  lease_owner: "pi-consumer-test",
  lease_version: 1,
  lease_expires_at: "2026-08-29T01:00:00Z",
  attempts: 1,
  deadline_at: "2026-08-29T01:00:00Z",
  ...timestamps(),
};

const session: AgentSession = {
  id: "session-consumer-1",
  run_id: "run-consumer-1",
  start_job_id: "job-start-consumer-1",
  task_id: "task-consumer-1",
  context_manifest_id: "ctx-consumer-1",
  role: "master",
  state: "starting",
  session_store_key: "pi_session-consumer-1",
  runner_id: "pi-consumer-test",
  ...timestamps(),
};

const powerSession: PowerPiSession = {
  id: "power-session-consumer-1",
  run_id: "run-consumer-1",
  start_job_id: "job-power-start-consumer-1",
  label: "A",
  role: "racer",
  provider: "openai",
  model: "gpt-5.6-sol",
  temperature: 0.2,
  archive_digest: "a".repeat(64),
  brief: "Use only CTFMesh custom tools for the authorized fixture.",
  target_host: null,
  target_port: null,
  workspace_id: `ws_${"a".repeat(32)}`,
  state: "running",
  runner_id: "pi-consumer-test",
  session_store_key: "power-pi-session-consumer-1",
  resumed_from_store_key: null,
  ...timestamps(),
};

async function fixtureConfig(): Promise<RunnerConfig> {
  const root = await mkdtemp(join(tmpdir(), "ctfmesh-pi-consumer-"));
  roots.push(root);
  const trustedCwd = join(root, "empty-cwd");
  const trustedAgentDir = join(root, "agent");
  const reviewedSkillPackRoot = join(root, "skills");
  const sessionRoot = join(root, "sessions");
  await Promise.all([
    mkdir(trustedCwd),
    mkdir(trustedAgentDir),
    mkdir(reviewedSkillPackRoot),
    mkdir(sessionRoot),
  ]);
  await writeFile(
    join(reviewedSkillPackRoot, "manifest.json"),
    JSON.stringify({ schema: "ctfmesh.pi-skill-library/v1", version: 1, packs: [] }),
  );
  return {
    runnerId: "pi-consumer-test",
    controlBaseUrl: "http://api:8000",
    controlToken: "fixture-runner-token-1234",
    trustedCwd,
    trustedAgentDir,
    reviewedSkillPackRoot,
    sessionRoot,
    mode: "fixture",
    pollIntervalMs: 100,
    requestTimeoutMs: 500,
    credentialBrokerBindHost: "127.0.0.1",
    credentialBrokerBindPort: 8090,
    credentialLeaseMaxTtlSeconds: 900,
    credentialLeaseWaitMs: 0,
    powerThinkingLevel: "medium" as const,
    powerRacerMaxSolveBatches: 200,
    powerProviderRetryAttempts: 2,
    powerProviderRetryBaseDelayMs: 1,
    powerProviderRetryMaxDelayMs: 1,
    modelProvider: null,
    modelId: null,
  };
}

describe("PiRunnerConsumer fixture flow", () => {
  it("never marks an SDK provider error as a ready Power session", () => {
    expect(powerModelTurnFailureCode([])).toBe("power_pi_model_turn_missing");
    expect(powerModelTurnFailureCode([
      { role: "user" },
      { role: "assistant", stopReason: "error" },
    ])).toBe("power_pi_model_turn_failed");
    expect(powerModelTurnFailureCode([
      { role: "assistant", stopReason: "aborted" },
    ])).toBe("power_pi_model_turn_aborted");
    expect(powerModelTurnFailureCode([
      { role: "assistant", stopReason: "stop" },
    ])).toBeNull();
    expect(powerModelTurnFailureCode([
      { role: "assistant", stopReason: "error", errorMessage: "Request failed with status 401" },
    ])).toBe("power_pi_provider_authentication_failed");
    expect(powerModelTurnFailureCode([
      { role: "assistant", stopReason: "error", errorMessage: "429 too many requests" },
    ])).toBe("power_pi_provider_rate_limited");
    expect(powerModelTurnFailureCode([
      {
        role: "assistant",
        stopReason: "error",
        errorMessage: "Invalid tools[0].function.name: string does not match expected pattern",
      },
    ])).toBe("power_pi_provider_tool_schema_rejected");
    expect(powerModelTurnFailureCode([
      { role: "assistant", stopReason: "error", errorMessage: "secret-upstream-detail" },
    ])).toBe("power_pi_model_turn_failed");
  });

  it("reconnects after a transient control-plane transport failure", async () => {
    const config = await fixtureConfig();
    const controller = new AbortController();
    const observedCodes: string[] = [];
    let attempts = 0;
    const fakeConsumer = {
      async beginOnce(): Promise<null> {
        attempts += 1;
        if (attempts === 1) {
          throw new ControlProtocolError("control_transport_failed");
        }
        controller.abort();
        return null;
      },
      disposeLocalSessions: vi.fn(async () => undefined),
    } as unknown as PiRunnerConsumer;

    await runRunnerLoop(config, controller.signal, fakeConsumer, (code) => observedCodes.push(code));

    expect(attempts).toBe(2);
    expect(observedCodes).toEqual(["control_transport_retry"]);
    expect(fakeConsumer.disposeLocalSessions).toHaveBeenCalledOnce();
  });

  it("reconnects after a typed transient control database failure", async () => {
    const config = await fixtureConfig();
    const controller = new AbortController();
    const observedCodes: string[] = [];
    let attempts = 0;
    const fakeConsumer = {
      async beginOnce(): Promise<null> {
        attempts += 1;
        if (attempts === 1) {
          throw new ControlProtocolError("control_database_unavailable");
        }
        controller.abort();
        return null;
      },
      disposeLocalSessions: vi.fn(async () => undefined),
    } as unknown as PiRunnerConsumer;

    await runRunnerLoop(config, controller.signal, fakeConsumer, (code) => observedCodes.push(code));

    expect(attempts).toBe(2);
    expect(observedCodes).toEqual(["control_transport_retry"]);
    expect(fakeConsumer.disposeLocalSessions).toHaveBeenCalledOnce();
  });

  it("still fails closed for a non-transient control protocol error", async () => {
    const config = await fixtureConfig();
    const fakeConsumer = {
      async beginOnce(): Promise<null> {
        throw new ControlProtocolError("control_response_contract_invalid");
      },
      disposeLocalSessions: vi.fn(async () => undefined),
    } as unknown as PiRunnerConsumer;

    await expect(runRunnerLoop(config, new AbortController().signal, fakeConsumer, vi.fn()))
      .rejects.toMatchObject({ code: "control_response_contract_invalid" });
    expect(fakeConsumer.disposeLocalSessions).toHaveBeenCalledOnce();
  });

  it("keeps three slots available for Power aborts while four model turns are active", async () => {
    const config = await fixtureConfig();
    const controller = new AbortController();
    const finishStarts: Array<() => void> = [];
    let abortsCompleted = 0;
    const claims: Array<{
      readonly kind: AgentJob["kind"];
      readonly completion: Promise<AgentJob["kind"]>;
    }> = Array.from({ length: 4 }, () => {
      let resolve: ((kind: AgentJob["kind"]) => void) | undefined;
      const completion = new Promise<AgentJob["kind"]>((complete) => {
        resolve = complete;
      });
      finishStarts.push(() => resolve?.("power_session_start"));
      return { kind: "power_session_start", completion };
    });
    claims.push(
      ...Array.from({ length: 3 }, () => ({
        kind: "power_abort" as const,
        completion: Promise.resolve("power_abort" as const).then((kind) => {
          abortsCompleted += 1;
          return kind;
        }),
      })),
    );
    const fakeConsumer = {
      async beginOnce(): Promise<{
        readonly kind: AgentJob["kind"];
        readonly completion: Promise<AgentJob["kind"]>;
      } | null> {
        return claims.shift() ?? null;
      },
      disposeLocalSessions: vi.fn(async () => undefined),
    } as unknown as PiRunnerConsumer;

    const loop = runRunnerLoop(config, controller.signal, fakeConsumer);
    await vi.waitFor(() => expect(abortsCompleted).toBe(3));
    controller.abort();
    for (const finish of finishStarts) {
      finish();
    }
    await loop;
    expect(fakeConsumer.disposeLocalSessions).toHaveBeenCalledOnce();
  });

  it("uses no provider key/model while preserving start and turn audit events", async () => {
    const config = await fixtureConfig();
    const startJob = job("start_session", "job-start-consumer-1");
    const turnJob = job("run_turn", "job-turn-consumer-1");
    const eventBatches: unknown[][] = [];
    const resultRefs: string[] = [];
    const claims = [startJob, turnJob, null];
    const fakeControl = {
      async claim(): Promise<AgentJob | null> {
        return claims.shift() ?? null;
      },
      async getStartSessionWork(): Promise<StartSessionWork> {
        return { job: startJob, task, context_manifest: context };
      },
      async reserveSession(): Promise<{ readonly session: AgentSession; readonly task: WorkerTask; readonly context_manifest: ContextManifest }> {
        return { session, task, context_manifest: context };
      },
      async appendEvents(_lease: unknown, events: unknown[]): Promise<void> {
        eventBatches.push(events);
      },
      async activateSession(): Promise<AgentSession> {
        return { ...session, state: "ready" };
      },
      async getTurnWork(): Promise<TurnWork> {
        return { job: turnJob, session: { ...session, state: "running" }, task, context_manifest: context };
      },
      async completeTurn(_lease: unknown, resultRef: string): Promise<AgentJob> {
        resultRefs.push(resultRef);
        return { ...turnJob, state: "completed" };
      },
      async fail(): Promise<AgentJob> {
        throw new Error("unexpected fixture failure");
      },
    } as unknown as ControlClient;
    const errors: string[] = [];
    const consumer = new PiRunnerConsumer(config, fakeControl, undefined, (code) => errors.push(code));
    try {
      expect(await consumer.consumeOnce()).toBe("start_session");
      expect(await consumer.consumeOnce()).toBe("run_turn");
      expect(await consumer.consumeOnce()).toBeNull();
      expect(errors).toEqual([]);
      expect(resultRefs).toEqual(["agent:inconclusive"]);
      const eventTypes = eventBatches.flatMap((batch) => (batch as Array<{ type: string }>).map((event) => event.type));
      expect(eventTypes).toEqual(expect.arrayContaining([
        "agent.session.started",
        "agent.session.ready",
        "agent.turn.started",
        "agent.turn.completed",
      ]));
      const sessionStarted = eventBatches
        .flatMap((batch) => batch as Array<Record<string, unknown>>)
        .find((event) => event.type === "agent.session.started");
      // M4 records a digest/version only; the reviewed prompt and local
      // skill-pack bodies never cross the control-plane event boundary.
      expect(sessionStarted).toMatchObject({
        prompt_contract_version: 1,
        prompt_contract_digest: expect.stringMatching(/^[a-f0-9]{64}$/),
      });
    } finally {
      await consumer.disposeLocalSessions();
    }
  });

  it("reopens a durable transcript before applying a safe-boundary steer after restart", async () => {
    const config = await fixtureConfig();
    const startJob = job("start_session", "job-start-restart-1");
    const steerJob = job("steer", "job-steer-restart-1");
    const durableReadySession = { ...session, state: "ready" as const };
    const steer: AgentSteer = {
      id: "steer-consumer-1",
      run_id: "run-consumer-1",
      session_id: durableReadySession.id,
      message: "Re-check the sealed evidence at the next safe turn.",
      message_digest: "d".repeat(64),
      state: "queued",
      created_at: "2026-08-29T00:01:00Z",
      applied_at: null,
    };
    const bootstrapControl = {
      async claim(): Promise<AgentJob | null> {
        return startJob;
      },
      async getStartSessionWork(): Promise<StartSessionWork> {
        return { job: startJob, task, context_manifest: context };
      },
      async reserveSession(): Promise<{
        readonly session: AgentSession;
        readonly task: WorkerTask;
        readonly context_manifest: ContextManifest;
      }> {
        return { session, task, context_manifest: context };
      },
      async appendEvents(): Promise<void> {},
      async activateSession(): Promise<AgentSession> {
        return durableReadySession;
      },
      async fail(): Promise<AgentJob> {
        throw new Error("unexpected fixture failure");
      },
    } as unknown as ControlClient;
    const firstConsumer = new PiRunnerConsumer(config, bootstrapControl, undefined, () => undefined);
    await firstConsumer.consumeOnce();
    await firstConsumer.disposeLocalSessions();

    let completed = false;
    const restartedControl = {
      async claim(): Promise<AgentJob | null> {
        return steerJob;
      },
      async getSteerWork(): Promise<SteerWork> {
        return {
          job: steerJob,
          session: durableReadySession,
          steer,
          context_manifest: context,
        };
      },
      async completeSteer(): Promise<AgentSteer> {
        completed = true;
        return { ...steer, state: "applied", applied_at: "2026-08-29T00:01:01Z" };
      },
      async fail(): Promise<AgentJob> {
        throw new Error("unexpected fixture failure");
      },
    } as unknown as ControlClient;
    const restartedConsumer = new PiRunnerConsumer(config, restartedControl, undefined, () => undefined);
    try {
      expect(await restartedConsumer.consumeOnce()).toBe("steer");
      expect(completed).toBe(true);
      const transcript = await readFile(join(config.sessionRoot, "pi_session-consumer-1.jsonl"), "utf8");
      expect(transcript).toContain("ctfmesh.operator-steer");
      expect(transcript).toContain(steer.message);
    } finally {
      await restartedConsumer.disposeLocalSessions();
    }
  });

  it("starts and aborts a no-key Power fixture session through separate durable jobs", async () => {
    const config = await fixtureConfig();
    const startJob = job("power_session_start", "job-power-start-consumer-1");
    const abortJob = job("power_abort", "job-power-abort-consumer-1");
    const claims = [startJob, abortJob, null];
    const completed: string[] = [];
    const fakeControl = {
      async claim(): Promise<AgentJob | null> {
        return claims.shift() ?? null;
      },
      async getPowerSessionWork(lease: { readonly jobId: string }): Promise<PowerSessionWork> {
        if (lease.jobId === startJob.id) {
          return { job: startJob, session: powerSession };
        }
        return { job: abortJob, session: { ...powerSession, state: "aborting" } };
      },
      async completePowerSessionStart(): Promise<AgentJob> {
        completed.push("start");
        return { ...startJob, state: "completed" };
      },
      async completePowerAbort(): Promise<AgentJob> {
        completed.push("abort");
        return { ...abortJob, state: "completed" };
      },
      async failPower(): Promise<AgentJob> {
        throw new Error("unexpected Power fixture failure");
      },
    } as unknown as ControlClient;
    const errors: string[] = [];
    const consumer = new PiRunnerConsumer(config, fakeControl, undefined, (code) => errors.push(code));
    try {
      expect(await consumer.consumeOnce()).toBe("power_session_start");
      expect(await consumer.consumeOnce()).toBe("power_abort");
      expect(await consumer.consumeOnce()).toBeNull();
      expect(completed).toEqual(["start", "abort"]);
      expect(errors).toEqual([]);
    } finally {
      await consumer.disposeLocalSessions();
    }
  });

  it("defers a leased Power job when the control database is transient", async () => {
    const config = await fixtureConfig();
    const startJob = job("power_session_start", "job-power-start-db-retry-1");
    const failPower = vi.fn(async (): Promise<AgentJob> => ({ ...startJob, state: "failed" }));
    const fakeControl = {
      async claim(): Promise<AgentJob | null> {
        return startJob;
      },
      async getPowerSessionWork(): Promise<PowerSessionWork> {
        throw new ControlProtocolError("control_database_unavailable");
      },
      failPower,
    } as unknown as ControlClient;
    const errors: string[] = [];
    const consumer = new PiRunnerConsumer(config, fakeControl, undefined, (code) => errors.push(code));
    try {
      expect(await consumer.consumeOnce()).toBe("power_session_start");
      expect(errors).toEqual(["control_job_retry_deferred"]);
      expect(failPower).not.toHaveBeenCalled();
    } finally {
      await consumer.disposeLocalSessions();
    }
  });

  it("defers a Power start when a restarted broker is waiting for browser renewal", async () => {
    const config = await fixtureConfig();
    const startJob = job("power_session_start", "job-power-start-credential-retry-1");
    const failPower = vi.fn(async (): Promise<AgentJob> => ({ ...startJob, state: "failed" }));
    const fakeControl = {
      async claim(): Promise<AgentJob | null> {
        return startJob;
      },
      async getPowerSessionWork(): Promise<PowerSessionWork> {
        return { job: startJob, session: powerSession };
      },
      failPower,
    } as unknown as ControlClient;
    const errors: string[] = [];
    const consumer = new PiRunnerConsumer(config, fakeControl, undefined, (code) => errors.push(code));
    const powerConsumer = consumer as unknown as {
      ensurePowerSession(work: PowerSessionWork): Promise<never>;
    };
    powerConsumer.ensurePowerSession = async (): Promise<never> => {
      throw new ControlProtocolError("pi_credential_lease_unavailable");
    };
    try {
      expect(await consumer.consumeOnce()).toBe("power_session_start");
      expect(errors).toEqual(["power_pi_credential_refresh_deferred"]);
      expect(failPower).not.toHaveBeenCalled();
    } finally {
      await consumer.disposeLocalSessions();
    }
  });
});

describe("transient provider faults", () => {
  it("keeps retry delay bounded and deterministic per racer session", async () => {
    const config = await fixtureConfig();
    const a = powerProviderRetryDelayMs("power-racer-a", 2, config);
    const b = powerProviderRetryDelayMs("power-racer-b", 2, config);

    expect(a).toBeGreaterThanOrEqual(1);
    expect(a).toBeLessThanOrEqual(config.powerProviderRetryMaxDelayMs);
    expect(b).toBeGreaterThanOrEqual(1);
    expect(b).toBeLessThanOrEqual(config.powerProviderRetryMaxDelayMs);
    expect(powerProviderRetryDelayMs("power-racer-a", 2, config)).toBe(a);
  });

  it("retries only the faults that asking again can clear", () => {
    // A transport blip or a rate limit is a property of the network and the
    // provider's queue, not of this racer's work. Failing the session for one
    // lost packet discarded its whole transcript, ended the run through
    // `all_power_racers_failed`, and left the operator unable even to steer —
    // which is exactly how one observed local run died.
    for (const code of [
      "power_pi_provider_transport_failed",
      "power_pi_provider_unavailable",
      "power_pi_provider_rate_limited",
      "power_pi_model_turn_failed",
      "power_pi_model_turn_missing",
    ]) {
      expect(RETRYABLE_POWER_MODEL_FAILURES.has(code)).toBe(true);
    }
  });

  it("never retries a fault that would repeat the same rejection", () => {
    // Deny path: retrying these only burns budget, and an abort is something
    // the control plane deliberately asked for.
    for (const code of [
      "power_pi_provider_authentication_failed",
      "power_pi_provider_quota_exhausted",
      "power_pi_provider_model_unavailable",
      "power_pi_provider_tool_schema_rejected",
      "power_pi_model_turn_aborted",
    ]) {
      expect(RETRYABLE_POWER_MODEL_FAILURES.has(code)).toBe(false);
    }
  });

  it("classifies a network fault as retryable end to end", () => {
    const failure = powerModelTurnFailureCode([
      { role: "assistant", stopReason: "error", errorMessage: "fetch failed: ECONNRESET" },
    ]);

    expect(failure).toBe("power_pi_provider_transport_failed");
    expect(RETRYABLE_POWER_MODEL_FAILURES.has(failure ?? "")).toBe(true);
  });

  it("retries a direct SDK transport rejection before releasing the durable job", async () => {
    const config = await fixtureConfig();
    const consumer = new PiRunnerConsumer(config);
    const prompt = vi.fn(async (): Promise<void> => {
      throw new Error("fetch failed: ECONNRESET");
    });
    const handle = {
      durable: powerSession,
      session: {
        prompt,
        waitForIdle: vi.fn(async (): Promise<void> => undefined),
        messages: [],
      },
      toolBatch: { candidateReviewRequired: false, exhausted: false },
      activity: { flush: vi.fn(async (): Promise<void> => undefined) },
      usage: { pending: vi.fn(() => null) },
    };
    const promptWithProviderRetry = consumer as unknown as {
      promptWithProviderRetry(
        lease: { readonly jobId: string; readonly leaseVersion: number },
        input: typeof handle,
        text: string,
      ): Promise<void>;
    };

    await expect(promptWithProviderRetry.promptWithProviderRetry(
      { jobId: "job-power-retry-1", leaseVersion: 1 },
      handle,
      "continue from evidence",
    )).rejects.toMatchObject({ code: "power_pi_provider_retry_deferred" });
    expect(prompt).toHaveBeenCalledTimes(config.powerProviderRetryAttempts);
    expect(handle.session.waitForIdle).not.toHaveBeenCalled();
  });

  it("ends a racer quietly when the control plane has already settled the run", async () => {
    // Reporting is fenced the moment a run settles, so the flush after a turn
    // is refused. A racer that reached its cap - or found the flag the whole
    // race exists to find - was recorded as a failed session because of it.
    const config = await fixtureConfig();

    for (const code of [
      "power_pi_budget_exhausted",
      "control_power_candidate_review_required",
    ]) {
      const logged: string[] = [];
      const consumer = new PiRunnerConsumer(config, undefined, undefined, (entry) =>
        logged.push(entry),
      );
      const handle = {
        durable: powerSession,
        session: {
          prompt: vi.fn(async (): Promise<void> => undefined),
          waitForIdle: vi.fn(async (): Promise<void> => undefined),
          messages: [],
        },
        toolBatch: { candidateReviewRequired: false, exhausted: false },
        activity: { flush: vi.fn(async (): Promise<void> => undefined) },
        usage: {
          pending: vi.fn(() => ({ inputTokens: 1, outputTokens: 1, costUsd: 0.001 })),
          settle: vi.fn(),
        },
      };
      const runner = consumer as unknown as {
        promptWithProviderRetry(
          lease: { readonly jobId: string; readonly leaseVersion: number },
          input: typeof handle,
          text: string,
        ): Promise<void>;
        flushPowerUsage(lease: unknown, input: typeof handle): Promise<void>;
      };
      runner.flushPowerUsage = async () => {
        throw new ControlProtocolError(code);
      };

      await expect(
        runner.promptWithProviderRetry({ jobId: "job-quiet-1", leaseVersion: 1 }, handle, "go"),
      ).resolves.toBeUndefined();
      expect(logged).toContain(code);
    }
  });

  it("keeps a racer's lease alive across a blip, and lets go when it is really gone", async () => {
    // A single failed renewal used to stop the heartbeat for good. The racer
    // kept working, its lease quietly expired, its job was reclaimed, and
    // every observation made after the blip was thrown away as a failure.
    const config = await fixtureConfig();
    vi.useFakeTimers();
    try {
      const outcomes: unknown[] = [
        new Error("socket hang up"),
        undefined,
        new ControlProtocolError("control_power_pi_job_lease_lost"),
      ];
      const renewPowerSessionStartLease = vi.fn(async (): Promise<void> => {
        const next = outcomes.shift();
        if (next !== undefined) throw next;
      });
      const abort = vi.fn(async (): Promise<void> => undefined);
      const consumer = new PiRunnerConsumer(config, {
        renewPowerSessionStartLease,
      } as never);
      const heartbeat = consumer as unknown as {
        startPowerLeaseHeartbeat(
          lease: { readonly jobId: string; readonly leaseVersion: number },
          handle: { session: { abort: typeof abort } },
        ): () => Promise<void>;
      };

      const stop = heartbeat.startPowerLeaseHeartbeat(
        { jobId: "job-lease-1", leaseVersion: 1 },
        { session: { abort } } as never,
      );

      // Blip, then a healthy renewal: the heartbeat is still beating.
      await vi.advanceTimersByTimeAsync(10_000);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(renewPowerSessionStartLease).toHaveBeenCalledTimes(2);
      expect(abort).not.toHaveBeenCalled();

      // The control plane says the lease is gone; that ends it, on evidence.
      await vi.advanceTimersByTimeAsync(10_000);
      expect(abort).toHaveBeenCalledOnce();
      await expect(stop()).rejects.toMatchObject({
        code: "control_power_pi_job_lease_lost",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not terminalize a Power racer after a retry burst", async () => {
    const config = await fixtureConfig();
    const startJob = job("power_session_start", "job-power-start-provider-retry-1");
    const failPower = vi.fn(async (): Promise<AgentJob> => ({ ...startJob, state: "failed" }));
    const fakeControl = {
      async claim(): Promise<AgentJob | null> {
        return startJob;
      },
      failPower,
    } as unknown as ControlClient;
    const errors: string[] = [];
    const consumer = new PiRunnerConsumer(config, fakeControl, undefined, (code) => errors.push(code));
    const powerConsumer = consumer as unknown as {
      startPowerSession(lease: { readonly jobId: string; readonly leaseVersion: number }): Promise<never>;
    };
    powerConsumer.startPowerSession = async (): Promise<never> => {
      throw new ControlProtocolError("power_pi_provider_retry_deferred");
    };

    try {
      expect(await consumer.consumeOnce()).toBe("power_session_start");
      expect(errors).toEqual(["power_pi_provider_retry_deferred"]);
      expect(failPower).not.toHaveBeenCalled();
    } finally {
      await consumer.disposeLocalSessions();
    }
  });

  it("keeps a direct provider authentication rejection terminal", async () => {
    const config = await fixtureConfig();
    const consumer = new PiRunnerConsumer(config);
    const prompt = vi.fn(async (): Promise<void> => {
      throw new Error("401 Unauthorized");
    });
    const handle = {
      durable: powerSession,
      session: {
        prompt,
        waitForIdle: vi.fn(async (): Promise<void> => undefined),
        messages: [],
      },
      toolBatch: { candidateReviewRequired: false, exhausted: false },
      activity: { flush: vi.fn(async (): Promise<void> => undefined) },
      usage: { pending: vi.fn(() => null) },
    };
    const promptWithProviderRetry = consumer as unknown as {
      promptWithProviderRetry(
        lease: { readonly jobId: string; readonly leaseVersion: number },
        input: typeof handle,
        text: string,
      ): Promise<void>;
    };

    await expect(promptWithProviderRetry.promptWithProviderRetry(
      { jobId: "job-power-auth-1", leaseVersion: 1 },
      handle,
      "continue from evidence",
    )).rejects.toMatchObject({ code: "power_pi_provider_authentication_failed" });
    expect(prompt).toHaveBeenCalledOnce();
  });

  it("classifies a bad credential as terminal end to end", () => {
    const failure = powerModelTurnFailureCode([
      { role: "assistant", stopReason: "error", errorMessage: "401 Unauthorized" },
    ]);

    expect(failure).toBe("power_pi_provider_authentication_failed");
    expect(RETRYABLE_POWER_MODEL_FAILURES.has(failure ?? "")).toBe(false);
  });
});

describe("reaching a configured cap", () => {
  it("reports budget exhaustion as itself, not as a generic start failure", async () => {
    // Observed live: a ten-minute wall-time cap fired exactly as configured,
    // and the runner surfaced it as `power_pi_session_start_failed` because
    // `power_pi_budget_exhausted` matched neither passthrough prefix. A
    // correct stop read as a crash to anyone looking at the run.
    const consumer = new PiRunnerConsumer(await fixtureConfig());
    const code = (consumer as unknown as {
      failureCode(kind: string, error: unknown): string;
    }).failureCode(
      "power_session_start",
      new ControlProtocolError("power_pi_budget_exhausted"),
    );

    expect(code).toBe("power_pi_budget_exhausted");
  });

  it("still reports an unrelated control fault as the job-kind failure", async () => {
    const consumer = new PiRunnerConsumer(await fixtureConfig());
    const code = (consumer as unknown as {
      failureCode(kind: string, error: unknown): string;
    }).failureCode(
      "power_session_start",
      new ControlProtocolError("power_usage_receipt_invalid"),
    );

    expect(code).toBe("power_pi_session_start_failed");
  });
});
