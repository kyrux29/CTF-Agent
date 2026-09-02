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

import { ControlProtocolError } from "../../services/pi-runner/src/contracts.js";

import {
  createPowerTools,
  PowerToolBatchLimiter,
  powerToolNames,
  POWER_TOOL_CONTEXT_MAX_CHARS,
  type PowerToolControl,
  type PowerToolObservation,
} from "../../services/pi-runner/src/power-tools.js";
import { createReviewedResources } from "../../services/pi-runner/src/resource-loader.js";
import { TurnAuthority } from "../../services/pi-runner/src/tools.js";

const roots: string[] = [];
const workspaceId = `ws_${"a".repeat(32)}`;
const artifactId = `sha256:${"b".repeat(64)}`;
const artifactSha = "b".repeat(64);

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => rm(root, { recursive: true, force: true })));
});

function observation(overrides: Partial<PowerToolObservation> = {}): PowerToolObservation {
  return {
    artifact: { id: artifactId, sha256: artifactSha, sizeBytes: 128 },
    stdout: "fixture observation",
    stderr: "",
    exitCode: 0,
    timedOut: false,
    outputTruncated: false,
    ...overrides,
  };
}

function scope(control: PowerToolControl, role: "autoprompter" | "racer" = "racer") {
  const authority = new TurnAuthority();
  authority.open({ jobId: "job-power-tools-1", leaseVersion: 1, sessionId: "session-power-tools-1" });
  return {
    role,
    runId: "run-power-tools-1",
    sessionId: "session-power-tools-1",
    workspaceId,
    authority,
    control,
  } as const;
}

function tool(name: string, control: PowerToolControl, role: "autoprompter" | "racer" = "racer") {
  const selected = createPowerTools(scope(control, role)).find((candidate) => candidate.name === name);
  if (selected === undefined) {
    throw new Error(`Power tool missing: ${name}`);
  }
  return selected;
}

/** Extract the runner-issued handle without assuming an SDK result generic. */
function observationHandle(result: { readonly details: unknown }): string {
  const details = result.details;
  if (details === null || typeof details !== "object" || Array.isArray(details)) {
    throw new Error("expected Power observation details");
  }
  const handle = (details as Record<string, unknown>).observation_handle;
  if (typeof handle !== "string") {
    throw new Error("expected Power observation handle");
  }
  return handle;
}

describe("Pi Power tool adapter", () => {
  it("requests an operator review when control observes a configured-format candidate", async () => {
    const calls: Array<{ readonly method: string; readonly request?: Record<string, unknown> }> = [];
    const transcripts: Array<{ tool: string; command: string; output: string }> = [];
    const candidate = "KCSC{captured_from_local_binary}";
    const limiter = new PowerToolBatchLimiter(10);
    const steers: string[] = [];
    limiter.bindSteer((reason) => steers.push(reason));
    const control = {
      async exec() {
        calls.push({ method: "exec" });
        return observation({
          stdout: `correct!\n${candidate}`,
          candidateReviewRequired: true,
          candidateCount: 1,
        });
      },
      async submitFlag(_lease: unknown, request: Record<string, unknown>) {
        calls.push({ method: "submitFlag", request });
        return { accepted: true };
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({
      ...scope(control),
      toolBatch: limiter,
      async onToolTranscript(_lease, transcript) {
        transcripts.push(transcript);
      },
    });
    const shell = tools.find((item) => item.name === "ctf_shell_exec");
    if (shell === undefined) {
      throw new Error("expected shell tool");
    }

    await shell.execute("call-capture-one", { command: ["/challenge/crackme"] }, undefined, undefined, undefined as never);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toEqual([{ method: "exec" }]);
    expect(limiter.candidateReviewRequired).toBe(true);
    expect(limiter.exhausted).toBe(true);
    expect(steers).toEqual(["candidate_review"]);
    expect(transcripts.some((item) => item.tool === "ctf_flag_submit")).toBe(false);
  });

  it("stops a sibling batch when the durable candidate gate fences its next tool", async () => {
    const limiter = new PowerToolBatchLimiter(10);
    const steers: string[] = [];
    limiter.bindSteer((reason) => steers.push(reason));
    const control = {
      async exec() {
        throw new ControlProtocolError("control_power_candidate_review_required");
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({ ...scope(control), toolBatch: limiter });
    const list = tools.find((item) => item.name === "ctf_fs_list");
    if (list === undefined) {
      throw new Error("expected list tool");
    }

    const result = await list.execute(
      "call-sibling-candidate-gate",
      { path: "/challenge" },
      undefined,
      undefined,
      undefined as never,
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(result.details).toEqual({ accepted: false, code: "power_candidate_review_required" });
    expect(limiter.candidateReviewRequired).toBe(true);
    expect(limiter.exhausted).toBe(true);
    expect(steers).toEqual(["candidate_review"]);
  });

  it("registers only custom Power tools and never gives AutoPrompter flag submission", () => {
    const control = {} as PowerToolControl;
    const racerNames = createPowerTools(scope(control)).map((candidate) => candidate.name);
    const autoprompterNames = createPowerTools(scope(control, "autoprompter")).map((candidate) => candidate.name);

    expect(racerNames).toEqual(powerToolNames("racer"));
    expect(autoprompterNames).toEqual(powerToolNames("autoprompter"));
    expect(racerNames).toContain("ctf_flag_submit");
    expect(autoprompterNames).not.toContain("ctf_flag_submit");
    expect(autoprompterNames).toEqual(["ctf_fs_list", "ctf_fs_read", "ctf_shell_exec"]);
    expect(racerNames.every((name) => /^[A-Za-z0-9_-]+$/.test(name))).toBe(true);
    expect(racerNames).not.toEqual(expect.arrayContaining(["bash", "read", "edit", "write"]));
  });

  it("caps a tool batch and holds a model-selected candidate for operator review", async () => {
    const limiter = new PowerToolBatchLimiter(1);
    let steers = 0;
    limiter.bindSteer(() => { steers += 1; });
    const calls: string[] = [];
    const control = {
      async exec() {
        calls.push("exec");
        return observation();
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({ ...scope(control), toolBatch: limiter });
    const read = tools.find((candidate) => candidate.name === "ctf_fs_read");
    const list = tools.find((candidate) => candidate.name === "ctf_fs_list");
    const submit = tools.find((candidate) => candidate.name === "ctf_flag_submit");
    if (read === undefined || list === undefined || submit === undefined) {
      throw new Error("expected Power tools");
    }
    const observed = await read.execute("call-batch-read", { path: "/challenge/flag.txt" }, undefined, undefined, undefined as never);
    const capped = await list.execute("call-batch-list", { path: "/challenge" }, undefined, undefined, undefined as never);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const submitted = await submit.execute(
      "call-batch-submit",
      { candidate: "CTF{fixture_candidate}", observation_handle: observationHandle(observed) },
      undefined,
      undefined,
      undefined as never,
    );

    expect(capped.details).toEqual({ accepted: false, code: "power_tool_batch_exhausted" });
    expect(limiter.exhausted).toBe(true);
    expect(steers).toBe(1);
    expect(calls).toEqual(["exec"]);
    expect(submitted.details).toEqual({
      accepted: false,
      code: "power_candidate_operator_review_required",
      truncated: false,
    });
  });

  it("denies a path escape before it reaches the typed control seam", async () => {
    const calls: unknown[] = [];
    const control = {
      async exec(...args: unknown[]) {
        calls.push(args);
        return observation();
      },
    } as unknown as PowerToolControl;
    const response = await tool("ctf_fs_read", control).execute(
      "call-path-escape",
      { path: "/challenge/../work/private" },
      undefined,
      undefined,
      undefined as never,
    );

    expect(response.details).toEqual({ accepted: false, code: "power_tool_workspace_path_invalid" });
    expect(calls).toEqual([]);
  });

  it("keeps a 64 KiB tool result in CAS and sends Pi a head-and-tail summary", async () => {
    const payload = `HEAD:${"x".repeat(64 * 1024 - 20)}:TAIL`;
    const control = {
      async exec() {
        return observation({ stdout: payload, outputTruncated: false });
      },
    } as unknown as PowerToolControl;
    const response = await tool("ctf_fs_list", control).execute(
      "call-large-output",
      { path: "/challenge" },
      undefined,
      undefined,
      undefined as never,
    );
    const content = response.content[0];

    expect(content?.type).toBe("text");
    if (content?.type !== "text") {
      throw new Error("Power tool result must be text");
    }
    expect(content.text.length).toBeLessThanOrEqual(POWER_TOOL_CONTEXT_MAX_CHARS);
    expect(content.text).toContain("HEAD:");
    expect(content.text).toContain(":TAIL");
    expect(response.details).toMatchObject({
      accepted: true,
      observation_handle: "obs_1",
      artifact_id: artifactId,
      artifact_sha256: artifactSha,
      truncated: true,
    });
    expect(JSON.stringify(response.details)).not.toContain("HEAD:");
  });

  it("maps every Power action to the typed control seam and keeps flag text out of results", async () => {
    const calls: Array<{ readonly method: string; readonly request: Record<string, unknown> }> = [];
    const transcripts: Array<{ tool: string; command: string; output: string }> = [];
    const ptyId = `pty_${"c".repeat(32)}`;
    const gdbId = `pty_${"d".repeat(32)}`;
    const tubeId = `tube_${"e".repeat(32)}`;
    const record = (method: string, request: Record<string, unknown>) => calls.push({ method, request });
    const control = {
      async exec(_lease: unknown, request: Record<string, unknown>) {
        record("exec", request);
        return observation();
      },
      async ptyStart(_lease: unknown, request: Record<string, unknown>) {
        record("ptyStart", request);
        const command = request.command;
        return observation(
          command instanceof Array && command[0] === "gdb"
            ? { interactiveId: gdbId, interactiveKind: "gdb" }
            : { interactiveId: ptyId, interactiveKind: "pty" },
        );
      },
      async ptySend(_lease: unknown, request: Record<string, unknown>) {
        record("ptySend", request);
        return { state: "open" as const };
      },
      async ptyRead(_lease: unknown, request: Record<string, unknown>) {
        record("ptyRead", request);
        return observation({ interactiveId: request.ptyId as string, interactiveKind: request.kind as "pty" | "gdb" });
      },
      async ptyClose(_lease: unknown, request: Record<string, unknown>) {
        record("ptyClose", request);
        return { state: "closed" as const };
      },
      async tubeConnect(_lease: unknown, request: Record<string, unknown>) {
        record("tubeConnect", request);
        return observation({ interactiveId: tubeId, interactiveKind: "tube" });
      },
      async tubeSend(_lease: unknown, request: Record<string, unknown>) {
        record("tubeSend", request);
        return { state: "open" as const };
      },
      async tubeReceive(_lease: unknown, request: Record<string, unknown>) {
        record("tubeReceive", request);
        return observation({ interactiveId: tubeId, interactiveKind: "tube" });
      },
      async tubeClose(_lease: unknown, request: Record<string, unknown>) {
        record("tubeClose", request);
        return { state: "closed" as const };
      },
      async submitFlag(_lease: unknown, request: Record<string, unknown>) {
        record("submitFlag", request);
        return { accepted: true };
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({
      ...scope(control),
      async onToolTranscript(_lease, transcript) {
        transcripts.push(transcript);
      },
    });
    const invoke = async (name: string, params: Record<string, unknown>) => {
      const selected = tools.find((candidate) => candidate.name === name);
      if (selected === undefined) {
        throw new Error(`Power tool missing: ${name}`);
      }
      return selected.execute(`call-${name}`, params, undefined, undefined, undefined as never);
    };

    const firstObservation = await invoke("ctf_shell_exec", { command: ["file", "/challenge/challenge.bin"] });
    await invoke("ctf_fs_list", { path: "/challenge" });
    await invoke("ctf_fs_read", { path: "/challenge/note.txt", max_bytes: 99 });
    const writeResult = await invoke("ctf_fs_write", { path: "/work/solve.py", content: "print('fixture')" });
    await invoke("ctf_pty_start", { command: ["python3", "-q"] });
    await invoke("ctf_pty_send", { pty_id: ptyId, data: "1 + 1\n" });
    await invoke("ctf_pty_read", { pty_id: ptyId });
    await invoke("ctf_pty_close", { pty_id: ptyId });
    await invoke("ctf_gdb_start", { path: "/challenge/challenge.bin" });
    await invoke("ctf_gdb_cmd", { gdb_id: gdbId, command: "break main" });
    await invoke("ctf_gdb_close", { gdb_id: gdbId });
    await invoke("ctf_tube_connect", { host: "ctf.example", port: 31337 });
    await invoke("ctf_tube_send", { tube_id: tubeId, data_base64: "cGluZw==" });
    await invoke("ctf_tube_recv", { tube_id: tubeId, delimiter_base64: "Cg==" });
    await invoke("ctf_tube_close", { tube_id: tubeId });
    const flagResult = await invoke("ctf_flag_submit", {
      candidate: "CTF{fixture_candidate}",
      observation_handle: observationHandle(firstObservation),
    });

    expect(calls.map((call) => call.method)).toEqual([
      "exec", "exec", "exec", "exec", "ptyStart", "ptySend", "ptyRead", "ptyClose", "ptyStart", "ptySend", "ptyRead", "ptyClose",
      "tubeConnect", "tubeSend", "tubeReceive", "tubeClose",
    ]);
    expect(calls.every((call) => call.request.workspaceId === workspaceId)).toBe(true);
    expect(flagResult.details).toEqual({
      accepted: false,
      code: "power_candidate_operator_review_required",
      truncated: false,
    });
    expect(JSON.stringify(flagResult)).not.toContain("CTF{fixture_candidate}");
    expect(JSON.stringify(writeResult.details)).not.toContain("print('fixture')");
    expect(transcripts.map((item) => item.tool)).toEqual([
      "ctf_shell_exec", "ctf_fs_list", "ctf_fs_read", "ctf_fs_write", "ctf_pty_start", "ctf_pty_send", "ctf_pty_read",
      "ctf_pty_close", "ctf_gdb_start", "ctf_gdb_cmd", "ctf_gdb_close", "ctf_tube_connect", "ctf_tube_send",
      "ctf_tube_recv", "ctf_tube_close", "ctf_flag_submit",
    ]);
    expect(transcripts[0]).toMatchObject({
      command: "file /challenge/challenge.bin",
      output: "fixture observation",
    });
    expect(transcripts.find((item) => item.tool === "ctf_fs_write")?.command)
      .toContain("byte write payload");
    expect(transcripts.find((item) => item.tool === "ctf_fs_write")?.command)
      .not.toContain("print('fixture')");
    expect(transcripts.at(-1)).toMatchObject({
      command: "flag-candidate-held evidence=obs_1",
      output: "Candidate held for local operator review.",
    });
  });

  it("holds a candidate with a session-issued evidence handle without contacting flag-router", async () => {
    const calls: Array<{ readonly method: string; readonly request: Record<string, unknown> }> = [];
    const control = {
      async exec() {
        return observation();
      },
      async submitFlag(_lease: unknown, request: Record<string, unknown>) {
        calls.push({ method: "submitFlag", request });
        return { accepted: false };
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools(scope(control));
    const read = tools.find((candidate) => candidate.name === "ctf_fs_read");
    const submit = tools.find((candidate) => candidate.name === "ctf_flag_submit");
    if (read === undefined || submit === undefined) {
      throw new Error("expected Power tools");
    }

    const readResult = await read.execute(
      "call-read",
      { path: "/challenge/flag.txt" },
      undefined,
      undefined,
      undefined as never,
    );
    const accepted = await submit.execute(
      "call-submit",
      { candidate: "CTF{fixture_candidate}", observation_handle: observationHandle(readResult) },
      undefined,
      undefined,
      undefined as never,
    );
    const rejected = await submit.execute(
      "call-unknown-handle",
      { candidate: "CTF{fixture_candidate}", observation_handle: "obs_999" },
      undefined,
      undefined,
      undefined as never,
    );

    expect(calls).toEqual([]);
    expect(JSON.stringify(accepted)).not.toContain("CTF{fixture_candidate}");
    expect(accepted.details).toEqual({
      accepted: false,
      code: "power_candidate_operator_review_required",
      truncated: false,
    });
    expect(rejected.details).toEqual({
      accepted: false,
      code: "power_tool_flag_observation_handle_unknown",
      truncated: false,
    });
  });

  it("lets a fixture Pi session call ctf_fs_list and receive an observation artifact", async () => {
    const root = await mkdtemp(join(tmpdir(), "ctfmesh-power-pi-tools-"));
    roots.push(root);
    const cwd = join(root, "empty-cwd");
    const agentDir = join(root, "agent");
    await Promise.all([mkdir(cwd), mkdir(agentDir)]);

    const calls: Array<{ readonly command: readonly string[]; readonly workspaceId: string }> = [];
    const control = {
      async exec(_lease: unknown, request: { readonly command: readonly string[]; readonly workspaceId: string }) {
        calls.push(request);
        return observation({ stdout: "challenge.bin\n", exitCode: 0 });
      },
    } as unknown as PowerToolControl;
    const runnerScope = scope(control);
    const faux = registerFauxProvider();
    const resources = await createReviewedResources(cwd, agentDir, "Power fixture system prompt.");
    const { session } = await createAgentSession({
      cwd,
      agentDir,
      model: faux.getModel(),
      // This fixture transport never contacts a provider. Pi still asks its
      // model runtime for credentials before a prompt, so give it a minimal
      // in-memory response rather than using a real key or auth file.
      modelRuntime: {
        hasConfiguredAuth() {
          return true;
        },
        async getAuth() {
          return { auth: { apiKey: "fixture-pi-key" } };
        },
      } as never,
      noTools: "all",
      tools: [...powerToolNames("racer")],
      customTools: createPowerTools(runnerScope),
      resourceLoader: resources.loader,
      settingsManager: resources.settings,
      sessionManager: SessionManager.inMemory(),
      thinkingLevel: "off",
    });
    try {
      // The upstream faux transport keeps this regression fully offline while
      // exercising a real Pi AgentSession tool-call cycle.
      session.agent.streamFunction = streamSimple;
      faux.setResponses([
        fauxAssistantMessage(fauxToolCall("ctf_fs_list", { path: "/challenge" }), { stopReason: "toolUse" }),
        fauxAssistantMessage("The fixture observation was received."),
      ]);

      await session.prompt("List the scoped challenge files.", { expandPromptTemplates: false });
      await session.waitForIdle();

      expect(session.getActiveToolNames()).toEqual(powerToolNames("racer"));
      expect(session.getActiveToolNames()).not.toContain("bash");
      expect(calls).toEqual([
        {
          workspaceId,
          command: ["find", "/challenge", "-maxdepth", "1", "-mindepth", "1", "-print"],
          timeoutSeconds: 30,
          workingDirectory: "/work",
        },
      ]);
      const toolMessage = session.messages.find((message) => message.role === "toolResult");
      expect(JSON.stringify(toolMessage)).toContain(artifactId);
      expect(JSON.stringify(toolMessage)).toContain("challenge.bin");
    } finally {
      session.dispose();
      faux.unregister();
    }
  });
});
