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

describe("power tool rejection guidance", () => {
  /** Render the model-facing half of a tool result. */
  function resultText(result: { readonly content: unknown }): string {
    if (!Array.isArray(result.content)) {
      throw new Error("expected tool result content");
    }
    return result.content
      .map((part) => (typeof part === "object" && part !== null && "text" in part
        ? String((part as { readonly text: unknown }).text)
        : ""))
      .join(" ");
  }

  it("tells a racer how to correct an argv mistake instead of only naming a code", async () => {
    // A bare "not accepted" plus an opaque code leaves nothing to act on: an
    // observed racer retried one malformed call five times, then reported it
    // could make no further observation and spent the rest of its run idle.
    const control = {
      async exec() {
        throw new Error("exec must not be reached for an invalid argv");
      },
    } as unknown as PowerToolControl;
    const shell = tool("ctf_shell_exec", control);

    const result = await shell.execute(
      "call-invalid-argv",
      { command: "bash -lc 'printf hi | ./zigzag'" } as never,
      undefined,
      undefined,
      undefined as never,
    );

    expect(result.details).toMatchObject({ accepted: false, code: "power_tool_command_invalid" });
    expect(resultText(result)).toContain("power_tool_command_invalid");
    expect(resultText(result)).toContain("argv array");
    expect(resultText(result)).toContain('["bash", "-lc"');
  });

  it("names a path rejection precisely enough to retry it", async () => {
    const control = {
      async exec() {
        throw new Error("exec must not be reached for an invalid path");
      },
    } as unknown as PowerToolControl;
    const read = tool("ctf_fs_read", control);

    const result = await read.execute(
      "call-invalid-path",
      { path: "/etc/passwd" },
      undefined,
      undefined,
      undefined as never,
    );

    expect(result.details).toMatchObject({
      accepted: false,
      code: "power_tool_workspace_path_invalid",
    });
    expect(resultText(result)).toContain("/challenge or /work");
  });

  it("keeps a stable code for a rejection that carries no specific guidance", async () => {
    const control = {
      async exec() {
        throw new ControlProtocolError("control_power_candidate_review_required");
      },
    } as unknown as PowerToolControl;
    const list = tool("ctf_fs_list", control);

    const result = await list.execute(
      "call-generic-rejection",
      { path: "/challenge" },
      undefined,
      undefined,
      undefined as never,
    );

    expect(result.details).toMatchObject({ code: "power_candidate_review_required" });
    expect(resultText(result)).toContain("power_candidate_review_required");
  });
});

describe("ctf_artifact_read", () => {
  function resultDetails(result: { readonly details: unknown }): Record<string, unknown> {
    const details = result.details;
    if (details === null || typeof details !== "object" || Array.isArray(details)) {
      throw new Error("expected tool details");
    }
    return details as Record<string, unknown>;
  }

  const digest = `sha256:${"a".repeat(64)}`;

  it("re-reads a stored observation instead of re-running the command", async () => {
    // Every tool result is cut before the model sees it; without this the rest
    // of a large disassembly or hexdump was reachable only by guessing new
    // head/dd arguments and paying for the command again.
    const requests: unknown[] = [];
    const control = {
      async readArtifact(_lease: unknown, request: unknown) {
        requests.push(request);
        return {
          artifactId: digest,
          offset: 4_000,
          totalBytes: 20_000,
          returnedBytes: 5,
          text: "tail!",
        };
      },
    } as unknown as PowerToolControl;
    const read = tool("ctf_artifact_read", control);

    const result = await read.execute(
      "call-artifact-read",
      { artifact_id: digest, offset: 4_000, length: 5 },
      undefined,
      undefined,
      undefined as never,
    );

    expect(requests).toEqual([{ artifactId: digest, offset: 4_000, length: 5 }]);
    expect(resultDetails(result)).toMatchObject({
      accepted: true,
      artifact_id: digest,
      offset: 4_000,
      total_bytes: 20_000,
      returned_bytes: 5,
    });
  });

  it("rejects an id that is not a content digest before contacting the control plane", async () => {
    const control = {
      async readArtifact() {
        throw new Error("control plane must not be reached for an invalid id");
      },
    } as unknown as PowerToolControl;
    const read = tool("ctf_artifact_read", control);

    const result = await read.execute(
      "call-artifact-read-invalid",
      { artifact_id: `sha256:${"z".repeat(64)}` },
      undefined,
      undefined,
      undefined as never,
    );

    expect(resultDetails(result)).toMatchObject({
      accepted: false,
      code: "power_tool_artifact_id_invalid",
    });
  });
});

describe("ctf_fs_write retention", () => {
  it("reads the file back so the written bytes survive the workspace", async () => {
    // /work is a tmpfs that dies with its container and no route exports a
    // file. A write whose observation held only printf's empty stdout left the
    // bytes unrecoverable: a racer could build and verify a working proof of
    // concept and still leave the operator nothing to reproduce it with.
    const commands: readonly string[][] = [];
    const seen: string[][] = [];
    const control = {
      async exec(_lease: unknown, request: { readonly command: readonly string[] }) {
        seen.push([...request.command]);
        return observation({ stdout: "print('poc')" });
      },
    } as unknown as PowerToolControl;
    const write = tool("ctf_fs_write", control);

    const result = await write.execute(
      "call-fs-write",
      { path: "/work/poc.py", content: "print('poc')" },
      undefined,
      undefined,
      undefined as never,
    );

    expect(commands).toEqual([]);
    expect(seen).toHaveLength(1);
    const argv = seen[0] ?? [];
    // The script both writes and reads back, in one argv-only command.
    expect(argv[2]).toBe('printf %s "$1" > "$2" && cat "$2"');
    expect(argv).toContain("print('poc')");
    expect(argv).toContain("/work/poc.py");
    // The observation now carries the file, so the operator can retrieve it.
    const text = Array.isArray(result.content)
      ? result.content.map((part) => (typeof part === "object" && part !== null && "text" in part
        ? String((part as { readonly text: unknown }).text)
        : "")).join(" ")
      : "";
    expect(text).toContain("print('poc')");
  });

  it("still keeps the payload itself out of the displayed command", async () => {
    // Deny path: a generated payload can contain a flag or a credential, so
    // the transcript shows the mechanism and a byte count, never the bytes.
    const transcripts: { readonly command: string }[] = [];
    const control = {
      async exec() {
        return observation({ stdout: "SECRET_PAYLOAD" });
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({
      ...scope(control),
      async onToolTranscript(_lease, transcript) {
        transcripts.push(transcript);
      },
    });
    const write = tools.find((item) => item.name === "ctf_fs_write");
    if (write === undefined) {
      throw new Error("expected write tool");
    }

    await write.execute(
      "call-fs-write-redaction",
      { path: "/work/poc.py", content: "SECRET_PAYLOAD" },
      undefined,
      undefined,
      undefined as never,
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(transcripts).toHaveLength(1);
    const displayed = transcripts[0]?.command ?? "";
    expect(displayed).toContain("byte write payload");
    expect(displayed).not.toContain("SECRET_PAYLOAD");
  });

  it("names the observation each receipt summarises", async () => {
    // The receipt output is redacted and capped, so it summarises evidence and
    // is never the evidence. The runner held the artifact id and dropped it,
    // which left the sealed bytes of a script a racer wrote unreachable to
    // anyone who could not read the artifact store on the host directly.
    const transcripts: { readonly artifactId?: string }[] = [];
    const control = {
      async exec() {
        return observation();
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools({
      ...scope(control),
      async onToolTranscript(_lease, transcript) {
        transcripts.push(transcript);
      },
    });
    const write = tools.find((item) => item.name === "ctf_fs_write");
    if (write === undefined) {
      throw new Error("expected write tool");
    }

    await write.execute(
      "call-fs-write-artifact",
      { path: "/work/poc.py", content: "import socket" },
      undefined,
      undefined,
      undefined as never,
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(transcripts).toHaveLength(1);
    expect(transcripts[0]?.artifactId).toBe(artifactId);
  });
});

describe("reading past the first window", () => {
  const GDB_ID = `pty_${"d".repeat(32)}`;
  const FOREIGN_GDB_ID = `pty_${"e".repeat(32)}`;

  function argvOf(seen: string[][]): string[] {
    const argv = seen[0];
    if (argv === undefined) {
      throw new Error("expected one control-plane exec");
    }
    return argv;
  }

  it("keeps the plain head form when no offset is asked for", async () => {
    const seen: string[][] = [];
    const control = {
      async exec(_lease: unknown, request: { readonly command: readonly string[] }) {
        seen.push([...request.command]);
        return observation({ stdout: "head" });
      },
    } as unknown as PowerToolControl;

    await tool("ctf_fs_read", control).execute(
      "call-read-head",
      { path: "/challenge/zigzag", max_bytes: 4096 },
      undefined,
      undefined,
      undefined as never,
    );

    expect(argvOf(seen)).toEqual(["head", "-c", "4096", "/challenge/zigzag"]);
  });

  it("seeks with positional arguments rather than shell interpolation", async () => {
    // `ctf_fs_read` was `head -c N`, so anything past the first window had to
    // be hand-rolled through the shell tool. `tail -c +K` seeks instead of
    // reading a byte at a time, and the path and numbers stay positional so
    // neither is parsed as shell source.
    const seen: string[][] = [];
    const control = {
      async exec(_lease: unknown, request: { readonly command: readonly string[] }) {
        seen.push([...request.command]);
        return observation({ stdout: "IJKL" });
      },
    } as unknown as PowerToolControl;

    await tool("ctf_fs_read", control).execute(
      "call-read-offset",
      { path: "/challenge/zigzag", max_bytes: 4, offset: 8 },
      undefined,
      undefined,
      undefined as never,
    );

    // K is one-based, so byte offset eight starts at nine.
    expect(argvOf(seen)).toEqual([
      "sh",
      "-c",
      'tail -c +"$1" "$3" | head -c "$2"',
      "ctfmesh",
      "9",
      "4",
      "/challenge/zigzag",
    ]);
  });

  it("drains a slow GDB command without sending another one", async () => {
    // ctf_gdb_cmd sends and reads exactly once, so a `run` or a large
    // `disassemble` that outlived its window lost the rest of its output:
    // ctf_pty_read rejects a gdb channel, and sending another gdb command to
    // drain one changes the debuggee's state.
    const reads: unknown[] = [];
    const control = {
      async ptyStart() {
        return observation({ interactiveId: GDB_ID, interactiveKind: "gdb" });
      },
      async ptyRead(_lease: unknown, request: unknown) {
        reads.push(request);
        return observation({ stdout: "Breakpoint 1, main ()" });
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools(scope(control));
    const start = tools.find((item) => item.name === "ctf_gdb_start");
    const read = tools.find((item) => item.name === "ctf_gdb_read");
    if (start === undefined || read === undefined) {
      throw new Error("expected gdb tools");
    }

    await start.execute(
      "call-gdb-start",
      { path: "/challenge/zigzag" },
      undefined,
      undefined,
      undefined as never,
    );
    const result = await read.execute(
      "call-gdb-read",
      { gdb_id: GDB_ID, max_bytes: 2048, wait_ms: 1500 },
      undefined,
      undefined,
      undefined as never,
    );

    expect(reads).toEqual([
      {
        workspaceId: `ws_${"a".repeat(32)}`,
        ptyId: GDB_ID,
        maxBytes: 2048,
        waitMs: 1500,
        kind: "gdb",
      },
    ]);
    expect(result.details).toMatchObject({ accepted: true, action: "ctf_gdb_read" });
  });

  it("refuses to drain a gdb channel this session does not own", async () => {
    const control = {
      async ptyRead() {
        throw new Error("control plane must not be reached for an unowned channel");
      },
    } as unknown as PowerToolControl;

    const result = await tool("ctf_gdb_read", control).execute(
      "call-gdb-read-unowned",
      { gdb_id: FOREIGN_GDB_ID },
      undefined,
      undefined,
      undefined as never,
    );

    expect(result.details).toMatchObject({
      accepted: false,
      code: "power_tool_interactive_channel_not_owned",
    });
  });
});

describe("a connection the racer can actually use", () => {
  it("names the session id in the text, not only in details", async () => {
    // `details` is for the host application; the model reads `content`. The
    // id lived only in details from the first commit, so every tube, pty and
    // debugger opened cleanly and then could not be sent a single byte -
    // racers rebuilt the socket by hand inside ctf_shell_exec instead.
    const tubeId = `tube_${"a".repeat(32)}`;
    const control = {
      async tubeConnect() {
        return observation({ interactiveId: tubeId, interactiveKind: "tube" });
      },
    } as unknown as PowerToolControl;
    const tools = createPowerTools(scope(control));
    const connect = tools.find((item) => item.name === "ctf_tube_connect");
    if (connect === undefined) {
      throw new Error("expected tube tool");
    }

    const result = await connect.execute(
      "call-tube-connect",
      { host: "target.example.test", port: 1337 },
      undefined,
      undefined,
      undefined as never,
    );

    const text = result.content.map((part) => ("text" in part ? part.text : "")).join("\n");
    expect(text).toContain(tubeId);
    expect(text).toMatch(/Use this exact id for every later tube call/);
  });
});
