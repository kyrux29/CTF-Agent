import { describe, expect, it } from "vitest";

import {
  PowerActivityReporter,
  POWER_ACTIVITY_MAX_CHARS,
  POWER_TOOL_TRANSCRIPT_MAX_CHARS,
  redactPowerActivityText,
  visibleAssistantText,
} from "../../services/pi-runner/src/power-activity.js";
import type { PowerActivityKind, PowerToolTranscript } from "../../services/pi-runner/src/power-activity.js";
import { ControlProtocolError } from "../../services/pi-runner/src/contracts.js";
import type { TurnLease } from "../../services/pi-runner/src/tools.js";

describe("Power Pi operator activity", () => {
  it("exports visible assistant prose but never hidden thinking or raw secrets", () => {
    const event = {
      type: "message_end",
      message: {
        role: "assistant",
        content: [
          { type: "thinking", thinking: "private chain of thought" },
          { type: "text", text: "Read config; candidate CTF{do_not_log}; token=abc" },
          { type: "toolCall", id: "call-1", name: "ctf_fs_read", arguments: { path: "/challenge/key" } },
        ],
      },
    } as never;

    expect(visibleAssistantText(event)).toBe("Read config; candidate [REDACTED_FLAG]; [REDACTED_SECRET]");
  });

  it("keeps only bounded redacted entries until the control API accepts them", async () => {
    const sent: Array<{ kind: string; content: string }> = [];
    const reporter = new PowerActivityReporter({
      async reportPowerActivity(_lease: TurnLease, kind: PowerActivityKind, content: string) {
        sent.push({ kind, content });
      },
    } as never);
    reporter.recordPrompt(`Use ${"x".repeat(POWER_ACTIVITY_MAX_CHARS + 200)}`);
    await reporter.flush({ jobId: "job-1", leaseVersion: 1, sessionId: "power-1" });

    expect(sent).toHaveLength(1);
    expect(sent[0]?.kind).toBe("prompt");
    expect(sent[0]?.content.length).toBeLessThanOrEqual(POWER_ACTIVITY_MAX_CHARS);
    expect(sent[0]?.content).toContain("[TRUNCATED]");
  });

  it("redacts provider keys before they leave Pi", () => {
    expect(redactPowerActivityText("Bearer abcdefghijkl sk-12345678 AIza1234567890123456"))
      .toBe("Bearer [REDACTED] [REDACTED_API_KEY] [REDACTED_API_KEY]");
  });

  it("redacts a Base64-shaped braced flag before it reaches the activity ledger", () => {
    const raw = "DH{YW55L2JvZHk9PQ==}";
    expect(redactPowerActivityText(`candidate ${raw}`)).toBe("candidate [REDACTED_FLAG]");
  });

  it("forwards a bounded terminal command and output without a raw flag or credential", async () => {
    const sent: Array<{ tool: string; command: string; output: string; outputTruncated: boolean }> = [];
    const reporter = new PowerActivityReporter({
      async reportPowerActivity() {},
      async reportPowerToolTranscript(_lease: TurnLease, transcript: PowerToolTranscript) {
        sent.push(transcript);
      },
    } as never);

    reporter.recordTool({
      tool: "ctf_shell_exec",
      command: "cat /challenge/flag.txt token=never-persist",
      output: `CTF{must_not_persist} ${"x".repeat(POWER_TOOL_TRANSCRIPT_MAX_CHARS + 200)}`,
      exitCode: 0,
      timedOut: false,
      outputTruncated: false,
    });
    await reporter.flush({ jobId: "job-1", leaseVersion: 1, sessionId: "power-1" });

    expect(sent).toHaveLength(1);
    expect(sent[0]?.command).toContain("[REDACTED_SECRET]");
    expect(sent[0]?.output).toContain("[REDACTED_FLAG]");
    expect(sent[0]?.output).not.toContain("CTF{must_not_persist}");
    expect(sent[0]?.output.length).toBeLessThanOrEqual(POWER_TOOL_TRANSCRIPT_MAX_CHARS);
    expect(sent[0]?.outputTruncated).toBe(true);
  });
});

describe("one refused receipt must not silence a racer", () => {
  it("records a blank result instead of one the control plane will refuse", async () => {
    // The control plane trims before deciding a receipt is empty. A
    // `ctf_tube_recv` that read only a trailing newline passed the runner's
    // own guard and was then refused there - and a peer that sent nothing is
    // a real observation, not something to discard.
    const sent: PowerToolTranscript[] = [];
    const reporter = new PowerActivityReporter({
      async reportPowerActivity() {},
      async reportPowerToolTranscript(_lease: TurnLease, transcript: PowerToolTranscript) {
        sent.push(transcript);
      },
    } as never);

    reporter.recordTool({
      tool: "ctf_tube_recv",
      command: "tube-recv",
      output: "\r\n",
      exitCode: 0,
      timedOut: false,
      outputTruncated: false,
    });
    await reporter.flush({ jobId: "job-1", leaseVersion: 1, sessionId: "session-1" } as never);

    expect(sent).toHaveLength(1);
    expect(sent[0]?.output.trim()).not.toBe("");
  });

  it("drops a receipt the control plane will never accept", async () => {
    // A refused item was never shifted off the queue, so every later receipt
    // for that session queued behind one the server had already rejected.
    const attempts: string[] = [];
    const reporter = new PowerActivityReporter({
      async reportPowerActivity() {},
      async reportPowerToolTranscript(_lease: TurnLease, transcript: PowerToolTranscript) {
        attempts.push(transcript.tool);
        if (transcript.tool === "ctf_tube_recv") {
          throw new ControlProtocolError("power_tool_transcript_invalid");
        }
      },
    } as never);

    const receipt = (tool: string) => ({
      tool,
      command: "cmd",
      output: "out",
      exitCode: 0,
      timedOut: false,
      outputTruncated: false,
    });
    reporter.recordTool(receipt("ctf_tube_recv"));
    reporter.recordTool(receipt("ctf_shell_exec"));

    const lease = { jobId: "job-1", leaseVersion: 1, sessionId: "session-1" } as never;
    await expect(reporter.flush(lease)).rejects.toThrow(/power_tool_transcript_invalid/);
    // The refused one is gone; the next flush delivers what was behind it.
    await reporter.flush(lease);

    expect(attempts).toEqual(["ctf_tube_recv", "ctf_shell_exec"]);
  });

  it("keeps the receipt for the observation that opened a candidate gate", async () => {
    // A candidate gate fences the session's reporting, so the receipt for the
    // very call that found the flag is refused. It is not the item's fault and
    // it is the one worth keeping - dropping it would discard the evidence the
    // operator is being asked to review.
    let attempts = 0;
    const reporter = new PowerActivityReporter({
      async reportPowerActivity() {},
      async reportPowerToolTranscript() {
        attempts += 1;
        if (attempts === 1) {
          throw new ControlProtocolError("control_power_candidate_review_required");
        }
      },
    } as never);

    reporter.recordTool({
      tool: "ctf_tube_recv",
      command: "tube-recv",
      output: "flag observed",
      exitCode: 0,
      timedOut: false,
      outputTruncated: false,
    });
    const lease = { jobId: "job-1", leaseVersion: 1, sessionId: "session-1" } as never;
    await expect(reporter.flush(lease)).rejects.toThrow(/candidate_review_required/);
    await reporter.flush(lease);

    expect(attempts).toBe(2);
  });

  it("keeps a receipt whose delivery merely failed in transit", async () => {
    let calls = 0;
    const reporter = new PowerActivityReporter({
      async reportPowerActivity() {},
      async reportPowerToolTranscript() {
        calls += 1;
        if (calls === 1) throw new Error("socket hang up");
      },
    } as never);

    reporter.recordTool({
      tool: "ctf_shell_exec",
      command: "cmd",
      output: "out",
      exitCode: 0,
      timedOut: false,
      outputTruncated: false,
    });
    const lease = { jobId: "job-1", leaseVersion: 1, sessionId: "session-1" } as never;
    await expect(reporter.flush(lease)).rejects.toThrow(/socket hang up/);
    await reporter.flush(lease);

    expect(calls).toBe(2);
  });
});
