import { describe, expect, it } from "vitest";

import {
  PowerActivityReporter,
  POWER_ACTIVITY_MAX_CHARS,
  POWER_TOOL_TRANSCRIPT_MAX_CHARS,
  redactPowerActivityText,
  visibleAssistantText,
} from "../../services/pi-runner/src/power-activity.js";
import type { PowerActivityKind, PowerToolTranscript } from "../../services/pi-runner/src/power-activity.js";
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
