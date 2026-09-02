import {
  SettingsManager,
  createAgentSession,
  defineTool,
  generateSummary,
  type AgentSession,
  type CreateAgentSessionOptions,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";

type RequiredSessionSurface = Pick<AgentSession, "abort" | "compact" | "steer">;

function acceptsRequiredSessionSurface(session: RequiredSessionSurface): RequiredSessionSurface {
  return session;
}

describe("reviewed Pi upstream API", () => {
  it("exports the pinned factory, tool, settings, and session contract", () => {
    expect(createAgentSession).toBeTypeOf("function");
    expect(defineTool).toBeTypeOf("function");
    expect(SettingsManager.inMemory).toBeTypeOf("function");

    const settings = SettingsManager.inMemory();
    expect(settings.applyOverrides).toBeTypeOf("function");

    const options: Pick<CreateAgentSessionOptions, "noTools"> = {
      noTools: "all",
    };
    expect(options.noTools).toBe("all");
    expect(acceptsRequiredSessionSurface).toBeTypeOf("function");
  });

  it("keeps registered tools out of the standalone compaction request", async () => {
    type SummaryArguments = Parameters<typeof generateSummary>;
    type SummaryStream = NonNullable<SummaryArguments[9]>;

    let observedContext: unknown;
    let observedOptions: unknown;
    const model = {
      api: "openai-completions",
      id: "fixture-model",
      provider: "fixture-provider",
      reasoning: false,
    } as SummaryArguments[1];
    const stream = ((requestedModel: SummaryArguments[1], context: unknown, options: unknown) => {
      observedContext = context;
      observedOptions = options;
      return {
        result: async () => ({
          api: requestedModel.api,
          content: [{ type: "text", text: "compacted without tools" }],
          model: requestedModel.id,
          provider: requestedModel.provider,
          role: "assistant",
          stopReason: "stop",
          timestamp: Date.now(),
          usage: {
            input: 1,
            output: 1,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 2,
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
          },
        }),
      };
    }) as SummaryStream;
    const messages = [{
      role: "user",
      content: [{ type: "text", text: "tool schema must not be forwarded" }],
      timestamp: Date.now(),
    }] as SummaryArguments[0];

    await expect(generateSummary(
      messages,
      model,
      512,
      "fixture-key",
      undefined,
      undefined,
      undefined,
      undefined,
      "off",
      stream,
    )).resolves.toBe("compacted without tools");

    expect(observedContext).not.toHaveProperty("tools");
    expect(observedOptions).not.toHaveProperty("tools");
  });
});
