import { afterEach, describe, expect, it, vi } from "vitest";

import { launchPowerRun } from "../../apps/web/src/api";

function reject(detail: Record<string, unknown>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(JSON.stringify({ detail }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
    ),
  );
}

const launch = {
  authorizedTarget: false,
  contestOffline: false,
  racers: [{ label: "A" as const, provider: "custom-openai" as const, model: "m", temperature: 0.2 }],
  providerKeys: { "custom-openai": "sk-test" },
  budget: { wallTimeSeconds: 600, maxCostUsd: 1, maxTurnCostUsd: 0.05 },
};

describe("what an operator is told when the API refuses a request", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("names the field the API objected to, not just that it objected", async () => {
    // "Request validation failed. (request_validation_failed)" was the whole
    // message for a launch missing its custom endpoint. The reason was in the
    // response the entire time and was being dropped here.
    reject({
      code: "request_validation_failed",
      message: "Request validation failed.",
      details: [
        { path: "body", reason_code: "value_error", message: "Value error, power_custom_base_url_mismatched" },
      ],
    });

    await expect(launchPowerRun("intake_x", launch)).rejects.toThrow(
      /power_custom_base_url_mismatched/,
    );
  });

  it("falls back to the code when a refusal carries no stable reason", async () => {
    // Validator prose is not something an operator can act on, and may name
    // internals; only this codebase's own codes are surfaced.
    reject({
      code: "request_validation_failed",
      message: "Request validation failed.",
      details: [{ path: "body", reason_code: "missing", message: "Field required" }],
    });

    await expect(launchPowerRun("intake_x", launch)).rejects.toThrow(
      /\(request_validation_failed\)/,
    );
  });
});
