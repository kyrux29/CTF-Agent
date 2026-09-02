/**
 * Pi Runner entry point.
 *
 * The implementation is added in the following M2 slice. Keeping this small
 * entry point separate makes the production image run a compiled, reviewed
 * service rather than an ad-hoc SDK command.
 */

/** Container entry point. All configuration failures are emitted as safe codes. */

import { loadRunnerConfig } from "./config.js";
import { CredentialLeaseBroker, CredentialLeaseStore } from "./credential-lease.js";
import { ControlProtocolError } from "./contracts.js";
import { configureReviewedProviderEgress } from "./provider-egress.js";
import { runRunnerLoop } from "./runner.js";
import { PiRunnerConsumer } from "./task-consumer.js";

export const PI_RUNNER_PACKAGE_VERSION = "0.1.0";

async function main(): Promise<void> {
  const controller = new AbortController();
  const stop = (): void => controller.abort();
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  let broker: CredentialLeaseBroker | undefined;
  try {
    const config = loadRunnerConfig();
    if (config.mode === "live") {
      // Pi and its OpenAI-compatible provider adapter share the dispatcher
      // installed here. Without it, the model call can bypass the reviewed
      // proxy implementation and fail before a racer reaches its first tool.
      configureReviewedProviderEgress();
    }
    // The HTTP ingress and the SDK consumer share exactly one in-memory lease
    // registry. Neither side has a persistence or event-output path for keys.
    const leases = new CredentialLeaseStore(config.credentialLeaseMaxTtlSeconds);
    broker = new CredentialLeaseBroker({
      controlToken: config.controlToken,
      bindHost: config.credentialBrokerBindHost,
      bindPort: config.credentialBrokerBindPort,
    }, leases);
    await broker.start();
    await runRunnerLoop(config, controller.signal, new PiRunnerConsumer(config, undefined, undefined, undefined, leases));
  } finally {
    await broker?.close();
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
  }
}

void main().catch((error: unknown) => {
  const code = error instanceof ControlProtocolError ? error.code : "pi_runner_startup_failed";
  process.stderr.write(`[ctfmesh-pi-runner] ${code}\n`);
  process.exitCode = 1;
});
