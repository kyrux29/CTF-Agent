/** Process loop for Pi Runner. Kept separate from index.ts for testability. */

import type { RunnerConfig } from "./config.js";
import { ControlProtocolError } from "./contracts.js";
import { PiRunnerConsumer } from "./task-consumer.js";
import { startEventLoopMonitor } from "./event-loop-monitor.js";
import type { SafeRunnerLogger } from "./task-consumer.js";

/**
 * Four Power model turns can run together. Three additional bounded slots let
 * abort jobs interrupt all losing racers immediately, rather than waiting for
 * an active model turn to become idle.
 */
const MAX_CONCURRENT_PI_JOBS = 7;
const MAX_CONTROL_RETRY_DELAY_MS = 5_000;

const TRANSIENT_CONTROL_CODES = new Set([
  "control_transport_failed",
  "control_request_timeout",
  // The control API emits this typed 503 for a transient database conflict
  // (for example PostgreSQL's deadlock victim).  Keep the runner alive so a
  // future poll can reclaim the durable job instead of restarting Pi.
  "control_database_unavailable",
]);

function defaultLogger(code: string): void {
  process.stderr.write(`[ctfmesh-pi-runner] ${code}\n`);
}

function isTransientControlFailure(error: unknown): boolean {
  return error instanceof ControlProtocolError && TRANSIENT_CONTROL_CODES.has(error.code);
}

function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/** Run until the service is asked to stop; no model or target work is spawned here. */
export async function runRunnerLoop(
  config: RunnerConfig,
  signal: AbortSignal,
  consumer = new PiRunnerConsumer(config),
  logger: SafeRunnerLogger = defaultLogger,
): Promise<void> {
  const inFlight = new Set<Promise<void>>();
  let consecutiveControlFailures = 0;
  // A blocked event loop does not fail anything visibly: the lease renewal
  // timer simply does not fire, and the racer's work is discarded when the
  // lease expires with no error anywhere to explain it.
  const stopEventLoopMonitor = startEventLoopMonitor(logger);
  try {
    while (!signal.aborted) {
      let claimedAny = false;
      while (!signal.aborted && inFlight.size < MAX_CONCURRENT_PI_JOBS) {
        let claimed;
        try {
          claimed = await consumer.beginOnce();
          consecutiveControlFailures = 0;
        } catch (error) {
          if (!isTransientControlFailure(error)) {
            throw error;
          }
          consecutiveControlFailures += 1;
          logger("control_transport_retry");
          const delay = Math.min(
            MAX_CONTROL_RETRY_DELAY_MS,
            config.pollIntervalMs * (2 ** Math.min(consecutiveControlFailures - 1, 4)),
          );
          await sleep(delay, signal);
          break;
        }
        if (claimed === null) {
          break;
        }
        claimedAny = true;
        let task: Promise<void>;
        task = claimed.completion
          .then(() => undefined)
          .catch(() => undefined)
          .finally(() => inFlight.delete(task));
        inFlight.add(task);
      }
      if (inFlight.size === 0) {
        await sleep(config.pollIntervalMs, signal);
      } else if (!claimedAny || inFlight.size >= MAX_CONCURRENT_PI_JOBS) {
        await Promise.race([sleep(config.pollIntervalMs, signal), ...inFlight]);
      }
    }
  } finally {
    stopEventLoopMonitor();
    await Promise.allSettled(inFlight);
    await consumer.disposeLocalSessions();
  }
}
