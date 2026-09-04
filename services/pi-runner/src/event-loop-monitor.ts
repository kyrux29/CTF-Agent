import { monitorEventLoopDelay } from "node:perf_hooks";

import type { SafeRunnerLogger } from "./task-consumer.js";

/**
 * Report when this process stops answering, and for how long.
 *
 * A racer's durable lease is renewed on a timer, so a blocked event loop does
 * not fail anything visibly - the timer simply does not fire. Renewal gaps of
 * 14, 20 and 49 seconds were observed against a 10 second interval and a 30
 * second lease, which expired the lease and discarded the racer's work with no
 * error anywhere to explain it. The delay itself is the missing evidence.
 *
 * `monitorEventLoopDelay` samples in libuv rather than in JavaScript, so it
 * records a stall that would prevent any JavaScript-based check from running
 * at all, and costs effectively nothing while nothing is wrong.
 */
export interface EventLoopMonitorOptions {
  /** Only a delay this long is worth a line; normal jitter is microseconds. */
  readonly thresholdMs?: number;
  readonly sampleIntervalMs?: number;
  /**
   * The delay source, for tests. Real measurement happens in libuv and cannot
   * be produced on demand from JavaScript, so the reporting rules are proven
   * against a supplied histogram rather than against the platform's.
   */
  readonly histogram?: DelayHistogram;
}

/** The part of `IntervalHistogram` this reads. */
export interface DelayHistogram {
  readonly max: number;
  enable(): boolean;
  disable(): boolean;
  reset(): void;
}

export function startEventLoopMonitor(
  logger: SafeRunnerLogger,
  options: EventLoopMonitorOptions = {},
): () => void {
  const thresholdMs = options.thresholdMs ?? 1_000;
  const sampleIntervalMs = options.sampleIntervalMs ?? 5_000;
  const histogram: DelayHistogram = options.histogram ?? monitorEventLoopDelay({ resolution: 20 });
  histogram.enable();

  const sample = (): void => {
    const worstMs = Math.round(histogram.max / 1_000_000);
    histogram.reset();
    if (worstMs >= thresholdMs) {
      // A fixed code plus a bucket: the logger is a safe-code channel, not a
      // place for free text, and the bucket is enough to tell a hiccup from
      // the kind of stall that outlives a lease.
      logger(`event_loop_stalled_ms:${bucket(worstMs)}`);
    }
  };

  const timer = setInterval(sample, sampleIntervalMs);
  timer.unref?.();
  return (): void => {
    clearInterval(timer);
    histogram.disable();
  };
}

/** Round to a coarse bucket so the code stays a stable, low-cardinality value. */
function bucket(milliseconds: number): number {
  if (milliseconds < 2_000) return 1_000;
  if (milliseconds < 5_000) return 2_000;
  if (milliseconds < 10_000) return 5_000;
  if (milliseconds < 30_000) return 10_000;
  return 30_000;
}
