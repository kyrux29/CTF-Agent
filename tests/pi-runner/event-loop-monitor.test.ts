import { describe, expect, it, vi } from "vitest";

import { startEventLoopMonitor } from "../../services/pi-runner/src/event-loop-monitor.js";

describe("reporting when the process stops answering", () => {
  it("says nothing while the loop is healthy", async () => {
    // Normal jitter is microseconds. A line per sample would bury the one
    // that matters, which is the whole reason nothing recorded the stall.
    const logged: string[] = [];
    vi.useFakeTimers();
    const stop = startEventLoopMonitor((code) => logged.push(code), {
      sampleIntervalMs: 10,
    });
    try {
      await vi.advanceTimersByTimeAsync(100);
    } finally {
      stop();
      vi.useRealTimers();
    }
    expect(logged).toEqual([]);
  });

  it("reports a stall in a coarse bucket, and only once per sample", async () => {
    // The logger is a safe-code channel, so the value stays low-cardinality;
    // the bucket still separates a hiccup from a stall that outlives a thirty
    // second lease. Each sample starts from zero so one stall is one line.
    const logged: string[] = [];
    let maxNs = 0;
    const histogram = {
      get max() {
        return maxNs;
      },
      enable: () => true,
      disable: () => true,
      reset: () => {
        maxNs = 0;
      },
    };

    vi.useFakeTimers();
    const stop = startEventLoopMonitor((code) => logged.push(code), {
      thresholdMs: 1_000,
      sampleIntervalMs: 10,
      histogram,
    });
    try {
      maxNs = 900 * 1_000_000; // under the threshold: not worth a line
      await vi.advanceTimersByTimeAsync(10);
      expect(logged).toEqual([]);

      maxNs = 49_000 * 1_000_000; // the gap that expired a real lease
      await vi.advanceTimersByTimeAsync(10);
      // The next sample sees a healthy loop again, so nothing repeats.
      await vi.advanceTimersByTimeAsync(10);
    } finally {
      stop();
      vi.useRealTimers();
    }

    expect(logged).toEqual(["event_loop_stalled_ms:30000"]);
  });
});
