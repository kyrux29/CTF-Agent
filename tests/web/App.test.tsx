import { webcrypto } from "node:crypto";

import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ArchiveIntake } from "../../apps/web/src/api";
import App from "../../apps/web/src/App";
import { consoleTestSnapshot } from "../../apps/web/src/fixtures/console";
import type { ConsoleSnapshot } from "../../apps/web/src/types";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const intake: ArchiveIntake = {
  schema_version: "ctfmesh.archive-intake/v1",
  intake_id: "intake_0123456789abcdef0123456789abcdef",
  created_at: "2026-09-01T10:00:00Z",
  boundary: {
    offline_only: true,
    network: "not authorized",
    code_execution: "not authorized",
    model_actions: "not authorized",
    verification: "not attempted",
  },
  archive: {
    name: "challenge.zip",
    format: "zip",
    size_bytes: 2048,
    sha256: "a".repeat(64),
  },
  inventory: {
    file_count: 2,
    expanded_size_bytes: 4096,
    media_type_counts: { "text/plain": 2 },
    files: [
      {
        id: "file-001",
        path: "README.md",
        size_bytes: 100,
        sha256: "b".repeat(64),
        media_hint: "text/plain",
      },
      {
        id: "file-002",
        path: "solve.py",
        size_bytes: 1948,
        sha256: "c".repeat(64),
        media_hint: "text/plain",
      },
    ],
  },
  analysis: {
    static: {
      status: "completed",
      category_hints: [{ category: "crypto", score: 4 }],
      candidate_flags: {
        classification: "unverified_input_candidate",
        count: 0,
        initial_scan_bytes: 4096,
        initial_scan_complete: true,
        reveal_available: true,
      },
      nested_archive_count: 0,
    },
    ai: {
      status: "not_requested",
      execution: "none",
      verification: "not_attempted",
    },
  },
};

const powerConsoleSnapshot: ConsoleSnapshot = {
  ...consoleTestSnapshot,
  run: {
    ...consoleTestSnapshot.run,
    id: "run_power_0123456789abcdef",
    status: "running",
    provider_label: "power-swarm",
  },
  events: [],
};

function runtimeCapabilities(ready = true): Response {
  return jsonResponse({
    schema_version: "ctfmesh.runtime-capabilities/v1",
    archive_intake: { status: "ready" },
    provider_triage: { status: "ready" },
    exact_instance: { status: "ready", missing: [] },
    power: {
      status: ready ? "ready" : "unavailable",
      missing: ready ? [] : ["power_profile"],
    },
  });
}

function workspaceFetchMock({
  archives = [],
  runs = [],
  powerReady = true,
  consoleSnapshot = powerConsoleSnapshot,
  powerSessions = [
    { id: "session-a", label: "A", role: "racer", state: "running" },
    { id: "session-b", label: "B", role: "racer", state: "ready" },
    { id: "session-c", label: "C", role: "racer", state: "running" },
  ],
}: {
  archives?: unknown[];
  runs?: unknown[];
  powerReady?: boolean;
  consoleSnapshot?: unknown;
  powerSessions?: unknown[];
} = {}) {
  return vi.fn<typeof fetch>(async (input, init) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const method = init?.method ?? "GET";
    if (method === "GET") {
      if (url === "/v1/archive-intakes?limit=50")
        return jsonResponse({ items: archives });
      if (url === "/v1/runs?limit=50") return jsonResponse({ items: runs });
      if (url === "/v1/runtime/capabilities")
        return runtimeCapabilities(powerReady);
      if (url === "/v1/runs/run_power_0123456789abcdef/console")
        return jsonResponse(consoleSnapshot);
      if (url === "/v1/runs/run_power_0123456789abcdef/power-sessions")
        return jsonResponse({ items: powerSessions });
    }
    if (method === "POST" && url === "/v1/archive-intakes")
      return jsonResponse(intake);
    if (method === "POST" && url === `/v1/archive-intakes/${intake.intake_id}/candidate-flags/reveal`)
      return jsonResponse({
        intake_id: intake.intake_id,
        classification: "unverified_input_candidate",
        candidate_flags: ["DH{manual_candidate}"],
        candidate_count: 1,
        scan_complete: true,
        message: "Candidate values were revealed for local review.",
      });
    if (method === "POST" && url === "/v1/runs/run_power_0123456789abcdef/candidate-flags/reveal")
      return jsonResponse({
        run_id: "run_power_0123456789abcdef",
        classification: "unverified_runtime_candidate",
        candidates: [
          { value: "DH{runtime_candidate_one}", racer_labels: ["A"] },
          { value: "DH{runtime_candidate_two}", racer_labels: ["B", "C"] },
        ],
        candidate_count: 2,
        scanned_artifact_count: 3,
        unavailable_artifact_count: 0,
        scan_complete: true,
        message: "Runtime candidates were revealed for local review.",
      });
    if (method === "POST" && url === "/v1/runs/run_power_0123456789abcdef/candidate-review/confirm")
      return jsonResponse({ accepted: true, status: "solved" });
    if (method === "POST" && url === "/v1/runs/run_power_0123456789abcdef/candidate-review/reject")
      return jsonResponse({ accepted: true, status: "running", resumed_racer_count: 3 });
    if (method === "POST" && url.endsWith("/power-runs")) {
      return jsonResponse({
        run_id: "run_power_0123456789abcdef",
        challenge_id: "challenge_power_01",
        status: "queued",
        progress: {
          console_url: "/v1/runs/run_power_0123456789abcdef/console",
          activity_stream_url: "/v1/runs/run_power_0123456789abcdef/events",
        },
      });
    }
    if (method === "POST" && /\/v1\/runs\/run_power_0123456789abcdef\/power-sessions\/session-[abc]\/steer$/.test(url)) {
      return jsonResponse({
        accepted: true,
        steer_id: "power-steer-accepted",
        state: "queued",
        message_sha256: "d".repeat(64),
      }, 202);
    }
    throw new Error(`Unexpected test request: ${method} ${url}`);
  });
}

async function openSettings(
  user: ReturnType<typeof userEvent.setup>,
): Promise<HTMLElement> {
  await user.click(screen.getAllByRole("button", { name: "Settings" })[0]);
  return screen.findByRole("dialog", { name: "Power settings" });
}

async function configureDeepSeek(
  user: ReturnType<typeof userEvent.setup>,
): Promise<void> {
  const dialog = await openSettings(user);
  await user.type(
    within(dialog).getByLabelText("DeepSeek API key"),
    "test-deepseek-key",
  );
  await user.click(within(dialog).getByRole("button", { name: "Save" }));
}

function chooseArchive(
  file = new File(["archive bytes"], "challenge.zip", {
    type: "application/zip",
  }),
): void {
  const input = screen
    .getByText("No case yet. Drop ZIP or TAR.")
    .closest("label")
    ?.querySelector("input");
  if (!input) throw new Error("Archive input not found.");
  fireEvent.change(input, { target: { files: [file] } });
}

describe("Power operator workspace", () => {
  beforeEach(() => {
    Object.defineProperty(window, "crypto", {
      configurable: true,
      value: webcrypto,
    });
    window.history.replaceState(null, "", "/");
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("keeps the launch surface compact and keys inside Settings", async () => {
    vi.stubGlobal("fetch", workspaceFetchMock());
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "New challenge" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Power launch" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("No case yet. Drop ZIP or TAR."),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/API key/i)).toBeNull();
    expect(screen.queryByRole("button", { name: "Start Power" })).toBeNull();
    expect(
      screen.getByRole("button", { name: "History" }),
    ).toHaveAttribute("aria-pressed", "true");

    await userEvent.setup().click(screen.getByRole("button", { name: "History" }));
    expect(screen.queryByLabelText("history panel")).toBeNull();

    const dialog = await openSettings(userEvent.setup());
    expect(within(dialog).getByLabelText("OpenAI API key")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Gemini API key")).toBeInTheDocument();
    expect(
      within(dialog).getByLabelText("DeepSeek API key"),
    ).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Racer A provider")).toHaveValue(
      "deepseek-chat",
    );
    expect(within(dialog).getByLabelText("Racer C temperature")).toHaveValue(
      0.8,
    );
  });

  it("traps keyboard focus inside Settings and restores its opener", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", workspaceFetchMock());
    render(<App />);

    const opener = screen.getAllByRole("button", { name: "Settings" })[0];
    if (!opener) throw new Error("Settings opener not found.");
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", {
      name: "Power settings",
    });
    const close = within(dialog).getByRole("button", {
      name: "Close settings",
    });
    const save = within(dialog).getByRole("button", { name: "Save" });

    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(save).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(
      screen.queryByRole("dialog", { name: "Power settings" }),
    ).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("inspects an archive locally and enables a configured Power launch", async () => {
    const user = userEvent.setup();
    const fetchMock = workspaceFetchMock();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await configureDeepSeek(user);
    chooseArchive();

    expect(await screen.findByText("challenge.zip")).toBeInTheDocument();
    expect(
      within(screen.getByRole("region", { name: "Archive receipt" })).getByText(
        /crypto · suggested/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start Power" })).toBeEnabled();
    const racerBoard = screen.getByRole("region", {
      name: "Configured racers",
    });
    expect(within(racerBoard).queryByRole("combobox")).toBeNull();
    expect(
      within(racerBoard).getByRole("button", { name: "Edit in Settings" }),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/archive-intakes",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("requires an acknowledged TCP target before starting a remote race", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", workspaceFetchMock());
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");

    await user.click(screen.getByText("Target · optional"));
    await user.type(screen.getByLabelText("TCP host"), "ctf.local");
    expect(screen.getByRole("status")).toHaveTextContent("target_host_port");
    await user.type(screen.getByLabelText("TCP port"), "31337");
    expect(screen.getByRole("button", { name: "Start Power" })).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(
      "target_authorization",
    );
    await user.click(screen.getByLabelText("Authorized CTF target"));
    expect(screen.getByRole("button", { name: "Start Power" })).toBeEnabled();
  });

  it("submits exactly three configured racers and keeps the key in browser storage", async () => {
    const user = userEvent.setup();
    const fetchMock = workspaceFetchMock();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");
    fireEvent.change(screen.getByLabelText("Flag format"), {
      target: { value: "picoCTF{...}" },
    });
    fireEvent.change(screen.getByLabelText("Challenge description"), {
      target: { value: "Recover the flag from the supplied service source." },
    });

    await user.click(screen.getByRole("button", { name: "Start Power" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/v1/archive-intakes/${intake.intake_id}/power-runs`,
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const call = fetchMock.mock.calls.find(
      ([url, init]) =>
        url === `/v1/archive-intakes/${intake.intake_id}/power-runs` &&
        init?.method === "POST",
    );
    expect(call).toBeDefined();
    const body = JSON.parse((call![1] as RequestInit).body as string) as {
      racers: unknown[];
      provider_keys: Record<string, string>;
      flag_format: string;
      challenge_description: string;
    };
    expect(body.racers).toHaveLength(3);
    expect(body.flag_format).toBe("picoCTF{...}");
    expect(body.challenge_description).toBe("Recover the flag from the supplied service source.");
    expect(body.provider_keys["deepseek-chat"]).toBe("test-deepseek-key");
    expect(
      window.localStorage.getItem("ctfmesh.provider-credentials/v2"),
    ).toContain("test-deepseek-key");
  });

  it("reveals local candidate suggestions and reloads racers without sending the raw value", async () => {
    const user = userEvent.setup();
    const fetchMock = workspaceFetchMock();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");

    await user.click(screen.getByRole("button", { name: "Start Power" }));
    expect(await screen.findByRole("heading", { name: "Race strip" })).toBeInTheDocument();

    const candidateRegion = screen.getByRole("region", { name: "Candidates" });
    await user.click(within(candidateRegion).getByRole("button", { name: "Load from archive" }));
    expect(await within(candidateRegion).findByText("DH{manual_candidate}")).toBeInTheDocument();
    await user.click(within(candidateRegion).getByRole("button", { name: "Wrong" }));
    expect(within(candidateRegion).getByText("DH{manual_candidate}")).toBeInTheDocument();

    await user.click(within(candidateRegion).getByRole("button", { name: "Reload search" }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.filter(
          ([url, init]) =>
            typeof url === "string"
            && url.includes("/power-sessions/")
            && url.endsWith("/steer")
            && init?.method === "POST",
        ),
      ).toHaveLength(3),
    );
    const steerBodies = fetchMock.mock.calls
      .filter(
        ([url, init]) =>
          typeof url === "string"
          && url.includes("/power-sessions/")
          && url.endsWith("/steer")
          && init?.method === "POST",
      )
      .map(([, init]) => JSON.parse((init as RequestInit).body as string) as { message: string });
    expect(steerBodies.every((body) => !body.message.includes("DH{manual_candidate}"))).toBe(true);
  });

  it("loads every explicit runtime candidate for local review without placing values in steering", async () => {
    const user = userEvent.setup();
    const fetchMock = workspaceFetchMock();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");

    await user.click(screen.getByRole("button", { name: "Start Power" }));
    const candidateRegion = await screen.findByRole("region", { name: "Candidates" });
    await user.click(within(candidateRegion).getByRole("button", { name: "Scan runtime" }));

    expect(await within(candidateRegion).findByText("DH{runtime_candidate_one}")).toBeInTheDocument();
    expect(within(candidateRegion).getByText("DH{runtime_candidate_two}")).toBeInTheDocument();
    expect(within(candidateRegion).getByText("runtime · B, C")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/runs/run_power_0123456789abcdef/candidate-flags/reveal",
      expect.objectContaining({ method: "POST", cache: "no-store" }),
    );
  });

  it("confirms or rejects a paused runtime candidate through the candidate gate", async () => {
    const user = userEvent.setup();
    const pausedSnapshot: ConsoleSnapshot = {
      ...powerConsoleSnapshot,
      run: { ...powerConsoleSnapshot.run, status: "paused" },
    };
    const fetchMock = workspaceFetchMock({ consoleSnapshot: pausedSnapshot });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");

    await user.click(screen.getByRole("button", { name: "Start Power" }));
    const candidateRegion = await screen.findByRole("region", { name: "Candidates" });
    await user.click(within(candidateRegion).getByRole("button", { name: "Scan runtime" }));
    await user.click(within(candidateRegion).getAllByRole("button", { name: "Confirm" })[0]!);
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/v1/runs/run_power_0123456789abcdef/candidate-review/confirm",
        expect.objectContaining({ method: "POST", cache: "no-store" }),
      ),
    );
    const confirmCall = fetchMock.mock.calls.find(
      ([url]) => url === "/v1/runs/run_power_0123456789abcdef/candidate-review/confirm",
    );
    expect(confirmCall).toBeDefined();
    expect(JSON.parse((confirmCall?.[1] as RequestInit).body as string)).toEqual({
      confirm: true,
      candidate: "DH{runtime_candidate_one}",
    });

    // The second runtime candidate is a separate operator decision. Reject
    // it to resume the existing racers rather than launching a new race.
    await user.click(within(candidateRegion).getAllByRole("button", { name: "Wrong · continue" })[0]!);
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/v1/runs/run_power_0123456789abcdef/candidate-review/reject",
        expect.objectContaining({ method: "POST", cache: "no-store" }),
      ),
    );
  });

  it("starts a fresh Power run when candidate reload is requested after racers stop", async () => {
    const user = userEvent.setup();
    const solvedConsole: ConsoleSnapshot = {
      ...powerConsoleSnapshot,
      run: { ...powerConsoleSnapshot.run, status: "solved" },
    };
    const fetchMock = workspaceFetchMock({
      consoleSnapshot: solvedConsole,
      powerSessions: [
        { id: "session-a", label: "A", role: "racer", state: "aborted" },
        { id: "session-b", label: "B", role: "racer", state: "aborted" },
        { id: "session-c", label: "C", role: "racer", state: "aborted" },
      ],
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await configureDeepSeek(user);
    chooseArchive();
    await screen.findByText("challenge.zip");

    await user.click(screen.getByRole("button", { name: "Start Power" }));
    const candidateRegion = await screen.findByRole("region", { name: "Candidates" });
    await user.click(within(candidateRegion).getByRole("button", { name: "Load from archive" }));
    await screen.findByText("DH{manual_candidate}");
    await user.click(within(candidateRegion).getByRole("button", { name: "Wrong" }));
    await user.click(within(candidateRegion).getByRole("button", { name: "Reload search" }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.filter(
          ([url, init]) =>
            typeof url === "string"
            && url.endsWith("/power-runs")
            && init?.method === "POST",
        ),
      ).toHaveLength(2),
    );
    expect(
      fetchMock.mock.calls.some(
        ([url, init]) =>
          typeof url === "string"
          && url.includes("/power-sessions/")
          && url.endsWith("/steer")
          && init?.method === "POST",
      ),
    ).toBe(false);
  });

  it("reports a missing Power runtime without exposing provider controls", async () => {
    const fetchMock = workspaceFetchMock({ powerReady: false });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    chooseArchive();

    expect(await screen.findByRole("status")).toHaveTextContent(
      "missing: power_profile · provider_key:deepseek-chat",
    );
    expect(
      screen.getByRole("button", { name: "Start Power" }),
    ).toBeDisabled();
    expect(
      fetchMock.mock.calls.some(
        ([url]) =>
          typeof url === "string" && url.endsWith("/power-runs"),
      ),
    ).toBe(false);
    expect(screen.queryByLabelText(/API key/i)).toBeNull();
  });

  it("keeps Start disabled and names the missing provider key", async () => {
    vi.stubGlobal("fetch", workspaceFetchMock());
    render(<App />);
    chooseArchive();

    expect(await screen.findByRole("button", { name: "Start Power" })).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(
      "provider_key:deepseek-chat",
    );
  });
});
