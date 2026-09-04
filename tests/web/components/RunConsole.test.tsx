import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { consoleTestSnapshot } from "../../../apps/web/src/fixtures/console";
import type { ConsoleSnapshot, HintTemplate } from "../../../apps/web/src/types";
import { RunConsole } from "../../../apps/web/src/components/RunConsole";

function useDrawerViewport(matches: boolean): void {
  const mediaQuery = {
    matches,
    media: "(max-width: 1199px)",
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  } as unknown as MediaQueryList;
  vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mediaQuery));
}

describe("RunConsole", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the run projection and evidence-centric navigation", async () => {
    const user = userEvent.setup();
    render(<RunConsole snapshot={consoleTestSnapshot} />);

    expect(screen.getByText("Imported artifact review")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("complementary", { name: "Chain of custody" })).toBeInTheDocument();
    expect(screen.getByText("From observation to replay")).toBeInTheDocument();
    const stages = screen.getByLabelText("Run stages");
    expect(within(stages).getAllByText("Complete")).toHaveLength(4);
    expect(within(stages).queryByText("Current")).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Verification/ }));
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).getByRole("heading", { name: "Verified" })).toBeInTheDocument();
    expect(within(panel).getByText("Replay ledger")).toBeInTheDocument();
    expect(within(panel).getByText("analysis-report.md")).toBeInTheDocument();
  });

  it("keeps completed triage proposals distinct from verified outcomes", async () => {
    const user = userEvent.setup();
    const triageSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        category: "ai_ml",
        current_stage: "triage",
        status: "completed",
        target_scope: "artifact://model-bundle",
        scope_kind: "artifact_bundle",
        execution_mode: "read_only_triage",
        provider_label: "openai-responses · read-only triage",
        triage: {
          read_only: true,
          actions_executed: 0,
          verification_attempted: false,
          selected_skill_ids: ["common.artifact-triage", "ai_ml.triage"],
        },
      },
      facts: [
        {
          ...consoleTestSnapshot.facts[0],
          state: "proposed",
        },
      ],
      hypotheses: [
        {
          ...consoleTestSnapshot.hypotheses[0],
          status: "open",
        },
      ],
      verification: {
        status: "pending",
        summary: "No verification was attempted in this read-only triage stage.",
        exploit_digest: null,
        environment_digest: null,
        flag: null,
        replay_required: 2,
        replay_passed: 0,
        flaky: false,
        replays: [],
      },
    };

    render(<RunConsole snapshot={triageSnapshot} />);

    expect(screen.getByRole("heading", { name: "Read-only triage remains a proposal" })).toBeInTheDocument();
    expect(screen.getByText("A proposal cannot solve a run.")).toBeInTheDocument();
    expect(screen.getByText("claims need evidence")).toBeInTheDocument();
    expect(within(screen.getByLabelText("Triage claim status")).getByText("2")).toBeInTheDocument();
    expect(screen.getAllByText("Declared scope")).not.toHaveLength(0);
    expect(screen.getAllByText("AI ML")).not.toHaveLength(0);
    expect(screen.getAllByText("openai-responses · read-only triage")).not.toHaveLength(0);
    expect(screen.getByText("common.artifact-triage · ai_ml.triage")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Proposed observation · not verified/ })).toBeInTheDocument();
    expect(within(screen.getByLabelText("Run stages")).getAllByText("Complete")).toHaveLength(1);

    await user.click(screen.getByRole("tab", { name: "Blackboard" }));
    expect(screen.getByRole("button", { name: /Open proposal · not verified/ })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Verification/ }));
    expect(screen.getByRole("heading", { name: "Verification record" })).toBeInTheDocument();
    expect(screen.getByText("No independent replay has been recorded for this run.")).toBeInTheDocument();
  });

  it("uses three Power racer columns and keeps the full trace explicit", async () => {
    const user = userEvent.setup();
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "failed",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-autoprompter",
          title: "Power autoprompter progress",
          summary: "AutoPrompter briefing started.",
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-racer-a",
          title: "Power command observed",
          summary: "Racer A: shell.exec (running).",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "State", content: { value: "running", classification: "public" } },
            { label: "Activity", content: { value: "Running a bounded analysis command.", classification: "public" } },
          ],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-failed",
          title: "Power swarm failed",
          summary: "Workspace could not read this archive. Restart the Power runtime, then retry.",
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.getByRole("heading", { name: "Race strip" })).toBeInTheDocument();
    expect(screen.getByLabelText("Power racer columns")).toHaveTextContent("Racer A");
    expect(screen.getByLabelText("Power racer columns")).toHaveTextContent("Racer B");
    expect(screen.getByLabelText("Power racer columns")).toHaveTextContent("Racer C");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Running a bounded analysis command.");
    expect(screen.queryByText("shell.exec (running)." )).not.toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Failed" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Blackboard" })).not.toBeInTheDocument();
    expect(screen.queryByText("Hint Deck")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open trace" }));
    expect(screen.getByRole("heading", { name: "Tool and verifier trace" })).toBeInTheDocument();
  });

  it("explains a Power budget stop as a reservation limit", () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "budget_exhausted",
        provider_label: "power-swarm",
      },
      budgets: consoleTestSnapshot.budgets.map((budget) => (
        budget.id === "cost"
          ? { ...budget, label: "Reserved cost", used: 10, limit: 10 }
          : budget
      )),
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-budget-exhausted",
          title: "Power swarm completed",
          summary: "Power swarm finished: budget_exhausted.",
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.getByText("Race cap reached")).toBeInTheDocument();
    expect(screen.getByLabelText("Run summary")).toHaveTextContent("$10.00 / $10.00");
    expect(screen.getByText("Adjust limits in Settings before retrying.")).toBeInTheDocument();
  });

  it("shows a Power racer's safe activity and evidence count without a transcript", () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-racer-safe-receipt",
          title: "Power command observed",
          summary: "Racer A: fs.ls (running).",
          tool_name: "fs.ls",
          details: [
            { label: "Turn", content: { value: "4", classification: "public" } },
            { label: "Activity", content: { value: "Mapping workspace files.", classification: "public" } },
            { label: "Evidence count", content: { value: "4", classification: "public" } },
          ],
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Mapping workspace files.");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Actions4");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Observations4");
    expect(screen.getByLabelText("Reviewed Power activity")).toHaveTextContent("racer-A");
    expect(screen.getByLabelText("Reviewed Power activity")).toHaveTextContent("Mapping workspace files.");
    expect(screen.queryByText("rm -rf /challenge")).not.toBeInTheDocument();
  });

  it("streams reviewed Pi input and output and lets the operator steer an active racer", async () => {
    const user = userEvent.setup();
    const steer = vi.fn(async () => undefined);
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-pi-brief",
          title: "Power pi activity",
          summary: "Racer A: Pi prompt recorded.",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "Message kind", content: { value: "prompt", classification: "public" } },
            { label: "Message", content: { value: "Category: web. Files: app.py.", classification: "public" } },
          ],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-pi-response",
          title: "Power pi activity",
          summary: "Racer A: Pi response recorded.",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "Message kind", content: { value: "response", classification: "public" } },
            { label: "Message", content: { value: "I will inspect the authentication handler next.", classification: "public" } },
          ],
        },
      ],
    };

    render(
      <RunConsole
        snapshot={powerSnapshot}
        embedded
        powerSessions={[{ id: "session-a", label: "A", role: "racer", state: "running" }]}
        onSteerRacer={steer}
      />,
    );

    const racer = screen.getByLabelText("Racer A");
    expect(within(racer).getByText("static analysis")).toBeInTheDocument();
    expect(within(racer).getByText("Running")).toBeInTheDocument();
    const terminal = within(racer).getByLabelText("Racer A live terminal");
    expect(terminal).toHaveTextContent("Pi terminal");
    // The stream belongs to the lane the operator chose to follow. Three of
    // them open at once is what pushed the candidate desk off the screen.
    await user.click(within(terminal).getByRole("button", { name: "Follow lane A" }));
    expect(terminal).toHaveTextContent("Category: web. Files: app.py.");
    expect(terminal).toHaveTextContent("I will inspect the authentication handler next.");
    const steerBox = within(racer).getByRole("textbox", { name: "Steer racer A" });
    await user.type(steerBox, "Check session validation before login.");
    await user.keyboard("{Control>}{Enter}{/Control}");
    await waitFor(() => expect(steer).toHaveBeenCalledWith("A", "Check session validation before login."));
    expect(within(racer).getByText("Steer queued — waiting for Pi.")).toBeInTheDocument();
  });

  it("offers the sealed bytes behind a receipt, and only for a real digest", async () => {
    // A receipt shows redacted output capped at 6 KiB, so a script a racer
    // wrote is only complete in the sealed observation. Those bytes were
    // reachable by API but nothing an operator could see named the artifact,
    // so recovering one meant reading the artifact store on the host.
    const user = userEvent.setup();
    const save = vi.fn().mockResolvedValue(undefined);
    const digest = `sha256:${"a".repeat(64)}`;
    const receipt = (id: string, artifactId: string) => ({
      ...consoleTestSnapshot.events[0],
      id,
      title: "Power pi tool transcript",
      summary: "Racer A: ctf_fs_write completed.",
      details: [
        { label: "Racer", content: { value: "A", classification: "public" as const } },
        { label: "Tool", content: { value: "ctf_fs_write", classification: "public" as const } },
        { label: "Command", content: { value: "write poc.py", classification: "public" as const } },
        { label: "Output", content: { value: "import socket", classification: "public" as const } },
        { label: "Exit code", content: { value: "0", classification: "public" as const } },
        { label: "Timed out", content: { value: "no", classification: "public" as const } },
        { label: "Output capped", content: { value: "yes", classification: "public" as const } },
        { label: "Artifact id", content: { value: artifactId, classification: "public" as const } },
      ],
    });

    render(
      <RunConsole
        snapshot={{
          ...consoleTestSnapshot,
          run: { ...consoleTestSnapshot.run, status: "running", provider_label: "power-swarm" },
          // The second receipt names something that is not a store digest. A
          // receipt cannot be allowed to point the console at an arbitrary
          // path, so it gets no control at all.
          events: [receipt("receipt-real", digest), receipt("receipt-forged", "../../etc/passwd")],
        }}
        embedded
        onSaveArtifact={save}
      />,
    );

    const racer = screen.getByLabelText("Racer A");
    await user.click(within(racer).getByText(/^Tool history$/));
    const buttons = within(racer).getAllByRole("button", { name: "Save bytes" });
    expect(buttons).toHaveLength(1);
    await user.click(buttons[0]);
    expect(save).toHaveBeenCalledWith(digest);
  });

  it("distinguishes sealed artifacts by size and offers the bytes of each", async () => {
    // Every row read "1 KB": the size was rounded up to a one-kilobyte floor,
    // so an empty result, a 30-byte reply and a 3.7 KB exploit script were
    // indistinguishable in the one column an operator scans to find them.
    const user = userEvent.setup();
    const save = vi.fn().mockResolvedValue(undefined);
    const artifact = (sha: string, size: number) => ({
      id: `sha256:${sha}`,
      name: `observation-${sha.slice(0, 12)}`,
      media_type: "application/octet-stream",
      digest: `sha256:${sha}`,
      size_bytes: size,
      classification: "secret" as const,
    });

    render(
      <RunConsole
        snapshot={{
          ...consoleTestSnapshot,
          artifacts: [artifact("a".repeat(64), 0), artifact("b".repeat(64), 30), artifact("c".repeat(64), 3_704)],
        }}
        embedded
        onSaveArtifact={save}
      />,
    );

    await user.click(screen.getByRole("tab", { name: /Verification/ }));
    const table = screen.getByRole("table", { name: "Sealed artifacts" });
    expect(within(table).getByText("0 B")).toBeInTheDocument();
    expect(within(table).getByText("30 B")).toBeInTheDocument();
    expect(within(table).getByText("3.6 KB")).toBeInTheDocument();

    // An empty observation has no bytes worth releasing, so it offers nothing.
    const saves = within(table).getAllByRole("button", { name: "Save" });
    expect(saves).toHaveLength(2);
    await user.click(saves[1]);
    expect(save).toHaveBeenCalledWith(`sha256:${"c".repeat(64)}`);
  });

  it("stops calling a parked Power run a race", () => {
    // The run status stays "running" while the sessions hold their leases, so
    // the status the header derives from it kept reading "Racing" through a
    // stall the operator was paying wall time for.
    const idleSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: { ...consoleTestSnapshot.run, status: "running", provider_label: "power-swarm" },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-move",
          sequence: 1,
          title: "Power command observed",
          summary: "Racer A: ctf_shell_exec observed.",
          details: [],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-idle",
          sequence: 2,
          title: "Power sessions idle",
          summary: "Every Power session is idle; steer a racer or stop the run.",
          details: [],
        },
      ],
    };

    const { rerender } = render(<RunConsole snapshot={idleSnapshot} embedded />);
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("Idle");
    expect(status).not.toHaveTextContent("Racing");
    expect(status).toHaveAccessibleName(/steer one or stop the run/);

    // A racer that moves again ends the idle state without a status change.
    rerender(
      <RunConsole
        snapshot={{
          ...idleSnapshot,
          events: [
            ...idleSnapshot.events,
            {
              ...consoleTestSnapshot.events[0],
              id: "power-move-again",
              sequence: 3,
              title: "Power pi tool transcript",
              summary: "Racer A: ctf_shell_exec completed.",
              details: [],
            },
          ],
        }}
        embedded
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Racing");
  });

  it("shows each racer's reviewed tool command and bounded output", async () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-pi-terminal-a",
          title: "Power pi tool transcript",
          summary: "Racer A: ctf_fs_read completed.",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "Tool", content: { value: "ctf_fs_read", classification: "public" } },
            { label: "Command", content: { value: "head -c 99 /challenge/app.py", classification: "public" } },
            { label: "Output", content: { value: "db = connect()\n[REDACTED_FLAG]", classification: "public" } },
            { label: "Exit code", content: { value: "0", classification: "public" } },
            { label: "Timed out", content: { value: "no", classification: "public" } },
            { label: "Output capped", content: { value: "yes", classification: "public" } },
          ],
        },
      ],
    };

    const user = userEvent.setup();
    render(<RunConsole snapshot={powerSnapshot} embedded />);

    const liveIo = screen.getByLabelText("Racer A live terminal");
    expect(liveIo).toHaveTextContent("Pi terminal");
    expect(within(liveIo).getByText("ctf_fs_read")).toBeInTheDocument();

    // Collapsed, the lane names its move and the numbers that qualify it, and
    // spends none of the column on argv the operator is not reading.
    expect(liveIo).toHaveTextContent("Read a workspace file");
    expect(liveIo).toHaveTextContent("30 B captured");
    expect(liveIo).not.toHaveTextContent("head -c 99");
    expect(liveIo).not.toHaveTextContent("db = connect()");

    await user.click(within(liveIo).getByRole("button", { name: "Follow lane A" }));
    const liveStream = within(liveIo).getByLabelText("Racer A live input and output");
    expect(within(liveStream).getByLabelText("Racer A live command")).toHaveTextContent(
      "$ head -c 99 /challenge/app.py",
    );
    expect(within(liveStream).getByLabelText("Racer A live output")).toHaveTextContent(
      /db = connect\(\)\s+\[REDACTED_FLAG\]/,
    );
    expect(liveIo).toHaveTextContent("output capped");

    // The reviewed live stream is visible for the followed lane. The redundant
    // full tool history is still available on demand.
    const racer = screen.getByLabelText("Racer A");
    expect(within(racer).getByText(/^Tool history$/).closest("details")).not.toHaveAttribute("open");

    // Collapsing puts the lane back to its receipt.
    await user.click(within(liveIo).getByRole("button", { name: "Collapse lane A" }));
    expect(liveIo).not.toHaveTextContent("head -c 99");
    expect(liveIo).toHaveTextContent("Read a workspace file");
  });

  it("rejects a terminal event that still contains a raw flag or credential", () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: { ...consoleTestSnapshot.run, status: "running", provider_label: "power-swarm" },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-hostile-terminal",
          title: "Power pi tool transcript",
          summary: "Racer A: ctf_shell_exec completed.",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "Tool", content: { value: "ctf_shell_exec", classification: "public" } },
            { label: "Command", content: { value: "cat /challenge/flag", classification: "public" } },
            { label: "Output", content: { value: "CTF{do_not_render}", classification: "public" } },
            { label: "Exit code", content: { value: "0", classification: "public" } },
            { label: "Timed out", content: { value: "no", classification: "public" } },
            { label: "Output capped", content: { value: "no", classification: "public" } },
          ],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-hostile-partial-pi-response",
          title: "Power pi activity",
          summary: "Racer A: Pi response recorded.",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "Message kind", content: { value: "response", classification: "public" } },
            { label: "Message", content: { value: "Candidate DH{partial_not_for_terminal", classification: "public" } },
          ],
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.queryByLabelText("Racer A tool terminal")).not.toBeInTheDocument();
    expect(screen.queryByText("CTF{do_not_render}")).not.toBeInTheDocument();
    expect(screen.queryByText("DH{partial_not_for_terminal")).not.toBeInTheDocument();
  });

  it("shows only an allowlisted provider failure diagnostic", () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "failed",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-provider-auth-failure",
          title: "Power pi session failed",
          summary: "power.pi.session.failed",
          details: [{
            label: "Failure",
            content: { value: "Provider rejected the saved API key.", classification: "public" },
          }],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-hostile-failure",
          title: "Power pi session failed",
          summary: "power.pi.session.failed",
          details: [{
            label: "Failure",
            content: { value: "raw upstream body with secret", classification: "public" },
          }],
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.getAllByText("Provider rejected the saved API key.").length).toBeGreaterThan(0);
    expect(screen.queryByText(/raw upstream body with secret/)).not.toBeInTheDocument();
  });

  it("shows actual Power header metrics, supports Stop, and rejects unreviewed activity text", async () => {
    const user = userEvent.setup();
    const cancel = vi.fn();
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        started_at: new Date().toISOString(),
        elapsed_seconds: 12,
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-safe-action",
          title: "Power command observed",
          summary: "Racer A: fs.read (running).",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "State", content: { value: "running", classification: "public" } },
            { label: "Turn", content: { value: "7", classification: "public" } },
            { label: "Activity", content: { value: "Reading one challenge file.", classification: "public" } },
            { label: "Evidence count", content: { value: "6", classification: "public" } },
          ],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-hostile-action",
          title: "Power command observed",
          summary: "Racer B: do-not-render-this --secret token (running).",
          details: [
            { label: "Racer", content: { value: "B", classification: "public" } },
            { label: "State", content: { value: "running", classification: "public" } },
            { label: "Activity", content: { value: "rm -rf /challenge --token secret", classification: "public" } },
          ],
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded onCancel={cancel} />);

    expect(screen.getByRole("status", { name: "Racing" })).toBeInTheDocument();
    expect(screen.getByLabelText("Run summary")).toHaveTextContent(/0:1[2-9] \/ 30:00/);
    expect(screen.getByLabelText("Run summary")).toHaveTextContent("$1.82 / $5.00");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Actions7");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Observations6");
    expect(screen.getByLabelText("Racer B")).toHaveTextContent("No reviewed action yet.");
    expect(screen.queryByText(/do-not-render-this|rm -rf|secret/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stop all" }));
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("projects current Pi action receipts and derives live counters", () => {
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
      events: [
        {
          ...consoleTestSnapshot.events[0],
          id: "power-pi-exec-1",
          title: "Power command observed",
          summary: "Racer A: exec (running).",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "State", content: { value: "running", classification: "public" } },
            { label: "Action", content: { value: "exec", classification: "public" } },
            { label: "Activity", content: { value: "Typed sandbox action completed.", classification: "public" } },
            { label: "Evidence", content: { value: "Captured immutable observation.", classification: "public" } },
          ],
        },
        {
          ...consoleTestSnapshot.events[0],
          id: "power-pi-exec-2",
          title: "Power command observed",
          summary: "Racer A: exec (running).",
          details: [
            { label: "Racer", content: { value: "A", classification: "public" } },
            { label: "State", content: { value: "running", classification: "public" } },
            { label: "Action", content: { value: "exec", classification: "public" } },
            { label: "Activity", content: { value: "Typed sandbox action completed.", classification: "public" } },
            { label: "Evidence", content: { value: "Captured immutable observation.", classification: "public" } },
          ],
        },
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Actions2");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Observations2");
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Running a bounded analysis command.");
    expect(screen.getByLabelText("Reviewed Power activity")).toHaveTextContent(
      "Running a bounded analysis command.",
    );
    expect(screen.queryByText("Typed sandbox action completed.")).not.toBeInTheDocument();
  });

  it("shows manual candidate review controls and reload steering", async () => {
    const user = userEvent.setup();
    const mark = vi.fn();
    const reveal = vi.fn().mockResolvedValue(undefined);
    const findMore = vi.fn().mockResolvedValue(undefined);
    const powerSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
    };

    render(
      <RunConsole
        snapshot={powerSnapshot}
        embedded
        candidateSuggestions={[
          {
            id: "candidate-one",
            value: "DH{manual_candidate}",
            source: "archive",
            status: "unreviewed",
            createdAt: "2026-09-02T10:00:00Z",
          },
        ]}
        canRevealInputCandidates
        onRevealInputCandidates={reveal}
        onFindMoreCandidates={findMore}
        onMarkCandidate={mark}
      />,
    );

    const region = screen.getByRole("region", { name: "Candidates" });
    expect(within(region).getByText("DH{manual_candidate}")).toBeInTheDocument();
    expect(within(region).getByText("Unchecked")).toBeInTheDocument();

    // The player scores the value on the challenge's own platform, so it has
    // to leave this screen before Confirm or Wrong can mean anything. Reading
    // it out of a code element by hand was the only way to do that.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    await user.click(within(region).getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith("DH{manual_candidate}");
    expect(within(region).getByRole("button", { name: "Copied" })).toBeInTheDocument();

    await user.click(within(region).getByRole("button", { name: "Dismiss" }));
    expect(mark).toHaveBeenCalledWith("candidate-one", "manual_rejected");
    await user.click(within(region).getByRole("button", { name: "Load from archive" }));
    expect(reveal).toHaveBeenCalledOnce();
    await user.click(within(region).getByRole("button", { name: "Reload search" }));
    expect(findMore).toHaveBeenCalledOnce();
  });

  it("holds only the source lane while sibling racers remain visible", async () => {
    const user = userEvent.setup();
    const mark = vi.fn();
    const findMore = vi.fn().mockResolvedValue(undefined);
    const stopAll = vi.fn();
    const runningSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "running",
        provider_label: "power-swarm",
      },
    };

    render(
      <RunConsole
        snapshot={runningSnapshot}
        embedded
        powerSessions={[
          { id: "session-a", label: "A", role: "racer", state: "awaiting_review" },
          { id: "session-b", label: "B", role: "racer", state: "running" },
          { id: "session-c", label: "C", role: "racer", state: "ready" },
        ]}
        candidateSuggestions={[
          {
            id: "candidate-runtime",
            value: "DH{runtime_candidate}",
            source: "runtime",
            status: "unreviewed",
            createdAt: "2026-09-02T10:00:00Z",
            racerLabels: ["A"],
            racerSessionIds: ["session-a"],
            reviewEligible: true,
          },
        ]}
        onFindMoreCandidates={findMore}
        onMarkCandidate={mark}
        onCancel={stopAll}
      />,
    );

    const region = screen.getByRole("region", { name: "Candidates" });
    expect(within(region).getByText("Review needed")).toBeInTheDocument();
    expect(screen.getByLabelText("Racer A")).toHaveTextContent("Review");
    expect(screen.getByLabelText("Racer B")).toHaveTextContent("Running");
    expect(within(region).queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    await user.click(within(region).getByRole("button", { name: "Confirm" }));
    expect(mark).toHaveBeenCalledWith("candidate-runtime", "manual_valid");
    await user.click(within(region).getByRole("button", { name: "Reload search" }));
    expect(findMore).toHaveBeenCalledOnce();
    await user.click(within(region).getByRole("button", { name: "Stop all" }));
    expect(stopAll).toHaveBeenCalledOnce();
  });

  it("reveals a verified Power flag once even after a repeated click", async () => {
    const user = userEvent.setup();
    const reveal = vi.fn();
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    const solvedSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      run: {
        ...consoleTestSnapshot.run,
        status: "solved",
        provider_label: "power-swarm",
      },
    };
    const sourcedSolvedSnapshot: ConsoleSnapshot = {
      ...solvedSnapshot,
      events: [
        ...solvedSnapshot.events,
        {
          sequence: 999,
          id: "power-candidate-confirmed",
          occurred_at: "2026-09-02T10:00:00Z",
          kind: "verifier",
          title: "Power candidate review confirmed",
          summary: "Racer B candidate confirmed for independent verification.",
          details: [
            { label: "Racer", content: { value: "B", classification: "public" } },
          ],
          artifact_refs: [],
          related_refs: [],
        },
      ],
    };
    const { rerender } = render(
      <RunConsole snapshot={sourcedSolvedSnapshot} embedded onRevealFlag={reveal} />,
    );

    const revealRegion = screen.getByRole("region", { name: "Verified flag" });
    expect(within(revealRegion).getByText("Racer B")).toBeInTheDocument();
    expect(within(revealRegion).getByRole("link", { name: "Export Markdown" })).toHaveAttribute(
      "href",
      "/v1/runs/run_test_projection_001/writeup",
    );
    expect(
      revealRegion.compareDocumentPosition(screen.getByRole("tablist", { name: "Run console views" }))
      & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(screen.queryByDisplayValue("HTB{verified-demo}")).not.toBeInTheDocument();
    await user.dblClick(screen.getByRole("button", { name: "Reveal flag" }));
    expect(reveal).toHaveBeenCalledOnce();
    expect(
      screen.getByRole("button", { name: "Revealing…" }),
    ).toBeDisabled();

    rerender(
      <RunConsole
        snapshot={sourcedSolvedSnapshot}
        embedded
        onRevealFlag={reveal}
        revealedFlag="HTB{verified-demo}"
      />,
    );
    expect(screen.queryByRole("button", { name: "Reveal flag" })).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Raw flag" })).toHaveValue("HTB{verified-demo}");
    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(writeText).toHaveBeenCalledWith("HTB{verified-demo}");
    expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("never places sensitive trace or flag values in the DOM", async () => {
    const user = userEvent.setup();
    render(<RunConsole snapshot={consoleTestSnapshot} />);

    await user.click(screen.getByRole("tab", { name: "Trace" }));
    await user.click(screen.getByRole("button", { name: "Show details for event 184" }));

    expect(screen.queryByText("restricted-test-value")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Restricted metadata masked")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Verification/ }));
    expect(screen.queryByText("restricted-test-value")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Verification evidence masked")).toBeInTheDocument();
  });

  it("renders hostile evidence as escaped React text", async () => {
    const user = userEvent.setup();
    const payload = '<img src=x onerror="window.__ctfmeshXss = true">';
    const maliciousSnapshot: ConsoleSnapshot = {
      ...consoleTestSnapshot,
      facts: [
        {
          ...consoleTestSnapshot.facts[0],
          statement: payload,
        },
      ],
    };

    render(<RunConsole snapshot={maliciousSnapshot} />);
    await user.click(screen.getByRole("tab", { name: "Blackboard" }));

    expect(screen.getByText(payload)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(document.body.innerHTML).not.toContain("<img");
  });

  it("renders the Hint Deck as unverified scheduler guidance with auditable links", async () => {
    const user = userEvent.setup();
    const attach = vi.fn(async () => undefined);
    const template: HintTemplate = {
      id: "web.path_traversal.suspect.v1",
      version: 1,
      label: "Suspect path traversal",
      technique_id: "web.path_traversal",
      category: "suspected_vulnerability",
      default_directive: "prioritize",
      recommended_roles: ["source_auditor", "http_tester"],
      recommended_tools: ["source.search", "source.read", "http.request"],
      branch_seed: "Check path normalization and the declared file boundary.",
      falsifiers: ["control path"],
    };

    render(
      <RunConsole
        snapshot={{
          ...consoleTestSnapshot,
          run: { ...consoleTestSnapshot.run, status: "running" },
          hints: [{ ...consoleTestSnapshot.hints[0], status: "active" }],
        }}
        hintTemplates={[template]}
        onCreateHint={attach}
      />,
    );

    expect(screen.getByRole("heading", { name: "Hint Deck" })).toBeInTheDocument();
    expect(screen.getByText("Human hypothesis · evidence required")).toBeInTheDocument();
    expect(screen.getByText("Scheduler impact")).toBeInTheDocument();
    expect(screen.getByText("Evidence timeline")).toBeInTheDocument();
    expect(screen.getByText(/The template fixes allowed roles and tools/)).toBeInTheDocument();

    // Filters operate on reviewed card metadata, not a free-form note.
    const filter = screen.getByRole("searchbox", { name: "Filter attached Hint Cards" });
    await user.type(filter, "unmatched-technique");
    expect(screen.getByText("No attached Hint Card matches this reviewed metadata filter.")).toBeInTheDocument();
    await user.clear(filter);

    await user.type(screen.getByLabelText(/Local note/), "Confirm only with sealed evidence.");
    await user.click(screen.getByRole("button", { name: "Attach Hint Card" }));
    expect(attach).toHaveBeenCalledWith({
      template_id: template.id,
      directive: "prioritize",
      target_ref: "run:all",
      priority: 3,
      note: "Confirm only with sealed evidence.",
    });

    // The custody drawer also contains the same evidence label; constrain the
    // interaction to the Hint Deck link being exercised by this regression.
    await user.click(screen.getAllByRole("button", { name: /E-014/ })[0]);
    expect(screen.getByRole("heading", { name: "Tool and verifier trace" })).toBeInTheDocument();
  });

  it("removes closed mobile custody controls from the focusable drawer and restores focus on close", async () => {
    useDrawerViewport(true);
    const user = userEvent.setup();
    render(<RunConsole snapshot={consoleTestSnapshot} />);

    const toggle = screen.getByRole("button", { name: "Evidence path" });
    const drawer = screen.getByRole("dialog", { hidden: true });
    expect(drawer).toHaveAttribute("aria-hidden", "true");
    expect(drawer.querySelectorAll("button")).toHaveLength(0);

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(drawer).not.toHaveAttribute("aria-hidden");
    expect(drawer).toHaveAttribute("aria-modal", "true");
    expect(screen.getByRole("dialog", { name: "Chain of custody" })).toBe(drawer);
    await waitFor(() => {
      expect(within(drawer).getByRole("button", { name: "Close evidence path" })).toHaveFocus();
    });

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(drawer).toHaveAttribute("aria-hidden", "true");
      expect(toggle).toHaveFocus();
    });
    expect(drawer.querySelectorAll("button")).toHaveLength(0);
  });
});
