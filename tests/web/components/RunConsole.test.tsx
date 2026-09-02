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

  it("shows reviewed Pi input and output and lets the operator steer an active racer", async () => {
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
    await user.click(within(racer).getByText(/Pi feed/));
    expect(within(racer).getByText("Category: web. Files: app.py.")).toBeInTheDocument();
    expect(within(racer).getByText("I will inspect the authentication handler next.")).toBeInTheDocument();
    await user.type(within(racer).getByRole("textbox", { name: "Direct racer A" }), "Check session validation before login.");
    await user.click(within(racer).getByRole("button", { name: "Send" }));
    await waitFor(() => expect(steer).toHaveBeenCalledWith("A", "Check session validation before login."));
  });

  it("shows each racer's reviewed tool command and bounded output", () => {
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

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    const terminal = screen.getByLabelText("Racer A tool terminal");
    expect(terminal).toHaveTextContent("ctf_fs_read");
    expect(terminal).toHaveTextContent("$ head -c 99 /challenge/app.py");
    expect(terminal).toHaveTextContent("db = connect()");
    expect(terminal).toHaveTextContent("[REDACTED_FLAG]");
    expect(terminal).toHaveTextContent("output capped");
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
      ],
    };

    render(<RunConsole snapshot={powerSnapshot} embedded />);

    expect(screen.queryByLabelText("Racer A tool terminal")).not.toBeInTheDocument();
    expect(screen.queryByText("CTF{do_not_render}")).not.toBeInTheDocument();
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

    await user.click(screen.getByRole("button", { name: "Stop" }));
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
    const { rerender } = render(
      <RunConsole snapshot={solvedSnapshot} embedded onRevealFlag={reveal} />,
    );

    expect(screen.queryByDisplayValue("HTB{verified-demo}")).not.toBeInTheDocument();
    await user.dblClick(screen.getByRole("button", { name: "Reveal flag" }));
    expect(reveal).toHaveBeenCalledOnce();
    expect(
      screen.getByRole("button", { name: "Revealing…" }),
    ).toBeDisabled();

    rerender(
      <RunConsole
        snapshot={solvedSnapshot}
        embedded
        onRevealFlag={reveal}
        revealedFlag="HTB{verified-demo}"
      />,
    );
    expect(screen.queryByRole("button", { name: "Reveal flag" })).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Verified flag" })).toHaveValue("HTB{verified-demo}");
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
