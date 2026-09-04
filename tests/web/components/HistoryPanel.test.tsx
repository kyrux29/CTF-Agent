import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  ArchiveIntakeSummary,
  TrackedRunSummary,
} from "../../../apps/web/src/api";
import { HistoryPanel } from "../../../apps/web/src/components/HistoryPanel";

const archive: ArchiveIntakeSummary = {
  intake_id: "intake_archive_0123456789abcdef",
  created_at: "2026-09-02T01:00:00Z",
  name: "archive-super-long-original-challenge-name.zip",
  format: "zip",
  file_count: 9,
  expanded_size_bytes: 4096,
  category: "crypto",
  ai_status: "not_requested",
};

const run: TrackedRunSummary = {
  id: "run_failed_123",
  challengeId: "challenge_123",
  status: "failed",
  createdAt: "2026-09-02T01:00:00Z",
  updatedAt: "2026-09-02T01:02:00Z",
};

describe("HistoryPanel", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("filters archives and runs by their searchable metadata", async () => {
    const user = userEvent.setup();
    render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={vi.fn()}
        onOpenRun={vi.fn()}
        onRemoveArchive={vi.fn()}
      />,
    );

    const search = screen.getByRole("searchbox", { name: "Search history" });
    await user.type(search, "failed");

    expect(screen.getByText("run_failed_123")).toBeInTheDocument();
    expect(screen.queryByText(/archive-super-long/)).not.toBeInTheDocument();
    expect(
      within(screen.getByRole("region", { name: "Archives history" })).getByText(
        "No match.",
      ),
    ).toBeInTheDocument();
  });

  it("persists aliases and reversible hide without mutating evidence APIs", async () => {
    const user = userEvent.setup();
    const openArchive = vi.fn();
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
    const view = render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={openArchive}
        onOpenRun={vi.fn()}
        onRemoveArchive={vi.fn()}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: "Actions for archive-super-long…",
      }),
    );
    await user.click(screen.getByRole("menuitem", { name: "Rename" }));
    const input = screen.getByRole("textbox", {
      name: `Display name for ${archive.name}`,
    });
    await user.clear(input);
    await user.type(input, "Crypto warmup");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(screen.getByText("Crypto warmup")).toBeInTheDocument();
    expect(screen.getByText(/archive-super-long… · crypto/)).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Actions for Crypto warmup" }),
    );
    await user.click(screen.getByRole("menuitem", { name: "Hide" }));
    expect(screen.getByText("Hide from History?")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm hide" }));

    expect(screen.queryByText("Crypto warmup")).not.toBeInTheDocument();
    expect(
      screen.getByText("Hidden from History. Server data was not deleted."),
    ).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(openArchive).not.toHaveBeenCalled();

    view.unmount();
    render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={openArchive}
        onOpenRun={vi.fn()}
        onRemoveArchive={vi.fn()}
      />,
    );
    expect(screen.queryByText("Crypto warmup")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Restore 1" }));
    await user.click(screen.getByText("Crypto warmup"));

    expect(openArchive).toHaveBeenCalledWith(archive);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps permanent archive removal distinct from reversible hide", async () => {
    const user = userEvent.setup();
    const removeArchive = vi.fn(async () => undefined);
    render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={vi.fn()}
        onOpenRun={vi.fn()}
        onRemoveArchive={removeArchive}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: "Actions for archive-super-long…",
      }),
    );
    const archiveMenu = screen.getByRole("menu");
    await user.click(within(archiveMenu).getByRole("menuitem", { name: "Remove" }));
    expect(screen.getByText("Remove archive and files?")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove permanently" }));

    expect(removeArchive).toHaveBeenCalledOnce();
    expect(removeArchive).toHaveBeenCalledWith(archive);
    expect(screen.getByText("Archive removed permanently.")).toBeInTheDocument();

    // Without a removal handler a run offers only the reversible action.
    await user.click(screen.getByRole("button", { name: "Actions for run_failed_123" }));
    expect(screen.queryByRole("menuitem", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Hide" })).toBeInTheDocument();
  });

  it("names what a run removal actually destroys", async () => {
    // Hiding a run affects one browser. Removing it erases the ledger, the
    // transcripts a continuation resumes from, and the sealed observations.
    // The confirmation said "Remove archive and files?" for both, which
    // described neither the loss nor the object.
    const user = userEvent.setup();
    const removeRun = vi.fn(async () => undefined);
    render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={vi.fn()}
        onOpenRun={vi.fn()}
        onRemoveArchive={vi.fn(async () => undefined)}
        onRemoveRun={removeRun}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Actions for run_failed_123" }));
    const menu = screen.getByRole("menu");
    await user.click(within(menu).getByRole("menuitem", { name: "Remove" }));
    expect(screen.getByText("Remove run, its ledger and its evidence?")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove permanently" }));

    expect(removeRun).toHaveBeenCalledWith(run.id);
    expect(screen.getByText("Run removed permanently.")).toBeInTheDocument();
  });

  it("reports the API's refusal to remove a run that is still live", async () => {
    const user = userEvent.setup();
    const removeRun = vi.fn(async () => {
      throw new Error("Stop this run before removing it.");
    });
    render(
      <HistoryPanel
        archives={[archive]}
        runs={[run]}
        onOpenArchive={vi.fn()}
        onOpenRun={vi.fn()}
        onRemoveArchive={vi.fn(async () => undefined)}
        onRemoveRun={removeRun}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Actions for run_failed_123" }));
    await user.click(
      within(screen.getByRole("menu")).getByRole("menuitem", { name: "Remove" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove permanently" }));

    expect(screen.getByText("Stop this run before removing it.")).toBeInTheDocument();
  });
});
