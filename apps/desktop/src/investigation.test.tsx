import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { ChronologyView, EvidenceDrawer, GraphView, QuickCheckView, type QuickCheck } from "./investigation";

const tauri = vi.hoisted(() => ({ invoke: vi.fn(), listen: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: tauri.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: tauri.listen }));

const quickCheck: QuickCheck = {
  policyVersion: "2",
  policySha256: "a".repeat(64),
  band: "review",
  findingCounts: { contextual: 0, low: 1, medium: 0, high: 0, total: 1 },
  topFindings: [{ findingId: "finding-1", title: "Review imported API", category: "capability", severity: "low", evidenceFamily: "capability" }],
  evidenceFamilies: [{ family: "capability", findingCount: 1, contributingFindingCount: 1, strongestSeverity: "low" }],
  statement: "One static capability warrants review.",
};

function analysis(runId = "run-1") {
  return {
    case: { id: "case-1", title: "inert.exe", createdAt: "2026-08-25T00:00:00Z", status: "complete" },
    artifact: { id: "artifact-1", sha256: "a".repeat(64), sha1: "b".repeat(40), md5: "c".repeat(32), sizeBytes: 2048, kind: "pe64", originalName: "inert.exe" },
    run: { id: runId, artifactId: "artifact-1", analyzer: "traceforge.pe", analyzerVersion: "1", startedAt: runId === "run-old" ? "2026-08-24T00:00:00Z" : "2026-08-25T00:00:00Z", finishedAt: "2026-08-25T00:00:01Z", status: "complete", errorCode: null },
    evidence: [], findings: [], provenances: [], runHistory: [], bookmarks: [], quickCheck,
  };
}

async function expectNoAxeViolations(container: HTMLElement) {
  const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(result.violations.map((violation) => violation.id)).toEqual([]);
}

beforeEach(() => {
  tauri.invoke.mockReset();
  tauri.listen.mockReset();
  tauri.listen.mockResolvedValue(() => undefined);
});

describe("investigation components", () => {
  it("connects Quick Check finding, evidence, and bookmark workflows", async () => {
    const user = userEvent.setup();
    const onFinding = vi.fn();
    const onEvidence = vi.fn();
    const onBookmark = vi.fn();
    const { container } = render(<main><QuickCheckView
      check={quickCheck}
      findings={[{ id: "finding-1", ruleId: "TF-1", ruleVersion: "1", title: "Review imported API", category: "capability", severity: "low", evidence: [{ evidenceId: "evidence-1", role: "supports" }] }]}
      onBookmark={onBookmark}
      onEvidence={onEvidence}
      onFinding={onFinding}
    /></main>);
    expect(screen.getByRole("heading", { name: "review" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Open finding" }));
    await user.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await user.click(screen.getByRole("button", { name: "Bookmark" }));
    expect(onFinding).toHaveBeenCalledWith("finding-1");
    expect(onEvidence).toHaveBeenCalledWith("evidence-1", expect.any(HTMLElement));
    expect(onBookmark).toHaveBeenCalledWith({ targetType: "finding", targetId: "finding-1" }, "Review imported API");
    await expectNoAxeViolations(container);
  });

  it("names the evidence dialog, wraps Tab focus, closes on Escape, and passes axe", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { container } = render(<main><EvidenceDrawer
      evidence={[{ id: "evidence-1", artifactId: "artifact-1", provenanceId: "provenance-1", kind: "pe.import", class: "observed", locator: { file_offset: 12 }, value: { dll: "KERNEL32.dll", function: "CreateFileW" }, previewText: "KERNEL32.dll!CreateFileW" }]}
      evidenceId="evidence-1"
      findings={[]}
      graph={null}
      onBookmark={vi.fn()}
      onClose={onClose}
      provenances={[{ id: "provenance-1", analysisRunId: "run-1", analyzer: "traceforge.pe", analyzerVersion: "1", inputSha256: "a".repeat(64) }]}
    /></main>);
    const dialog = screen.getByRole("dialog", { name: "pe.import" });
    const close = screen.getByRole("button", { name: "Close evidence inspector" });
    const summary = screen.getByText("Raw persisted JSON");
    await waitFor(() => expect(document.activeElement).toBe(close));
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(summary);
    await user.tab();
    expect(document.activeElement).toBe(close);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    await expectNoAxeViolations(container);
  });

  it("provides graph zoom controls and lists isolated entities in the keyboard fallback", async () => {
    const { container } = render(<GraphView
      focusTarget={null}
      graph={{ caseId: "case-1", projectionVersion: 1, sourceAnalysisRunId: "run-1", entities: [{ id: "entity-1", caseId: "case-1", entityType: "file", canonicalValue: "isolated.exe", displayValue: "isolated.exe", metadata: {} }], edges: [], entityEvidence: [] }}
      onBookmark={vi.fn()}
      onEvidence={vi.fn()}
    />);
    const zoom = screen.getByText(/^\d+%$/);
    const initialZoom = Number.parseInt(zoom.textContent ?? "0", 10);
    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    await waitFor(() =>
      expect(Number.parseInt(zoom.textContent ?? "0", 10)).toBeGreaterThan(initialZoom),
    );
    fireEvent.click(screen.getByRole("button", { name: "Zoom out" }));
    fireEvent.click(screen.getByRole("button", { name: "Fit" }));
    fireEvent.click(screen.getByText(/Accessible entity and relationship list/));
    expect(screen.getByText("isolated.exe")).toBeTruthy();
    expect(screen.getByText("Isolated entity")).toBeTruthy();
    await expectNoAxeViolations(container);
  });

  it("exposes accessible graph and chronology cross-navigation actions", async () => {
    const user = userEvent.setup();
    const onShowInChronology = vi.fn();
    const onShowInGraph = vi.fn();
    const { container } = render(<main>
      <GraphView
        focusTarget={null}
        graph={{ caseId: "case-1", projectionVersion: 1, sourceAnalysisRunId: "run-1", entities: [{ id: "entity-1", caseId: "case-1", entityType: "file", canonicalValue: "linked.exe", displayValue: "linked.exe", metadata: {} }], edges: [], entityEvidence: [{ entityId: "entity-1", evidenceId: "evidence-1", role: "supports" }] }}
        onBookmark={vi.fn()}
        onEvidence={vi.fn()}
        onShowInChronology={onShowInChronology}
      />
      <ChronologyView
        chronology={{ caseId: "case-1", projectionVersion: 1, sourceAnalysisRunId: "run-1", events: [{ id: "event-1", caseId: "case-1", timestampUtc: "2026-08-25T00:00:00Z", timestampType: "pe_compile", reliability: "attacker_controlled", eventType: "pe.timestamp", artifactId: "artifact-1", evidenceId: "evidence-1", summary: "PE timestamp" }] }}
        highlightedEventId="event-1"
        onBookmark={vi.fn()}
        onEvidence={vi.fn()}
        onShowInGraph={onShowInGraph}
      />
    </main>);

    await user.click(screen.getByText(/Accessible entity and relationship list/));
    await user.click(screen.getByRole("button", { name: "Show in timeline" }));
    await user.click(screen.getByRole("button", { name: "Show in graph" }));
    expect(onShowInChronology).toHaveBeenCalledWith("evidence-1");
    expect(onShowInGraph).toHaveBeenCalledWith("evidence-1");
    expect(screen.getByText("Timeline event highlighted: PE timestamp")).toBeTruthy();
    expect(document.querySelector("#event-event-1")?.getAttribute("aria-current")).toBe("true");
    await expectNoAxeViolations(container);
  });
});

describe("mocked desktop workflow", () => {
  it("authorizes opaque intake tokens and opens the completed analysis without renderer paths", async () => {
    const completedAnalysis = analysis();
    tauri.invoke.mockImplementation((command: string, payload?: unknown) => {
      if (command === "app_status") return Promise.resolve({ version: "test", platform: "windows", analysisMode: "static", networkPolicy: "PE/YARA workers use zero-capability AppContainer network denial" });
      if (command === "list_cases" || command === "take_startup_intake") return Promise.resolve([]);
      if (command === "choose_intake_files") return Promise.resolve([{ token: "opaque-token", name: "inert.exe" }]);
      if (command === "analyze_intake_batch") {
        expect(payload).toEqual({ tokens: ["opaque-token"] });
        return Promise.resolve([{ token: "opaque-token", name: "inert.exe", status: "complete", analysis: completedAnalysis }]);
      }
      return Promise.reject(new Error(`unexpected command ${command}`));
    });
    const user = userEvent.setup();
    const { container } = render(<App />);
    await user.click(screen.getByRole("button", { name: "Choose multiple files" }));
    await user.click(await screen.findByRole("button", { name: "Analyze 1 authorized file" }));
    expect(await screen.findByRole("heading", { name: "inert.exe" })).toBeTruthy();
    await expectNoAxeViolations(container);
  });

  it("removes all consumed partial-batch offers while preserving success and failure states", async () => {
    tauri.invoke.mockImplementation((command: string) => {
      if (command === "app_status") return Promise.resolve({ version: "test", platform: "windows", analysisMode: "static", networkPolicy: "PE/YARA workers use zero-capability AppContainer network denial" });
      if (command === "list_cases" || command === "take_startup_intake") return Promise.resolve([]);
      if (command === "choose_intake_files") return Promise.resolve([{ token: "one", name: "one.exe" }, { token: "two", name: "two.exe" }]);
      if (command === "analyze_intake_batch") return Promise.resolve([
        { token: "one", name: "one.exe", status: "complete", analysis: analysis() },
        { token: "two", name: "two.exe", status: "failed", error: "Invalid PE", analysis: null },
      ]);
      return Promise.reject(new Error(`unexpected command ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Choose multiple files" }));
    await user.click(await screen.findByRole("button", { name: "Analyze 2 authorized files" }));
    expect(await screen.findByText(/1 file failed independently/)).toBeTruthy();
    expect(screen.getByText("one.exe")).toBeTruthy();
    expect(screen.getByText("two.exe")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Analyze .* authorized/ })).toBeNull();
  });

  it("merges durable forwarded intake with active renderer offers", async () => {
    let ready: (() => void) | undefined;
    tauri.listen.mockImplementation((event: string, callback: (event: { payload: unknown }) => void) => {
      if (event === "artifacta://intake-ready") ready = () => callback({ payload: undefined });
      return Promise.resolve(() => undefined);
    });
    let pendingTakes = 0;
    tauri.invoke.mockImplementation((command: string) => {
      if (command === "app_status") return Promise.resolve({ version: "test", platform: "windows", analysisMode: "static", networkPolicy: "PE/YARA workers use zero-capability AppContainer network denial" });
      if (command === "list_cases") return Promise.resolve([]);
      if (command === "take_startup_intake") return Promise.resolve(pendingTakes++ === 0 ? [] : [{ token: "forwarded", name: "forwarded.exe" }]);
      if (command === "choose_intake_files") return Promise.resolve([{ token: "selected", name: "selected.exe" }]);
      return Promise.reject(new Error(`unexpected command ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Choose multiple files" }));
    await waitFor(() => expect(ready).toBeTypeOf("function"));
    ready!();
    expect(await screen.findByRole("button", { name: "Analyze 2 authorized files" })).toBeTruthy();
    expect(screen.getByText("selected.exe")).toBeTruthy();
    expect(screen.getByText("forwarded.exe")).toBeTruthy();
  });

  it("exports the selected historical run in every report workflow and retains bundle hashes", async () => {
    const latestRun = analysis("run-new");
    const oldRun = analysis("run-old");
    const runHistory = [latestRun.run, oldRun.run];
    const latest = { ...latestRun, runHistory };
    const old = { ...oldRun, runHistory };
    tauri.invoke.mockImplementation((command: string) => {
      if (command === "app_status") return Promise.resolve({ version: "test", platform: "windows", analysisMode: "static", networkPolicy: "PE/YARA workers use zero-capability AppContainer network denial" });
      if (command === "list_cases") return Promise.resolve([latest.case]);
      if (command === "take_startup_intake") return Promise.resolve([]);
      if (command === "get_case_analysis") return Promise.resolve(latest);
      if (command === "get_case_analysis_run") return Promise.resolve(old);
      if (command === "export_case_report") return Promise.resolve(null);
      if (command === "export_case_report_bundle") return Promise.resolve({ verificationToken: "verify", reportFileName: "report.html", manifestFileName: "report.html.manifest.json", reportSha256: "r".repeat(64), manifestSha256: "m".repeat(64), snapshotSha256: "s".repeat(64) });
      return Promise.reject(new Error(`unexpected command ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("button", { name: /Cases/ }));
    await user.click(await screen.findByRole("button", { name: "Open inert.exe" }));
    await user.selectOptions(await screen.findByLabelText("Analysis run history"), "run-old");
    await user.click(await screen.findByRole("button", { name: "Export JSON" }));
    expect(tauri.invoke).toHaveBeenCalledWith("export_case_report", { caseId: "case-1", runId: "run-old", format: "json" });
    await user.click(screen.getByRole("button", { name: "Export HTML + integrity manifest" }));
    expect(tauri.invoke).toHaveBeenCalledWith("export_case_report_bundle", { caseId: "case-1", runId: "run-old", format: "html" });
    expect(await screen.findByText("r".repeat(64))).toBeTruthy();
    expect(screen.getByText("m".repeat(64))).toBeTruthy();
    expect(screen.getByText("s".repeat(64))).toBeTruthy();
  });

  it("focuses Cancel, traps focus, closes on Escape, and returns focus for destructive dialogs", async () => {
    const item = analysis().case;
    tauri.invoke.mockImplementation((command: string) => {
      if (command === "app_status") return Promise.resolve({ version: "test", platform: "windows", analysisMode: "static", networkPolicy: "PE/YARA workers use zero-capability AppContainer network denial" });
      if (command === "list_cases") return Promise.resolve([item]);
      if (command === "take_startup_intake") return Promise.resolve([]);
      return Promise.reject(new Error(`unexpected command ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("button", { name: /Cases/ }));
    const trigger = await screen.findByRole("button", { name: "Delete" });
    await user.click(trigger);
    const cancel = screen.getByRole("button", { name: "Cancel" });
    await waitFor(() => expect(document.activeElement).toBe(cancel));
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Permanently delete case" }));
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });
});
