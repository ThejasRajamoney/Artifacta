import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import indexHtml from "../index.html?raw";
import App from "./App";

const tauri = vi.hoisted(() => ({ invoke: vi.fn(), listen: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: tauri.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: tauri.listen }));

const cases = [
  {
    id: "case-1",
    title: "inert.exe",
    createdAt: "2026-08-25T00:00:00Z",
    status: "complete",
  },
  {
    id: "case-2",
    title: "candidate.exe",
    createdAt: "2026-08-26T00:00:00Z",
    status: "complete",
  },
] as const;

const evidence = [
  {
    id: "evidence-import",
    artifactId: "artifact-1",
    provenanceId: "provenance-1",
    kind: "pe.import",
    class: "observed",
    locator: { descriptor_file_offset: 128 },
    value: {
      dll: "KERNEL32.dll",
      function: "CreateFileW",
      hint: 1,
      iat_rva: 4096,
      thunk_rva: 8192,
    },
    previewText: "KERNEL32.dll!CreateFileW",
  },
  {
    id: "evidence-string",
    artifactId: "artifact-1",
    provenanceId: "provenance-1",
    kind: "pe.string",
    class: "observed",
    locator: { file_offset: 512 },
    value: {
      text: "powershell.exe",
      category: "commands",
      section_name: ".rdata",
      encoding: "ascii",
    },
    previewText: "powershell.exe",
  },
  {
    id: "evidence-section",
    artifactId: "artifact-1",
    provenanceId: "provenance-1",
    kind: "pe.section",
    class: "observed",
    locator: { index: 0 },
    value: {
      name: ".text",
      virtual_address: 4096,
      virtual_size: 1024,
      raw_offset: 512,
      raw_size: 1024,
      entropy: 5.2,
      characteristics: 1610612768,
    },
    previewText: ".text",
  },
  {
    id: "evidence-yara",
    artifactId: "artifact-1",
    provenanceId: "provenance-1",
    kind: "yara.match",
    class: "observed",
    locator: { rule: "Suspicious_Test" },
    value: {
      namespace: "default",
      rule_identifier: "Suspicious_Test",
      pack_name: "Local review pack",
      pack_version: "1",
      pack_sha256: "d".repeat(64),
      tags: ["review"],
      matched_strings: ["$a"],
      string_instances_truncated: false,
    },
    previewText: "Suspicious_Test",
  },
];

const finding = {
  id: "finding-1",
  analysisRunId: "run-1",
  artifactId: "artifact-1",
  ruleId: "TF-1",
  ruleVersion: "1",
  title: "Review imported API",
  category: "capability",
  severity: "low",
  confidence: 0.8,
  confidenceBand: "high",
  state: "new",
  observation: "The import is present in the persisted image.",
  whyItMatters: "The API can access files.",
  limitations: "Static presence does not establish execution.",
  evidence: [{ evidenceId: "evidence-import", role: "supports" }],
  attackMappings: [],
};

const completedAnalysis = {
  case: cases[0],
  artifact: {
    id: "artifact-1",
    caseId: "case-1",
    sha256: "a".repeat(64),
    sha1: "b".repeat(40),
    md5: "c".repeat(32),
    sizeBytes: 2048,
    kind: "pe64",
    mime: "application/vnd.microsoft.portable-executable",
    originalName: "inert.exe",
  },
  run: {
    id: "run-1",
    artifactId: "artifact-1",
    analyzer: "traceforge.pe",
    analyzerVersion: "1",
    startedAt: "2026-08-25T00:00:00Z",
    finishedAt: "2026-08-25T00:00:01Z",
    status: "complete",
    errorCode: null,
  },
  provenances: [
    {
      id: "provenance-1",
      analysisRunId: "run-1",
      analyzer: "traceforge.pe",
      analyzerVersion: "1",
      inputSha256: "a".repeat(64),
    },
  ],
  runHistory: [],
  evidence,
  findings: [finding],
  graph: {
    caseId: "case-1",
    projectionVersion: 1,
    sourceAnalysisRunId: "run-1",
    entities: [
      {
        id: "entity-file",
        caseId: "case-1",
        entityType: "file",
        canonicalValue: "inert.exe",
        displayValue: "inert.exe",
        metadata: {},
      },
      {
        id: "entity-api",
        caseId: "case-1",
        entityType: "api",
        canonicalValue: "createfilew",
        displayValue: "CreateFileW",
        metadata: {},
      },
    ],
    edges: [
      {
        id: "edge-imports",
        sourceEntityId: "entity-file",
        targetEntityId: "entity-api",
        relationship: "imports",
        evidenceId: "evidence-import",
        confidence: 1,
      },
    ],
    entityEvidence: [
      {
        entityId: "entity-api",
        evidenceId: "evidence-import",
        role: "supports",
      },
    ],
  },
  chronology: {
    caseId: "case-1",
    projectionVersion: 1,
    sourceAnalysisRunId: "run-1",
    events: [
      {
        id: "event-1",
        caseId: "case-1",
        timestampUtc: "2026-08-25T00:00:00Z",
        timestampType: "coff_header",
        reliability: "attacker_controlled",
        eventType: "pe.coff_timestamp",
        artifactId: "artifact-1",
        evidenceId: "evidence-import",
        summary: "Persisted COFF timestamp",
      },
    ],
  },
  bookmarks: [
    {
      id: "bookmark-1",
      caseId: "case-1",
      target: { type: "finding", findingId: "finding-1" },
      label: "Review imported API",
      createdAt: "2026-08-25T01:00:00Z",
      updatedAt: "2026-08-25T01:00:00Z",
    },
  ],
  quickCheck: {
    policyVersion: "2",
    policySha256: "e".repeat(64),
    band: "review",
    findingCounts: {
      contextual: 0,
      low: 1,
      medium: 0,
      high: 0,
      total: 1,
    },
    topFindings: [
      {
        findingId: "finding-1",
        title: "Review imported API",
        category: "capability",
        severity: "low",
        evidenceFamily: "capability",
      },
    ],
    evidenceFamilies: [
      {
        family: "capability",
        findingCount: 1,
        contributingFindingCount: 1,
        strongestSeverity: "low",
      },
    ],
    statement: "One static capability warrants review.",
  },
};

const emptyGroup = { added: [], removed: [], changed: [] };
const comparison = {
  left: completedAnalysis.artifact,
  right: {
    ...completedAnalysis.artifact,
    id: "artifact-2",
    caseId: "case-2",
    originalName: "candidate.exe",
    sha256: "f".repeat(64),
  },
  hashes: {
    added: [],
    removed: [],
    changed: [
      {
        delta: "changed",
        key: "sha256",
        left: {
          key: "sha256",
          value: completedAnalysis.artifact.sha256,
          evidenceIds: [],
        },
        right: { key: "sha256", value: "f".repeat(64), evidenceIds: [] },
      },
    ],
  },
  headers: emptyGroup,
  sections: emptyGroup,
  imports: emptyGroup,
  strings: emptyGroup,
  signatures: emptyGroup,
  findings: emptyGroup,
};

const note = {
  id: "note-1",
  caseId: "case-1",
  entityId: null,
  findingId: "finding-1",
  body: "Verify this import against the investigation context.",
  createdAt: "2026-08-25T02:00:00Z",
  updatedAt: "2026-08-25T02:05:00Z",
};

const yaraPack = {
  id: "pack-1",
  sha256: "1".repeat(64),
  name: "Local review pack",
  version: "1",
  source: "Internal review",
  license: "Apache-2.0",
  importedAt: "2026-08-25T03:00:00Z",
  enabled: true,
  ruleCount: 4,
};

function mockApplication() {
  tauri.invoke.mockImplementation((command: string) => {
    if (command === "app_status")
      return Promise.resolve({
        version: "test",
        platform: "windows",
        analysisMode: "static",
        networkPolicy: "No intended application network access",
      });
    if (command === "list_cases") return Promise.resolve(cases);
    if (command === "take_startup_intake") return Promise.resolve([]);
    if (command === "get_case_analysis")
      return Promise.resolve(completedAnalysis);
    if (command === "list_notes") return Promise.resolve([note]);
    if (command === "list_yara_packs") return Promise.resolve([yaraPack]);
    if (command === "compare_cases") return Promise.resolve(comparison);
    if (command === "choose_intake_files")
      return Promise.resolve([{ token: "opaque-token", name: "queued.exe" }]);
    if (command === "export_case_report")
      return Promise.resolve({
        fileName: "inert.json",
        format: "json",
        sha256: "2".repeat(64),
      });
    return Promise.reject(new Error(`unexpected command ${command}`));
  });
}

async function audit(container: HTMLElement) {
  // jsdom has no layout engine, so contrast is covered by deterministic CSS tests below.
  const result = await axe.run(container, {
    rules: { "color-contrast": { enabled: false } },
  });
  const details = result.violations
    .map(
      (violation) =>
        `${violation.id} (${violation.impact ?? "unknown"}): ${violation.nodes
          .map((node) => node.target.join(" "))
          .join(", ")}`,
    )
    .join("\n");
  expect(
    result.violations.map((violation) => violation.id),
    `axe-core violations:\n${details}`,
  ).toEqual([]);
}

async function openCompletedAnalysis(user: ReturnType<typeof userEvent.setup>) {
  const rendered = render(<App />);
  await user.click(screen.getByRole("button", { name: /Cases/ }));
  await user.click(
    await screen.findByRole("button", { name: "Open inert.exe" }),
  );
  await screen.findByRole("heading", { name: "inert.exe" });
  return rendered;
}

function relativeLuminance(hex: string) {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)!
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045
        ? channel / 12.92
        : ((channel + 0.055) / 1.055) ** 2.4,
    );
  return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
}

function contrastRatio(foreground: string, background: string) {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  return (
    (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
    (Math.min(foregroundLuminance, backgroundLuminance) + 0.05)
  );
}

beforeEach(() => {
  tauri.invoke.mockReset();
  tauri.listen.mockReset();
  tauri.listen.mockResolvedValue(() => undefined);
  mockApplication();
});

describe("document accessibility metadata", () => {
  it("defines the actual desktop document language and title", () => {
    const html = new DOMParser().parseFromString(indexHtml, "text/html");

    expect(html.documentElement.lang).toBe("en");
    expect(html.title).toBe("Artifacta");
  });
});

describe("automated application state audits", () => {
  it("audits initial and authorized intake states with named landmarks and live results", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);

    expect(screen.getByRole("main")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Primary navigation" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Choose multiple files" })).toBeTruthy();
    await audit(container);

    await user.click(screen.getByRole("button", { name: "Choose multiple files" }));
    expect(await screen.findByRole("list", { name: "Intake results" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Analyze 1 authorized file" })).toBeTruthy();
    await audit(container);
  });

  it("audits completed Quick Check and enforces valid tabindex values", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    expect(screen.getByRole("heading", { name: "review" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Analysis run and report exports" })).toBeTruthy();
    for (const element of container.querySelectorAll<HTMLElement>("[tabindex]")) {
      expect(Number(element.getAttribute("tabindex"))).toBeLessThanOrEqual(0);
    }
    await audit(container);
  });

  it("supports the complete roving-tab keyboard model", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);
    const tablist = screen.getByRole("tablist", { name: "Case analysis views" });
    const selected = () => tablist.querySelectorAll('[role="tab"][tabindex="0"]');
    const quick = screen.getByRole("tab", { name: "Quick Check" });

    quick.focus();
    await user.keyboard("{ArrowRight}");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Overview" }));
    expect(selected()).toHaveLength(1);
    await user.keyboard("{End}");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Notes" }));
    expect(selected()).toHaveLength(1);
    await user.keyboard("{Home}");
    expect(document.activeElement).toBe(quick);
    await user.keyboard("{ArrowLeft}");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Notes" }));
    expect(selected()).toHaveLength(1);
    await audit(container);
  });

  it("audits findings and the integrated evidence dialog and restores focus", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByRole("tab", { name: "Findings 1" }));
    expect(screen.getByRole("heading", { name: "Review imported API" })).toBeTruthy();
    const trigger = screen.getByRole("button", {
      name: /supports.*pe\.import.*evidence-import/i,
    });
    await user.click(trigger);
    expect(await screen.findByRole("dialog", { name: "pe.import" })).toBeTruthy();
    await audit(container);

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });

  it("audits graph controls and exercises the open keyboard fallback action", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByRole("tab", { name: "Graph" }));
    expect(screen.getByRole("searchbox", { name: "Search persisted entities" })).toBeTruthy();
    const graphImage = screen.getByRole("img", { name: /relationship graph/i });
    expect(graphImage.hasAttribute("tabindex")).toBe(false);
    expect(screen.getByRole("group", { name: "Graph zoom controls" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Zoom out" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Zoom in" })).toBeTruthy();
    await user.click(screen.getByText(/Accessible entity and relationship list/));
    const fallbackAction = screen.getByRole("button", {
      name: "Inspect evidence for CreateFileW, api",
    });
    fallbackAction.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "pe.import" })).toBeTruthy();
    await audit(container);
  });

  it("audits chronology with machine-readable timestamps", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByRole("tab", { name: "Chronology" }));
    expect(screen.getByRole("heading", { name: "Persisted COFF timestamp" })).toBeTruthy();
    expect(container.querySelector("time")?.getAttribute("datetime")).toBe(
      "2026-08-25T00:00:00Z",
    );
    expect(screen.getByRole("button", { name: "Inspect evidence" })).toBeTruthy();
    await audit(container);
  });

  it("audits captioned import, string, and section tables", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByRole("tab", { name: "Imports" }));
    expect(screen.getByRole("table", { name: "Normal imports grouped by imported library" })).toBeTruthy();
    await audit(container);

    await user.click(screen.getByRole("tab", { name: "Strings" }));
    expect(screen.getByRole("table", { name: "Extracted strings and indicators" })).toBeTruthy();
    await audit(container);

    await user.click(screen.getByRole("tab", { name: "Sections" }));
    expect(screen.getByRole("table", { name: "PE image sections" })).toBeTruthy();
    await audit(container);
  });

  it("audits comparison controls and rendered differences", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);

    await user.click(screen.getByRole("button", { name: /Compare$/ }));
    await user.selectOptions(screen.getByLabelText("Left / baseline"), "case-1");
    await user.selectOptions(screen.getByLabelText("Right / candidate"), "case-2");
    await user.click(screen.getByRole("button", { name: "Compare cases" }));
    expect(await screen.findByText("sha256")).toBeTruthy();
    expect(screen.getByRole("form").getAttribute("aria-busy")).toBe("false");
    await audit(container);
  });

  it("audits notes, bookmarks, and machine-readable note dates", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByText("Bookmarks / 1"));
    expect(screen.getByRole("button", { name: /Review imported API/ })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Notes" }));
    expect(await screen.findByText(note.body)).toBeTruthy();
    expect(screen.getByRole("textbox", { name: "Note" })).toBeTruthy();
    expect(container.querySelector("time")?.getAttribute("datetime")).toBe(note.updatedAt);
    await audit(container);
  });

  it("audits report and export controls with announced completion", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    expect(screen.getByRole("button", { name: "Export HTML + integrity manifest" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Export JSON" }));
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("inert.json");
    await audit(container);
  });

  it("audits YARA results and the reachable Rule Library", async () => {
    const user = userEvent.setup();
    const { container } = await openCompletedAnalysis(user);

    await user.click(screen.getByRole("tab", { name: "YARA 1" }));
    expect(screen.getByRole("heading", { name: "default:Suspicious Test" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Inspect evidence and provenance" })).toBeTruthy();
    await audit(container);

    await user.click(screen.getByRole("button", { name: /Rule Library$/ }));
    expect(await screen.findByRole("heading", { name: "Rule Library" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Local review pack" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Disable for future runs" })).toBeTruthy();
    await audit(container);
  });
});

describe("CSS small-text contrast", () => {
  it("keeps actual quiet and intake caveat colors at 4.5:1 on used dark backgrounds", () => {
    const workspacePath = resolve(
      process.cwd(),
      "apps/desktop/src/styles.css",
    );
    const styles = readFileSync(
      existsSync(workspacePath)
        ? workspacePath
        : resolve(process.cwd(), "src/styles.css"),
      "utf8",
    );
    const quiet = styles.match(/--quiet:\s*(#[0-9a-f]{6})/i)?.[1];
    const caveat = styles.match(
      /\.drop-panel \.drop-caveat\s*\{[^}]*color:\s*(#[0-9a-f]{6})/is,
    )?.[1];

    expect(quiet).toBe("#858c80");
    expect(caveat).toBe("#8b9286");
    for (const background of [
      "#111310",
      "#171916",
      "#1d201c",
      "#181a17",
      "#151714",
      "#141613",
      "#10120f",
    ]) {
      expect(contrastRatio(quiet!, background)).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrastRatio(caveat!, "#181a17")).toBeGreaterThanOrEqual(4.5);
  });
});
