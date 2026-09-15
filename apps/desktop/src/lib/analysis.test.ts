import { describe, expect, it } from "vitest";
import {
  boundedUtf8,
  comparisonEvidenceIds,
  countEvidenceKinds,
  filterEvidence,
  filterStringEvidence,
  formatConfidence,
  getSignatureState,
  groupImports,
  orderedComparisonEntries,
  projectPersistedGraph,
  semanticStringChanges,
  stringEvidenceCategory,
  runStatusLabel,
  type EvidenceLike,
} from "./analysis";

const evidence = (overrides: Partial<EvidenceLike>): EvidenceLike => ({
  id: "ev-1",
  kind: "pe.header",
  class: "observed",
  locator: {},
  value: {},
  ...overrides,
});

describe("analysis helpers", () => {
  it("searches every user-visible evidence field and applies exact filters", () => {
    const items = [
      evidence({ id: "a", kind: "pe.string", previewText: "PowerShell marker", locator: { file_offset: 42 } }),
      evidence({ id: "b", kind: "pe.indicator", class: "inferred", value: { category: "domain", value: "example.test" } }),
    ];
    expect(filterEvidence(items, { search: "42", kind: "", observationClass: "" }).map((item) => item.id)).toEqual(["a"]);
    expect(filterEvidence(items, { search: "EXAMPLE", kind: "pe.indicator", observationClass: "inferred" }).map((item) => item.id)).toEqual(["b"]);
    expect(filterEvidence(items, { search: "PowerShell", kind: "", observationClass: "inferred" })).toEqual([]);
  });

  it("groups imports case-insensitively and retains ordinal imports", () => {
    const groups = groupImports([
      evidence({ id: "a", kind: "pe.import", value: { dll: "KERNEL32.dll", function: "CreateFileW" } }),
      evidence({ id: "b", kind: "pe.import", value: { dll: "kernel32.DLL", ordinal: 12 } }),
      evidence({ id: "c", kind: "pe.section" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.dll).toBe("KERNEL32.dll");
    expect(groups[0]?.items.map((item) => item.id)).toEqual(["a", "b"]);
  });

  it("groups both normal and delay imports", () => {
    const groups = groupImports([
      evidence({ id: "a", kind: "pe.delay_import", value: { dll: "USER32.dll", function: "MessageBoxW" } }),
      evidence({ id: "b", kind: "pe.import", value: { dll: "KERNEL32.dll", function: "Sleep" } }),
    ]);
    expect(groups.map((group) => group.dll)).toEqual(["KERNEL32.dll", "USER32.dll"]);
  });

  it("distinguishes absent, present, malformed, and unavailable signatures", () => {
    expect(getSignatureState([])).toBe("unavailable");
    expect(getSignatureState([evidence({ kind: "pe.authenticode", value: { present: false, structural_status: "absent" } })])).toBe("absent");
    expect(getSignatureState([evidence({ kind: "pe.authenticode", value: { present: true, structural_status: "parsed", pkcs7: { status: "parsed" } } })])).toBe("present");
    expect(getSignatureState([evidence({ kind: "pe.authenticode", value: { present: true, structural_status: "parsed", pkcs7: { status: "malformed_signed_data" } } })])).toBe("malformed");
  });

  it("formats bounded confidence values", () => {
    expect(formatConfidence(0.824)).toBe("82%");
    expect(formatConfidence(4)).toBe("100%");
    expect(formatConfidence(Number.NaN)).toBe("Unavailable");
  });

  it("orders comparison rows deterministically and merges evidence identifiers", () => {
    const entries = orderedComparisonEntries({
      added: [{ delta: "added", key: "z", right: { evidenceIds: ["ev-2"] } }],
      changed: [{ delta: "changed", key: "a", left: { evidenceIds: ["ev-1"] }, right: { evidenceIds: ["ev-1", "ev-3"] } }],
    });
    expect(entries.map((entry) => entry.key)).toEqual(["a", "z"]);
    expect(comparisonEvidenceIds(entries[0]!)).toEqual(["ev-1", "ev-3"]);
  });

  it("separates interesting strings from high-entropy raw extraction", () => {
    const items = [
      evidence({ id: "a", kind: "pe.string", value: { text: "xQ4z", analyst_category: "raw", interesting: false } }),
      evidence({ id: "b", kind: "pe.string", value: { text: "version=2.0", analyst_category: "metadata", interesting: true } }),
      evidence({ id: "c", kind: "pe.indicator", value: { category: "url", value: "https://example.test" } }),
    ];
    expect(filterStringEvidence(items, "interesting").map((item) => item.id)).toEqual(["b", "c"]);
    expect(filterStringEvidence(items, "all")).toHaveLength(3);
    expect(stringEvidenceCategory(items[2]!)).toBe("urls_domains_ips");
  });

  it("pairs version and URL replacements as semantic string changes", () => {
    const changes = semanticStringChanges({
      removed: [
        { delta: "removed", key: "ascii:version=1.0", left: { value: { text: "version=1.0" }, evidenceIds: ["left-version"] } },
        { delta: "removed", key: "ascii:https://updates.example.test/v1", left: { value: { text: "https://updates.example.test/v1" }, evidenceIds: ["left-url"] } },
      ],
      added: [
        { delta: "added", key: "ascii:version=2.0", right: { value: { text: "version=2.0" }, evidenceIds: ["right-version"] } },
        { delta: "added", key: "ascii:https://updates.example.test/v2", right: { value: { text: "https://updates.example.test/v2" }, evidenceIds: ["right-url"] } },
      ],
    });
    expect(changes.map((change) => [change.label, change.left, change.right])).toEqual([
      ["Update URL", "https://updates.example.test/v1", "https://updates.example.test/v2"],
      ["version", "version=1.0", "version=2.0"],
    ]);
    expect(changes[1]?.evidenceIds).toEqual(["left-version", "right-version"]);
  });

  it("bounds UTF-8 search input without splitting characters", () => {
    expect(boundedUtf8("ab\u{1F600}c", 6)).toBe("ab\u{1F600}");
    expect(boundedUtf8("short", 256)).toBe("short");
  });

  it("normalizes run status labels and counts v2 evidence groups", () => {
    expect(runStatusLabel("resource_limit")).toBe("resource limit");
    expect(runStatusLabel(null)).toBe("not analyzed");
    expect(countEvidenceKinds([
      evidence({ kind: "pe.relocation" }),
      evidence({ kind: "pe.runtime_function" }),
      evidence({ kind: "pe.section" }),
    ], ["pe.relocation", "pe.runtime_function"])).toBe(2);
  });

  it("caps graph nodes and retains only persisted filtered relationships", () => {
    const entities = [
      { id: "a", entityType: "artifact", displayValue: "sample.exe", canonicalValue: "sample.exe" },
      { id: "b", entityType: "domain", displayValue: "example.test", canonicalValue: "example.test" },
      { id: "c", entityType: "imported_api", displayValue: "CreateFileW", canonicalValue: "createfilew" },
    ];
    const edges = [
      { id: "ab", sourceEntityId: "a", targetEntityId: "b", relationship: "contains_indicator" },
      { id: "ac", sourceEntityId: "a", targetEntityId: "c", relationship: "imports" },
    ];
    const capped = projectPersistedGraph(entities, edges, { search: "", nodeType: "", relationship: "", expanded: new Set(), cap: 2 });
    expect(capped.entities.map((item) => item.id)).toEqual(["a", "b"]);
    expect(capped.edges.map((item) => item.id)).toEqual(["ab"]);
    const expanded = projectPersistedGraph(entities, edges, { search: "sample", nodeType: "", relationship: "imports", expanded: new Set(["c"]), cap: 1 });
    expect(expanded.entities.map((item) => item.id)).toEqual(["a", "c"]);
    expect(expanded.edges.map((item) => item.id)).toEqual(["ac"]);
  });
});
