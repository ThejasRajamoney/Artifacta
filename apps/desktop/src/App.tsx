import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useId,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import {
  boundedUtf8,
  comparisonEvidenceIds,
  filterEvidence,
  filterStringEvidence,
  formatConfidence,
  getSignatureState,
  groupImports,
  orderedComparisonEntries,
  runStatusLabel,
  semanticStringChanges,
  stringEvidenceCategory,
  type StringView,
} from "./lib/analysis";
import { formatBytes } from "./lib/format";
import {
  BookmarkAction,
  BookmarksBar,
  ChronologyView,
  EvidenceDrawer,
  GraphView,
  QuickCheckView,
  type BookmarkInput,
  type BookmarkRecord,
  type BookmarkTarget,
  type CaseChronology,
  type CaseGraph,
  type QuickCheck,
} from "./investigation";

type HostStatus = {
  version: string;
  platform: string;
  analysisMode: "static";
  networkPolicy: string;
};
type CaseStatus = "active" | "complete" | "archived" | "error";
type RunStatus =
  | "queued"
  | "running"
  | "complete"
  | "partial"
  | "failed"
  | "cancelled"
  | "timed_out"
  | "resource_limit";
type CaseSummary = {
  id: string;
  title: string;
  createdAt: string;
  updatedAt?: string;
  status: CaseStatus;
};
type ArtifactView = {
  id: string;
  caseId?: string;
  parentArtifactId?: string | null;
  sha256: string;
  sha1: string;
  md5: string;
  sizeBytes: number;
  kind: string;
  mime?: string | null;
  originalName: string;
  createdAt?: string;
};
type RunView = {
  id: string;
  artifactId: string;
  analyzer: string;
  analyzerVersion: string;
  startedAt: string;
  finishedAt: string | null;
  status: RunStatus;
  errorCode: string | null;
};
type ProvenanceView = {
  id: string;
  analysisRunId: string;
  analyzer: string;
  analyzerVersion: string;
  ruleId?: string | null;
  ruleVersion?: string | null;
  rulePackSha256?: string | null;
  inputSha256: string;
};
type EvidenceView = {
  id: string;
  artifactId?: string;
  provenanceId?: string;
  kind: string;
  class: string;
  locator: Record<string, unknown>;
  value: unknown;
  previewText: string | null;
};
type AttackMapping = {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
};
type FindingState = "new" | "reviewed" | "accepted" | "dismissed";
type FindingView = {
  id: string;
  analysisRunId?: string;
  artifactId?: string;
  ruleId: string;
  ruleVersion: string;
  title: string;
  category: string;
  severity: string;
  confidence: number;
  confidenceBand: string;
  explanationTemplateId?: string;
  state?: FindingState;
  observation: string;
  whyItMatters: string;
  limitations: string;
  evidence: { evidenceId: string; role: string }[];
  attackMappings?: AttackMapping[];
};
type CaseAnalysis = {
  case: CaseSummary;
  artifact: ArtifactView;
  run: RunView | null;
  provenance?: ProvenanceView | null;
  provenances?: ProvenanceView[];
  runHistory?: RunView[];
  evidence?: EvidenceView[];
  findings?: FindingView[];
  graph?: CaseGraph | null;
  chronology?: CaseChronology | null;
  bookmarks?: BookmarkRecord[];
  quickCheck?: QuickCheck;
};
type NoteView = {
  id: string;
  caseId: string;
  entityId: string | null;
  findingId: string | null;
  body: string;
  createdAt: string;
  updatedAt: string;
};
type SearchField =
  | "sha256"
  | "sha1"
  | "md5"
  | "case_title"
  | "import"
  | "indicator"
  | "certificate"
  | "signer"
  | "rule_id"
  | "finding_title"
  | "finding_category"
  | "evidence_value";
type SearchHit = {
  caseId: string;
  caseTitle: string;
  caseStatus: CaseStatus;
  artifactId: string | null;
  analysisRunId: string | null;
  evidenceId: string | null;
  findingId: string | null;
  field: SearchField;
  value: string;
};
type ComparisonValue = { key: string; value: unknown; evidenceIds: string[] };
type ComparisonEntry = {
  delta: "added" | "removed" | "changed";
  key: string;
  left: ComparisonValue | null;
  right: ComparisonValue | null;
};
type ComparisonGroup = {
  added: ComparisonEntry[];
  removed: ComparisonEntry[];
  changed: ComparisonEntry[];
};
type Comparison = {
  left: ArtifactView;
  right: ArtifactView;
  hashes: ComparisonGroup;
  headers: ComparisonGroup;
  sections: ComparisonGroup;
  imports: ComparisonGroup;
  strings: ComparisonGroup;
  signatures: ComparisonGroup;
  findings: ComparisonGroup;
};
type YaraPack = {
  id: string;
  sha256: string;
  name: string;
  version: string;
  source: string;
  license: string;
  importedAt: string;
  enabled: boolean;
  ruleCount: number;
};
type YaraFolderResult = {
  fileName: string;
  status: "complete" | "failed";
  pack: YaraPack | null;
  error: string | null;
};
type Cleanup = {
  sha256: string;
  cleanup: "removed" | "retained_shared" | "already_missing" | "deferred";
};
type DeleteCaseReceipt = { caseId: string; objects: Cleanup[] };
type ReportReceipt = { fileName: string; format: string; sha256: string };
type ReportBundleReceipt = {
  verificationToken: string;
  reportFileName: string;
  manifestFileName: string;
  reportSha256: string;
  manifestSha256: string;
  snapshotSha256: string;
};
type BundleVerification = {
  status: string;
  detail: string;
  snapshotSha256: string | null;
  artifactVerification: string;
  safetyClaim: false;
};
type IntakeOffer = { token: string; name: string };
type IntakeStatus = IntakeOffer & {
  status: "queued" | "running" | "complete" | "failed";
  stage?: string | null;
  error?: string | null;
};
type IntakeResult = IntakeStatus & { analysis?: CaseAnalysis | null };
type View = "intake" | "cases" | "search" | "compare" | "rules" | "detail";
type AnalysisTab =
  | "quick"
  | "overview"
  | "findings"
  | "graph"
  | "chronology"
  | "imports"
  | "strings"
  | "sections"
  | "signature"
  | "yara"
  | "evidence"
  | "notes";

const TABS: { id: AnalysisTab; label: string }[] = [
  { id: "quick", label: "Quick Check" },
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "graph", label: "Graph" },
  { id: "chronology", label: "Chronology" },
  { id: "imports", label: "Imports" },
  { id: "strings", label: "Strings" },
  { id: "sections", label: "Sections" },
  { id: "signature", label: "Signature" },
  { id: "yara", label: "YARA" },
  { id: "evidence", label: "Evidence" },
  { id: "notes", label: "Notes" },
];
const SEARCH_FIELDS: { id: SearchField; label: string }[] = [
  { id: "sha256", label: "SHA-256" },
  { id: "sha1", label: "SHA-1" },
  { id: "md5", label: "MD5" },
  { id: "case_title", label: "Case title" },
  { id: "import", label: "Imports" },
  { id: "indicator", label: "Indicators" },
  { id: "certificate", label: "Certificates" },
  { id: "signer", label: "Signers" },
  { id: "rule_id", label: "Rule ID" },
  { id: "finding_title", label: "Finding title" },
  { id: "finding_category", label: "Finding category" },
  { id: "evidence_value", label: "Evidence values" },
];
const COMPARISON_GROUPS = [
  "hashes",
  "headers",
  "sections",
  "imports",
  "strings",
  "signatures",
  "findings",
] as const;
const EMPTY_VALUE: Record<string, unknown> = {};

function mergeIntakeOffers(current: IntakeOffer[], incoming: IntakeOffer[]) {
  const merged = new Map(current.map((offer) => [offer.token, offer]));
  for (const offer of incoming) merged.set(offer.token, offer);
  return [...merged.values()];
}

function addQueuedStatuses(
  current: Map<string, IntakeStatus>,
  offers: IntakeOffer[],
) {
  const next = new Map(current);
  for (const offer of offers)
    if (!next.has(offer.token))
      next.set(offer.token, { ...offer, status: "queued" });
  return next;
}

function BrandMark() {
  return (
    <svg aria-hidden="true" className="brand-mark" viewBox="0 0 40 40">
      <path d="M5 34 16 6h8l11 28h-7L20 14l-8 20z" />
      <path className="brand-mark-accent" d="M13 24h14l3 6H10z" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20">
      <path d="M4 10h11M11 6l4 4-4 4" />
    </svg>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : EMPTY_VALUE;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function displayValue(value: unknown, hexadecimal = false): string {
  if (value === null || value === undefined || value === "")
    return "Not recorded";
  if (typeof value === "number")
    return hexadecimal
      ? `0x${value.toString(16).toUpperCase()}`
      : value.toLocaleString();
  if (typeof value === "string") return value.replaceAll("_", " ");
  if (typeof value === "boolean") return value ? "Yes" : "No";
  try {
    return JSON.stringify(value);
  } catch {
    return "Value unavailable";
  }
}

function evidenceSummary(item: EvidenceView | undefined) {
  if (!item) return "Persisted evidence record unavailable in this run view";
  const value = asRecord(item.value);
  if (item.kind === "pe.import" || item.kind === "pe.delay_import") {
    return `${displayValue(value.dll)}!${displayValue(value.function ?? value.ordinal)}`;
  }
  if (item.kind === "pe.indicator")
    return `${displayValue(value.category)}: ${displayValue(value.value)}`;
  return (
    item.previewText ?? displayValue(value.name ?? value.text ?? item.locator)
  );
}

function exactJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2) ?? "null";
  } catch {
    return "Exact JSON could not be displayed.";
  }
}

function formatDate(value: string | null | undefined) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function EmptyState({ children }: { children: ReactNode }) {
  return <div className="tab-empty">{children}</div>;
}

function ErrorMessage({ children }: { children: ReactNode }) {
  return (
    <p className="page-error" role="alert">
      {children}
    </p>
  );
}

function StatusBadge({ status }: { status: string | null | undefined }) {
  return (
    <span className={`status-badge status-${status ?? "unknown"}`}>
      {runStatusLabel(status)}
    </span>
  );
}

function FactGrid({
  facts,
}: {
  facts: { label: string; value: unknown; hex?: boolean }[];
}) {
  return (
    <dl className="fact-grid">
      {facts.map((fact) => (
        <div key={fact.label}>
          <dt>{fact.label}</dt>
          <dd>{displayValue(fact.value, fact.hex)}</dd>
        </div>
      ))}
    </dl>
  );
}

function ConfirmDialog({
  title,
  body,
  confirmLabel,
  busy,
  onCancel,
  onConfirm,
}: {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const titleId = useId();
  const dialog = useRef<HTMLElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const cancelAction = useEffectEvent(onCancel);
  useEffect(() => {
    const returnFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    cancel.current?.focus();
    function keydown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        cancelAction();
        return;
      }
      if (event.key !== "Tab" || !dialog.current) return;
      const focusable = [
        ...dialog.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
        ),
      ];
      if (!focusable.length) {
        event.preventDefault();
        dialog.current.focus();
        return;
      }
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (
        event.shiftKey &&
        (document.activeElement === first ||
          document.activeElement === dialog.current)
      ) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      requestAnimationFrame(() => returnFocus?.focus());
    };
  }, []);
  return (
    <div
      aria-labelledby={titleId}
      aria-modal="true"
      className="confirm-backdrop"
      role="dialog"
    >
      <section className="confirm-dialog" ref={dialog} tabIndex={-1}>
        <p className="eyebrow">Explicit confirmation</p>
        <h2 id={titleId}>{title}</h2>
        <div>{body}</div>
        <div className="confirm-actions">
          <button
            className="secondary-button"
            disabled={busy}
            onClick={onCancel}
            ref={cancel}
            type="button"
          >
            Cancel
          </button>
          <button
            className="danger-button"
            disabled={busy}
            onClick={onConfirm}
            type="button"
          >
            {busy ? "Working..." : confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}

function ShowMore({
  shown,
  total,
  onClick,
}: {
  shown: number;
  total: number;
  onClick: () => void;
}) {
  return (
    <div className="show-more">
      <span>
        Showing {Math.min(shown, total).toLocaleString()} of{" "}
        {total.toLocaleString()}
      </span>
      <button className="secondary-button" onClick={onClick} type="button">
        Show more
      </button>
    </div>
  );
}

function OverviewTab({
  analysis,
  evidence,
  findings,
  onEvidence,
}: {
  analysis: CaseAnalysis;
  evidence: EvidenceView[];
  findings: FindingView[];
  onEvidence: (id: string) => void;
}) {
  const first = (kind: string) => evidence.find((item) => item.kind === kind);
  const count = (kind: string) =>
    evidence.filter((item) => item.kind === kind).length;
  const headerEvidence = first("pe.header");
  const header = asRecord(headerEvidence?.value);
  const richHeader = asRecord(first("pe.rich_header")?.value);
  const richChecksum = asRecord(richHeader.checksum_context);
  const imphash = asRecord(first("pe.imphash")?.value);
  const overlay = asRecord(first("pe.overlay")?.value);
  const clr = asRecord(first("pe.clr")?.value);
  const clrEntryPoint = asRecord(clr.entry_point);
  const manifest = asRecord(first("pe.manifest")?.value);
  const version = asRecord(first("pe.version_info")?.value);
  const loadConfig = asRecord(first("pe.load_config")?.value);
  const mitigations = asRecord(loadConfig.mitigations);
  const topFindings = [...findings]
    .sort((left, right) => {
      const rank: Record<string, number> = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        informational: 1,
      };
      return (
        (rank[right.severity] ?? 0) - (rank[left.severity] ?? 0) ||
        right.confidence - left.confidence
      );
    })
    .slice(0, 3);
  return (
    <div className="tab-stack">
      <section className="metric-grid" aria-label="Artifact overview">
        <article>
          <span>Format</span>
          <strong>{analysis.artifact.kind?.toUpperCase() || "Unknown"}</strong>
          <small>{analysis.artifact.mime ?? "Detected from bytes"}</small>
        </article>
        <article>
          <span>File size</span>
          <strong>
            {Number.isFinite(analysis.artifact.sizeBytes)
              ? formatBytes(analysis.artifact.sizeBytes)
              : "Unknown"}
          </strong>
          <small>
            {analysis.artifact.sizeBytes?.toLocaleString?.() ?? "?"} bytes
          </small>
        </article>
        <article>
          <span>Imphash</span>
          <strong>{displayValue(imphash.value)}</strong>
          <small>{displayValue(imphash.import_count)} canonical imports</small>
        </article>
        <article>
          <span>Run context</span>
          <strong>
            {analysis.run ? runStatusLabel(analysis.run.status) : "Legacy case"}
          </strong>
          <small>
            {findings.length} findings, {evidence.length} evidence
          </small>
        </article>
      </section>
      <div className="analysis-columns">
        <section className="evidence-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Rich header context</p>
              <h2>PE image header</h2>
            </div>
            <span>
              {headerEvidence ? `Evidence ${headerEvidence.id}` : "Unavailable"}
            </span>
          </div>
          {headerEvidence ? (
            <FactGrid
              facts={[
                { label: "Machine", value: header.machine, hex: true },
                {
                  label: "Entry point RVA",
                  value: header.entry_point_rva,
                  hex: true,
                },
                { label: "Image base", value: header.image_base, hex: true },
                { label: "Subsystem", value: header.subsystem },
                { label: "Image size", value: header.size_of_image, hex: true },
                {
                  label: "Header size",
                  value: header.size_of_headers,
                  hex: true,
                },
                {
                  label: "Section alignment",
                  value: header.section_alignment,
                  hex: true,
                },
                {
                  label: "File alignment",
                  value: header.file_alignment,
                  hex: true,
                },
                { label: "COFF timestamp", value: header.coff_timestamp },
                {
                  label: "Characteristics",
                  value: header.characteristics,
                  hex: true,
                },
              ]}
            />
          ) : (
            <EmptyState>
              No PE header evidence is available in this case.
            </EmptyState>
          )}
          <div className="rich-header-strip">
            <div>
              <span>Microsoft Rich header</span>
              <strong>
                {richHeader.present === true
                  ? displayValue(richHeader.structural_status ?? "observed")
                  : richHeader.present === false
                    ? "Not present"
                    : "Not recorded"}
              </strong>
            </div>
            <div>
              <span>Decoded entries</span>
              <strong>{displayValue(richHeader.entries_emitted)}</strong>
            </div>
            <div>
              <span>Checksum context</span>
              <strong>
                {richChecksum.matches === true
                  ? "Match"
                  : richChecksum.matches === false
                    ? "Mismatch"
                    : "Not recorded"}
              </strong>
            </div>
          </div>
          {richHeader.present === true ? (
            <details className="json-details">
              <summary>Inspect decoded Rich header entries</summary>
              <pre>{exactJson(richHeader)}</pre>
            </details>
          ) : null}
        </section>
        <section className="evidence-panel hash-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Immutable identity</p>
              <h2>Artifact hashes</h2>
            </div>
          </div>
          <div className="hash-row">
            <span>SHA-256</span>
            <code>{analysis.artifact.sha256 || "Not recorded"}</code>
          </div>
          <div className="hash-row">
            <span>SHA-1</span>
            <code>{analysis.artifact.sha1 || "Not recorded"}</code>
          </div>
          <div className="hash-row">
            <span>MD5</span>
            <code>{analysis.artifact.md5 || "Not recorded"}</code>
          </div>
          <div className="hash-row">
            <span>Artifact ID</span>
            <code>{analysis.artifact.id}</code>
          </div>
        </section>
      </div>
      <section className="evidence-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Analysis v2 context</p>
            <h2>Image structure and runtime context</h2>
          </div>
          <span>Absence means not recorded, not safe</span>
        </div>
        <div className="context-grid v2-context-grid">
          <article>
            <span>Overlay</span>
            <strong>
              {overlay.present === true
                ? `${displayValue(overlay.size)} bytes`
                : overlay.present === false
                  ? "Not present"
                  : "Not recorded"}
            </strong>
            <small>
              {typeof overlay.sha256 === "string"
                ? `SHA-256 ${overlay.sha256.slice(0, 16)}...`
                : "No overlay digest"}
            </small>
          </article>
          <article>
            <span>Manifest</span>
            <strong>{manifest.text ? "Observed" : "Not recorded"}</strong>
            <small>{displayValue(manifest.encoding)}</small>
          </article>
          <article>
            <span>Version info</span>
            <strong>{displayValue(version.structural_status)}</strong>
            <small>
              {version.metadata ? "Metadata retained" : "No metadata retained"}
            </small>
          </article>
          <article>
            <span>Relocations</span>
            <strong>{count("pe.relocation").toLocaleString()}</strong>
            <small>Bounded relocation records</small>
          </article>
          <article>
            <span>Load config</span>
            <strong>
              {loadConfig.present === true
                ? "Present"
                : loadConfig.present === false
                  ? "Not present"
                  : "Not recorded"}
            </strong>
            <small>
              ASLR {displayValue(mitigations.aslr)} / DEP{" "}
              {displayValue(mitigations.dep)} / CFG{" "}
              {displayValue(mitigations.cfg_declared)}
            </small>
          </article>
          <article>
            <span>Runtime functions</span>
            <strong>{count("pe.runtime_function").toLocaleString()}</strong>
            <small>Exception/unwind context</small>
          </article>
          <article>
            <span>CLR / managed entry point</span>
            <strong>
              {clr.present === true
                ? displayValue(
                    clrEntryPoint.display ?? clr.entry_point_token_or_rva,
                    clrEntryPoint.display === undefined,
                  )
                : "Not present"}
            </strong>
            <small>
              {clr.present === true
                ? `${displayValue(clrEntryPoint.kind)} / ${displayValue(clr.metadata_version)}`
                : "No CLR directory observed"}
            </small>
          </article>
        </div>
        {manifest.text || version.metadata || Object.keys(loadConfig).length ? (
          <details className="json-details">
            <summary>
              Inspect retained manifest, version, and load-config context
            </summary>
            <pre>
              {exactJson({ manifest, versionInfo: version, loadConfig })}
            </pre>
          </details>
        ) : null}
      </section>
      <section className="evidence-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Highest-priority context</p>
            <h2>Top findings</h2>
          </div>
          <span>{findings.length} total</span>
        </div>
        {topFindings.length ? (
          <div className="top-finding-list">
            {topFindings.map((finding) => (
              <article key={finding.id}>
                <div>
                  <span className={`severity severity-${finding.severity}`}>
                    {finding.severity}
                  </span>
                  <span>{finding.state ?? "new"}</span>
                </div>
                <h3>{finding.title}</h3>
                <p>{finding.observation || "No observation text persisted."}</p>
                {finding.evidence[0] ? (
                  <button
                    className="text-button"
                    onClick={() => onEvidence(finding.evidence[0]!.evidenceId)}
                    type="button"
                  >
                    Open linked evidence
                  </button>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <EmptyState>
            No findings were recorded. This is not a safety claim.
          </EmptyState>
        )}
      </section>
    </div>
  );
}

function FindingsTab({
  caseId,
  evidence,
  findings,
  busyId,
  onEvidence,
  onState,
  onNote,
  onBookmark,
}: {
  caseId: string;
  evidence: EvidenceView[];
  findings: FindingView[];
  busyId: string | null;
  onEvidence: (id: string, trigger?: HTMLElement) => void;
  onState: (
    finding: FindingView,
    action: "review" | "accept" | "dismiss" | "reopen",
  ) => void;
  onNote: (findingId: string) => void;
  onBookmark?: (target: BookmarkInput, label?: string) => void;
}) {
  const byId = new Map(evidence.map((item) => [item.id, item]));
  if (!findings.length)
    return (
      <EmptyState>
        No findings were recorded for this run. Absence of findings is not a
        safety claim.
      </EmptyState>
    );
  return (
    <div className="finding-list">
      <p className="confidence-notice">
        Confidence is a deterministic rule-strength score, not a malware
        probability or safety likelihood.
      </p>
      {findings.map((finding) => {
        const linked = [...finding.evidence].sort(
          (left, right) =>
            Number(right.role === "supports") -
              Number(left.role === "supports") ||
            left.evidenceId.localeCompare(right.evidenceId),
        );
        const supportCount = linked.filter(
          (link) => link.role === "supports",
        ).length;
        return (
          <article
            className="finding-card"
            id={`finding-${finding.id}`}
            key={finding.id}
          >
            <header>
              <div>
                <span className={`severity severity-${finding.severity}`}>
                  {finding.severity}
                </span>
                <span
                  className="confidence"
                  title="Deterministic rule-strength score; not a probability"
                >
                  Confidence: {finding.confidenceBand}{" "}
                  <small>
                    ({formatConfidence(finding.confidence)} rule score)
                  </small>
                </span>
                <span className="finding-state">
                  State: {finding.state ?? "new"}
                </span>
              </div>
              <code>
                {finding.ruleId} v{finding.ruleVersion}
              </code>
            </header>
            <p className="finding-category">{finding.category}</p>
            <h2>{finding.title}</h2>
            <div
              className="finding-actions"
              aria-label={`Actions for ${finding.title}`}
            >
              {(finding.state ?? "new") !== "reviewed" &&
              (finding.state ?? "new") !== "accepted" ? (
                <button
                  className="secondary-button"
                  disabled={busyId === finding.id}
                  onClick={() => onState(finding, "review")}
                  type="button"
                >
                  Review
                </button>
              ) : null}
              {(finding.state ?? "new") !== "accepted" &&
              (finding.state ?? "new") !== "dismissed" ? (
                <button
                  className="secondary-button"
                  disabled={busyId === finding.id}
                  onClick={() => onState(finding, "accept")}
                  type="button"
                >
                  Accept
                </button>
              ) : null}
              {(finding.state ?? "new") !== "dismissed" ? (
                <button
                  className="secondary-button"
                  disabled={busyId === finding.id}
                  onClick={() => onState(finding, "dismiss")}
                  type="button"
                >
                  Dismiss
                </button>
              ) : null}
              {(finding.state ?? "new") !== "new" ? (
                <button
                  className="secondary-button"
                  disabled={busyId === finding.id}
                  onClick={() => onState(finding, "reopen")}
                  type="button"
                >
                  Reopen
                </button>
              ) : null}
              <button
                className="text-button compact"
                onClick={() => onNote(finding.id)}
                type="button"
              >
                Add linked note
              </button>
              {onBookmark ? (
                <BookmarkAction
                  onClick={() =>
                    onBookmark(
                      { targetType: "finding", targetId: finding.id },
                      finding.title,
                    )
                  }
                />
              ) : null}
            </div>
            <div className="explanation-grid">
              <div>
                <h3>Observation</h3>
                <p>
                  {finding.observation || "No observation text was persisted."}
                </p>
              </div>
              <div>
                <h3>Why it matters</h3>
                <p>
                  {finding.whyItMatters ||
                    "No contextual explanation was persisted."}
                </p>
              </div>
              <div>
                <h3>Limitations</h3>
                <p>
                  {finding.limitations || "No limitations text was persisted."}
                </p>
              </div>
            </div>
            {(finding.attackMappings ?? []).length ? (
              <section className="attack-context">
                <h3>ATT&amp;CK capability context</h3>
                <p>
                  Static mappings describe possible capability context only.
                  They do not establish execution, intent, attribution, or
                  compromise.
                </p>
                <div>
                  {finding.attackMappings!.map((mapping) => (
                    <span
                      key={`${finding.id}-${mapping.techniqueId}-${mapping.tactic}`}
                    >
                      <strong>{mapping.techniqueId}</strong>{" "}
                      {mapping.techniqueName} / {mapping.tactic}
                    </span>
                  ))}
                </div>
              </section>
            ) : null}
            <div className="linked-evidence">
              <h3>
                Correlated evidence <span>{linked.length}</span>
              </h3>
              <p className="correlation-summary">
                {supportCount} supporting observation
                {supportCount === 1 ? "" : "s"}; {linked.length - supportCount}{" "}
                contextual observation
                {linked.length - supportCount === 1 ? "" : "s"}. Each link opens
                the exact persisted record.
              </p>
              {linked.length ? (
                linked.map((link) => {
                  const item = byId.get(link.evidenceId);
                  return (
                    <button
                      className={`correlated-evidence evidence-role-${link.role}`}
                      key={`${caseId}-${finding.id}-${link.evidenceId}`}
                      onClick={(event) =>
                        onEvidence(link.evidenceId, event.currentTarget)
                      }
                      type="button"
                    >
                      <span className="evidence-role">{link.role}</span>
                      <code>
                        {item
                          ? `${item.kind} / ${link.evidenceId}`
                          : link.evidenceId}
                      </code>
                      <span>{evidenceSummary(item)}</span>
                      <ArrowIcon />
                    </button>
                  );
                })
              ) : (
                <p className="empty-inline">
                  No evidence links were persisted for this finding.
                </p>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function ImportGroup({
  title,
  kind,
  evidence,
}: {
  title: string;
  kind: "pe.import" | "pe.delay_import";
  evidence: EvidenceView[];
}) {
  const imports = evidence.filter((item) => item.kind === kind);
  const [limit, setLimit] = useState(200);
  const groups = groupImports(imports.slice(0, limit));
  return (
    <section className="import-section">
      <div className="panel-heading standalone">
        <div>
          <p className="eyebrow">
            {kind === "pe.delay_import"
              ? "Deferred resolution"
              : "Loader resolution"}
          </p>
          <h2>{title}</h2>
        </div>
        <span>{imports.length.toLocaleString()} records</span>
      </div>
      {groups.length ? (
        <div className="import-groups">
          {groups.map((group) => (
            <section
              className="evidence-panel import-group"
              key={`${kind}-${group.dll}`}
            >
              <div className="panel-heading">
                <h3>{group.dll}</h3>
                <span>{group.items.length} shown</span>
              </div>
              <div className="section-table-wrap">
                <table className="section-table">
                  <caption className="visually-hidden">
                    {title} grouped by imported library
                  </caption>
                  <thead>
                    <tr>
                      <th>Name / ordinal</th>
                      <th>Hint</th>
                      <th>IAT RVA</th>
                      <th>Thunk RVA</th>
                      <th>Descriptor offset</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.items.map((item) => {
                      const value = asRecord(item.value);
                      return (
                        <tr key={item.id}>
                          <td>
                            <strong>
                              {typeof value.function === "string"
                                ? value.function
                                : `Ordinal ${displayValue(value.ordinal)}`}
                            </strong>
                          </td>
                          <td>{displayValue(value.hint)}</td>
                          <td>{displayValue(value.iat_rva, true)}</td>
                          <td>{displayValue(value.thunk_rva, true)}</td>
                          <td>
                            {displayValue(
                              item.locator.descriptor_file_offset,
                              true,
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
          {limit < imports.length ? (
            <ShowMore
              shown={limit}
              total={imports.length}
              onClick={() => setLimit((value) => value + 200)}
            />
          ) : null}
        </div>
      ) : (
        <EmptyState>No {title.toLocaleLowerCase()} were recorded.</EmptyState>
      )}
    </section>
  );
}

function ImportsTab({ evidence }: { evidence: EvidenceView[] }) {
  return (
    <div className="tab-stack">
      <ImportGroup
        evidence={evidence}
        kind="pe.import"
        title="Normal imports"
      />
      <ImportGroup
        evidence={evidence}
        kind="pe.delay_import"
        title="Delay imports"
      />
    </div>
  );
}

function StringsTab({ evidence }: { evidence: EvidenceView[] }) {
  const strings = evidence.filter(
    (item) => item.kind === "pe.string" || item.kind === "pe.indicator",
  );
  const [view, setView] = useState<StringView>("interesting");
  const [limit, setLimit] = useState(100);
  const shown = filterStringEvidence(strings, view);
  const views: { id: StringView; label: string }[] = [
    { id: "interesting", label: "Interesting" },
    { id: "indicators", label: "Indicators" },
    { id: "commands", label: "Commands" },
    { id: "paths_registry", label: "Paths / Registry" },
    { id: "urls_domains_ips", label: "URLs / Domains / IPs" },
    { id: "imports_apis", label: "Imports / APIs" },
    { id: "metadata", label: "Metadata" },
    { id: "raw", label: "Raw" },
    { id: "all", label: "All records" },
  ];
  if (!strings.length)
    return (
      <EmptyState>
        No string or indicator records were emitted. Incomplete or older
        analyses may lack this context.
      </EmptyState>
    );
  return (
    <section className="evidence-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Bounded extraction</p>
          <h2>Strings and indicators</h2>
        </div>
        <span>
          {shown.length.toLocaleString()} of {strings.length.toLocaleString()}{" "}
          records
        </span>
      </div>
      <div
        className="string-filters"
        role="group"
        aria-label="String categories"
      >
        {views.map((item) => (
          <button
            aria-pressed={view === item.id}
            className={view === item.id ? "string-filter-active" : ""}
            key={item.id}
            onClick={() => {
              setView(item.id);
              setLimit(100);
            }}
            type="button"
          >
            {item.label}
          </button>
        ))}
      </div>
      {shown.length ? (
        <div className="section-table-wrap">
          <table className="section-table strings-table">
            <caption className="visually-hidden">
              Extracted strings and indicators
            </caption>
            <thead>
              <tr>
                <th>Value</th>
                <th>Category</th>
                <th>Section</th>
                <th>Class</th>
                <th>Encoding</th>
                <th>Offset</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, limit).map((item) => {
                const value = asRecord(item.value);
                return (
                  <tr key={item.id}>
                    <td>
                      <strong>
                        {item.previewText ??
                          displayValue(value.text ?? value.value)}
                      </strong>
                    </td>
                    <td>
                      {item.kind === "pe.indicator"
                        ? displayValue(value.category)
                        : stringEvidenceCategory(item).replaceAll("_", " / ")}
                    </td>
                    <td>{displayValue(value.section_name)}</td>
                    <td>
                      <span className={`class-tag class-${item.class}`}>
                        {item.class || "unclassified"}
                      </span>
                    </td>
                    <td>
                      {displayValue(
                        value.encoding ??
                          item.locator.source_encoding ??
                          item.locator.encoding,
                      )}
                    </td>
                    <td>
                      {displayValue(
                        item.locator.file_offset ??
                          item.locator.source_file_offset,
                        true,
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState>No records are in this category.</EmptyState>
      )}
      {limit < shown.length ? (
        <ShowMore
          shown={limit}
          total={shown.length}
          onClick={() => setLimit((value) => value + 100)}
        />
      ) : null}
      <p className="cap-notice">
        Interesting is the default analyst view. Raw and All records retain the
        complete bounded extraction, including high-entropy section noise.
      </p>
    </section>
  );
}

function SectionsTab({ evidence }: { evidence: EvidenceView[] }) {
  const sections = evidence.filter((item) => item.kind === "pe.section");
  if (!sections.length)
    return (
      <EmptyState>
        No section records were emitted. Incomplete or older analyses may lack
        this context.
      </EmptyState>
    );
  return (
    <section className="evidence-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Observed layout</p>
          <h2>Sections</h2>
        </div>
        <span>{sections.length} records</span>
      </div>
      <div className="section-table-wrap">
        <table className="section-table">
          <caption className="visually-hidden">PE image sections</caption>
          <thead>
            <tr>
              <th>Name</th>
              <th>Virtual address</th>
              <th>Virtual size</th>
              <th>Raw offset</th>
              <th>Raw size</th>
              <th>Entropy</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((section) => {
              const value = asRecord(section.value);
              return (
                <tr key={section.id}>
                  <td>
                    <strong>{displayValue(value.name)}</strong>
                  </td>
                  <td>{displayValue(value.virtual_address, true)}</td>
                  <td>{displayValue(value.virtual_size)}</td>
                  <td>{displayValue(value.raw_offset, true)}</td>
                  <td>{displayValue(value.raw_size)}</td>
                  <td>{displayValue(value.entropy)}</td>
                  <td>{displayValue(value.characteristics, true)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function VerificationStatus({
  label,
  value,
}: {
  label: string;
  value: unknown;
}) {
  const record = asRecord(value);
  const state = displayValue(record.status ?? value);
  return (
    <article>
      <span>{label}</span>
      <strong>{state}</strong>
      <small>{displayValue(record.reason ?? record.scope)}</small>
    </article>
  );
}

function SignatureTab({ evidence }: { evidence: EvidenceView[] }) {
  const signatures = evidence.filter((item) => item.kind === "pe.authenticode");
  const verifications = evidence.filter(
    (item) => item.kind === "pe.authenticode.verification",
  );
  const trustEvidence = evidence.find(
    (item) => item.kind === "pe.authenticode.trust",
  );
  const trust = asRecord(trustEvidence?.value);
  const state = getSignatureState(signatures);
  return (
    <div className="tab-stack">
      <section className={`signature-summary signature-${state}`}>
        <div>
          <p className="eyebrow">Authenticode observation</p>
          <h2>{state}</h2>
          <p>
            {state === "present"
              ? "A certificate table and parseable signature structure were observed."
              : state === "absent"
                ? "No certificate table was observed."
                : state === "malformed"
                  ? "Signature structure was present but malformed."
                  : "Signature evidence is unavailable for this case."}
          </p>
        </div>
        <span>Not a safety verdict</span>
      </section>
      <section className="trust-notice">
        <strong>Offline trust is deliberately limited</strong>
        <p>
          Verification is cache-only and performs no network retrieval or online
          revocation checks. A local-root chain is not a complete WinVerifyTrust
          or EKU policy verdict. Cryptographic validity never establishes that a
          file is safe.
        </p>
      </section>
      {verifications.map((item, index) => {
        const value = asRecord(item.value);
        const digest = asRecord(value.image_digest);
        const cms = asArray(value.cms_signatures);
        const timestamps = asArray(value.timestamps);
        return (
          <section className="evidence-panel" key={item.id}>
            <div className="panel-heading">
              <div>
                <p className="eyebrow">
                  Verification entry {displayValue(value.entry_index ?? index)}
                </p>
                <h2>Digest, CMS, chain, and timestamp</h2>
              </div>
              <span>{item.id}</span>
            </div>
            <div className="verification-grid">
              <VerificationStatus
                label="Image digest match"
                value={
                  digest.matches === true
                    ? { status: "match" }
                    : digest.matches === false
                      ? { status: "mismatch" }
                      : digest
                }
              />
              <VerificationStatus
                label="CMS signature"
                value={cms[0] ?? { status: "unknown", reason: "not recorded" }}
              />
              <VerificationStatus
                label="Timestamp"
                value={
                  asRecord(timestamps[0]).timestamp_validity ?? {
                    status: timestamps.length ? "recorded" : "not recorded",
                  }
                }
              />
              <VerificationStatus
                label="Local chain build"
                value={value.chain_build}
              />
              <VerificationStatus
                label="Publisher / local root"
                value={value.publisher_trust}
              />
              <VerificationStatus label="Revocation" value={value.revocation} />
            </div>
            {timestamps.length > 1 || cms.length > 1 ? (
              <details className="json-details">
                <summary>Inspect all CMS signatures and timestamps</summary>
                <pre>{exactJson({ cmsSignatures: cms, timestamps })}</pre>
              </details>
            ) : null}
            <details className="json-details">
              <summary>Exact verification evidence</summary>
              <pre>{exactJson(item)}</pre>
            </details>
          </section>
        );
      })}
      {!verifications.length ? (
        <EmptyState>
          No v2 verification evidence was persisted. Structural evidence may
          still be available below.
        </EmptyState>
      ) : null}
      {signatures.map((item) => (
        <details
          className="evidence-panel json-details structural-signature"
          key={item.id}
        >
          <summary>Structural signature evidence {item.id}</summary>
          <pre>{exactJson(item)}</pre>
        </details>
      ))}
      {trustEvidence ? (
        <section className="trust-record">
          <strong>Persisted offline trust record</strong>
          <span>
            {displayValue(trust.state ?? trust.status)} /{" "}
            {displayValue(trust.reason)}
          </span>
        </section>
      ) : null}
    </div>
  );
}

function YaraTab({
  evidence,
  onEvidence,
}: {
  evidence: EvidenceView[];
  onEvidence: (id: string, trigger?: HTMLElement) => void;
}) {
  const matches = evidence.filter((item) => item.kind === "yara.match");
  if (!matches.length)
    return (
      <EmptyState>
        No YARA matches were recorded for this run. This can mean no enabled
        pack matched, no pack was enabled, or the case predates YARA analysis.
        It is not a safety claim.
      </EmptyState>
    );
  return (
    <div className="yara-list">
      {matches.slice(0, 200).map((item) => {
        const value = asRecord(item.value);
        const strings = asArray(value.matched_strings);
        return (
          <article className="evidence-panel yara-match" key={item.id}>
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Observed YARA-X match</p>
                <h2>
                  {displayValue(value.namespace)}:
                  {displayValue(value.rule_identifier)}
                </h2>
              </div>
              <span>
                {displayValue(value.pack_name)} v
                {displayValue(value.pack_version)}
              </span>
            </div>
            <FactGrid
              facts={[
                { label: "Pack SHA-256", value: value.pack_sha256 },
                { label: "Tags", value: value.tags },
                { label: "Matched string groups", value: strings.length },
                {
                  label: "Instances truncated",
                  value: value.string_instances_truncated,
                },
              ]}
            />
            <button
              className="text-button"
              onClick={(event) => onEvidence(item.id, event.currentTarget)}
              type="button"
            >
              Inspect evidence and provenance
            </button>
            <details className="json-details">
              <summary>
                Exact match metadata and bounded string evidence
              </summary>
              <pre>{exactJson(item)}</pre>
            </details>
          </article>
        );
      })}
      {matches.length > 200 ? (
        <p className="cap-notice">
          Showing the first 200 of {matches.length.toLocaleString()} YARA
          matches to keep rendering responsive.
        </p>
      ) : null}
    </div>
  );
}

function EvidenceTab({
  evidence,
  selectedId,
}: {
  evidence: EvidenceView[];
  selectedId: string | null;
}) {
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [kind, setKind] = useState("");
  const [observationClass, setObservationClass] = useState("");
  const [limit, setLimit] = useState(100);
  const kinds = [...new Set(evidence.map((item) => item.kind))].sort();
  const classes = [
    ...new Set(evidence.map((item) => item.class).filter(Boolean)),
  ].sort();
  const filtered = filterEvidence(evidence, {
    search: deferredSearch,
    kind,
    observationClass,
  });
  const shown = filtered.slice(0, limit);
  const selected = selectedId
    ? filtered.find((item) => item.id === selectedId)
    : undefined;
  const displayed =
    selected && !shown.some((item) => item.id === selected.id)
      ? [selected, ...shown]
      : shown;
  return (
    <div className="tab-stack">
      <section className="evidence-controls" aria-label="Evidence filters">
        <label className="search-field">
          <span>Search exact evidence</span>
          <input
            maxLength={256}
            onChange={(event) => {
              setSearch(event.target.value);
              setLimit(100);
            }}
            placeholder="Kind, class, preview, locator, or value"
            type="search"
            value={search}
          />
        </label>
        <label>
          <span>Class</span>
          <select
            onChange={(event) => {
              setObservationClass(event.target.value);
              setLimit(100);
            }}
            value={observationClass}
          >
            <option value="">All classes</option>
            {classes.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Kind</span>
          <select
            onChange={(event) => {
              setKind(event.target.value);
              setLimit(100);
            }}
            value={kind}
          >
            <option value="">All kinds</option>
            {kinds.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <div className="result-count" aria-live="polite">
          <strong>{filtered.length.toLocaleString()}</strong>
          <span>of {evidence.length.toLocaleString()} records</span>
        </div>
      </section>
      {displayed.length ? (
        <div className="evidence-list">
          {displayed.map((item) => (
            <details
              className={`evidence-record${item.id === selectedId ? " evidence-record-selected" : ""}`}
              id={`evidence-${item.id}`}
              key={item.id}
              open={item.id === selectedId}
            >
              <summary>
                <span className={`class-dot class-${item.class}`} />
                <span>
                  <code>{item.kind}</code>
                  <strong>
                    {item.previewText ?? displayValue(item.value)}
                  </strong>
                </span>
                <span>{item.class || "unclassified"}</span>
                <ArrowIcon />
              </summary>
              <div className="evidence-record-body">
                <dl>
                  <div>
                    <dt>Evidence ID</dt>
                    <dd>
                      <code>{item.id}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Locator</dt>
                    <dd>
                      <code>{displayValue(item.locator)}</code>
                    </dd>
                  </div>
                </dl>
                <pre>{exactJson(item)}</pre>
              </div>
            </details>
          ))}
        </div>
      ) : (
        <EmptyState>
          {evidence.length
            ? "No evidence matches the filters."
            : "No evidence was persisted. This case may be older or incomplete."}
        </EmptyState>
      )}
      {limit < filtered.length ? (
        <ShowMore
          shown={limit}
          total={filtered.length}
          onClick={() => setLimit((value) => value + 100)}
        />
      ) : null}
    </div>
  );
}

function NotesPanel({
  caseId,
  findings,
  linkedFinding,
}: {
  caseId: string;
  findings: FindingView[];
  linkedFinding: string | null;
}) {
  const [notes, setNotes] = useState<NoteView[]>([]);
  const [body, setBody] = useState("");
  const [findingId, setFindingId] = useState(linkedFinding ?? "");
  const [editing, setEditing] = useState<string | null>(null);
  const [editBody, setEditBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    invoke<NoteView[]>("list_notes", { caseId })
      .then((value) => {
        if (!cancelled) setNotes(value);
      })
      .catch((reason) => {
        if (!cancelled) setError(String(reason));
      });
    return () => {
      cancelled = true;
    };
  }, [caseId]);
  async function create(event: FormEvent) {
    event.preventDefault();
    if (!body.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const note = await invoke<NoteView>("create_note", {
        caseId,
        entityId: null,
        findingId: findingId || null,
        body,
      });
      setNotes((current) => [note, ...current]);
      setBody("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  async function update(noteId: string) {
    if (!editBody.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const note = await invoke<NoteView>("update_note", {
        caseId,
        noteId,
        body: editBody,
      });
      setNotes((current) =>
        current.map((item) => (item.id === note.id ? note : item)),
      );
      setEditing(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  async function remove(noteId: string) {
    setBusy(true);
    setError(null);
    try {
      await invoke("delete_note", { caseId, noteId });
      setNotes((current) => current.filter((item) => item.id !== noteId));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  const findingTitles = new Map(
    findings.map((finding) => [finding.id, finding.title]),
  );
  return (
    <div className="notes-layout">
      <form
        aria-busy={busy}
        className="note-composer evidence-panel"
        onSubmit={(event) => void create(event)}
      >
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Analyst record</p>
            <h2>Add note</h2>
          </div>
          <span>16 KiB maximum</span>
        </div>
        <label>
          <span>Link scope</span>
          <select
            onChange={(event) => setFindingId(event.target.value)}
            value={findingId}
          >
            <option value="">Case note</option>
            {findings.map((finding) => (
              <option key={finding.id} value={finding.id}>
                Finding: {finding.title}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Note</span>
          <textarea
            maxLength={16384}
            onChange={(event) => setBody(event.target.value)}
            placeholder="Record analysis context, decisions, or follow-up..."
            rows={5}
            value={body}
          />
        </label>
        <button
          className="choose-button"
          disabled={busy || !body.trim()}
          type="submit"
        >
          Add note
        </button>
      </form>
      {error ? <ErrorMessage>{error}</ErrorMessage> : null}
      <div aria-live="polite" className="note-list">
        {notes.map((note) => (
          <article className="evidence-panel note-card" key={note.id}>
            <header>
              <div>
                <strong>
                  {note.findingId
                    ? "Finding-linked note"
                    : note.entityId
                      ? "Entity-linked note"
                      : "Case note"}
                </strong>
                <span>
                  {note.findingId
                    ? (findingTitles.get(note.findingId) ?? note.findingId)
                    : "Entire case"}
                </span>
              </div>
              <time dateTime={note.updatedAt}>{formatDate(note.updatedAt)}</time>
            </header>
            {editing === note.id ? (
              <>
                <label className="visually-hidden" htmlFor={`edit-${note.id}`}>
                  Edit note
                </label>
                <textarea
                  id={`edit-${note.id}`}
                  maxLength={16384}
                  onChange={(event) => setEditBody(event.target.value)}
                  rows={5}
                  value={editBody}
                />
                <div className="inline-actions">
                  <button
                    className="secondary-button"
                    disabled={busy}
                    onClick={() => void update(note.id)}
                    type="button"
                  >
                    Save note
                  </button>
                  <button
                    className="text-button compact"
                    onClick={() => setEditing(null)}
                    type="button"
                  >
                    Cancel
                  </button>
                </div>
              </>
            ) : (
              <p>{note.body}</p>
            )}
            <footer>
              <button
                className="text-button compact"
                onClick={() => {
                  setEditing(note.id);
                  setEditBody(note.body);
                }}
                type="button"
              >
                Edit
              </button>
              <button
                className="text-button danger-text compact"
                disabled={busy}
                onClick={() => void remove(note.id)}
                type="button"
              >
                Delete note
              </button>
            </footer>
          </article>
        ))}
        {!notes.length ? (
          <EmptyState>
            No analyst notes have been added to this case.
          </EmptyState>
        ) : null}
      </div>
    </div>
  );
}

function AnalysisDetail({
  analysis,
  onAnalysis,
  onNew,
}: {
  analysis: CaseAnalysis;
  onAnalysis: (value: CaseAnalysis) => void;
  onNew: () => void;
}) {
  const evidence = analysis.evidence ?? [];
  const findings = analysis.findings ?? [];
  const history = analysis.runHistory ?? [];
  const [tab, setTab] = useState<AnalysisTab>("quick");
  const [selectedEvidence, setSelectedEvidence] = useState<string | null>(null);
  const [graphFocus, setGraphFocus] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [highlightedChronologyEvent, setHighlightedChronologyEvent] = useState<string | null>(null);
  const evidenceReturnFocus = useRef<HTMLElement | null>(null);
  const [linkedFinding, setLinkedFinding] = useState<string | null>(null);
  const [exporting, setExporting] = useState<"json" | "html" | "pdf" | "csv" | "stix" | null>(null);
  const [reportReceipt, setReportReceipt] = useState<ReportReceipt | null>(
    null,
  );
  const [bundleReceipt, setBundleReceipt] =
    useState<ReportBundleReceipt | null>(null);
  const [bundleVerification, setBundleVerification] =
    useState<BundleVerification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [loadingRun, setLoadingRun] = useState(false);
  const [findingBusy, setFindingBusy] = useState<string | null>(null);
  useEffect(
    () => () => {
      if (highlightTimer.current) clearTimeout(highlightTimer.current);
    },
    [],
  );
  function clearChronologyHighlight() {
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = null;
    setHighlightedChronologyEvent(null);
  }
  function openEvidence(id: string, trigger?: HTMLElement) {
    evidenceReturnFocus.current =
      trigger ??
      (document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null);
    setSelectedEvidence(id);
  }
  function closeEvidence() {
    setSelectedEvidence(null);
    requestAnimationFrame(() => evidenceReturnFocus.current?.focus());
  }
  function openFinding(id: string) {
    clearChronologyHighlight();
    setTab("findings");
    requestAnimationFrame(() =>
      document
        .getElementById(`finding-${id}`)
        ?.scrollIntoView({ behavior: "smooth", block: "center" }),
    );
  }
  function showInChronology(evidenceId: string) {
    const chronology = analysis.chronology;
    if (!chronology) {
      setError("No chronology is available for this analysis run.");
      return;
    }
    const matching = chronology.events.find(
      (event) => event.evidenceId === evidenceId,
    );
    if (!matching) {
      setError("This graph evidence has no corresponding chronology event.");
      return;
    }
    clearChronologyHighlight();
    setError(null);
    setHighlightedChronologyEvent(matching.id);
    setGraphFocus(null);
    setTab("chronology");
    requestAnimationFrame(() =>
      document
        .getElementById(`event-${matching.id}`)
        ?.scrollIntoView({ behavior: "smooth", block: "center" }),
    );
    highlightTimer.current = setTimeout(() => {
      highlightTimer.current = null;
      setHighlightedChronologyEvent(null);
    }, 3000);
  }
  function showInGraph(evidenceId: string) {
    const graph = analysis.graph;
    if (!graph) {
      setError("No graph is available for this analysis run.");
      return;
    }
    const link = graph.entityEvidence.find(
      (item) => item.evidenceId === evidenceId,
    );
    if (!link) {
      setError("This chronology event has no corresponding graph entity.");
      return;
    }
    clearChronologyHighlight();
    setError(null);
    setGraphFocus(link.entityId);
    setTab("graph");
  }
  async function exportReport(format: "json" | "html" | "pdf" | "csv" | "stix") {
    setExporting(format);
    setError(null);
    setReportReceipt(null);
    try {
      const receipt = await invoke<ReportReceipt | null>("export_case_report", {
        caseId: analysis.case.id,
        runId: analysis.run?.id ?? null,
        format,
      });
      if (receipt) setReportReceipt(receipt);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setExporting(null);
    }
  }
  async function exportBundle(format: "json" | "html" | "pdf" | "csv" | "stix") {
    setExporting(format);
    setError(null);
    setBundleReceipt(null);
    setBundleVerification(null);
    try {
      const receipt = await invoke<ReportBundleReceipt | null>(
        "export_case_report_bundle",
        { caseId: analysis.case.id, runId: analysis.run?.id ?? null, format },
      );
      if (receipt) setBundleReceipt(receipt);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setExporting(null);
    }
  }
  async function verifyBundle() {
    if (!bundleReceipt) return;
    setError(null);
    try {
      setBundleVerification(
        await invoke<BundleVerification>("verify_case_report_bundle", {
          verificationToken: bundleReceipt.verificationToken,
        }),
      );
    } catch (reason) {
      setError(String(reason));
    }
  }
  async function createBookmark(target: BookmarkInput, label?: string) {
    setError(null);
    try {
      const bookmark = await invoke<BookmarkRecord>("create_bookmark", {
        caseId: analysis.case.id,
        target,
        label: label ?? null,
      });
      onAnalysis({
        ...analysis,
        bookmarks: [...(analysis.bookmarks ?? []), bookmark],
      });
    } catch (reason) {
      setError(String(reason));
    }
  }
  async function deleteBookmark(bookmark: BookmarkRecord) {
    setError(null);
    try {
      await invoke("delete_bookmark", {
        caseId: analysis.case.id,
        bookmarkId: bookmark.id,
      });
      onAnalysis({
        ...analysis,
        bookmarks: (analysis.bookmarks ?? []).filter(
          (item) => item.id !== bookmark.id,
        ),
      });
    } catch (reason) {
      setError(String(reason));
    }
  }
  async function renameBookmark(bookmark: BookmarkRecord, label: string) {
    setError(null);
    try {
      const updated = await invoke<BookmarkRecord>("update_bookmark", {
        caseId: analysis.case.id,
        bookmarkId: bookmark.id,
        label,
      });
      onAnalysis({
        ...analysis,
        bookmarks: (analysis.bookmarks ?? []).map((item) =>
          item.id === updated.id ? updated : item,
        ),
      });
    } catch (reason) {
      setError(String(reason));
    }
  }
  function openBookmark(target: BookmarkTarget) {
    if (target.type === "evidence") {
      openEvidence(target.evidenceId);
      return;
    }
    if (target.type === "finding") {
      openFinding(target.findingId);
      return;
    }
    if (target.type === "event") {
      clearChronologyHighlight();
      setGraphFocus(null);
      setHighlightedChronologyEvent(target.eventId);
      setTab("chronology");
      requestAnimationFrame(() =>
        document
          .getElementById(`event-${target.eventId}`)
          ?.scrollIntoView({ behavior: "smooth", block: "center" }),
      );
      highlightTimer.current = setTimeout(() => {
        highlightTimer.current = null;
        setHighlightedChronologyEvent(null);
      }, 3000);
      return;
    }
    clearChronologyHighlight();
    setGraphFocus(target.type === "entity" ? target.entityId : target.edgeId);
    setTab("graph");
  }
  async function reanalyze() {
    setReanalyzing(true);
    setError(null);
    try {
      onAnalysis(
        await invoke<CaseAnalysis>("reanalyze_case", {
          caseId: analysis.case.id,
        }),
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setReanalyzing(false);
    }
  }
  async function loadRun(runId: string) {
    if (!runId || runId === analysis.run?.id) return;
    setLoadingRun(true);
    setError(null);
    try {
      const result = await invoke<CaseAnalysis | null>(
        "get_case_analysis_run",
        { caseId: analysis.case.id, runId },
      );
      if (!result) throw new Error("The selected analysis run was not found.");
      onAnalysis(result);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoadingRun(false);
    }
  }
  async function transitionFinding(
    finding: FindingView,
    action: "review" | "accept" | "dismiss" | "reopen",
  ) {
    setFindingBusy(finding.id);
    setError(null);
    try {
      onAnalysis(
        await invoke<CaseAnalysis>("transition_finding", {
          caseId: analysis.case.id,
          findingId: finding.id,
          action,
        }),
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setFindingBusy(null);
    }
  }
  function onTabKey(event: KeyboardEvent<HTMLButtonElement>, id: AnalysisTab) {
    if (
      event.key !== "ArrowLeft" &&
      event.key !== "ArrowRight" &&
      event.key !== "Home" &&
      event.key !== "End"
    )
      return;
    event.preventDefault();
    const current = TABS.findIndex((item) => item.id === id);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? TABS.length - 1
          : (current + (event.key === "ArrowRight" ? 1 : -1) + TABS.length) %
            TABS.length;
    const nextTab = TABS[next]!.id;
    if (nextTab === "notes") setLinkedFinding(null);
    if (nextTab !== "chronology") clearChronologyHighlight();
    setTab(nextTab);
    document.getElementById(`tab-${nextTab}`)?.focus();
  }
  const complete = analysis.run?.status === "complete";
  return (
    <div
      aria-busy={
        reanalyzing ||
        loadingRun ||
        exporting !== null ||
        findingBusy !== null
      }
      className="analysis-page"
    >
      <section className="analysis-hero">
        <div>
          <p className="eyebrow">
            Case {analysis.case.id.slice(-8)} / artifact{" "}
            {analysis.artifact.id.slice(-8)}
          </p>
          <h1>
            {analysis.case.title ||
              analysis.artifact.originalName ||
              "Untitled case"}
          </h1>
          <p className="analysis-subtitle">
            <strong>
              {analysis.artifact.originalName || "Unnamed artifact"}
            </strong>{" "}
            / immutable SHA-256-addressed copy /{" "}
            {formatDate(analysis.run?.startedAt)}
          </p>
        </div>
        <div className="analysis-actions">
          <StatusBadge
            status={reanalyzing ? "running" : analysis.run?.status}
          />
          <button
            className="secondary-button"
            disabled={reanalyzing}
            onClick={() => void reanalyze()}
            type="button"
          >
            {reanalyzing ? "Reanalyzing..." : "Reanalyze"}
          </button>
          <button className="secondary-button" onClick={onNew} type="button">
            Analyze another
          </button>
        </div>
      </section>
      {reanalyzing ? (
        <section className="progress-panel" role="status">
          <span className="progress-track">
            <span />
          </span>
          <strong>Static reanalysis in progress</strong>
          <p>
            Current enabled rule packs are applied. The existing run remains
            preserved.
          </p>
        </section>
      ) : null}
      {!complete ? (
        <section className="analysis-warning" role="alert">
          <strong>Analysis is not complete.</strong>
          <span>
            Available observations may be partial. Worker code:{" "}
            <code>{analysis.run?.errorCode ?? "not recorded"}</code>.
          </span>
        </section>
      ) : null}
      <section
        aria-busy={exporting !== null || loadingRun}
        aria-label="Analysis run and report exports"
        className="run-report-bar"
      >
        <label>
          <span>Analysis run</span>
          <select
            aria-label="Analysis run history"
            disabled={loadingRun || reanalyzing}
            onChange={(event) => void loadRun(event.target.value)}
            value={analysis.run?.id ?? ""}
          >
            {history.length ? (
              history.map((run) => (
                <option key={run.id} value={run.id}>
                  {formatDate(run.startedAt)} / {runStatusLabel(run.status)} /{" "}
                  {run.analyzerVersion}
                </option>
              ))
            ) : (
              <option value={analysis.run?.id ?? ""}>
                {analysis.run
                  ? `${formatDate(analysis.run.startedAt)} / ${runStatusLabel(analysis.run.status)}`
                  : "No run recorded"}
              </option>
            )}
          </select>
        </label>
        <div className="report-actions">
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportReport("json")}
            type="button"
          >
            Export JSON
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportReport("html")}
            type="button"
          >
            Export HTML
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportReport("pdf")}
            type="button"
          >
            Export PDF
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportReport("csv")}
            type="button"
          >
            Export CSV
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportReport("stix")}
            type="button"
          >
            Export STIX
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportBundle("json")}
            type="button"
          >
            Export JSON + integrity manifest
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportBundle("html")}
            type="button"
          >
            Export HTML + integrity manifest
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportBundle("pdf")}
            type="button"
          >
            Export PDF + integrity manifest
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportBundle("csv")}
            type="button"
          >
            Export CSV + integrity manifest
          </button>
          <button
            className="secondary-button"
            disabled={exporting !== null}
            onClick={() => void exportBundle("stix")}
            type="button"
          >
            Export STIX + integrity manifest
          </button>
        </div>
      </section>
      {reportReceipt ? (
        <p className="report-result" role="status">
          <strong>{reportReceipt.fileName}</strong>
          <span>
            {reportReceipt.format.toUpperCase()} / SHA-256{" "}
            <code>{reportReceipt.sha256}</code>
          </span>
        </p>
      ) : null}
      {bundleReceipt ? (
        <p className="report-result" role="status">
          <strong>
            {bundleReceipt.reportFileName} + {bundleReceipt.manifestFileName}
          </strong>
          <span>
            Report SHA-256 <code>{bundleReceipt.reportSha256}</code>
          </span>
          <span>
            Manifest SHA-256 <code>{bundleReceipt.manifestSha256}</code>
          </span>
          <span>
            Snapshot SHA-256 <code>{bundleReceipt.snapshotSha256}</code>
          </span>
          <button
            className="secondary-button"
            onClick={() => void verifyBundle()}
            type="button"
          >
            Verify exact bundle bytes
          </button>
          {bundleVerification ? (
            <span>
              {bundleVerification.status} / artifact{" "}
              {bundleVerification.artifactVerification}:{" "}
              {bundleVerification.detail}
            </span>
          ) : null}
        </p>
      ) : null}
      <BookmarksBar
        bookmarks={analysis.bookmarks ?? []}
        onDelete={(bookmark) => void deleteBookmark(bookmark)}
        onOpen={openBookmark}
        onRename={(bookmark, label) => void renameBookmark(bookmark, label)}
      />
      {error ? <ErrorMessage>{error}</ErrorMessage> : null}
      <div
        className="analysis-tabs"
        role="tablist"
        aria-label="Case analysis views"
      >
        {TABS.map((item) => (
          <button
            aria-controls={`panel-${item.id}`}
            aria-selected={tab === item.id}
            className={tab === item.id ? "analysis-tab-active" : ""}
            id={`tab-${item.id}`}
            key={item.id}
            onClick={() => {
              if (item.id === "notes") setLinkedFinding(null);
              if (item.id !== "chronology") clearChronologyHighlight();
              setTab(item.id);
            }}
            onKeyDown={(event) => onTabKey(event, item.id)}
            role="tab"
            tabIndex={tab === item.id ? 0 : -1}
            type="button"
          >
            {item.label}
            {item.id === "findings" ? (
              <span>{findings.length}</span>
            ) : item.id === "evidence" ? (
              <span>{evidence.length}</span>
            ) : item.id === "yara" ? (
              <span>
                {evidence.filter((entry) => entry.kind === "yara.match").length}
              </span>
            ) : null}
          </button>
        ))}
      </div>
      <div
        aria-labelledby={`tab-${tab}`}
        className="analysis-tab-panel"
        id={`panel-${tab}`}
        role="tabpanel"
      >
        {tab === "quick" && analysis.quickCheck ? (
          <QuickCheckView
            check={analysis.quickCheck}
            findings={findings}
            onBookmark={(target, label) => void createBookmark(target, label)}
            onEvidence={openEvidence}
            onFinding={openFinding}
          />
        ) : null}
        {tab === "overview" ? (
          <OverviewTab
            analysis={analysis}
            evidence={evidence}
            findings={findings}
            onEvidence={openEvidence}
          />
        ) : null}
        {tab === "findings" ? (
          <FindingsTab
            busyId={findingBusy}
            caseId={analysis.case.id}
            evidence={evidence}
            findings={findings}
            onBookmark={(target, label) => void createBookmark(target, label)}
            onEvidence={openEvidence}
            onNote={(findingId) => {
              setLinkedFinding(findingId);
              setTab("notes");
            }}
            onState={(finding, action) =>
              void transitionFinding(finding, action)
            }
          />
        ) : null}
        {tab === "graph" ? (
          <GraphView
            focusTarget={graphFocus}
            graph={analysis.graph ?? null}
            onBookmark={(target, label) => void createBookmark(target, label)}
            onEvidence={openEvidence}
            onShowInChronology={showInChronology}
          />
        ) : null}
        {tab === "chronology" ? (
          <ChronologyView
            chronology={analysis.chronology ?? null}
            onBookmark={(target, label) => void createBookmark(target, label)}
            onEvidence={openEvidence}
            onShowInGraph={showInGraph}
            highlightedEventId={highlightedChronologyEvent}
          />
        ) : null}
        {tab === "imports" ? <ImportsTab evidence={evidence} /> : null}
        {tab === "strings" ? <StringsTab evidence={evidence} /> : null}
        {tab === "sections" ? <SectionsTab evidence={evidence} /> : null}
        {tab === "signature" ? <SignatureTab evidence={evidence} /> : null}
        {tab === "yara" ? (
          <YaraTab evidence={evidence} onEvidence={openEvidence} />
        ) : null}
        {tab === "evidence" ? (
          <EvidenceTab evidence={evidence} selectedId={selectedEvidence} />
        ) : null}
        {tab === "notes" ? (
          <NotesPanel
            caseId={analysis.case.id}
            findings={findings}
            linkedFinding={linkedFinding}
          />
        ) : null}
      </div>
      <footer className="provenance-bar">
        <div>
          <span>Analyzer</span>
          <strong>
            {analysis.provenance?.analyzer ??
              analysis.run?.analyzer ??
              "Unavailable"}{" "}
            {analysis.provenance?.analyzerVersion ??
              analysis.run?.analyzerVersion ??
              ""}
          </strong>
        </div>
        <div>
          <span>Provenance records</span>
          <strong>
            {analysis.provenances?.length ?? (analysis.provenance ? 1 : 0)}
          </strong>
        </div>
        <div>
          <span>Input verification</span>
          <strong>
            {(
              analysis.provenances ??
              (analysis.provenance ? [analysis.provenance] : [])
            ).some((item) => item.inputSha256 === analysis.artifact.sha256)
              ? "SHA-256 match"
              : "Unavailable"}
          </strong>
        </div>
        <p>
          Direct and contextual static observations only. Artifacta did not
          execute the artifact and makes no malware or safety verdict.
        </p>
      </footer>
      <EvidenceDrawer
        evidence={evidence}
        evidenceId={selectedEvidence}
        findings={findings}
        graph={analysis.graph ?? null}
        onBookmark={(target, label) => void createBookmark(target, label)}
        onClose={closeEvidence}
        provenances={
          analysis.provenances ??
          (analysis.provenance ? [analysis.provenance] : [])
        }
      />
    </div>
  );
}

function CasesPage({
  cases,
  busy,
  error,
  onOpen,
  onRefresh,
}: {
  cases: CaseSummary[];
  busy: boolean;
  error: string | null;
  onOpen: (item: CaseSummary) => void;
  onRefresh: (cases: CaseSummary[]) => void;
}) {
  const [showArchived, setShowArchived] = useState(true);
  const [editing, setEditing] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [confirmCase, setConfirmCase] = useState<CaseSummary | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [receipt, setReceipt] = useState<DeleteCaseReceipt | null>(null);
  const visible = cases.filter(
    (item) => showArchived || item.status !== "archived",
  );
  async function rename(item: CaseSummary) {
    if (!title.trim()) return;
    setActionBusy(true);
    setActionError(null);
    try {
      const updated = await invoke<CaseSummary>("rename_case", {
        caseId: item.id,
        title,
      });
      onRefresh(cases.map((entry) => (entry.id === item.id ? updated : entry)));
      setEditing(null);
    } catch (reason) {
      setActionError(String(reason));
    } finally {
      setActionBusy(false);
    }
  }
  async function archive(item: CaseSummary) {
    setActionBusy(true);
    setActionError(null);
    try {
      const command =
        item.status === "archived" ? "unarchive_case" : "archive_case";
      const updated = await invoke<CaseSummary>(command, { caseId: item.id });
      onRefresh(cases.map((entry) => (entry.id === item.id ? updated : entry)));
    } catch (reason) {
      setActionError(String(reason));
    } finally {
      setActionBusy(false);
    }
  }
  async function remove() {
    if (!confirmCase) return;
    setActionBusy(true);
    setActionError(null);
    try {
      const result = await invoke<DeleteCaseReceipt>("delete_case", {
        caseId: confirmCase.id,
      });
      setReceipt(result);
      onRefresh(cases.filter((entry) => entry.id !== confirmCase.id));
      setConfirmCase(null);
    } catch (reason) {
      setActionError(String(reason));
    } finally {
      setActionBusy(false);
    }
  }
  return (
    <section className="cases-page">
      <div className="page-heading split-heading">
        <div>
          <p className="eyebrow">Local workspace</p>
          <h1>Cases</h1>
          <p>
            Persisted artifacts, run history, findings, evidence, and analyst
            notes.
          </p>
        </div>
        <label className="toggle-label">
          <input
            checked={showArchived}
            onChange={(event) => setShowArchived(event.target.checked)}
            type="checkbox"
          />{" "}
          Show archived cases
        </label>
      </div>
      {error || actionError ? (
        <ErrorMessage>{actionError ?? error}</ErrorMessage>
      ) : null}
      {receipt ? (
        <section className="cleanup-receipt" role="status">
          <strong>Case deleted / cleanup receipt</strong>
          <span>Case {receipt.caseId}</span>
          {receipt.objects.length ? (
            <ul>
              {receipt.objects.map((object) => (
                <li key={object.sha256}>
                  <code>{object.sha256}</code>
                  <span>{object.cleanup.replaceAll("_", " ")}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p>No content-addressed objects required cleanup.</p>
          )}
        </section>
      ) : null}
      <div className="case-list">
        {visible.map((item) => (
          <article
            className={`case-row${item.status === "archived" ? " case-row-archived" : ""}`}
            key={item.id}
          >
            <span
              aria-hidden="true"
              className={`case-status status-${item.status}`}
            />
            <div className="case-primary">
              {editing === item.id ? (
                <div className="rename-form">
                  <label
                    className="visually-hidden"
                    htmlFor={`rename-${item.id}`}
                  >
                    New case title
                  </label>
                  <input
                    id={`rename-${item.id}`}
                    maxLength={256}
                    onChange={(event) => setTitle(event.target.value)}
                    value={title}
                  />
                  <button
                    className="secondary-button"
                    disabled={actionBusy}
                    onClick={() => void rename(item)}
                    type="button"
                  >
                    Save
                  </button>
                  <button
                    className="text-button compact"
                    onClick={() => setEditing(null)}
                    type="button"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <>
                  <button
                    className="case-open"
                    disabled={busy || actionBusy}
                    onClick={() => onOpen(item)}
                    type="button"
                  >
                    <strong>{item.title || "Untitled case"}</strong>
                    <small>{item.id}</small>
                  </button>
                  <time dateTime={item.updatedAt ?? item.createdAt}>
                    {formatDate(item.updatedAt ?? item.createdAt)}
                  </time>
                </>
              )}
            </div>
            <span className={`case-state status-${item.status}`}>
              {item.status}
            </span>
            <div className="case-actions">
              <button
                className="text-button compact"
                onClick={() => {
                  setEditing(item.id);
                  setTitle(item.title);
                }}
                type="button"
              >
                Rename
              </button>
              <button
                className="text-button compact"
                disabled={actionBusy}
                onClick={() => void archive(item)}
                type="button"
              >
                {item.status === "archived" ? "Unarchive" : "Archive"}
              </button>
              <button
                className="text-button danger-text compact"
                onClick={() => setConfirmCase(item)}
                type="button"
              >
                Delete
              </button>
            </div>
            <button
              aria-label={`Open ${item.title}`}
              className="icon-button"
              disabled={busy || actionBusy}
              onClick={() => onOpen(item)}
              type="button"
            >
              <ArrowIcon />
            </button>
          </article>
        ))}
        {!visible.length ? (
          <EmptyState>
            {cases.length
              ? "No cases match the archived-state filter."
              : "No local cases yet. Start a static analysis."}
          </EmptyState>
        ) : null}
      </div>
      {confirmCase ? (
        <ConfirmDialog
          body={
            <p>
              Permanently delete <strong>{confirmCase.title}</strong>, its
              persisted analysis data, notes, and unshared artifact objects? A
              redacted cleanup receipt will be shown. This cannot be undone.
            </p>
          }
          busy={actionBusy}
          confirmLabel="Permanently delete case"
          onCancel={() => setConfirmCase(null)}
          onConfirm={() => void remove()}
          title="Delete case and cleanup data?"
        />
      ) : null}
    </section>
  );
}

function SearchPage({ onOpenCase }: { onOpenCase: (id: string) => void }) {
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [fields, setFields] = useState<SearchField[]>(
    SEARCH_FIELDS.map((item) => item.id),
  );
  const [includeArchived, setIncludeArchived] = useState(false);
  const [results, setResults] = useState<SearchHit[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const normalized = deferredQuery.trim();
    if (!normalized || !fields.length) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setLoading(true);
      setError(null);
      invoke<SearchHit[]>("search_cases", {
        query: normalized,
        fields,
        includeArchived,
        limit: 100,
      })
        .then((value) => {
          if (!cancelled) setResults(value);
        })
        .catch((reason) => {
          if (!cancelled) {
            setResults([]);
            setError(String(reason));
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [deferredQuery, fields, includeArchived]);
  function toggleField(field: SearchField) {
    setFields((current) =>
      current.includes(field)
        ? current.filter((item) => item !== field)
        : [...current, field],
    );
  }
  const normalizedQuery = query.trim();
  const visibleResults = normalizedQuery && fields.length ? results : [];
  const visibleError =
    normalizedQuery && !fields.length
      ? "Select at least one search field."
      : normalizedQuery
        ? error
        : null;
  return (
    <section className="cases-page">
      <div className="page-heading">
        <p className="eyebrow">Bounded local index</p>
        <h1>Search</h1>
        <p>
          Search persisted identity, findings, imports, indicators,
          certificates, signers, and evidence values. Results are capped at 100.
        </p>
      </div>
      <section className="search-console">
        <label className="search-query">
          <span>Query / 256 UTF-8 bytes maximum</span>
          <input
            autoComplete="off"
            onChange={(event) => setQuery(boundedUtf8(event.target.value, 256))}
            placeholder="Hash, API, rule, signer, indicator..."
            type="search"
            value={query}
          />
        </label>
        <fieldset>
          <legend>Fields</legend>
          <div className="field-grid">
            {SEARCH_FIELDS.map((field) => (
              <label key={field.id}>
                <input
                  checked={fields.includes(field.id)}
                  onChange={() => toggleField(field.id)}
                  type="checkbox"
                />{" "}
                {field.label}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="toggle-label">
          <input
            checked={includeArchived}
            onChange={(event) => setIncludeArchived(event.target.checked)}
            type="checkbox"
          />{" "}
          Include archived cases
        </label>
      </section>
      <div aria-live="polite" className="search-status">
        {normalizedQuery
          ? loading
            ? "Searching local case index..."
            : `${visibleResults.length} result${visibleResults.length === 1 ? "" : "s"}${visibleResults.length === 100 ? " (display cap reached)" : ""}`
          : "Enter a query to search."}
      </div>
      {visibleError ? <ErrorMessage>{visibleError}</ErrorMessage> : null}
      {visibleResults.length ? (
        <div className="search-results">
          {visibleResults.map((hit, index) => (
            <button
              className="search-result"
              key={`${hit.caseId}-${hit.field}-${hit.evidenceId ?? hit.findingId ?? index}`}
              onClick={() => onOpenCase(hit.caseId)}
              type="button"
            >
              <span className="search-field-tag">
                {hit.field.replaceAll("_", " ")}
              </span>
              <div>
                <strong>{hit.caseTitle}</strong>
                <p>{hit.value}</p>
                <small>
                  {hit.caseStatus}
                  {hit.evidenceId ? ` / evidence ${hit.evidenceId}` : ""}
                  {hit.findingId ? ` / finding ${hit.findingId}` : ""}
                </small>
              </div>
              <ArrowIcon />
            </button>
          ))}
        </div>
      ) : normalizedQuery && fields.length > 0 && !loading && !visibleError ? (
        <EmptyState>
          No matching persisted records. Try more fields, include archived
          cases, or use a less specific query.
        </EmptyState>
      ) : null}
    </section>
  );
}

function ComparisonEntryCard({
  entry,
  group,
}: {
  entry: ComparisonEntry;
  group: string;
}) {
  const evidenceIds = comparisonEvidenceIds(entry);
  return (
    <article className={`comparison-entry delta-${entry.delta}`}>
      <header>
        <span>{entry.delta}</span>
        <code>{entry.key}</code>
      </header>
      <div>
        <section>
          <strong>Left</strong>
          <pre>{exactJson(entry.left?.value ?? null)}</pre>
        </section>
        <section>
          <strong>Right</strong>
          <pre>{exactJson(entry.right?.value ?? null)}</pre>
        </section>
      </div>
      {evidenceIds.length ? (
        <footer>
          <span>Evidence IDs</span>
          {evidenceIds.map((id) => (
            <code key={`${group}-${entry.key}-${id}`}>{id}</code>
          ))}
        </footer>
      ) : null}
    </article>
  );
}

function ComparisonGroupPanel({
  group,
  name,
}: {
  group: ComparisonGroup;
  name: string;
}) {
  const entries = orderedComparisonEntries(group) as ComparisonEntry[];
  const semantic = name === "strings" ? semanticStringChanges(group) : [];
  return (
    <section className="comparison-group evidence-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Deterministic group</p>
          <h2>{name}</h2>
        </div>
        <span>{entries.length} differences</span>
      </div>
      {semantic.length ? (
        <section className="semantic-changes">
          <div>
            <strong>Meaningful replacements</strong>
            <span>Paired from exact directional evidence</span>
          </div>
          {semantic.map((change) => (
            <article key={`${change.label}-${change.left}-${change.right}`}>
              <strong>{change.label}</strong>
              <span>{change.left}</span>
              <ArrowIcon />
              <span>{change.right}</span>
              <footer>
                {change.evidenceIds.map((id) => (
                  <code key={id}>{id}</code>
                ))}
              </footer>
            </article>
          ))}
        </section>
      ) : null}
      {entries.length ? (
        name === "strings" ? (
          <details className="raw-comparison">
            <summary>
              All raw string additions and removals ({entries.length})
            </summary>
            <div className="comparison-list">
              {entries.slice(0, 300).map((entry) => (
                <ComparisonEntryCard
                  entry={entry}
                  group={name}
                  key={`${name}-${entry.delta}-${entry.key}`}
                />
              ))}
            </div>
          </details>
        ) : (
          <div className="comparison-list">
            {entries.slice(0, 300).map((entry) => (
              <ComparisonEntryCard
                entry={entry}
                group={name}
                key={`${name}-${entry.delta}-${entry.key}`}
              />
            ))}
          </div>
        )
      ) : (
        <EmptyState>
          No additions, removals, or changes in this group.
        </EmptyState>
      )}
      {entries.length > 300 ? (
        <p className="cap-notice">
          Showing the first 300 deterministic entries in this group.
        </p>
      ) : null}
    </section>
  );
}

function ComparePage({ cases }: { cases: CaseSummary[] }) {
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function compare(event: FormEvent) {
    event.preventDefault();
    if (!left || !right || left === right) {
      setError("Choose two distinct cases.");
      return;
    }
    setBusy(true);
    setError(null);
    setComparison(null);
    try {
      setComparison(
        await invoke<Comparison>("compare_cases", {
          leftCaseId: left,
          rightCaseId: right,
        }),
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  const caseLabel = (id: string) =>
    cases.find((item) => item.id === id)?.title ?? id;
  return (
    <section className="cases-page">
      <div className="page-heading">
        <p className="eyebrow">Deterministic artifact delta</p>
        <h1>Compare</h1>
        <p>
          Compare the latest persisted analysis for two distinct cases.
          Additions and removals are directional from left to right.
        </p>
      </div>
      <form
        aria-busy={busy}
        aria-label="Case comparison"
        className="compare-form"
        onSubmit={(event) => void compare(event)}
      >
        <label>
          <span>Left / baseline</span>
          <select
            onChange={(event) => setLeft(event.target.value)}
            value={left}
          >
            <option value="">Choose a case</option>
            {cases.map((item) => (
              <option
                disabled={item.id === right}
                key={item.id}
                value={item.id}
              >
                {item.title} [{item.status}]
              </option>
            ))}
          </select>
        </label>
        <span aria-hidden="true" className="compare-arrow">
          -&gt;
        </span>
        <label>
          <span>Right / candidate</span>
          <select
            onChange={(event) => setRight(event.target.value)}
            value={right}
          >
            <option value="">Choose a different case</option>
            {cases.map((item) => (
              <option disabled={item.id === left} key={item.id} value={item.id}>
                {item.title} [{item.status}]
              </option>
            ))}
          </select>
        </label>
        <button
          className="choose-button"
          disabled={busy || !left || !right || left === right}
          type="submit"
        >
          {busy ? "Comparing..." : "Compare cases"}
        </button>
      </form>
      {error ? <ErrorMessage>{error}</ErrorMessage> : null}
      {comparison ? (
        <div className="comparison-results">
          <section className="comparison-header">
            <article>
              <span>Left</span>
              <strong>{caseLabel(left)}</strong>
              <code>{comparison.left.sha256}</code>
            </article>
            <article>
              <span>Right</span>
              <strong>{caseLabel(right)}</strong>
              <code>{comparison.right.sha256}</code>
            </article>
          </section>
          {COMPARISON_GROUPS.map((name) => (
            <ComparisonGroupPanel
              group={comparison[name]}
              key={name}
              name={name}
            />
          ))}
        </div>
      ) : !busy ? (
        <EmptyState>
          Select two cases to compare hashes and deterministic evidence groups.
        </EmptyState>
      ) : null}
    </section>
  );
}

function RuleLibraryPage() {
  const [packs, setPacks] = useState<YaraPack[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmPack, setConfirmPack] = useState<YaraPack | null>(null);
  const [folderResults, setFolderResults] = useState<YaraFolderResult[]>([]);
  const [metadata, setMetadata] = useState({
    name: "",
    version: "",
    source: "",
    license: "",
  });
  async function refresh() {
    setError(null);
    try {
      setPacks(await invoke<YaraPack[]>("list_yara_packs"));
      setStatus("Rule library refreshed from local storage.");
    } catch (reason) {
      setError(String(reason));
    }
  }
  useEffect(() => {
    let cancelled = false;
    invoke<YaraPack[]>("list_yara_packs")
      .then((value) => {
        if (!cancelled) setPacks(value);
      })
      .catch((reason) => {
        if (!cancelled) setError(String(reason));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  async function importPack(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setStatus("Opening the native YARA file picker...");
    try {
      const pack = await invoke<YaraPack | null>("import_yara_pack", {
        metadata,
      });
      if (pack) {
        setPacks((current) => [
          pack,
          ...current.filter((item) => item.id !== pack.id),
        ]);
        setMetadata({ name: "", version: "", source: "", license: "" });
        setStatus(
          `Imported ${pack.name} v${pack.version}. It will apply to future analysis and reanalysis only.`,
        );
      } else setStatus("Import cancelled. No pack was changed.");
    } catch (reason) {
      setError(String(reason));
      setStatus(null);
    } finally {
      setBusy(false);
    }
  }
  async function importFolder() {
    setBusy(true);
    setError(null);
    setFolderResults([]);
    setStatus("Opening the native YARA folder picker...");
    try {
      const results = await invoke<YaraFolderResult[] | null>(
        "import_yara_folder",
        { metadata },
      );
      if (results) {
        setFolderResults(results);
        const imported = results.flatMap((item) =>
          item.pack ? [item.pack] : [],
        );
        setPacks((current) => [
          ...imported,
          ...current.filter(
            (pack) => !imported.some((item) => item.id === pack.id),
          ),
        ]);
        setStatus(
          `Folder validation finished: ${imported.length} imported, ${results.length - imported.length} failed. Refresh remains manual.`,
        );
      } else setStatus("Folder import cancelled.");
    } catch (reason) {
      setError(String(reason));
      setStatus(null);
    } finally {
      setBusy(false);
    }
  }
  async function toggle(pack: YaraPack) {
    setBusy(true);
    setError(null);
    try {
      const updated = await invoke<YaraPack>(
        pack.enabled ? "disable_yara_pack" : "enable_yara_pack",
        { packId: pack.id },
      );
      setPacks((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      setStatus(
        `${updated.name} is ${updated.enabled ? "enabled" : "disabled"}. This affects future analysis and reanalysis only.`,
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    if (!confirmPack) return;
    setBusy(true);
    setError(null);
    try {
      const cleanup = await invoke<Cleanup>("delete_yara_pack", {
        packId: confirmPack.id,
      });
      setPacks((current) =>
        current.filter((item) => item.id !== confirmPack.id),
      );
      setStatus(
        `Deleted ${confirmPack.name}. Object cleanup: ${cleanup.cleanup.replaceAll("_", " ")}. Existing case runs remain unchanged.`,
      );
      setConfirmPack(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section aria-busy={busy} className="cases-page">
      <div className="page-heading split-heading">
        <div>
          <p className="eyebrow">Redacted local rule packs</p>
          <h1>Rule Library</h1>
          <p>
            Manage bounded YARA-X packs without exposing rule source or
            filesystem paths.
          </p>
        </div>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => void refresh()}
          type="button"
        >
          Refresh manually
        </button>
      </div>
      <section className="future-notice">
        <strong>Future-run scope</strong>
        <p>
          Enabled packs apply only to future analysis and reanalysis. Existing
          run history and evidence never change retroactively.
        </p>
      </section>
      <form
        className="rule-import evidence-panel"
        onSubmit={(event) => void importPack(event)}
      >
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Native import</p>
            <h2>Import YARA pack or folder</h2>
          </div>
          <span>.yar or .yara / bounded to 64 files</span>
        </div>
        <div className="metadata-grid">
          <label>
            <span>Pack name / single-file fallback</span>
            <input
              maxLength={256}
              onChange={(event) =>
                setMetadata({ ...metadata, name: event.target.value })
              }
              required
              value={metadata.name}
            />
          </label>
          <label>
            <span>Version</span>
            <input
              maxLength={128}
              onChange={(event) =>
                setMetadata({ ...metadata, version: event.target.value })
              }
              required
              value={metadata.version}
            />
          </label>
          <label>
            <span>Source attribution (not a path)</span>
            <input
              maxLength={1024}
              onChange={(event) =>
                setMetadata({ ...metadata, source: event.target.value })
              }
              required
              value={metadata.source}
            />
          </label>
          <label>
            <span>License</span>
            <input
              maxLength={256}
              onChange={(event) =>
                setMetadata({ ...metadata, license: event.target.value })
              }
              required
              value={metadata.license}
            />
          </label>
        </div>
        <div className="inline-actions">
          <button className="choose-button" disabled={busy} type="submit">
            {busy ? "Working..." : "Choose one pack"}
          </button>
          <button
            className="secondary-button"
            disabled={
              busy ||
              !metadata.name ||
              !metadata.version ||
              !metadata.source ||
              !metadata.license
            }
            onClick={() => void importFolder()}
            type="button"
          >
            Choose local folder
          </button>
        </div>
      </form>
      {error ? <ErrorMessage>{error}</ErrorMessage> : null}
      {status ? (
        <p className="live-status" role="status">
          {status}
        </p>
      ) : null}
      {folderResults.length ? (
        <ul className="folder-import-results">
          {folderResults.map((item) => (
            <li key={item.fileName}>
              <StatusBadge status={item.status} />
              <strong>{item.fileName}</strong>
              <span>
                {item.pack
                  ? `${item.pack.ruleCount} rules imported`
                  : item.error}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="pack-list">
        {packs.map((pack) => (
          <article className="pack-card" key={pack.id}>
            <header>
              <div>
                <span
                  className={`status-badge status-${pack.enabled ? "complete" : "archived"}`}
                >
                  {pack.enabled ? "enabled" : "disabled"}
                </span>
                <h2>{pack.name}</h2>
                <span>v{pack.version}</span>
              </div>
              <code>{pack.sha256}</code>
            </header>
            <dl>
              <div>
                <dt>Rules</dt>
                <dd>{pack.ruleCount.toLocaleString()}</dd>
              </div>
              <div>
                <dt>License</dt>
                <dd>{pack.license}</dd>
              </div>
              <div>
                <dt>Source attribution</dt>
                <dd>{pack.source}</dd>
              </div>
              <div>
                <dt>Imported</dt>
                <dd>{formatDate(pack.importedAt)}</dd>
              </div>
            </dl>
            <footer>
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() => void toggle(pack)}
                type="button"
              >
                {pack.enabled
                  ? "Disable for future runs"
                  : "Enable for future runs"}
              </button>
              <button
                className="text-button danger-text compact"
                onClick={() => setConfirmPack(pack)}
                type="button"
              >
                Delete pack
              </button>
            </footer>
          </article>
        ))}
        {!packs.length ? (
          <EmptyState>
            No YARA packs are imported. Native import validates and compiles a
            local pack before storing its redacted metadata.
          </EmptyState>
        ) : null}
      </div>
      {confirmPack ? (
        <ConfirmDialog
          body={
            <p>
              Permanently delete the redacted pack{" "}
              <strong>
                {confirmPack.name} v{confirmPack.version}
              </strong>
              ? Existing case evidence remains immutable, but this pack will not
              be available to future analysis or reanalysis.
            </p>
          }
          busy={busy}
          confirmLabel="Permanently delete pack"
          onCancel={() => setConfirmPack(null)}
          onConfirm={() => void remove()}
          title="Delete YARA pack?"
        />
      ) : null}
    </section>
  );
}

function IntakePage({
  busy,
  error,
  offers,
  statuses,
  dragging,
  onChoose,
  onAnalyze,
  onClear,
}: {
  busy: boolean;
  error: string | null;
  offers: IntakeOffer[];
  statuses: Map<string, IntakeStatus>;
  dragging: boolean;
  onChoose: () => void;
  onAnalyze: () => void;
  onClear: () => void;
}) {
  const displayed = [...statuses.values()];
  return (
    <>
      <section className="intake-layout">
        <div className="intake-copy">
          <p className="eyebrow">Static Windows triage</p>
          <h1>Understand the file before you trust it.</h1>
          <p className="lead">
            Inspect Windows executables locally. Artifacta records identity, PE
            structure, findings, YARA matches, and exact provenance.
          </p>
          <div className="trust-row">
            <span>Never executed</span>
            <span>Never uploaded</span>
            <span>Evidence-backed</span>
          </div>
        </div>
        <div
          aria-busy={busy}
          className={`drop-panel${dragging ? " drop-panel-dragging" : ""}`}
        >
          <div className="drop-symbol">
            <span>PE</span>
            <div className="drop-symbol-line" />
          </div>
          <div>
            <h2>
              {dragging
                ? "Drop files to authorize intake"
                : offers.length
                  ? `${offers.length} file${offers.length === 1 ? "" : "s"} authorized by host`
                  : displayed.length
                    ? "Intake results"
                    : "Drop or select Windows executables"}
            </h2>
            <p>
              PE32 or PE32+ executable, DLL, driver, screen saver, or
              control-panel file
            </p>
          </div>
          {displayed.length ? (
            <ul
              aria-label="Intake results"
              aria-live="polite"
              className="intake-queue"
            >
              {displayed.map((item) => (
                <li key={item.token}>
                  <StatusBadge status={item.status} />
                  <strong>{item.name}</strong>
                  <span>
                    {item.status === "running" && item.stage
                      ? item.stage
                      : item.error ?? item.status}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="inline-actions">
            <button
              className="secondary-button"
              disabled={busy}
              onClick={onChoose}
              type="button"
            >
              Choose multiple files
            </button>
            {offers.length ? (
              <button
                className="choose-button"
                disabled={busy}
                onClick={onAnalyze}
                type="button"
              >
                {busy
                  ? (() => {
                      const runningItem = displayed.find(
                        (item) => item.status === "running" && item.stage,
                      );
                      return runningItem?.stage
                        ? runningItem.stage
                        : "Analyzing serially...";
                    })()
                  : `Analyze ${offers.length} authorized file${offers.length === 1 ? "" : "s"}`}
                <ArrowIcon />
              </button>
            ) : null}
            {displayed.length && !busy ? (
              <button
                className="text-button compact"
                onClick={onClear}
                type="button"
              >
                Clear intake results
              </button>
            ) : null}
          </div>
          {error ? (
            <p className="intake-error" role="alert">
              {error}
            </p>
          ) : null}
          <p className="drop-caveat">
            Native picker, OS drop, and exact --analyze startup requests mint
            one-time opaque tokens. The renderer cannot submit filesystem paths.
            Files run serially with isolated failure results.
          </p>
        </div>
      </section>
      <section className="method-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Method</p>
            <h2>A verdict is not evidence.</h2>
          </div>
          <p>
            Artifacta reports direct structure and contextual observations.
            Signature validity, YARA matches, and ATT&amp;CK mappings are
            context, not claims that a file is malicious or safe.
          </p>
        </div>
        <div className="method-grid">
          <article>
            <span className="method-number">01</span>
            <h3>Acquire</h3>
            <p>
              Hash and preserve an immutable content-addressed artifact copy.
            </p>
          </article>
          <article>
            <span className="method-number">02</span>
            <h3>Observe</h3>
            <p>
              Parse PE and scan enabled packs in disposable bounded workers.
            </p>
          </article>
          <article>
            <span className="method-number">03</span>
            <h3>Investigate</h3>
            <p>
              Search, compare, annotate, transition findings, and preserve run
              history.
            </p>
          </article>
        </div>
      </section>
    </>
  );
}

function App() {
  const [hostStatus, setHostStatus] = useState<HostStatus | null>(null);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [view, setView] = useState<View>("intake");
  const [analysis, setAnalysis] = useState<CaseAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [intakeOffers, setIntakeOffers] = useState<IntakeOffer[]>([]);
  const [intakeStatuses, setIntakeStatuses] = useState<
    Map<string, IntakeStatus>
  >(new Map());
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    let cancelled = false;
    invoke<HostStatus>("app_status")
      .then((value) => {
        if (!cancelled) setHostStatus(value);
      })
      .catch(() => {});
    invoke<CaseSummary[]>("list_cases")
      .then((value) => {
        if (!cancelled) setCases(value);
      })
      .catch((reason) => {
        if (!cancelled) setError(String(reason));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  useEffect(() => {
    let active = true;
    const unlisteners: (() => void)[] = [];
    const takePending = () =>
      invoke<IntakeOffer[]>("take_startup_intake").then((offers) => {
        if (active && offers.length) {
          setIntakeOffers((current) => mergeIntakeOffers(current, offers));
          setIntakeStatuses((current) => addQueuedStatuses(current, offers));
          setView("intake");
        }
      });
    void listen<void>("artifacta://intake-ready", () => {
      void takePending();
    }).then((unlisten) => {
      if (active) {
        unlisteners.push(unlisten);
        void takePending();
      }
      else unlisten();
    });
    void listen<boolean>("artifacta://drag-state", (event) => {
      if (active) setDragging(event.payload);
    }).then((unlisten) => {
      if (active) unlisteners.push(unlisten);
      else unlisten();
    });
    void listen<IntakeStatus>("artifacta://intake-status", (event) => {
      if (active)
        setIntakeStatuses((current) =>
          new Map(current).set(event.payload.token, event.payload),
        );
    }).then((unlisten) => {
      if (active) unlisteners.push(unlisten);
      else unlisten();
    });
    return () => {
      active = false;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);
  async function chooseFiles() {
    setError(null);
    try {
      const offers = await invoke<IntakeOffer[]>("choose_intake_files");
      if (offers.length) {
        setIntakeOffers((current) => mergeIntakeOffers(current, offers));
        setIntakeStatuses((current) => addQueuedStatuses(current, offers));
      }
    } catch (reason) {
      setError(String(reason));
    }
  }
  async function analyzeOffers() {
    if (!intakeOffers.length) return;
    const submitted = intakeOffers;
    const submittedTokens = new Set(submitted.map((offer) => offer.token));
    setError(null);
    setBusy(true);
    setIntakeStatuses((current) => {
      const next = new Map(current);
      for (const offer of submitted)
        next.set(offer.token, { ...offer, status: "running" });
      return next;
    });
    try {
      const results = await invoke<IntakeResult[]>("analyze_intake_batch", {
        tokens: submitted.map((offer) => offer.token),
      });
      setIntakeOffers((current) =>
        current.filter((offer) => !submittedTokens.has(offer.token)),
      );
      setIntakeStatuses((current) => {
        const next = new Map(current);
        for (const result of results) next.set(result.token, result);
        return next;
      });
      const completed = results.flatMap((result) =>
        result.analysis ? [result.analysis] : [],
      );
      if (completed.length) {
        setCases((current) => [
          ...completed.map((item) => item.case),
          ...current.filter(
            (item) => !completed.some((value) => value.case.id === item.id),
          ),
        ]);
        setAnalysis(completed[0]!);
        if (results.every((result) => result.status === "complete")) {
          setView("detail");
        }
      }
      const failures = results.filter((result) => result.status === "failed");
      if (failures.length)
        setError(
          `${failures.length} file${failures.length === 1 ? "" : "s"} failed independently. Successful cases were preserved.`,
        );
    } catch (reason) {
      setIntakeOffers((current) =>
        current.filter((offer) => !submittedTokens.has(offer.token)),
      );
      setIntakeStatuses((current) => {
        const next = new Map(current);
        for (const offer of submitted)
          next.set(offer.token, {
            ...offer,
            status: "failed",
            error: "Intake stopped before a result was returned",
          });
        return next;
      });
      void invoke("discard_intake", {
        tokens: submitted.map((offer) => offer.token),
      });
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  async function openCaseId(caseId: string) {
    const item = cases.find((entry) => entry.id === caseId) ?? {
      id: caseId,
      title: "Case",
      createdAt: "",
      status: "active" as const,
    };
    await openCase(item);
  }
  async function openCase(item: CaseSummary) {
    setError(null);
    setBusy(true);
    try {
      const result = await invoke<CaseAnalysis | null>("get_case_analysis", {
        caseId: item.id,
      });
      if (!result) throw new Error("Case was not found.");
      setAnalysis(result);
      setView("detail");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }
  function updateAnalysis(value: CaseAnalysis) {
    setAnalysis(value);
    setCases((current) =>
      current.map((item) => (item.id === value.case.id ? value.case : item)),
    );
  }
  const labels: Record<View, string> = {
    intake: "New Analysis",
    cases: "Cases",
    search: "Search",
    compare: "Compare",
    rules: "Rule Library",
    detail: analysis?.case.title ?? "Case",
  };
  const nav: { view: Exclude<View, "detail">; label: string }[] = [
    { view: "intake", label: "New Analysis" },
    { view: "cases", label: "Cases" },
    { view: "search", label: "Search" },
    { view: "compare", label: "Compare" },
    { view: "rules", label: "Rule Library" },
  ];
  return (
    <div className="app-frame">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <div>
            <strong>Artifacta</strong>
            <span>Investigator workspace</span>
          </div>
        </div>
        <nav aria-label="Primary navigation" className="primary-nav">
          {nav.map((item, index) => {
            const active =
              view === item.view ||
              (item.view === "cases" && view === "detail");
            return (
              <button
                aria-current={active ? "page" : undefined}
                className={`nav-item${active ? " nav-item-active" : ""}`}
                key={item.view}
                onClick={() => {
                  setError(null);
                  setView(item.view);
                }}
                type="button"
              >
                <span className="nav-index">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span>
                  {item.label}
                  {item.view === "cases" && cases.length
                    ? ` / ${cases.length}`
                    : ""}
                </span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <div className="privacy-seal">
            <span className="privacy-dot" />
            <div>
              <strong>Local static analysis</strong>
              <span>
                {hostStatus?.networkPolicy ??
                  "PE/YARA workers use zero-capability AppContainer network denial"}
              </span>
            </div>
          </div>
          <span className="version-label">
            v{hostStatus?.version ?? "1.0.0"} / static
          </span>
        </div>
      </aside>
      <main aria-busy={busy} className="main-surface">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span>/</span>
            <strong>{labels[view]}</strong>
          </div>
          <div aria-live="polite" className="host-state">
            <span
              className={
                hostStatus ? "host-light host-light-ready" : "host-light"
              }
            />
            {busy
              ? "Static worker running"
              : hostStatus
                ? `${hostStatus.platform} host ready`
                : "Connecting to host"}
          </div>
        </header>
        {view === "intake" ? (
          <IntakePage
            busy={busy}
            dragging={dragging}
            error={error}
            offers={intakeOffers}
            onAnalyze={() => void analyzeOffers()}
            onChoose={() => void chooseFiles()}
            onClear={() => {
              void invoke("discard_intake", {
                tokens: intakeOffers.map((offer) => offer.token),
              });
              setIntakeOffers([]);
              setIntakeStatuses(new Map());
            }}
            statuses={intakeStatuses}
          />
        ) : null}
        {view === "cases" ? (
          <CasesPage
            busy={busy}
            cases={cases}
            error={error}
            onOpen={(item) => void openCase(item)}
            onRefresh={setCases}
          />
        ) : null}
        {view === "search" ? (
          <SearchPage onOpenCase={(id) => void openCaseId(id)} />
        ) : null}
        {view === "compare" ? <ComparePage cases={cases} /> : null}
        {view === "rules" ? <RuleLibraryPage /> : null}
        {view === "detail" && analysis ? (
          <AnalysisDetail
            analysis={analysis}
            key={`${analysis.case.id}:${analysis.run?.id ?? "no-run"}`}
            onAnalysis={updateAnalysis}
            onNew={() => setView("intake")}
          />
        ) : null}
      </main>
    </div>
  );
}

export default App;
