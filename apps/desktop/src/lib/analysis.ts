export type EvidenceLike = {
  id: string;
  kind: string;
  class?: string;
  locator: unknown;
  value: unknown;
  previewText?: string | null;
};

export type EvidenceFilters = {
  search: string;
  kind: string;
  observationClass: string;
};

function searchableJson(value: unknown) {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

export function filterEvidence<T extends EvidenceLike>(items: T[], filters: EvidenceFilters) {
  const query = filters.search.trim().toLocaleLowerCase();
  return items.filter((item) => {
    if (filters.kind && item.kind !== filters.kind) return false;
    if (filters.observationClass && item.class !== filters.observationClass) return false;
    if (!query) return true;
    return [item.kind, item.class, item.previewText, searchableJson(item.locator), searchableJson(item.value)]
      .filter((value) => value !== null && value !== undefined)
      .some((value) => String(value).toLocaleLowerCase().includes(query));
  });
}

export function groupImports<T extends EvidenceLike>(items: T[]) {
  const groups = new Map<string, { dll: string; items: T[] }>();
  for (const item of items) {
    if (!(["pe.import", "pe.delay_import"] as string[]).includes(item.kind) || !item.value || typeof item.value !== "object" || Array.isArray(item.value)) continue;
    const dllValue = (item.value as Record<string, unknown>).dll;
    const dll = typeof dllValue === "string" && dllValue ? dllValue : "Unknown DLL";
    const key = dll.toLocaleLowerCase();
    const group = groups.get(key);
    if (group) group.items.push(item);
    else groups.set(key, { dll, items: [item] });
  }
  return [...groups.values()].sort((left, right) => left.dll.localeCompare(right.dll));
}

export type ComparisonEntryLike = {
  delta: "added" | "removed" | "changed";
  key: string;
  left?: { value?: unknown; evidenceIds?: string[] } | null;
  right?: { value?: unknown; evidenceIds?: string[] } | null;
};

export type ComparisonGroupLike = {
  added?: ComparisonEntryLike[];
  removed?: ComparisonEntryLike[];
  changed?: ComparisonEntryLike[];
};

export function orderedComparisonEntries(group: ComparisonGroupLike | null | undefined) {
  return [...(group?.added ?? []), ...(group?.removed ?? []), ...(group?.changed ?? [])]
    .sort((left, right) => left.key.localeCompare(right.key) || left.delta.localeCompare(right.delta));
}

export function comparisonEvidenceIds(entry: ComparisonEntryLike) {
  return [...new Set([...(entry.left?.evidenceIds ?? []), ...(entry.right?.evidenceIds ?? [])])].sort();
}

export type StringView = "interesting" | "indicators" | "commands" | "paths_registry" | "urls_domains_ips" | "imports_apis" | "metadata" | "raw" | "all";

function evidenceRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function stringEvidenceCategory(item: EvidenceLike): Exclude<StringView, "interesting" | "indicators" | "all"> {
  const value = evidenceRecord(item.value);
  if (item.kind === "pe.indicator") {
    const category = typeof value.category === "string" ? value.category : "";
    if (category === "command") return "commands";
    if (category === "windows_path" || category === "registry_key") return "paths_registry";
    return "urls_domains_ips";
  }
  const persisted = typeof value.analyst_category === "string" ? value.analyst_category : "";
  if (["commands", "paths_registry", "urls_domains_ips", "imports_apis", "metadata", "raw"].includes(persisted)) {
    return persisted as Exclude<StringView, "interesting" | "indicators" | "all">;
  }
  return "raw";
}

export function filterStringEvidence<T extends EvidenceLike>(items: T[], view: StringView) {
  return items.filter((item) => {
    if (view === "all") return true;
    if (view === "indicators") return item.kind === "pe.indicator";
    if (view === "interesting") {
      if (item.kind === "pe.indicator") return true;
      return evidenceRecord(item.value).interesting !== false;
    }
    return stringEvidenceCategory(item) === view;
  });
}

export type SemanticStringChange = {
  label: string;
  left: string;
  right: string;
  evidenceIds: string[];
};

function comparisonString(entry: ComparisonEntryLike, side: "left" | "right") {
  const value = evidenceRecord(entry[side]?.value);
  return typeof value.text === "string" ? value.text : null;
}

function semanticStringKey(value: string) {
  const metadata = /^([A-Za-z][A-Za-z0-9_.-]{1,63})=(.+)$/.exec(value);
  if (metadata) return { key: `metadata:${metadata[1]!.toLocaleLowerCase()}`, label: metadata[1]! };
  try {
    const url = new URL(value);
    if (url.protocol === "http:" || url.protocol === "https:") return { key: `url:${url.origin}`, label: "Update URL" };
  } catch {
    return null;
  }
  return null;
}

export function semanticStringChanges(group: ComparisonGroupLike | null | undefined): SemanticStringChange[] {
  const removed = [...(group?.removed ?? [])];
  const added = [...(group?.added ?? [])];
  const changes: SemanticStringChange[] = [];
  for (const leftEntry of removed) {
    const left = comparisonString(leftEntry, "left");
    if (!left) continue;
    const semantic = semanticStringKey(left);
    if (!semantic) continue;
    const rightIndex = added.findIndex((entry) => {
      const right = comparisonString(entry, "right");
      return right !== null && semanticStringKey(right)?.key === semantic.key;
    });
    if (rightIndex < 0) continue;
    const rightEntry = added.splice(rightIndex, 1)[0]!;
    const right = comparisonString(rightEntry, "right")!;
    changes.push({
      label: semantic.label,
      left,
      right,
      evidenceIds: [...new Set([...comparisonEvidenceIds(leftEntry), ...comparisonEvidenceIds(rightEntry)])].sort(),
    });
  }
  return changes.sort((left, right) => left.label.localeCompare(right.label) || left.left.localeCompare(right.left));
}

export function boundedUtf8(value: string, maxBytes: number) {
  const encoder = new TextEncoder();
  if (encoder.encode(value).length <= maxBytes) return value;
  let result = "";
  for (const character of value) {
    if (encoder.encode(result + character).length > maxBytes) break;
    result += character;
  }
  return result;
}

export function runStatusLabel(status: string | null | undefined) {
  return status ? status.replaceAll("_", " ") : "not analyzed";
}

export function stageLabel(stage: string | null | undefined) {
  if (!stage) return null;
  return stage.replaceAll("_", " ");
}

export function countEvidenceKinds(items: EvidenceLike[], kinds: string[]) {
  const accepted = new Set(kinds);
  return items.reduce((count, item) => count + Number(accepted.has(item.kind)), 0);
}

const MALFORMED_SIGNATURE_STATUSES = new Set([
  "table_out_of_bounds",
  "truncated_win_certificate_header",
  "invalid_win_certificate_length",
  "malformed_content_info",
  "malformed_signed_data",
  "not_signed_data",
]);

export type SignatureState = "absent" | "present" | "malformed" | "unavailable";

export function getSignatureState(items: EvidenceLike[]): SignatureState {
  const signatures = items.filter((item) => item.kind === "pe.authenticode");
  if (!signatures.length) return "unavailable";
  let hasPresent = false;
  for (const signature of signatures) {
    if (!signature.value || typeof signature.value !== "object" || Array.isArray(signature.value)) continue;
    const value = signature.value as Record<string, unknown>;
    if (value.present === false || value.structural_status === "absent") continue;
    hasPresent ||= value.present === true;
    const pkcs7 = value.pkcs7 && typeof value.pkcs7 === "object" && !Array.isArray(value.pkcs7)
      ? value.pkcs7 as Record<string, unknown>
      : undefined;
    if (MALFORMED_SIGNATURE_STATUSES.has(String(value.structural_status)) || MALFORMED_SIGNATURE_STATUSES.has(String(pkcs7?.status))) {
      return "malformed";
    }
  }
  return hasPresent ? "present" : "absent";
}

export function formatConfidence(value: number) {
  if (!Number.isFinite(value)) return "Unavailable";
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

export type GraphEntityLike = { id: string; entityType: string; displayValue: string; canonicalValue: string };
export type GraphEdgeLike = { sourceEntityId: string; targetEntityId: string; relationship: string };

export function projectPersistedGraph<E extends GraphEntityLike, R extends GraphEdgeLike>(
  entities: E[],
  edges: R[],
  options: { search: string; nodeType: string; relationship: string; expanded: Set<string>; cap: number },
) {
  const query = options.search.trim().toLocaleLowerCase();
  const matched = entities.filter((entity) => {
    if (options.nodeType && entity.entityType !== options.nodeType) return false;
    return !query || `${entity.displayValue} ${entity.canonicalValue} ${entity.entityType}`.toLocaleLowerCase().includes(query);
  });
  const visibleIds = new Set(matched.slice(0, options.cap).map((entity) => entity.id));
  for (const id of options.expanded) visibleIds.add(id);
  return {
    entities: entities.filter((entity) => visibleIds.has(entity.id)),
    edges: edges.filter((edge) => visibleIds.has(edge.sourceEntityId) && visibleIds.has(edge.targetEntityId) && (!options.relationship || edge.relationship === options.relationship)),
  };
}
