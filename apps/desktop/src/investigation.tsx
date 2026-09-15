import cytoscape, {
  type Core,
  type ElementDefinition,
  type EventObjectEdge,
  type EventObjectNode,
  type LayoutOptions,
  type NodeSingular,
} from "cytoscape";
import {
  useDeferredValue,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { projectPersistedGraph } from "./lib/analysis";

export type EvidenceRecord = {
  id: string;
  artifactId?: string;
  provenanceId?: string;
  kind: string;
  class: string;
  locator: Record<string, unknown>;
  value: unknown;
  previewText: string | null;
};

export type FindingRecord = {
  id: string;
  ruleId: string;
  ruleVersion: string;
  title: string;
  category: string;
  severity: string;
  evidence: { evidenceId: string; role: string }[];
};

export type ProvenanceRecord = {
  id: string;
  analysisRunId: string;
  analyzer: string;
  analyzerVersion: string;
  ruleId?: string | null;
  ruleVersion?: string | null;
  rulePackSha256?: string | null;
  inputSha256: string;
};

export type GraphEntity = {
  id: string;
  caseId: string;
  entityType: string;
  canonicalValue: string;
  displayValue: string;
  metadata: Record<string, unknown>;
};
export type GraphEdge = {
  id: string;
  sourceEntityId: string;
  targetEntityId: string;
  relationship: string;
  evidenceId: string;
  confidence: number;
};
export type CaseGraph = {
  caseId: string;
  projectionVersion: number;
  sourceAnalysisRunId: string | null;
  entities: GraphEntity[];
  edges: GraphEdge[];
  entityEvidence: { entityId: string; evidenceId: string; role: string }[];
};
export type ChronologyEvent = {
  id: string;
  caseId: string;
  timestampUtc: string;
  timestampType: string;
  reliability: string;
  eventType: string;
  artifactId: string | null;
  evidenceId: string | null;
  summary: string;
};
export type CaseChronology = {
  caseId: string;
  projectionVersion: number;
  sourceAnalysisRunId: string | null;
  events: ChronologyEvent[];
};
export type QuickCheck = {
  policyVersion: string;
  policySha256: string;
  band: string;
  findingCounts: {
    contextual: number;
    low: number;
    medium: number;
    high: number;
    total: number;
  };
  topFindings: {
    findingId: string;
    title: string;
    category: string;
    severity: string;
    evidenceFamily: string;
  }[];
  evidenceFamilies: {
    family: string;
    findingCount: number;
    contributingFindingCount: number;
    strongestSeverity: string | null;
  }[];
  statement: string;
};
export type BookmarkTarget =
  | { type: "evidence"; evidenceId: string }
  | { type: "finding"; findingId: string }
  | { type: "entity"; entityId: string }
  | { type: "edge"; edgeId: string }
  | { type: "event"; eventId: string };
export type BookmarkRecord = {
  id: string;
  caseId: string;
  target: BookmarkTarget;
  label: string | null;
  createdAt: string;
  updatedAt: string;
};
export type BookmarkInput = {
  targetType: BookmarkTarget["type"];
  targetId: string;
};

function json(value: unknown) {
  try {
    return JSON.stringify(value, null, 2) ?? "null";
  } catch {
    return "Exact JSON unavailable";
  }
}

function targetId(target: BookmarkTarget) {
  if (target.type === "evidence") return target.evidenceId;
  if (target.type === "finding") return target.findingId;
  if (target.type === "entity") return target.entityId;
  if (target.type === "edge") return target.edgeId;
  return target.eventId;
}

export function QuickCheckView({
  check,
  findings,
  onEvidence,
  onFinding,
  onBookmark,
}: {
  check: QuickCheck;
  findings: FindingRecord[];
  onEvidence: (id: string, trigger?: HTMLElement) => void;
  onFinding: (id: string) => void;
  onBookmark: (target: BookmarkInput, label?: string) => void;
}) {
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  return (
    <div className="tab-stack quick-check">
      <section className={`quick-band quick-band-${check.band}`}>
        <div>
          <p className="eyebrow">Quick Check / policy {check.policyVersion}</p>
          <h2>{check.band.replaceAll("_", " ")}</h2>
          <p>{check.statement}</p>
        </div>
        <span>Non-verdict static summary</span>
      </section>
      <p className="confidence-notice">
        This deterministic band summarizes persisted static findings. It does
        not establish malware, safety, execution, intent, attribution, or
        compromise.
      </p>
      <section className="quick-counts" aria-label="Active finding counts">
        <article>
          <strong>{check.findingCounts.high}</strong>
          <span>High</span>
        </article>
        <article>
          <strong>{check.findingCounts.medium}</strong>
          <span>Medium</span>
        </article>
        <article>
          <strong>{check.findingCounts.low}</strong>
          <span>Low</span>
        </article>
        <article>
          <strong>{check.findingCounts.contextual}</strong>
          <span>Contextual</span>
        </article>
      </section>
      <section className="evidence-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Independent axes</p>
            <h2>Evidence families</h2>
          </div>
          <span>Strongest eligible signal per family</span>
        </div>
        <div className="quick-families">
          {check.evidenceFamilies.map((family) => (
            <article key={family.family}>
              <strong>{family.family.replaceAll("_", " ")}</strong>
              <span>{family.strongestSeverity ?? "No active signal"}</span>
              <small>
                {family.findingCount} findings /{" "}
                {family.contributingFindingCount} contributing
              </small>
            </article>
          ))}
        </div>
      </section>
      <section className="evidence-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Policy-selected</p>
            <h2>Top findings</h2>
          </div>
          <code title={check.policySha256}>
            Policy SHA-256 {check.policySha256.slice(0, 12)}...
          </code>
        </div>
        <div className="top-finding-list">
          {check.topFindings.map((top) => {
            const finding = byId.get(top.findingId);
            return (
              <article key={top.findingId}>
                <div>
                  <span className={`severity severity-${top.severity}`}>
                    {top.severity}
                  </span>
                  <span>{top.evidenceFamily.replaceAll("_", " ")}</span>
                </div>
                <h3>{top.title}</h3>
                <p>{top.category}</p>
                <div className="inline-actions">
                  <button
                    className="text-button compact"
                    onClick={() => onFinding(top.findingId)}
                    type="button"
                  >
                    Open finding
                  </button>
                  {finding?.evidence[0] ? (
                    <button
                      className="text-button compact"
                      onClick={(event) =>
                        onEvidence(
                          finding.evidence[0]!.evidenceId,
                          event.currentTarget,
                        )
                      }
                      type="button"
                    >
                      Inspect evidence
                    </button>
                  ) : null}
                  <button
                    className="text-button compact"
                    onClick={() =>
                      onBookmark(
                        { targetType: "finding", targetId: top.findingId },
                        top.title,
                      )
                    }
                    type="button"
                  >
                    Bookmark
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}

const NODE_CAP = 120;
const GRAPH_MIN_ZOOM = 0.25;
const GRAPH_MAX_ZOOM = 2.5;

function graphLabel(value: string) {
  return value.length > 34 ? `${value.slice(0, 31)}...` : value;
}

function graphRank(node: NodeSingular) {
  switch (node.data("kind")) {
    case "artifact":
      return 5;
    case "finding":
    case "yara_rule":
    case "certificate":
    case "signer":
      return 4;
    case "url":
    case "domain":
    case "ip_address":
    case "file_path":
    case "registry_path":
    case "registry_key":
    case "command_string":
      return 3;
    case "section":
    case "export":
      return 2;
    default:
      return 1;
  }
}

function graphLayout(): LayoutOptions {
  return {
    name: "concentric",
    animate: false,
    avoidOverlap: true,
    clockwise: true,
    concentric: graphRank,
    equidistant: false,
    fit: true,
    levelWidth: () => 1,
    minNodeSpacing: 48,
    padding: 64,
    spacingFactor: 1.08,
    startAngle: -Math.PI / 2,
  };
}

function clearGraphHighlight(cy: Core) {
  cy.elements().removeClass("is-dimmed is-active-path");
  cy.elements().unselect();
}

function highlightGraphElement(cy: Core, id: string) {
  const target = cy.$id(id);
  if (!target.length) return;
  cy.elements().removeClass("is-active-path").addClass("is-dimmed");
  target.removeClass("is-dimmed").select();
  if (!target.data("source")) {
    target
      .connectedEdges()
      .removeClass("is-dimmed")
      .addClass("is-active-path")
      .connectedNodes()
      .removeClass("is-dimmed");
  } else {
    target
      .removeClass("is-dimmed")
      .addClass("is-active-path")
      .connectedNodes()
      .removeClass("is-dimmed");
  }
}

export function GraphView({
  graph,
  focusTarget,
  onEvidence,
  onBookmark,
  onShowInChronology,
}: {
  graph: CaseGraph | null;
  focusTarget: string | null;
  onEvidence: (id: string, trigger?: HTMLElement) => void;
  onBookmark: (target: BookmarkInput, label?: string) => void;
  onShowInChronology?: (evidenceId: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const instance = useRef<Core | null>(null);
  const graphRef = useRef(graph);
  const onEvidenceRef = useRef(onEvidence);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search.trim().toLocaleLowerCase());
  const [nodeType, setNodeType] = useState("");
  const [relationship, setRelationship] = useState("");
  const [focusId, setFocusId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [zoomPercent, setZoomPercent] = useState(100);
  const entities = graph?.entities ?? [];
  const allEdges = graph?.edges ?? [];
  const nodeTypes = [
    ...new Set(entities.map((entity) => entity.entityType)),
  ].sort();
  const relationships = [
    ...new Set(allEdges.map((edge) => edge.relationship)),
  ].sort();
  const included = new Set(expanded);
  if (focusTarget) {
    included.add(focusTarget);
    const focusedEdge = allEdges.find((edge) => edge.id === focusTarget);
    if (focusedEdge) {
      included.add(focusedEdge.sourceEntityId);
      included.add(focusedEdge.targetEntityId);
    }
  }
  const projection = projectPersistedGraph(entities, allEdges, {
    search: deferredSearch,
    nodeType,
    relationship,
    expanded: included,
    cap: NODE_CAP,
  });
  const edges = projection.edges;
  const nodes = projection.entities;
  const graphIdentity = graph
    ? `${graph.caseId}:${graph.sourceAnalysisRunId ?? "none"}`
    : "none";
  const projectionRef = useRef({ nodes, edges });
  const elementSignature = [
    ...nodes.map((node) => `n:${node.id}:${node.displayValue}:${node.entityType}`),
    ...edges.map(
      (edge) =>
        `e:${edge.id}:${edge.sourceEntityId}:${edge.targetEntityId}:${edge.relationship}`,
    ),
  ].join("|");
  useEffect(() => {
    graphRef.current = graph;
    onEvidenceRef.current = onEvidence;
    projectionRef.current = { nodes, edges };
  });
  useEffect(() => {
    if (!container.current || graphIdentity === "none") return;
    const current = projectionRef.current;
    const elements: ElementDefinition[] = [
      ...current.nodes.map((entity) => ({
        data: {
          id: entity.id,
          label: graphLabel(entity.displayValue),
          kind: entity.entityType,
        },
      })),
      ...current.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.sourceEntityId,
          target: edge.targetEntityId,
          label: edge.relationship,
          evidenceId: edge.evidenceId,
        },
      })),
    ];
    const headless = import.meta.env.MODE === "test";
    const cy = cytoscape({
      container: headless ? null : container.current,
      elements,
      headless,
      layout: graphLayout(),
      minZoom: GRAPH_MIN_ZOOM,
      maxZoom: GRAPH_MAX_ZOOM,
      panningEnabled: true,
      userPanningEnabled: true,
      userZoomingEnabled: true,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#7f8a80",
            "border-color": "#111310",
            "border-width": 2,
            color: "#ecebe5",
            label: "data(label)",
            "font-family": "Cascadia Mono, Consolas, monospace",
            "font-size": "10px",
            "min-zoomed-font-size": 11,
            "text-background-color": "#111310",
            "text-background-opacity": 0.9,
            "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
            "text-wrap": "ellipsis",
            "text-max-width": "150px",
            "text-valign": "bottom",
            "text-margin-y": 9,
            width: 16,
            height: 16,
          },
        },
        {
          selector: 'node[kind = "artifact"]',
          style: {
            "background-color": "#e0ad43",
            "border-color": "#f1d183",
            "border-width": 3,
            "font-size": "12px",
            "font-weight": 700,
            "min-zoomed-font-size": 0,
            shape: "diamond",
            width: 38,
            height: 38,
          },
        },
        {
          selector: 'node[kind = "finding"]',
          style: {
            "background-color": "#c9785e",
            "border-color": "#e2a38d",
            "min-zoomed-font-size": 8,
            shape: "roundrectangle",
            width: 27,
            height: 27,
          },
        },
        {
          selector: 'node[kind = "yara_rule"]',
          style: {
            "background-color": "#9b82b4",
            "border-color": "#c1add2",
            shape: "hexagon",
            width: 24,
            height: 24,
          },
        },
        {
          selector: 'node[kind = "section"]',
          style: {
            "background-color": "#789aae",
            "border-color": "#a9c2cf",
            shape: "round-rectangle",
            width: 22,
            height: 22,
          },
        },
        {
          selector: 'node[kind = "certificate"], node[kind = "signer"]',
          style: {
            "background-color": "#709b89",
            "border-color": "#a0c4b5",
            shape: "pentagon",
            width: 23,
            height: 23,
          },
        },
        {
          selector:
            'node[kind = "url"], node[kind = "domain"], node[kind = "ip_address"], node[kind = "file_path"], node[kind = "registry_path"], node[kind = "registry_key"], node[kind = "command_string"]',
          style: {
            "background-color": "#b47f5e",
            "border-color": "#d6a88c",
            shape: "diamond",
            width: 21,
            height: 21,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.25,
            "line-color": "#4f5750",
            "target-arrow-color": "#4f5750",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.7,
            "curve-style": "straight",
            color: "#92998d",
            "font-size": "8px",
            opacity: 0.72,
          },
        },
        {
          selector: 'edge[label = "supports_finding"]',
          style: {
            "line-color": "#9d6d58",
            "target-arrow-color": "#9d6d58",
            width: 1.8,
          },
        },
        {
          selector: 'edge[label = "contradicts_finding"]',
          style: {
            "line-color": "#b85f5f",
            "line-style": "dashed",
            "target-arrow-color": "#b85f5f",
          },
        },
        {
          selector: ".is-active-path",
          style: {
            label: "data(label)",
            "line-color": "#d8a947",
            "target-arrow-color": "#d8a947",
            "text-background-color": "#111310",
            "text-background-opacity": 0.95,
            "text-background-padding": "3px",
            width: 2.4,
            opacity: 1,
            "z-index": 20,
          },
        },
        {
          selector: ".is-dimmed",
          style: { opacity: 0.12 },
        },
        {
          selector: ":selected",
          style: {
            "background-color": "#ecebe5",
            "border-color": "#d8a947",
            "border-width": 4,
            "line-color": "#d8a947",
            "target-arrow-color": "#d8a947",
            "z-index": 30,
          },
        },
      ],
    });
    instance.current = cy;
    const syncZoom = () => setZoomPercent(Math.round(cy.zoom() * 100));
    cy.on("zoom", syncZoom);
    syncZoom();
    cy.on("tap", "node", (event: EventObjectNode) => {
      const id = event.target.id();
      setFocusId(id);
      highlightGraphElement(cy, id);
      const evidenceId = graphRef.current?.entityEvidence.find(
        (link) => link.entityId === id,
      )?.evidenceId;
      if (evidenceId)
        onEvidenceRef.current(evidenceId, container.current ?? undefined);
    });
    cy.on("tap", "edge", (event: EventObjectEdge) => {
      highlightGraphElement(cy, event.target.id());
      const edge = graphRef.current?.edges.find(
        (item) => item.id === event.target.id(),
      );
      if (edge)
        onEvidenceRef.current(edge.evidenceId, container.current ?? undefined);
    });
    cy.on("tap", (event) => {
      if (event.target !== cy) return;
      clearGraphHighlight(cy);
      setFocusId(null);
    });
    return () => {
      instance.current = null;
      cy.destroy();
    };
  }, [graphIdentity]);
  useEffect(() => {
    const cy = instance.current;
    if (!cy) return;
    const current = projectionRef.current;
    const expectedIds = new Set([
      ...current.nodes.map((node) => node.id),
      ...current.edges.map((edge) => edge.id),
    ]);
    const sameMembership =
      cy.elements().length === expectedIds.size &&
      cy
        .elements()
        .toArray()
        .every((element) => expectedIds.has(element.id()));
    if (sameMembership) {
      for (const entity of current.nodes)
        cy.$id(entity.id).data({
          id: entity.id,
          label: graphLabel(entity.displayValue),
          kind: entity.entityType,
        });
      for (const edge of current.edges)
        cy.$id(edge.id).data({
          id: edge.id,
          source: edge.sourceEntityId,
          target: edge.targetEntityId,
          label: edge.relationship,
          evidenceId: edge.evidenceId,
        });
      return;
    }
    cy.elements().remove();
    cy.add([
      ...current.nodes.map((entity) => ({
        data: {
            id: entity.id,
            label: graphLabel(entity.displayValue),
            kind: entity.entityType,
        },
      })),
      ...current.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.sourceEntityId,
          target: edge.targetEntityId,
          label: edge.relationship,
          evidenceId: edge.evidenceId,
        },
      })),
    ]);
    clearGraphHighlight(cy);
    setFocusId(null);
    cy.layout(graphLayout()).run();
  }, [elementSignature, graphIdentity]);
  useEffect(() => {
    const cy = instance.current;
    if (!cy || !focusTarget) return;
    const target = cy.$id(focusTarget);
    if (!target.length) return;
    cy.elements().unselect();
    highlightGraphElement(cy, focusTarget);
    cy.center(target);
    if (target.isNode()) setFocusId(focusTarget);
  }, [focusTarget, graphIdentity, elementSignature]);
  if (!graph)
    return (
      <div className="tab-empty">
        No persisted graph projection is available for this analysis run.
      </div>
    );
  const focus = focusId
    ? entities.find((entity) => entity.id === focusId)
    : undefined;
  const focusEntityEvidenceId = focusId
    ? graph.entityEvidence.find((link) => link.entityId === focusId)?.evidenceId
    : undefined;
  function expandRelated() {
    if (!focusId) return;
    const related = new Set(expanded);
    related.add(focusId);
    for (const edge of allEdges) {
      if (edge.sourceEntityId === focusId) related.add(edge.targetEntityId);
      if (edge.targetEntityId === focusId) related.add(edge.sourceEntityId);
    }
    setExpanded(related);
  }
  function changeZoom(factor: number) {
    const cy = instance.current;
    if (!cy) return;
    const level = Math.min(
      GRAPH_MAX_ZOOM,
      Math.max(GRAPH_MIN_ZOOM, cy.zoom() * factor),
    );
    cy.zoom({ level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }
  function fitGraph() {
    const cy = instance.current;
    if (!cy) return;
    clearGraphHighlight(cy);
    setFocusId(null);
    cy.fit(undefined, 64);
  }
  const visibleTypes = [...new Set(nodes.map((node) => node.entityType))]
    .map((type) => ({
      type,
      count: nodes.filter((node) => node.entityType === type).length,
    }))
    .sort((left, right) => right.count - left.count || left.type.localeCompare(right.type));
  return (
    <div className="tab-stack">
      <h2 className="visually-hidden">Persisted relationship graph</h2>
      <section className="graph-controls">
        <label>
          <span>Search persisted entities</span>
          <input
            onChange={(event) => setSearch(event.target.value)}
            type="search"
            value={search}
          />
        </label>
        <label>
          <span>Node type</span>
          <select
            onChange={(event) => setNodeType(event.target.value)}
            value={nodeType}
          >
            <option value="">All types</option>
            {nodeTypes.map((type) => (
              <option key={type}>{type}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Relationship</span>
          <select
            onChange={(event) => setRelationship(event.target.value)}
            value={relationship}
          >
            <option value="">All relationships</option>
            {relationships.map((type) => (
              <option key={type}>{type}</option>
            ))}
          </select>
        </label>
        <button
          className="secondary-button"
          onClick={fitGraph}
          type="button"
        >
          Fit graph
        </button>
      </section>
      <section className="graph-shell">
        <div className="graph-stage">
          <div
            aria-label="Interactive persisted relationship graph. Pan by dragging and zoom with the mouse wheel or the controls. Use the relationship list below for keyboard navigation."
            className="graph-canvas"
            ref={container}
            role="img"
          />
          <div
            aria-label="Graph zoom controls"
            className="graph-viewport-controls"
            role="group"
          >
            <button
              aria-label="Zoom out"
              onClick={() => changeZoom(0.8)}
              title="Zoom out"
              type="button"
            >
              -
            </button>
            <output aria-live="polite">{zoomPercent}%</output>
            <button
              aria-label="Zoom in"
              onClick={() => changeZoom(1.25)}
              title="Zoom in"
              type="button"
            >
              +
            </button>
            <button onClick={fitGraph} title="Fit all entities" type="button">
              Fit
            </button>
          </div>
        </div>
        <div className="graph-inspector">
          <span className="eyebrow">Projection v{graph.projectionVersion}</span>
          <strong>
            {nodes.length} / {entities.length} entities
          </strong>
          <span>
            {edges.length} / {allEdges.length} relationships
          </span>
          {entities.length > NODE_CAP ? (
            <small>
              Default view capped at {NODE_CAP}; search or expand persisted
              neighbors.
            </small>
          ) : null}
          <p className="graph-instructions">
            Drag to pan. Scroll or use the controls to zoom. Select an entity to
            isolate its evidence path.
          </p>
          {focus ? (
            <>
              <h3>{focus.displayValue}</h3>
              <code>{focus.entityType}</code>
              <button
                className="secondary-button"
                onClick={expandRelated}
                type="button"
              >
                Expand related
              </button>
              <button
                className="text-button compact"
                onClick={() =>
                  onBookmark(
                    { targetType: "entity", targetId: focus.id },
                    focus.displayValue,
                  )
                }
                type="button"
              >
                Bookmark entity
              </button>
              {focusEntityEvidenceId && onShowInChronology ? (
                <button
                  className="text-button compact"
                  onClick={() => onShowInChronology(focusEntityEvidenceId)}
                  type="button"
                >
                  Show in timeline
                </button>
              ) : null}
            </>
          ) : (
            <small>Select a node to inspect its linked evidence.</small>
          )}
          <div className="graph-legend" aria-label="Visible entity types">
            <h3>Visible entity types</h3>
            <ul>
              {visibleTypes.map(({ type, count }) => (
                <li key={type}>
                  <span className={`graph-legend-swatch kind-${type}`} />
                  <span>{type.replaceAll("_", " ")}</span>
                  <strong>{count}</strong>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
      <details className="relationship-fallback">
        <summary>
          Accessible entity and relationship list ({nodes.length} entities, {edges.length}{" "}
          relationships)
        </summary>
        <h3>Entities</h3>
        <ul className="entity-fallback-list">
          {[...nodes]
            .sort((left, right) => left.id.localeCompare(right.id))
            .map((entity) => {
              const evidenceId = graph.entityEvidence.find(
                (link) => link.entityId === entity.id,
              )?.evidenceId;
              const isolated = !edges.some(
                (edge) =>
                  edge.sourceEntityId === entity.id ||
                  edge.targetEntityId === entity.id,
              );
              return (
                <li key={entity.id}>
                  {evidenceId ? (
                    <button
                      aria-label={`Inspect evidence for ${entity.displayValue}, ${entity.entityType.replaceAll("_", " ")}`}
                      onClick={(event) =>
                        onEvidence(evidenceId, event.currentTarget)
                      }
                      type="button"
                    >
                      <strong>{entity.displayValue}</strong>
                      <span>{entity.entityType.replaceAll("_", " ")}</span>
                      {isolated ? <small>Isolated entity</small> : null}
                    </button>
                  ) : (
                    <div>
                      <strong>{entity.displayValue}</strong>
                      <span>{entity.entityType.replaceAll("_", " ")}</span>
                      {isolated ? <small>Isolated entity</small> : null}
                    </div>
                  )}
                  {evidenceId && onShowInChronology ? (
                    <button
                      className="text-button compact"
                      onClick={() => onShowInChronology(evidenceId)}
                      type="button"
                    >
                      Show in timeline
                    </button>
                  ) : null}
                </li>
              );
            })}
        </ul>
        <h3>Relationships</h3>
        <ol>
          {[...edges]
            .sort((left, right) => left.id.localeCompare(right.id))
            .map((edge) => {
              const source = entities.find(
                (item) => item.id === edge.sourceEntityId,
              );
              const target = entities.find(
                (item) => item.id === edge.targetEntityId,
              );
              return (
                <li key={edge.id}>
                  <button
                    aria-label={`Inspect ${edge.relationship.replaceAll("_", " ")} relationship from ${source?.displayValue ?? edge.sourceEntityId} to ${target?.displayValue ?? edge.targetEntityId}`}
                    onClick={(event) =>
                      onEvidence(edge.evidenceId, event.currentTarget)
                    }
                    type="button"
                  >
                    <span>{source?.displayValue ?? edge.sourceEntityId}</span>
                    <strong>{edge.relationship.replaceAll("_", " ")}</strong>
                    <span>{target?.displayValue ?? edge.targetEntityId}</span>
                  </button>
                  <button
                    className="text-button compact"
                    onClick={() =>
                      onBookmark(
                        { targetType: "edge", targetId: edge.id },
                        `${source?.displayValue ?? "Entity"} ${edge.relationship} ${target?.displayValue ?? "entity"}`,
                      )
                    }
                    type="button"
                  >
                    Bookmark edge
                  </button>
                </li>
              );
            })}
        </ol>
      </details>
    </div>
  );
}

export function ChronologyView({
  chronology,
  onEvidence,
  onBookmark,
  onShowInGraph,
  highlightedEventId,
}: {
  chronology: CaseChronology | null;
  onEvidence: (id: string, trigger?: HTMLElement) => void;
  onBookmark: (target: BookmarkInput, label?: string) => void;
  onShowInGraph?: (evidenceId: string) => void;
  highlightedEventId?: string | null;
}) {
  if (!chronology)
    return (
      <div className="tab-empty">
        No persisted chronology projection is available for this analysis run.
      </div>
    );
  const highlightedEvent = highlightedEventId
    ? chronology.events.find((event) => event.id === highlightedEventId)
    : undefined;
  return (
    <div className="tab-stack">
      <p aria-live="polite" className="visually-hidden" role="status">
        {highlightedEvent
          ? `Timeline event highlighted: ${highlightedEvent.summary}`
          : ""}
      </p>
      <p className="confidence-notice">
        Timestamps are persisted artifact or application observations with
        explicit reliability labels. They do not establish that code ran at the
        recorded time.
      </p>
      <ol className="chronology-list">
        {chronology.events.map((event) => (
          <li
            aria-current={highlightedEventId === event.id ? "true" : undefined}
            id={`event-${event.id}`}
            key={event.id}
            className={highlightedEventId === event.id ? "is-highlighted" : undefined}
          >
            <time dateTime={event.timestampUtc}>{event.timestampUtc}</time>
            <div>
              <span className={`reliability reliability-${event.reliability}`}>
                {event.reliability.replaceAll("_", " ")}
              </span>
              <span>{event.timestampType.replaceAll("_", " ")}</span>
              <h2>{event.summary}</h2>
              <code>{event.eventType}</code>
              <div className="inline-actions">
                {event.evidenceId ? (
                  <button
                    className="text-button compact"
                    onClick={(click) =>
                      onEvidence(event.evidenceId!, click.currentTarget)
                    }
                    type="button"
                  >
                    Inspect evidence
                  </button>
                ) : null}
                {event.evidenceId && onShowInGraph ? (
                  <button
                    className="text-button compact"
                    onClick={() => onShowInGraph(event.evidenceId!)}
                    type="button"
                  >
                    Show in graph
                  </button>
                ) : null}
                <button
                  className="text-button compact"
                  onClick={() =>
                    onBookmark(
                      { targetType: "event", targetId: event.id },
                      event.summary,
                    )
                  }
                  type="button"
                >
                  Bookmark event
                </button>
              </div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function EvidenceDrawer({
  evidenceId,
  evidence,
  findings,
  provenances,
  graph,
  onClose,
  onBookmark,
}: {
  evidenceId: string | null;
  evidence: EvidenceRecord[];
  findings: FindingRecord[];
  provenances: ProvenanceRecord[];
  graph: CaseGraph | null;
  onClose: () => void;
  onBookmark: (target: BookmarkInput, label?: string) => void;
}) {
  const close = useRef<HTMLButtonElement>(null);
  const drawer = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!evidenceId) return;
    close.current?.focus();
    function keydown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !drawer.current) return;
      const focusable = [
        ...drawer.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), summary, input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ];
      if (!focusable.length) return;
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", keydown);
    return () => document.removeEventListener("keydown", keydown);
  }, [evidenceId, onClose]);
  if (!evidenceId) return null;
  const item = evidence.find((entry) => entry.id === evidenceId);
  const provenance = item
    ? provenances.find((entry) => entry.id === item.provenanceId)
    : undefined;
  const relatedFindings = findings.filter((finding) =>
    finding.evidence.some((link) => link.evidenceId === evidenceId),
  );
  const entityIds = new Set(
    (graph?.entityEvidence ?? [])
      .filter((link) => link.evidenceId === evidenceId)
      .map((link) => link.entityId),
  );
  const relatedEntities = (graph?.entities ?? []).filter((entity) =>
    entityIds.has(entity.id),
  );
  return (
    <div
      className="drawer-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        aria-labelledby="evidence-drawer-title"
        aria-modal="true"
        className="evidence-drawer"
        ref={drawer}
        role="dialog"
        tabIndex={-1}
      >
        <header>
          <div>
            <p className="eyebrow">Shared evidence inspector</p>
            <h2 id="evidence-drawer-title">
              {item?.kind ?? "Evidence unavailable"}
            </h2>
          </div>
          <button
            aria-label="Close evidence inspector"
            className="icon-button"
            onClick={onClose}
            ref={close}
            type="button"
          >
            Close
          </button>
        </header>
        {item ? (
          <>
            <p className="drawer-preview">
              {item.previewText ?? "No preview text persisted."}
            </p>
            <dl className="drawer-facts">
              <div>
                <dt>Evidence ID</dt>
                <dd>
                  <code>{item.id}</code>
                </dd>
              </div>
              <div>
                <dt>Class</dt>
                <dd>{item.class}</dd>
              </div>
              <div>
                <dt>Analyzer</dt>
                <dd>
                  {provenance
                    ? `${provenance.analyzer} ${provenance.analyzerVersion}`
                    : "Unavailable"}
                </dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd>
                  {provenance?.ruleId
                    ? `${provenance.ruleId} ${provenance.ruleVersion ?? ""}`
                    : "Direct analyzer observation"}
                </dd>
              </div>
              <div>
                <dt>Input SHA-256</dt>
                <dd>
                  <code>{provenance?.inputSha256 ?? "Unavailable"}</code>
                </dd>
              </div>
              <div>
                <dt>Provenance ID</dt>
                <dd>
                  <code>{item.provenanceId ?? "Unavailable"}</code>
                </dd>
              </div>
            </dl>
            <section className="drawer-related">
              <h3>Related findings</h3>
              {relatedFindings.length ? (
                relatedFindings.map((finding) => (
                  <span key={finding.id}>
                    {finding.title} / {finding.ruleId}
                  </span>
                ))
              ) : (
                <span>None persisted</span>
              )}
              <h3>Related entities</h3>
              {relatedEntities.length ? (
                relatedEntities.map((entity) => (
                  <span key={entity.id}>
                    {entity.entityType}: {entity.displayValue}
                  </span>
                ))
              ) : (
                <span>None persisted</span>
              )}
            </section>
            <button
              className="secondary-button"
              onClick={() =>
                onBookmark(
                  { targetType: "evidence", targetId: item.id },
                  item.previewText ?? item.kind,
                )
              }
              type="button"
            >
              Bookmark evidence
            </button>
            <details className="json-details" open>
              <summary>Raw persisted JSON</summary>
              <pre>{json(item)}</pre>
            </details>
          </>
        ) : (
          <p>The selected evidence record is not part of this analysis run.</p>
        )}
      </section>
    </div>
  );
}

export function BookmarksBar({
  bookmarks,
  onOpen,
  onDelete,
  onRename,
}: {
  bookmarks: BookmarkRecord[];
  onOpen: (target: BookmarkTarget) => void;
  onDelete: (bookmark: BookmarkRecord) => void;
  onRename: (bookmark: BookmarkRecord, label: string) => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  if (!bookmarks.length) return null;
  return (
    <details className="bookmarks-bar">
      <summary>Bookmarks / {bookmarks.length}</summary>
      <ul>
        {bookmarks.map((bookmark) => (
          <li key={bookmark.id}>
            {editing === bookmark.id ? (
              <>
                <label>
                  <span className="visually-hidden">Bookmark label</span>
                  <input
                    autoFocus
                    maxLength={256}
                    onChange={(event) => setLabel(event.target.value)}
                    value={label}
                  />
                </label>
                <button
                  className="secondary-button"
                  onClick={() => {
                    onRename(bookmark, label);
                    setEditing(null);
                  }}
                  type="button"
                >
                  Save
                </button>
              </>
            ) : (
              <button onClick={() => onOpen(bookmark.target)} type="button">
                <strong>
                  {bookmark.label ??
                    `${bookmark.target.type} ${targetId(bookmark.target)}`}
                </strong>
                <code>{bookmark.target.type}</code>
              </button>
            )}
            <button
              className="text-button compact"
              onClick={() => {
                setEditing(bookmark.id);
                setLabel(bookmark.label ?? "");
              }}
              type="button"
            >
              Rename
            </button>
            <button
              className="text-button compact danger-text"
              onClick={() => onDelete(bookmark)}
              type="button"
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
    </details>
  );
}

export function BookmarkAction({
  children = "Bookmark",
  onClick,
}: {
  children?: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-button compact" onClick={onClick} type="button">
      {children}
    </button>
  );
}
