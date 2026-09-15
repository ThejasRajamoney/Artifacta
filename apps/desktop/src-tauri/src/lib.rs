use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{DragDropEvent, Emitter, Manager, State, WindowEvent};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tf_case::{
    AnalysisStage, CaseAnalysis, CaseService, ReportBundleRecord, ReportBundleVerification,
    ReportFormat,
};
use tf_model::{
    AnalysisRun, AnalysisRunId, AnalysisStatus, AnalystNote, ArtifactComparison, ArtifactKind,
    ArtifactSummary, AttackMapping, Bookmark, BookmarkId, Case, CaseChronology, CaseGraph, CaseId,
    CaseSearchHit, CaseSearchRequest, CleanupStatus, ComparisonEntry, ComparisonGroup,
    ComparisonValue, EdgeId, EntityId, EventId, EvidenceId, EvidenceRole, Finding, FindingAction,
    FindingId, FindingState, NavigationTarget, NoteId, ObjectCleanupResult, ObservationClass,
    QuickCheck, SearchField, YaraPack, YaraPackId,
};
use tf_report::{MAX_REPORT_BYTES, render_csv, render_html, render_json, render_stix};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_CASE_TITLE_BYTES: usize = 256;
const MAX_NOTE_BYTES: usize = 16 * 1024;
const MAX_SEARCH_QUERY_BYTES: usize = 256;
const MAX_SEARCH_RESULTS: u32 = 100;
const MAX_INTAKE_FILES: usize = 64;
const MAX_OUTSTANDING_INTAKE_GRANTS: usize = 64;
const MAX_YARA_FOLDER_FILES: usize = 64;
const INTAKE_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

struct IntakeGrant {
    path: PathBuf,
    name: String,
    minted_at: Instant,
}

struct AppState {
    cases: Arc<CaseService>,
    intake_grants: Mutex<HashMap<String, IntakeGrant>>,
    pending_intake: Mutex<Vec<IntakeOffer>>,
    report_bundles: Mutex<HashMap<String, ReportBundleRecord>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntakeOffer {
    token: String,
    name: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntakeBatchStatus {
    token: String,
    name: String,
    status: &'static str,
    stage: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntakeBatchResult {
    token: String,
    name: String,
    status: &'static str,
    analysis: Option<CaseAnalysisView>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    version: &'static str,
    platform: &'static str,
    analysis_mode: &'static str,
    network_policy: &'static str,
}

#[tauri::command]
fn app_status() -> AppStatus {
    AppStatus {
        version: env!("CARGO_PKG_VERSION"),
        platform: "Windows x64",
        analysis_mode: "static",
        network_policy: "PE/YARA workers use zero-capability AppContainer network denial",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseSummary {
    id: String,
    title: String,
    created_at: String,
    updated_at: String,
    status: tf_model::CaseStatus,
}

impl From<Case> for CaseSummary {
    fn from(case: Case) -> Self {
        Self {
            id: case.id.as_str().to_owned(),
            title: case.title,
            created_at: case.created_at,
            updated_at: case.updated_at,
            status: case.status,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactView {
    id: String,
    case_id: String,
    parent_artifact_id: Option<String>,
    sha256: String,
    sha1: String,
    md5: String,
    size_bytes: u64,
    kind: ArtifactKind,
    mime: Option<String>,
    original_name: String,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunView {
    id: String,
    artifact_id: String,
    analyzer: String,
    analyzer_version: String,
    started_at: String,
    finished_at: Option<String>,
    status: AnalysisStatus,
    error_code: Option<String>,
}

impl From<AnalysisRun> for RunView {
    fn from(run: AnalysisRun) -> Self {
        Self {
            id: run.id.as_str().to_owned(),
            artifact_id: run.artifact_id.as_str().to_owned(),
            analyzer: run.analyzer,
            analyzer_version: run.analyzer_version,
            started_at: run.started_at,
            finished_at: run.finished_at,
            status: run.status,
            error_code: run.error_code,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvenanceView {
    id: String,
    analysis_run_id: String,
    analyzer: String,
    analyzer_version: String,
    rule_id: Option<String>,
    rule_version: Option<String>,
    rule_pack_sha256: Option<String>,
    input_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceView {
    id: String,
    artifact_id: String,
    provenance_id: String,
    kind: String,
    class: ObservationClass,
    locator: Value,
    value: Value,
    preview_text: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceLinkView {
    evidence_id: String,
    role: EvidenceRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackMappingView {
    technique_id: String,
    technique_name: String,
    tactic: String,
}

impl From<AttackMapping> for AttackMappingView {
    fn from(mapping: AttackMapping) -> Self {
        Self {
            technique_id: mapping.technique_id,
            technique_name: mapping.technique_name,
            tactic: mapping.tactic,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingView {
    id: String,
    analysis_run_id: String,
    artifact_id: String,
    rule_id: String,
    rule_version: String,
    title: String,
    category: String,
    severity: tf_model::Severity,
    confidence: f32,
    confidence_band: tf_model::ConfidenceBand,
    explanation_template_id: String,
    state: FindingState,
    observation: String,
    why_it_matters: String,
    limitations: String,
    evidence: Vec<EvidenceLinkView>,
    attack_mappings: Vec<AttackMappingView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingStateView {
    id: String,
    analysis_run_id: String,
    artifact_id: String,
    state: FindingState,
}

impl From<Finding> for FindingStateView {
    fn from(finding: Finding) -> Self {
        Self {
            id: finding.id.as_str().to_owned(),
            analysis_run_id: finding.analysis_run_id.as_str().to_owned(),
            artifact_id: finding.artifact_id.as_str().to_owned(),
            state: finding.state,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseAnalysisView {
    case: CaseSummary,
    artifact: ArtifactView,
    run: Option<RunView>,
    // Retained for the current desktop renderer while v2 consumers use `provenances`.
    provenance: Option<ProvenanceView>,
    provenances: Vec<ProvenanceView>,
    run_history: Vec<RunView>,
    evidence: Vec<EvidenceView>,
    findings: Vec<FindingView>,
    graph: Option<CaseGraphView>,
    chronology: Option<CaseChronologyView>,
    bookmarks: Vec<BookmarkView>,
    quick_check: QuickCheckView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEntityView {
    id: String,
    case_id: String,
    entity_type: tf_model::EntityType,
    canonical_value: String,
    display_value: String,
    metadata: BTreeMap<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdgeView {
    id: String,
    source_entity_id: String,
    target_entity_id: String,
    relationship: tf_model::Relationship,
    evidence_id: String,
    confidence: f32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntityEvidenceView {
    entity_id: String,
    evidence_id: String,
    role: EvidenceRole,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseGraphView {
    case_id: String,
    projection_version: u32,
    source_analysis_run_id: Option<String>,
    entities: Vec<GraphEntityView>,
    edges: Vec<GraphEdgeView>,
    entity_evidence: Vec<EntityEvidenceView>,
}

impl From<CaseGraph> for CaseGraphView {
    fn from(graph: CaseGraph) -> Self {
        Self {
            case_id: graph.case_id.as_str().to_owned(),
            projection_version: graph.projection_version,
            source_analysis_run_id: graph
                .source_analysis_run_id
                .map(|id| id.as_str().to_owned()),
            entities: graph
                .entities
                .into_iter()
                .map(|entity| GraphEntityView {
                    id: entity.id.as_str().to_owned(),
                    case_id: entity.case_id.as_str().to_owned(),
                    entity_type: entity.entity_type,
                    canonical_value: entity.canonical_value,
                    display_value: entity.display_value,
                    metadata: entity.metadata,
                })
                .collect(),
            edges: graph
                .edges
                .into_iter()
                .map(|edge| GraphEdgeView {
                    id: edge.id.as_str().to_owned(),
                    source_entity_id: edge.source_entity_id.as_str().to_owned(),
                    target_entity_id: edge.target_entity_id.as_str().to_owned(),
                    relationship: edge.relationship,
                    evidence_id: edge.evidence_id.as_str().to_owned(),
                    confidence: edge.confidence.value(),
                })
                .collect(),
            entity_evidence: graph
                .entity_evidence
                .into_iter()
                .map(|link| EntityEvidenceView {
                    entity_id: link.entity_id.as_str().to_owned(),
                    evidence_id: link.evidence_id.as_str().to_owned(),
                    role: link.role,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChronologyEventView {
    id: String,
    case_id: String,
    timestamp_utc: String,
    timestamp_type: String,
    reliability: tf_model::TimestampReliability,
    event_type: String,
    artifact_id: Option<String>,
    evidence_id: Option<String>,
    summary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseChronologyView {
    case_id: String,
    projection_version: u32,
    source_analysis_run_id: Option<String>,
    events: Vec<ChronologyEventView>,
}

impl From<CaseChronology> for CaseChronologyView {
    fn from(chronology: CaseChronology) -> Self {
        Self {
            case_id: chronology.case_id.as_str().to_owned(),
            projection_version: chronology.projection_version,
            source_analysis_run_id: chronology
                .source_analysis_run_id
                .map(|id| id.as_str().to_owned()),
            events: chronology
                .events
                .into_iter()
                .map(|event| ChronologyEventView {
                    id: event.id.as_str().to_owned(),
                    case_id: event.case_id.as_str().to_owned(),
                    timestamp_utc: event.timestamp_utc,
                    timestamp_type: event.timestamp_type,
                    reliability: event.reliability,
                    event_type: event.event_type,
                    artifact_id: event.artifact_id.map(|id| id.as_str().to_owned()),
                    evidence_id: event.evidence_id.map(|id| id.as_str().to_owned()),
                    summary: event.summary,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum NavigationTargetView {
    Evidence { evidence_id: String },
    Finding { finding_id: String },
    Entity { entity_id: String },
    Edge { edge_id: String },
    Event { event_id: String },
}

impl From<NavigationTarget> for NavigationTargetView {
    fn from(target: NavigationTarget) -> Self {
        match target {
            NavigationTarget::Evidence { evidence_id } => Self::Evidence {
                evidence_id: evidence_id.as_str().to_owned(),
            },
            NavigationTarget::Finding { finding_id } => Self::Finding {
                finding_id: finding_id.as_str().to_owned(),
            },
            NavigationTarget::Entity { entity_id } => Self::Entity {
                entity_id: entity_id.as_str().to_owned(),
            },
            NavigationTarget::Edge { edge_id } => Self::Edge {
                edge_id: edge_id.as_str().to_owned(),
            },
            NavigationTarget::Event { event_id } => Self::Event {
                event_id: event_id.as_str().to_owned(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BookmarkView {
    id: String,
    case_id: String,
    target: NavigationTargetView,
    label: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<Bookmark> for BookmarkView {
    fn from(bookmark: Bookmark) -> Self {
        Self {
            id: bookmark.id.as_str().to_owned(),
            case_id: bookmark.case_id.as_str().to_owned(),
            target: bookmark.target.into(),
            label: bookmark.label,
            created_at: bookmark.created_at,
            updated_at: bookmark.updated_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickCheckView {
    policy_version: String,
    policy_sha256: String,
    band: tf_model::SuspicionBand,
    finding_counts: QuickCheckFindingCountsView,
    top_findings: Vec<QuickCheckTopFindingView>,
    evidence_families: Vec<QuickCheckFamilyView>,
    statement: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickCheckFindingCountsView {
    contextual: u32,
    low: u32,
    medium: u32,
    high: u32,
    total: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickCheckTopFindingView {
    finding_id: String,
    title: String,
    category: String,
    severity: tf_model::Severity,
    evidence_family: tf_model::QuickCheckEvidenceFamily,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuickCheckFamilyView {
    family: tf_model::QuickCheckEvidenceFamily,
    finding_count: u32,
    contributing_finding_count: u32,
    strongest_severity: Option<tf_model::Severity>,
}

impl From<QuickCheck> for QuickCheckView {
    fn from(check: QuickCheck) -> Self {
        Self {
            policy_version: check.policy_version,
            policy_sha256: check.policy_sha256,
            band: check.band,
            finding_counts: QuickCheckFindingCountsView {
                contextual: check.finding_counts.contextual,
                low: check.finding_counts.low,
                medium: check.finding_counts.medium,
                high: check.finding_counts.high,
                total: check.finding_counts.total,
            },
            top_findings: check
                .top_findings
                .into_iter()
                .map(|finding| QuickCheckTopFindingView {
                    finding_id: finding.finding_id.as_str().to_owned(),
                    title: finding.title,
                    category: finding.category,
                    severity: finding.severity,
                    evidence_family: finding.evidence_family,
                })
                .collect(),
            evidence_families: check
                .evidence_families
                .into_iter()
                .map(|family| QuickCheckFamilyView {
                    family: family.family,
                    finding_count: family.finding_count,
                    contributing_finding_count: family.contributing_finding_count,
                    strongest_severity: family.strongest_severity,
                })
                .collect(),
            statement: check.statement,
        }
    }
}

impl From<CaseAnalysis> for CaseAnalysisView {
    fn from(analysis: CaseAnalysis) -> Self {
        let graph = analysis.graph.map(Into::into);
        let chronology = analysis.chronology.map(Into::into);
        let bookmarks = analysis.bookmarks.into_iter().map(Into::into).collect();
        let quick_check = analysis.quick_check.into();
        let mut links = BTreeMap::<String, Vec<EvidenceLinkView>>::new();
        for link in analysis.finding_evidence {
            links
                .entry(link.finding_id.as_str().to_owned())
                .or_default()
                .push(EvidenceLinkView {
                    evidence_id: link.evidence_id.as_str().to_owned(),
                    role: link.role,
                });
        }
        let explanations = analysis
            .explanations
            .into_iter()
            .map(|item| (item.finding_id.as_str().to_owned(), item))
            .collect::<BTreeMap<_, _>>();
        let mut attack_mappings = BTreeMap::<String, Vec<AttackMappingView>>::new();
        for item in analysis.attack_mappings {
            attack_mappings
                .entry(item.finding_id.as_str().to_owned())
                .or_default()
                .push(item.mapping.into());
        }
        let findings = analysis
            .findings
            .into_iter()
            .map(|item| {
                let id = item.id.as_str().to_owned();
                let explanation = explanations.get(&id);
                FindingView {
                    id: id.clone(),
                    analysis_run_id: item.analysis_run_id.as_str().to_owned(),
                    artifact_id: item.artifact_id.as_str().to_owned(),
                    rule_id: item.rule_id,
                    rule_version: item.rule_version,
                    title: item.title,
                    category: item.category,
                    severity: item.severity,
                    confidence: item.confidence.value(),
                    confidence_band: item.confidence_band,
                    explanation_template_id: item.explanation_template_id,
                    state: item.state,
                    observation: explanation
                        .map(|value| value.observation.clone())
                        .unwrap_or_default(),
                    why_it_matters: explanation
                        .map(|value| value.why_it_matters.clone())
                        .unwrap_or_default(),
                    limitations: explanation
                        .map(|value| value.limitations.clone())
                        .unwrap_or_default(),
                    evidence: links.remove(&id).unwrap_or_default(),
                    attack_mappings: attack_mappings.remove(&id).unwrap_or_default(),
                }
            })
            .collect();
        let evidence = analysis
            .evidence
            .into_iter()
            .map(|item| EvidenceView {
                id: item.id.as_str().to_owned(),
                artifact_id: item.artifact_id.as_str().to_owned(),
                provenance_id: item.provenance_id.as_str().to_owned(),
                kind: item.kind,
                class: item.class,
                locator: serde_json::to_value(item.locator).unwrap_or(Value::Null),
                value: item.value,
                preview_text: item.preview_text,
            })
            .collect();
        let provenance = analysis.provenance.map(provenance_view);
        let provenances = analysis
            .provenances
            .into_iter()
            .map(provenance_view)
            .collect();

        Self {
            case: analysis.case.into(),
            artifact: ArtifactView {
                id: analysis.artifact.id.as_str().to_owned(),
                case_id: analysis.artifact.case_id.as_str().to_owned(),
                parent_artifact_id: analysis
                    .artifact
                    .parent_artifact_id
                    .map(|id| id.as_str().to_owned()),
                sha256: analysis.artifact.sha256,
                sha1: analysis.artifact.sha1,
                md5: analysis.artifact.md5,
                size_bytes: analysis.artifact.size_bytes,
                kind: analysis.artifact.kind,
                mime: analysis.artifact.mime,
                original_name: analysis.artifact.original_name,
                created_at: analysis.artifact.created_at,
            },
            run: analysis.analysis_run.map(Into::into),
            provenance,
            provenances,
            run_history: analysis.run_history.into_iter().map(Into::into).collect(),
            evidence,
            findings,
            graph,
            chronology,
            bookmarks,
            quick_check,
        }
    }
}

fn provenance_view(provenance: tf_model::Provenance) -> ProvenanceView {
    ProvenanceView {
        id: provenance.id.as_str().to_owned(),
        analysis_run_id: provenance.analysis_run_id.as_str().to_owned(),
        analyzer: provenance.analyzer,
        analyzer_version: provenance.analyzer_version,
        rule_id: provenance.rule_id,
        rule_version: provenance.rule_version,
        rule_pack_sha256: provenance.rule_pack_sha256,
        input_sha256: provenance.input_sha256,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NoteView {
    id: String,
    case_id: String,
    entity_id: Option<String>,
    finding_id: Option<String>,
    body: String,
    created_at: String,
    updated_at: String,
}

impl From<AnalystNote> for NoteView {
    fn from(note: AnalystNote) -> Self {
        Self {
            id: note.id.as_str().to_owned(),
            case_id: note.case_id.as_str().to_owned(),
            entity_id: note.entity_id.map(|id| id.as_str().to_owned()),
            finding_id: note.finding_id.map(|id| id.as_str().to_owned()),
            body: note.body,
            created_at: note.created_at,
            updated_at: note.updated_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteNoteReceipt {
    case_id: String,
    note_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHitView {
    case_id: String,
    case_title: String,
    case_status: tf_model::CaseStatus,
    artifact_id: Option<String>,
    analysis_run_id: Option<String>,
    evidence_id: Option<String>,
    finding_id: Option<String>,
    field: SearchField,
    value: String,
}

impl From<CaseSearchHit> for SearchHitView {
    fn from(hit: CaseSearchHit) -> Self {
        Self {
            case_id: hit.case_id.as_str().to_owned(),
            case_title: hit.case_title,
            case_status: hit.case_status,
            artifact_id: hit.artifact_id.map(|id| id.as_str().to_owned()),
            analysis_run_id: hit.analysis_run_id.map(|id| id.as_str().to_owned()),
            evidence_id: hit.evidence_id.map(|id| id.as_str().to_owned()),
            finding_id: hit.finding_id.map(|id| id.as_str().to_owned()),
            field: hit.field,
            value: hit.value,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactSummaryView {
    id: String,
    case_id: String,
    sha256: String,
    sha1: String,
    md5: String,
    size_bytes: u64,
    kind: ArtifactKind,
    mime: Option<String>,
    original_name: String,
    created_at: String,
}

impl From<ArtifactSummary> for ArtifactSummaryView {
    fn from(artifact: ArtifactSummary) -> Self {
        Self {
            id: artifact.id.as_str().to_owned(),
            case_id: artifact.case_id.as_str().to_owned(),
            sha256: artifact.sha256,
            sha1: artifact.sha1,
            md5: artifact.md5,
            size_bytes: artifact.size_bytes,
            kind: artifact.kind,
            mime: artifact.mime,
            original_name: artifact.original_name,
            created_at: artifact.created_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComparisonValueView {
    key: String,
    value: Value,
    evidence_ids: Vec<String>,
}

impl From<ComparisonValue> for ComparisonValueView {
    fn from(value: ComparisonValue) -> Self {
        Self {
            key: value.key,
            value: value.value,
            evidence_ids: value
                .evidence_ids
                .into_iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComparisonEntryView {
    delta: tf_model::ComparisonDelta,
    key: String,
    left: Option<ComparisonValueView>,
    right: Option<ComparisonValueView>,
}

impl From<ComparisonEntry> for ComparisonEntryView {
    fn from(entry: ComparisonEntry) -> Self {
        Self {
            delta: entry.delta,
            key: entry.key,
            left: entry.left.map(Into::into),
            right: entry.right.map(Into::into),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComparisonGroupView {
    added: Vec<ComparisonEntryView>,
    removed: Vec<ComparisonEntryView>,
    changed: Vec<ComparisonEntryView>,
}

impl From<ComparisonGroup> for ComparisonGroupView {
    fn from(group: ComparisonGroup) -> Self {
        Self {
            added: group.added.into_iter().map(Into::into).collect(),
            removed: group.removed.into_iter().map(Into::into).collect(),
            changed: group.changed.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactComparisonView {
    left: ArtifactSummaryView,
    right: ArtifactSummaryView,
    hashes: ComparisonGroupView,
    headers: ComparisonGroupView,
    sections: ComparisonGroupView,
    imports: ComparisonGroupView,
    strings: ComparisonGroupView,
    signatures: ComparisonGroupView,
    findings: ComparisonGroupView,
}

impl From<ArtifactComparison> for ArtifactComparisonView {
    fn from(comparison: ArtifactComparison) -> Self {
        Self {
            left: comparison.left.into(),
            right: comparison.right.into(),
            hashes: comparison.hashes.into(),
            headers: comparison.headers.into(),
            sections: comparison.sections.into(),
            imports: comparison.imports.into(),
            strings: comparison.strings.into(),
            signatures: comparison.signatures.into(),
            findings: comparison.findings.into(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupView {
    sha256: String,
    cleanup: CleanupStatus,
}

impl From<ObjectCleanupResult> for CleanupView {
    fn from(result: ObjectCleanupResult) -> Self {
        // Cleanup diagnostics may contain host filesystem details and are intentionally dropped.
        Self {
            sha256: result.sha256,
            cleanup: result.cleanup,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteCaseView {
    case_id: String,
    objects: Vec<CleanupView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct YaraPackView {
    id: String,
    sha256: String,
    name: String,
    version: String,
    source: String,
    license: String,
    imported_at: String,
    enabled: bool,
    rule_count: u32,
}

impl From<YaraPack> for YaraPackView {
    fn from(pack: YaraPack) -> Self {
        Self {
            id: pack.id.as_str().to_owned(),
            sha256: pack.sha256,
            name: pack.name,
            version: pack.version,
            source: pack.source,
            license: pack.license,
            imported_at: pack.imported_at,
            enabled: pack.enabled,
            rule_count: pack.rule_count,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct YaraPackMetadataInput {
    name: String,
    version: String,
    source: String,
    license: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct YaraFolderImportResult {
    file_name: String,
    status: &'static str,
    pack: Option<YaraPackView>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportReceipt {
    file_name: String,
    format: String,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportBundleReceipt {
    verification_token: String,
    report_file_name: String,
    manifest_file_name: String,
    report_sha256: String,
    manifest_sha256: String,
    snapshot_sha256: String,
}

fn parse_id<T: FromStr>(value: &str, label: &str) -> Result<T, String> {
    value.parse().map_err(|_| format!("Invalid {label}"))
}

fn validate_text(
    value: &str,
    max_bytes: usize,
    label: &str,
    multiline: bool,
) -> Result<String, String> {
    let value = value.trim();
    let invalid_control = value.chars().any(|character| {
        character == '\0'
            || (character.is_control() && (!multiline || (character != '\n' && character != '\t')))
    });
    if value.is_empty() || value.len() > max_bytes || invalid_control {
        return Err(format!("Invalid {label}"));
    }
    Ok(value.to_owned())
}

fn parse_finding_action(value: &str) -> Result<FindingAction, String> {
    match value {
        "review" => Ok(FindingAction::Review),
        "accept" => Ok(FindingAction::Accept),
        "dismiss" => Ok(FindingAction::Dismiss),
        "reopen" => Ok(FindingAction::Reopen),
        _ => Err("Unsupported finding action".to_owned()),
    }
}

fn parse_search_fields(values: Vec<String>) -> Result<Vec<SearchField>, String> {
    values
        .into_iter()
        .map(|value| {
            SearchField::from_str(&value).map_err(|_| "Unsupported search field".to_owned())
        })
        .collect()
}

fn validate_yara_metadata(
    metadata: YaraPackMetadataInput,
) -> Result<YaraPackMetadataInput, String> {
    Ok(YaraPackMetadataInput {
        name: validate_text(&metadata.name, 256, "YARA pack name", false)?,
        version: validate_text(&metadata.version, 128, "YARA pack version", false)?,
        source: validate_text(&metadata.source, 1024, "YARA pack source", false)?,
        license: validate_text(&metadata.license, 256, "YARA pack license", false)?,
    })
}

fn is_yara_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
        })
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn mint_intake_paths(state: &AppState, paths: Vec<PathBuf>) -> Vec<IntakeOffer> {
    let mut grants = state
        .intake_grants
        .lock()
        .unwrap_or_else(|lock| lock.into_inner());
    grants.retain(|_, grant| grant.minted_at.elapsed() <= INTAKE_TOKEN_TTL);
    let available = MAX_OUTSTANDING_INTAKE_GRANTS.saturating_sub(grants.len());
    let mut offers = Vec::new();
    for path in paths.into_iter().take(MAX_INTAKE_FILES) {
        if offers.len() >= available {
            break;
        }
        let Some(name) = fs::metadata(&path)
            .ok()
            .filter(|metadata| metadata.is_file())
            .and_then(|_| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
        else {
            continue;
        };
        let token = ulid::Ulid::new().to_string();
        grants.insert(
            token.clone(),
            IntakeGrant {
                path,
                name: name.clone(),
                minted_at: Instant::now(),
            },
        );
        offers.push(IntakeOffer { token, name });
    }
    offers
}

fn queue_intake_paths(state: &AppState, paths: Vec<PathBuf>) -> Vec<IntakeOffer> {
    let offers = mint_intake_paths(state, paths);
    state
        .pending_intake
        .lock()
        .unwrap_or_else(|lock| lock.into_inner())
        .extend(offers.iter().cloned());
    offers
}

fn forwarded_analyze_path(arguments: &[String]) -> Option<PathBuf> {
    (arguments.len() == 3 && arguments[1] == "--analyze").then(|| PathBuf::from(&arguments[2]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NavigationTargetInput {
    target_type: String,
    target_id: String,
}

fn parse_navigation_target(input: NavigationTargetInput) -> Result<NavigationTarget, String> {
    match input.target_type.as_str() {
        "evidence" => Ok(NavigationTarget::Evidence {
            evidence_id: parse_id::<EvidenceId>(&input.target_id, "evidence identifier")?,
        }),
        "finding" => Ok(NavigationTarget::Finding {
            finding_id: parse_id::<FindingId>(&input.target_id, "finding identifier")?,
        }),
        "entity" => Ok(NavigationTarget::Entity {
            entity_id: parse_id::<EntityId>(&input.target_id, "entity identifier")?,
        }),
        "edge" => Ok(NavigationTarget::Edge {
            edge_id: parse_id::<EdgeId>(&input.target_id, "edge identifier")?,
        }),
        "event" => Ok(NavigationTarget::Event {
            event_id: parse_id::<EventId>(&input.target_id, "event identifier")?,
        }),
        _ => Err("Unsupported bookmark target".to_owned()),
    }
}

fn validate_bookmark_label(label: Option<String>) -> Result<Option<String>, String> {
    label
        .map(|value| {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                validate_text(&value, 256, "bookmark label", false).map(Some)
            }
        })
        .transpose()
        .map(Option::flatten)
}

#[tauri::command]
fn get_case_graph(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<Option<CaseGraphView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .get_case_graph(&case_id)
        .map(|graph| graph.map(Into::into))
        .map_err(|_| "Could not load case graph".to_owned())
}

#[tauri::command]
fn get_case_chronology(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<Option<CaseChronologyView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .get_case_chronology(&case_id)
        .map(|chronology| chronology.map(Into::into))
        .map_err(|_| "Could not load case chronology".to_owned())
}

#[tauri::command]
fn list_bookmarks(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<BookmarkView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .list_bookmarks(&case_id)
        .map(|bookmarks| bookmarks.into_iter().map(Into::into).collect())
        .map_err(|_| "Could not list bookmarks".to_owned())
}

#[tauri::command]
fn create_bookmark(
    case_id: String,
    target: NavigationTargetInput,
    label: Option<String>,
    state: State<'_, AppState>,
) -> Result<BookmarkView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let target = parse_navigation_target(target)?;
    let label = validate_bookmark_label(label)?;
    state
        .cases
        .create_bookmark(&case_id, target, label)
        .map(Into::into)
        .map_err(|_| "Could not create bookmark".to_owned())
}

#[tauri::command]
fn update_bookmark(
    case_id: String,
    bookmark_id: String,
    label: Option<String>,
    state: State<'_, AppState>,
) -> Result<BookmarkView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let bookmark_id = parse_id::<BookmarkId>(&bookmark_id, "bookmark identifier")?;
    let label = validate_bookmark_label(label)?;
    state
        .cases
        .update_bookmark_label(&case_id, &bookmark_id, label)
        .map(Into::into)
        .map_err(|_| "Could not update bookmark".to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteBookmarkReceipt {
    case_id: String,
    bookmark_id: String,
}

#[tauri::command]
fn delete_bookmark(
    case_id: String,
    bookmark_id: String,
    state: State<'_, AppState>,
) -> Result<DeleteBookmarkReceipt, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let bookmark_id = parse_id::<BookmarkId>(&bookmark_id, "bookmark identifier")?;
    state
        .cases
        .delete_bookmark(&case_id, &bookmark_id)
        .map_err(|_| "Could not delete bookmark".to_owned())?;
    Ok(DeleteBookmarkReceipt {
        case_id: case_id.as_str().to_owned(),
        bookmark_id: bookmark_id.as_str().to_owned(),
    })
}

#[tauri::command]
fn choose_intake_files(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<IntakeOffer>, String> {
    let selected = app
        .dialog()
        .file()
        .add_filter(
            "All supported files",
            &[
                "exe", "dll", "sys", "scr", "cpl", "zip", "evtx", "pcap", "pcapng", "jsonl", "csv",
                "log", "txt",
            ],
        )
        .add_filter("PE files", &["exe", "dll", "sys", "scr", "cpl"])
        .add_filter("Archives", &["zip"])
        .add_filter("Event logs", &["evtx"])
        .add_filter("Network captures", &["pcap", "pcapng"])
        .add_filter("Log files", &["jsonl", "csv", "log", "txt"])
        .add_filter("All files", &["*"])
        .blocking_pick_files()
        .unwrap_or_default();
    let paths = selected
        .into_iter()
        .map(|selected| match selected {
            FilePath::Path(path) => Ok(path),
            _ => Err("Artifacta only accepts local filesystem artifacts".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(mint_intake_paths(&state, paths))
}

#[tauri::command]
fn take_startup_intake(state: State<'_, AppState>) -> Vec<IntakeOffer> {
    let valid_tokens = {
        let mut grants = state
            .intake_grants
            .lock()
            .unwrap_or_else(|lock| lock.into_inner());
        grants.retain(|_, grant| grant.minted_at.elapsed() <= INTAKE_TOKEN_TTL);
        grants
            .keys()
            .cloned()
            .collect::<std::collections::HashSet<_>>()
    };
    let mut pending = state
        .pending_intake
        .lock()
        .unwrap_or_else(|lock| lock.into_inner());
    std::mem::take(&mut *pending)
        .into_iter()
        .filter(|offer| valid_tokens.contains(&offer.token))
        .collect()
}

#[tauri::command]
fn discard_intake(tokens: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    if tokens.len() > MAX_INTAKE_FILES {
        return Err("Too many intake tokens".to_owned());
    }
    let tokens = tokens.into_iter().collect::<std::collections::HashSet<_>>();
    state
        .intake_grants
        .lock()
        .map_err(|_| "Intake authorization is unavailable".to_owned())?
        .retain(|token, _| !tokens.contains(token));
    state
        .pending_intake
        .lock()
        .map_err(|_| "Pending intake is unavailable".to_owned())?
        .retain(|offer| !tokens.contains(&offer.token));
    Ok(())
}

fn detect_and_ingest(
    cases: &CaseService,
    path: &std::path::Path,
    app: &tauri::AppHandle,
    token: &str,
    name: &str,
) -> Result<CaseAnalysis, tf_case::IntakeError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() >= 2 {
        if tf_archive::is_archive(&bytes) {
            let result = cases.ingest_archive(path)?;
            let analysis = cases
                .get_case_analysis(&result.case.id)?
                .ok_or(tf_case::IntakeError::CaseNotFound)?;
            return Ok(analysis);
        }
        if tf_evtx::is_evtx_bytes(&bytes) {
            let result = cases.ingest_evtx(path)?;
            let analysis = cases
                .get_case_analysis(&result.case.id)?
                .ok_or(tf_case::IntakeError::CaseNotFound)?;
            return Ok(analysis);
        }
        if tf_pcap::is_pcap_bytes(&bytes) {
            let result = cases.ingest_pcap(path)?;
            let analysis = cases
                .get_case_analysis(&result.case.id)?
                .ok_or(tf_case::IntakeError::CaseNotFound)?;
            return Ok(analysis);
        }
    }
    if tf_store::detect_pe(path).is_ok() {
        let result = cases.ingest_pe_with_stages(path, &|stage: AnalysisStage| {
            let _ = app.emit(
                "artifacta://intake-status",
                IntakeBatchStatus {
                    token: token.to_owned(),
                    name: name.to_owned(),
                    status: "running",
                    stage: Some(stage.display_name().to_owned()),
                    error: None,
                },
            );
        })?;
        let analysis = cases
            .get_case_analysis(&result.case.id)?
            .ok_or(tf_case::IntakeError::CaseNotFound)?;
        return Ok(analysis);
    }
    let result = cases.ingest_generic(path)?;
    let analysis = cases
        .get_case_analysis(&result.case.id)?
        .ok_or(tf_case::IntakeError::CaseNotFound)?;
    Ok(analysis)
}

#[tauri::command]
async fn analyze_intake_batch(
    app: tauri::AppHandle,
    tokens: Vec<String>,
    state: State<'_, AppState>,
) -> Result<Vec<IntakeBatchResult>, String> {
    if tokens.is_empty() || tokens.len() > MAX_INTAKE_FILES {
        return Err("Intake batch must contain between 1 and 64 tokens".to_owned());
    }
    let grants = {
        let mut available = state
            .intake_grants
            .lock()
            .map_err(|_| "Intake authorization is unavailable".to_owned())?;
        available.retain(|_, grant| grant.minted_at.elapsed() <= INTAKE_TOKEN_TTL);
        tokens
            .into_iter()
            .map(|token| (token.clone(), available.remove(&token)))
            .collect::<Vec<_>>()
    };
    let cases = Arc::clone(&state.cases);
    tauri::async_runtime::spawn_blocking(move || {
        grants
            .into_iter()
            .map(|(token, grant)| {
                let Some(grant) = grant else {
                    return IntakeBatchResult {
                        token,
                        name: "Unavailable intake".to_owned(),
                        status: "failed",
                        analysis: None,
                        error: Some(
                            "Intake authorization is invalid, expired, or already used".to_owned(),
                        ),
                    };
                };
                let _ = app.emit(
                    "artifacta://intake-status",
                    IntakeBatchStatus {
                        token: token.clone(),
                        name: grant.name.clone(),
                        status: "running",
                        stage: None,
                        error: None,
                    },
                );
                let app_clone = app.clone();
                let token_clone = token.clone();
                let name_clone = grant.name.clone();
                let result =
                    detect_and_ingest(&cases, &grant.path, &app_clone, &token_clone, &name_clone);
                let result = result.and_then(|intake| {
                    cases
                        .get_case_analysis(&intake.case.id)?
                        .ok_or(tf_case::IntakeError::CaseNotFound)
                });
                match result {
                    Ok(analysis) => {
                        let complete = analysis
                            .analysis_run
                            .as_ref()
                            .is_some_and(|run| run.status == AnalysisStatus::Complete);
                        let status = if complete { "complete" } else { "failed" };
                        let error = (!complete)
                            .then(|| "Static analysis did not complete for this file".to_owned());
                        let _ = app.emit(
                            "artifacta://intake-status",
                            IntakeBatchStatus {
                                token: token.clone(),
                                name: grant.name.clone(),
                                status,
                                stage: complete.then(|| "complete".to_owned()),
                                error: error.clone(),
                            },
                        );
                        IntakeBatchResult {
                            token,
                            name: grant.name,
                            status,
                            analysis: Some(analysis.into()),
                            error,
                        }
                    }
                    Err(_error) => {
                        #[cfg(debug_assertions)]
                        eprintln!("Artifacta intake analysis failed: {_error}");
                        let error = "Could not analyze this authorized file".to_owned();
                        let _ = app.emit(
                            "artifacta://intake-status",
                            IntakeBatchStatus {
                                token: token.clone(),
                                name: grant.name.clone(),
                                status: "failed",
                                stage: None,
                                error: Some(error.clone()),
                            },
                        );
                        IntakeBatchResult {
                            token,
                            name: grant.name,
                            status: "failed",
                            analysis: None,
                            error: Some(error),
                        }
                    }
                }
            })
            .collect()
    })
    .await
    .map_err(|_| "Intake batch stopped unexpectedly".to_owned())
}

#[tauri::command]
fn list_cases(state: State<'_, AppState>) -> Result<Vec<CaseSummary>, String> {
    state
        .cases
        .list_cases()
        .map(|cases| cases.into_iter().map(Into::into).collect())
        .map_err(|_| "Could not list cases".to_owned())
}

#[tauri::command]
fn get_case_analysis(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<Option<CaseAnalysisView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .get_case_analysis(&case_id)
        .map(|analysis| analysis.map(Into::into))
        .map_err(|_| "Could not load case analysis".to_owned())
}

#[tauri::command]
fn rename_case(
    case_id: String,
    title: String,
    state: State<'_, AppState>,
) -> Result<CaseSummary, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let title = validate_text(&title, MAX_CASE_TITLE_BYTES, "case title", true)?;
    state
        .cases
        .rename_case(&case_id, &title)
        .map(Into::into)
        .map_err(|_| "Could not rename case".to_owned())
}

#[tauri::command]
fn archive_case(case_id: String, state: State<'_, AppState>) -> Result<CaseSummary, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .archive_case(&case_id)
        .map(Into::into)
        .map_err(|_| "Could not archive case".to_owned())
}

#[tauri::command]
fn unarchive_case(case_id: String, state: State<'_, AppState>) -> Result<CaseSummary, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .unarchive_case(&case_id)
        .map(Into::into)
        .map_err(|_| "Could not unarchive case".to_owned())
}

#[tauri::command]
async fn delete_case(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<DeleteCaseView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let cases = Arc::clone(&state.cases);
    let result = tauri::async_runtime::spawn_blocking(move || cases.delete_case(&case_id))
        .await
        .map_err(|_| "Case deletion stopped unexpectedly".to_owned())?
        .map_err(|_| "Could not delete case".to_owned())?;
    Ok(DeleteCaseView {
        case_id: result.case_id.as_str().to_owned(),
        objects: result.objects.into_iter().map(Into::into).collect(),
    })
}

fn transition_finding_inner(
    cases: &CaseService,
    case_id: String,
    finding_id: String,
    action: FindingAction,
) -> Result<FindingStateView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let finding_id = parse_id::<FindingId>(&finding_id, "finding identifier")?;
    cases
        .transition_finding(&case_id, &finding_id, action)
        .map(Into::into)
        .map_err(|_| "Could not update finding state".to_owned())
}

#[tauri::command]
fn transition_finding(
    case_id: String,
    finding_id: String,
    action: String,
    state: State<'_, AppState>,
) -> Result<CaseAnalysisView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let finding_id = parse_id::<FindingId>(&finding_id, "finding identifier")?;
    let action = parse_finding_action(&action)?;
    let finding = state
        .cases
        .transition_finding(&case_id, &finding_id, action)
        .map_err(|_| "Could not update finding state".to_owned())?;
    state.cases.rebuild_case_projection(&case_id).map_err(|_| {
        "Finding changed, but its case projection could not be refreshed".to_owned()
    })?;
    state
        .cases
        .get_case_analysis_run(&case_id, &finding.analysis_run_id)
        .map_err(|_| "Finding changed, but its analysis could not be reloaded".to_owned())?
        .map(Into::into)
        .ok_or_else(|| "Finding changed, but its analysis run was not found".to_owned())
}

#[tauri::command]
fn acknowledge_finding(
    case_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingStateView, String> {
    transition_finding_inner(&state.cases, case_id, finding_id, FindingAction::Review)
}

#[tauri::command]
fn accept_finding(
    case_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingStateView, String> {
    transition_finding_inner(&state.cases, case_id, finding_id, FindingAction::Accept)
}

#[tauri::command]
fn dismiss_finding(
    case_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingStateView, String> {
    transition_finding_inner(&state.cases, case_id, finding_id, FindingAction::Dismiss)
}

#[tauri::command]
fn reopen_finding(
    case_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingStateView, String> {
    transition_finding_inner(&state.cases, case_id, finding_id, FindingAction::Reopen)
}

#[tauri::command]
fn list_notes(case_id: String, state: State<'_, AppState>) -> Result<Vec<NoteView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .list_notes(&case_id)
        .map(|notes| notes.into_iter().map(Into::into).collect())
        .map_err(|_| "Could not list notes".to_owned())
}

#[tauri::command]
fn create_note(
    case_id: String,
    entity_id: Option<String>,
    finding_id: Option<String>,
    body: String,
    state: State<'_, AppState>,
) -> Result<NoteView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let entity_id = entity_id
        .as_deref()
        .map(|id| parse_id::<EntityId>(id, "entity identifier"))
        .transpose()?;
    let finding_id = finding_id
        .as_deref()
        .map(|id| parse_id::<FindingId>(id, "finding identifier"))
        .transpose()?;
    let body = validate_text(&body, MAX_NOTE_BYTES, "note body", true)?;
    state
        .cases
        .create_note(&case_id, entity_id, finding_id, body)
        .map(Into::into)
        .map_err(|_| "Could not create note".to_owned())
}

#[tauri::command]
fn update_note(
    case_id: String,
    note_id: String,
    body: String,
    state: State<'_, AppState>,
) -> Result<NoteView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let note_id = parse_id::<NoteId>(&note_id, "note identifier")?;
    let body = validate_text(&body, MAX_NOTE_BYTES, "note body", true)?;
    state
        .cases
        .update_note(&case_id, &note_id, &body)
        .map(Into::into)
        .map_err(|_| "Could not update note".to_owned())
}

#[tauri::command]
fn delete_note(
    case_id: String,
    note_id: String,
    state: State<'_, AppState>,
) -> Result<DeleteNoteReceipt, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let note_id = parse_id::<NoteId>(&note_id, "note identifier")?;
    state
        .cases
        .delete_note(&case_id, &note_id)
        .map_err(|_| "Could not delete note".to_owned())?;
    Ok(DeleteNoteReceipt {
        case_id: case_id.as_str().to_owned(),
        note_id: note_id.as_str().to_owned(),
    })
}

#[tauri::command]
async fn reanalyze_case(
    case_id: String,
    state: State<'_, AppState>,
) -> Result<CaseAnalysisView, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let cases = Arc::clone(&state.cases);
    let analysis = tauri::async_runtime::spawn_blocking(move || {
        cases.reanalyze_case(&case_id)?;
        cases
            .get_case_analysis(&case_id)?
            .ok_or(tf_case::IntakeError::CaseNotFound)
    })
    .await
    .map_err(|_| "Reanalysis stopped unexpectedly".to_owned())?
    .map_err(|_| "Could not reanalyze case".to_owned())?;
    Ok(analysis.into())
}

#[tauri::command]
fn list_analysis_runs(case_id: String, state: State<'_, AppState>) -> Result<Vec<RunView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    state
        .cases
        .get_case_analysis(&case_id)
        .map_err(|_| "Could not list analysis runs".to_owned())?
        .map(|analysis| analysis.run_history.into_iter().map(Into::into).collect())
        .ok_or_else(|| "Case not found".to_owned())
}

#[tauri::command]
fn get_case_analysis_run(
    case_id: String,
    run_id: String,
    state: State<'_, AppState>,
) -> Result<Option<CaseAnalysisView>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let run_id = parse_id::<AnalysisRunId>(&run_id, "analysis run identifier")?;
    state
        .cases
        .get_case_analysis_run(&case_id, &run_id)
        .map(|analysis| analysis.map(Into::into))
        .map_err(|_| "Could not load analysis run".to_owned())
}

#[tauri::command]
fn search_cases(
    query: String,
    fields: Vec<String>,
    include_archived: bool,
    limit: u32,
    state: State<'_, AppState>,
) -> Result<Vec<SearchHitView>, String> {
    let query = validate_text(&query, MAX_SEARCH_QUERY_BYTES, "search query", true)?;
    if !(1..=MAX_SEARCH_RESULTS).contains(&limit) {
        return Err("Search limit must be between 1 and 100".to_owned());
    }
    let request = CaseSearchRequest {
        query,
        fields: parse_search_fields(fields)?,
        include_archived,
        limit,
    };
    state
        .cases
        .search_cases(&request)
        .map(|hits| hits.into_iter().map(Into::into).collect())
        .map_err(|_| "Could not search cases".to_owned())
}

#[tauri::command]
async fn compare_cases(
    left_case_id: String,
    right_case_id: String,
    state: State<'_, AppState>,
) -> Result<ArtifactComparisonView, String> {
    let left_case_id = parse_id::<CaseId>(&left_case_id, "left case identifier")?;
    let right_case_id = parse_id::<CaseId>(&right_case_id, "right case identifier")?;
    if left_case_id == right_case_id {
        return Err("Comparison requires two different cases".to_owned());
    }
    let cases = Arc::clone(&state.cases);
    tauri::async_runtime::spawn_blocking(move || cases.compare_cases(&left_case_id, &right_case_id))
        .await
        .map_err(|_| "Comparison stopped unexpectedly".to_owned())?
        .map(Into::into)
        .map_err(|_| "Could not compare cases".to_owned())
}

#[tauri::command]
fn list_yara_packs(state: State<'_, AppState>) -> Result<Vec<YaraPackView>, String> {
    state
        .cases
        .list_yara_packs()
        .map(|packs| packs.into_iter().map(Into::into).collect())
        .map_err(|_| "Could not list YARA packs".to_owned())
}

#[tauri::command]
async fn import_yara_pack(
    app: tauri::AppHandle,
    metadata: YaraPackMetadataInput,
    state: State<'_, AppState>,
) -> Result<Option<YaraPackView>, String> {
    let metadata = validate_yara_metadata(metadata)?;
    let selected = app
        .dialog()
        .file()
        .add_filter("YARA rule pack", &["yar", "yara"])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let FilePath::Path(path) = selected else {
        return Err("Artifacta only accepts local YARA files".to_owned());
    };
    if !is_yara_path(&path) {
        return Err("YARA pack must use a .yar or .yara extension".to_owned());
    }
    let file_metadata = fs::symlink_metadata(&path)
        .map_err(|_| "Could not inspect the selected YARA pack".to_owned())?;
    if !file_metadata.is_file() || is_link_or_reparse(&file_metadata) {
        return Err("YARA packs must be regular, non-symlink files".to_owned());
    }

    let cases = Arc::clone(&state.cases);
    let pack = tauri::async_runtime::spawn_blocking(move || {
        cases.import_yara_pack(
            path,
            metadata.name,
            metadata.version,
            metadata.source,
            metadata.license,
        )
    })
    .await
    .map_err(|_| "YARA import stopped unexpectedly".to_owned())?
    .map_err(|_| "Could not import YARA pack".to_owned())?;
    Ok(Some(pack.into()))
}

#[tauri::command]
async fn import_yara_folder(
    app: tauri::AppHandle,
    metadata: YaraPackMetadataInput,
    state: State<'_, AppState>,
) -> Result<Option<Vec<YaraFolderImportResult>>, String> {
    let metadata = validate_yara_metadata(metadata)?;
    let Some(FilePath::Path(folder)) = app.dialog().file().blocking_pick_folder() else {
        return Ok(None);
    };
    let folder_metadata = fs::symlink_metadata(&folder)
        .map_err(|_| "Could not inspect the selected YARA folder".to_owned())?;
    if !folder_metadata.is_dir() || is_link_or_reparse(&folder_metadata) {
        return Err("YARA import requires a local, non-symlink folder".to_owned());
    }
    let mut entries = fs::read_dir(&folder)
        .map_err(|_| "Could not read the selected YARA folder".to_owned())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| is_yara_path(path))
        .collect::<Vec<_>>();
    entries.sort();
    if entries.len() > MAX_YARA_FOLDER_FILES {
        return Err("YARA folders are limited to 64 supported files".to_owned());
    }
    let cases = Arc::clone(&state.cases);
    let results = tauri::async_runtime::spawn_blocking(move || {
        entries
            .into_iter()
            .map(|path| {
                let file_name = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Unsupported file".to_owned());
                let safe_file = fs::symlink_metadata(&path)
                    .is_ok_and(|value| value.is_file() && !is_link_or_reparse(&value));
                if !safe_file {
                    return YaraFolderImportResult {
                        file_name,
                        status: "failed",
                        pack: None,
                        error: Some("Symlinks and non-regular files are not imported".to_owned()),
                    };
                }
                let name = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .filter(|stem| !stem.is_empty())
                    .unwrap_or(&metadata.name)
                    .to_owned();
                match cases.import_yara_pack(
                    path,
                    name,
                    metadata.version.clone(),
                    metadata.source.clone(),
                    metadata.license.clone(),
                ) {
                    Ok(pack) => YaraFolderImportResult {
                        file_name,
                        status: "complete",
                        pack: Some(pack.into()),
                        error: None,
                    },
                    Err(_) => YaraFolderImportResult {
                        file_name,
                        status: "failed",
                        pack: None,
                        error: Some("Validation or import failed for this file".to_owned()),
                    },
                }
            })
            .collect()
    })
    .await
    .map_err(|_| "YARA folder import stopped unexpectedly".to_owned())?;
    Ok(Some(results))
}

fn set_yara_pack_enabled_inner(
    cases: &CaseService,
    pack_id: String,
    enabled: bool,
) -> Result<YaraPackView, String> {
    let pack_id = parse_id::<YaraPackId>(&pack_id, "YARA pack identifier")?;
    cases
        .set_yara_pack_enabled(&pack_id, enabled)
        .map(Into::into)
        .map_err(|_| "Could not update YARA pack".to_owned())
}

#[tauri::command]
fn enable_yara_pack(pack_id: String, state: State<'_, AppState>) -> Result<YaraPackView, String> {
    set_yara_pack_enabled_inner(&state.cases, pack_id, true)
}

#[tauri::command]
fn disable_yara_pack(pack_id: String, state: State<'_, AppState>) -> Result<YaraPackView, String> {
    set_yara_pack_enabled_inner(&state.cases, pack_id, false)
}

#[tauri::command]
async fn delete_yara_pack(
    pack_id: String,
    state: State<'_, AppState>,
) -> Result<CleanupView, String> {
    let pack_id = parse_id::<YaraPackId>(&pack_id, "YARA pack identifier")?;
    let cases = Arc::clone(&state.cases);
    tauri::async_runtime::spawn_blocking(move || cases.delete_yara_pack(&pack_id))
        .await
        .map_err(|_| "YARA deletion stopped unexpectedly".to_owned())?
        .map(Into::into)
        .map_err(|_| "Could not delete YARA pack".to_owned())
}

#[tauri::command]
async fn choose_and_analyze_pe(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<CaseAnalysisView>, String> {
    let selected = app
        .dialog()
        .file()
        .add_filter("Windows executable", &["exe", "dll", "sys", "scr", "cpl"])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let FilePath::Path(path) = selected else {
        return Err("Artifacta only accepts local filesystem artifacts".to_owned());
    };

    let cases = Arc::clone(&state.cases);
    let analysis = tauri::async_runtime::spawn_blocking(move || {
        let result = cases.ingest_pe(path)?;
        cases
            .get_case_analysis(&result.case.id)?
            .ok_or(tf_case::IntakeError::CaseNotFound)
    })
    .await
    .map_err(|_| "Analysis stopped unexpectedly".to_owned())?
    .map_err(|_| "Could not analyze the selected file".to_owned())?;
    Ok(Some(analysis.into()))
}

fn report_analysis(
    cases: &CaseService,
    case_id: &CaseId,
    run_id: Option<&str>,
) -> Result<CaseAnalysis, String> {
    match run_id {
        Some(run_id) => {
            let run_id = parse_id::<AnalysisRunId>(run_id, "analysis run identifier")?;
            cases
                .get_case_analysis_run(case_id, &run_id)
                .map_err(|_| "Could not load the selected analysis run".to_owned())?
                .ok_or_else(|| "The selected analysis run was not found".to_owned())
        }
        None => cases
            .get_case_analysis(case_id)
            .map_err(|_| "Could not load case analysis".to_owned())?
            .ok_or_else(|| "Case not found".to_owned()),
    }
}

fn find_edge_executable() -> Option<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        PathBuf::from(r"C:\Program Files (Arm)\Microsoft\Edge\Application\msedge.exe"),
    ];
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        candidates
            .push(PathBuf::from(local_app_data).join(r"Microsoft\Edge\Application\msedge.exe"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn html_to_pdf(html_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let edge = find_edge_executable()
        .ok_or_else(|| "Microsoft Edge is required for PDF export but was not found".to_owned())?;
    let temp_dir =
        tempfile::tempdir().map_err(|error| format!("Could not create temp directory: {error}"))?;
    let html_path = temp_dir.path().join("report.html");
    let pdf_path = temp_dir.path().join("report.pdf");
    let profile_path = temp_dir.path().join("edge-profile");
    fs::write(&html_path, html_bytes)
        .map_err(|error| format!("Could not write temp HTML report: {error}"))?;
    let child = std::process::Command::new(edge)
        .arg("--headless=new")
        .arg("--disable-background-networking")
        .arg("--disable-component-update")
        .arg("--disable-default-apps")
        .arg("--disable-extensions")
        .arg("--disable-gpu")
        .arg("--disable-sync")
        .arg("--metrics-recording-only")
        .arg("--no-first-run")
        .arg("--run-all-compositor-stages-before-draw")
        .arg(format!("--user-data-dir={}", profile_path.display()))
        .arg(format!("--print-to-pdf={}", pdf_path.display()))
        .arg(&html_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("Could not launch Edge for PDF conversion: {error}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut child = Some(child);
    loop {
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    child.take();
                    if !status.success() {
                        return Err(format!(
                            "Edge PDF conversion failed with exit status {status}"
                        ));
                    }
                    break;
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        if let Some(mut c) = child.take() {
                            let _ = c.kill();
                            let _ = c.wait();
                        }
                        return Err("Edge PDF conversion timed out after 30 seconds".to_owned());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => {
                    if let Some(mut c) = child.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    return Err(format!("Could not check Edge process status: {error}"));
                }
            }
        }
    }
    let pdf =
        fs::read(&pdf_path).map_err(|error| format!("Could not read generated PDF: {error}"))?;
    if !pdf.starts_with(b"%PDF-") {
        return Err("Edge did not produce a valid PDF document".to_owned());
    }
    if pdf.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "Generated PDF exceeds the {MAX_REPORT_BYTES} byte report limit"
        ));
    }
    Ok(pdf)
}

fn render_report(
    analysis: &CaseAnalysis,
    format: ReportFormat,
    generated_at: &str,
    manifest_file_name: Option<&str>,
) -> Result<Vec<u8>, String> {
    let input = analysis
        .report_input_with_manifest(generated_at, manifest_file_name)
        .map_err(|_| "Could not build the selected analysis report".to_owned())?;
    let bytes = match format {
        ReportFormat::Json => render_json(&input)
            .map_err(|_| "Could not render the selected analysis report".to_owned())?,
        ReportFormat::Html => render_html(&input)
            .map_err(|_| "Could not render the selected analysis report".to_owned())?,
        ReportFormat::Csv => render_csv(&input)
            .map_err(|_| "Could not render the selected analysis report".to_owned())?,
        ReportFormat::Stix => render_stix(&input)
            .map_err(|_| "Could not render the selected analysis report".to_owned())?,
        ReportFormat::Pdf => {
            let html = render_html(&input)
                .map_err(|_| "Could not render the selected analysis report".to_owned())?;
            html_to_pdf(&html)?
        }
    };
    Ok(bytes)
}

#[tauri::command]
async fn export_case_report(
    app: tauri::AppHandle,
    case_id: String,
    run_id: Option<String>,
    format: String,
    state: State<'_, AppState>,
) -> Result<Option<ReportReceipt>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let report_format = match format.as_str() {
        "json" => ReportFormat::Json,
        "html" => ReportFormat::Html,
        "pdf" => ReportFormat::Pdf,
        "csv" => ReportFormat::Csv,
        "stix" => ReportFormat::Stix,
        _ => return Err("Unsupported report format".to_owned()),
    };
    let extension = report_format.as_str();
    let selected = app
        .dialog()
        .file()
        .add_filter(
            match report_format {
                ReportFormat::Html => "Artifacta HTML report",
                ReportFormat::Pdf => "Artifacta PDF report",
                ReportFormat::Csv => "Artifacta CSV report",
                ReportFormat::Stix => "Artifacta STIX report",
                _ => "Artifacta JSON report",
            },
            &[extension],
        )
        .set_file_name(format!("artifacta-report.{extension}"))
        .blocking_save_file();
    let Some(FilePath::Path(destination)) = selected else {
        return Ok(None);
    };
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| "Could not create report timestamp".to_owned())?;
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("report")
        .to_owned();
    let cases = Arc::clone(&state.cases);
    let report = tauri::async_runtime::spawn_blocking(move || {
        let analysis = report_analysis(&cases, &case_id, run_id.as_deref())?;
        let bytes = render_report(&analysis, report_format, &generated_at, None)?;
        let report = cases
            .export_rendered_report(&case_id, report_format, generated_at, &destination, &bytes)
            .map_err(|_| "Could not persist the selected analysis report".to_owned())?;
        Ok::<_, String>((report.format, report.sha256))
    })
    .await
    .map_err(|_| "Report export stopped unexpectedly".to_owned())?
    .map_err(|error| format!("Could not export report: {error}"))?;
    Ok(Some(ReportReceipt {
        file_name,
        format: report.0,
        sha256: report.1,
    }))
}

#[tauri::command]
async fn export_case_report_bundle(
    app: tauri::AppHandle,
    case_id: String,
    run_id: Option<String>,
    format: String,
    state: State<'_, AppState>,
) -> Result<Option<ReportBundleReceipt>, String> {
    let case_id = parse_id::<CaseId>(&case_id, "case identifier")?;
    let report_format = match format.as_str() {
        "json" => ReportFormat::Json,
        "html" => ReportFormat::Html,
        "pdf" => ReportFormat::Pdf,
        "csv" => ReportFormat::Csv,
        "stix" => ReportFormat::Stix,
        _ => return Err("Unsupported report format".to_owned()),
    };
    let extension = report_format.as_str();
    let selected = app
        .dialog()
        .file()
        .add_filter("Artifacta report bundle", &[extension])
        .set_file_name(format!("artifacta-report.{extension}"))
        .blocking_save_file();
    let Some(FilePath::Path(report_destination)) = selected else {
        return Ok(None);
    };
    let report_file_name = report_destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Report file name is invalid".to_owned())?
        .to_owned();
    let manifest_file_name = format!("{report_file_name}.manifest.json");
    let manifest_destination = report_destination.with_file_name(&manifest_file_name);
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| "Could not create report timestamp".to_owned())?;
    let receipt_report_file_name = report_file_name.clone();
    let receipt_manifest_file_name = manifest_file_name.clone();
    let cases = Arc::clone(&state.cases);
    let bundle = tauri::async_runtime::spawn_blocking(move || {
        let analysis = report_analysis(&cases, &case_id, run_id.as_deref())?;
        let report_bytes = render_report(
            &analysis,
            report_format,
            &generated_at,
            Some(&manifest_file_name),
        )?;
        cases
            .export_rendered_report_bundle(
                &analysis,
                report_format,
                generated_at,
                report_destination,
                manifest_destination,
                &report_bytes,
            )
            .map_err(|_| "Could not persist the selected report bundle".to_owned())
    })
    .await
    .map_err(|_| "Report bundle export stopped unexpectedly".to_owned())?
    .map_err(|error| format!("Could not export report bundle: {error}"))?;
    let verification_token = ulid::Ulid::new().to_string();
    let receipt = ReportBundleReceipt {
        verification_token: verification_token.clone(),
        report_file_name: receipt_report_file_name,
        manifest_file_name: receipt_manifest_file_name,
        report_sha256: bundle.report.sha256.clone(),
        manifest_sha256: bundle.manifest.manifest_sha256.clone(),
        snapshot_sha256: bundle.manifest.snapshot_sha256.clone(),
    };
    let mut bundles = state
        .report_bundles
        .lock()
        .map_err(|_| "Report verification state is unavailable".to_owned())?;
    if bundles.len() >= 64 {
        bundles.clear();
    }
    bundles.insert(verification_token, bundle);
    Ok(Some(receipt))
}

#[tauri::command]
fn verify_case_report_bundle(
    verification_token: String,
    state: State<'_, AppState>,
) -> Result<ReportBundleVerification, String> {
    let bundles = state
        .report_bundles
        .lock()
        .map_err(|_| "Report verification state is unavailable".to_owned())?;
    let bundle = bundles
        .get(&verification_token)
        .ok_or_else(|| "Report bundle verification token is invalid".to_owned())?;
    Ok(state.cases.verify_report_bundle(bundle))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run(startup_path: Option<PathBuf>) {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, arguments, _| {
            if let Some(path) = forwarded_analyze_path(&arguments) {
                let offers = queue_intake_paths(&app.state::<AppState>(), vec![path]);
                if !offers.is_empty() {
                    let _ = app.emit("artifacta://intake-ready", ());
                }
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let data_root = app.path().app_local_data_dir()?;
            let state = AppState {
                cases: Arc::new(CaseService::open(data_root)?),
                intake_grants: Mutex::new(HashMap::new()),
                pending_intake: Mutex::new(Vec::new()),
                report_bundles: Mutex::new(HashMap::new()),
            };
            queue_intake_paths(&state, startup_path.into_iter().collect());
            app.manage(state);
            if let Some(window) = app.get_webview_window("main") {
                let event_window = window.clone();
                window.on_window_event(move |event| match event {
                    WindowEvent::DragDrop(DragDropEvent::Enter { .. }) => {
                        let _ = event_window.emit("artifacta://drag-state", true);
                    }
                    WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) => {
                        let offers =
                            queue_intake_paths(&event_window.state::<AppState>(), paths.clone());
                        let _ = event_window.emit("artifacta://drag-state", false);
                        if !offers.is_empty() {
                            let _ = event_window.emit("artifacta://intake-ready", ());
                        }
                    }
                    WindowEvent::DragDrop(DragDropEvent::Leave) => {
                        let _ = event_window.emit("artifacta://drag-state", false);
                    }
                    _ => {}
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            acknowledge_finding,
            accept_finding,
            analyze_intake_batch,
            app_status,
            archive_case,
            choose_and_analyze_pe,
            choose_intake_files,
            compare_cases,
            create_bookmark,
            create_note,
            delete_bookmark,
            delete_case,
            delete_note,
            delete_yara_pack,
            discard_intake,
            disable_yara_pack,
            dismiss_finding,
            enable_yara_pack,
            export_case_report,
            export_case_report_bundle,
            get_case_analysis,
            get_case_analysis_run,
            get_case_chronology,
            get_case_graph,
            import_yara_folder,
            import_yara_pack,
            list_analysis_runs,
            list_bookmarks,
            list_cases,
            list_notes,
            list_yara_packs,
            reanalyze_case,
            rename_case,
            reopen_finding,
            search_cases,
            take_startup_intake,
            transition_finding,
            unarchive_case,
            update_bookmark,
            update_note,
            verify_case_report_bundle
        ])
        .run(tauri::generate_context!())
        .expect("Artifacta desktop host failed");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::{
        AppState, IntakeOffer, MAX_OUTSTANDING_INTAKE_GRANTS, NavigationTargetInput,
        NavigationTargetView, ProvenanceView, YaraPackMetadataInput, app_status,
        find_edge_executable, forwarded_analyze_path, html_to_pdf, is_yara_path,
        parse_finding_action, parse_navigation_target, parse_search_fields, queue_intake_paths,
        validate_text, validate_yara_metadata,
    };

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("artifacta-desktop-{label}-{}", ulid::Ulid::new()))
    }

    #[test]
    fn edge_pdf_conversion_produces_pdf_bytes_when_edge_is_available() {
        if find_edge_executable().is_none() {
            return;
        }
        let pdf = html_to_pdf(
            b"<!doctype html><html><head><meta charset=\"utf-8\"></head><body>Artifacta PDF smoke test</body></html>",
        )
        .expect("PDF conversion");
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(pdf.windows(5).any(|window| window == b"%%EOF"));
    }

    #[test]
    fn provenance_dto_is_camel_case_and_has_no_parameters() {
        let value = serde_json::to_value(ProvenanceView {
            id: "provenance".to_owned(),
            analysis_run_id: "run".to_owned(),
            analyzer: "pe".to_owned(),
            analyzer_version: "1".to_owned(),
            rule_id: None,
            rule_version: None,
            rule_pack_sha256: None,
            input_sha256: "hash".to_owned(),
        })
        .expect("serialize provenance view");
        assert_eq!(value["analysisRunId"], json!("run"));
        assert_eq!(value["inputSha256"], json!("hash"));
        assert!(value.get("parameters").is_none());
        assert!(value.get("analysis_run_id").is_none());
    }

    #[test]
    fn typed_string_helpers_reject_unknown_values() {
        assert!(matches!(
            parse_finding_action("review"),
            Ok(tf_model::FindingAction::Review)
        ));
        assert!(parse_finding_action("close").is_err());
        assert!(parse_search_fields(vec!["sha256".to_owned()]).is_ok());
        assert!(parse_search_fields(vec!["path".to_owned()]).is_err());
    }

    #[test]
    fn bounded_text_and_yara_metadata_are_validated() {
        assert_eq!(
            validate_text("  note  ", 8, "note", true).expect("valid note"),
            "note"
        );
        assert!(validate_text("", 8, "note", true).is_err());
        assert!(validate_text("bad\rtext", 32, "note", true).is_err());
        assert!(
            validate_yara_metadata(YaraPackMetadataInput {
                name: "pack".to_owned(),
                version: "1".to_owned(),
                source: "internal".to_owned(),
                license: "Apache-2.0".to_owned(),
            })
            .is_ok()
        );
    }

    #[test]
    fn yara_picker_extension_is_rechecked() {
        assert!(is_yara_path(Path::new("pack.yar")));
        assert!(is_yara_path(Path::new("pack.YARA")));
        assert!(!is_yara_path(Path::new("pack.txt")));
    }

    #[test]
    fn forwarded_startup_analysis_requires_exact_arguments() {
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\samples\item.exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(r"C:\samples\item.exe"))
        );
        assert!(forwarded_analyze_path(&["artifacta.exe".to_owned()]).is_none());
        assert!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                "item.exe".to_owned(),
                "extra".to_owned(),
            ])
            .is_none()
        );
    }

    #[test]
    fn forwarded_startup_analysis_handles_unicode_and_special_characters() {
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\Users\Test\path with spaces\file.exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(
                r"C:\Users\Test\path with spaces\file.exe"
            ))
        );
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\Samples\тест\файл.exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(r"C:\Samples\тест\файл.exe"))
        );
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\Samples\日本語\ファイル.exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(r"C:\Samples\日本語\ファイル.exe"))
        );
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\path (1)\file (copy).exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(r"C:\path (1)\file (copy).exe"))
        );
        assert_eq!(
            forwarded_analyze_path(&[
                "artifacta.exe".to_owned(),
                "--analyze".to_owned(),
                r"C:\path&special!file.exe".to_owned(),
            ]),
            Some(std::path::PathBuf::from(r"C:\path&special!file.exe"))
        );
    }

    #[test]
    fn intake_and_navigation_dtos_are_path_free_and_exact() {
        let offer = serde_json::to_value(IntakeOffer {
            token: "opaque".to_owned(),
            name: "item.exe".to_owned(),
        })
        .expect("serialize intake offer");
        assert_eq!(offer, json!({ "token": "opaque", "name": "item.exe" }));
        assert!(offer.get("path").is_none());

        let evidence_id = tf_model::EvidenceId::new();
        let target = parse_navigation_target(NavigationTargetInput {
            target_type: "evidence".to_owned(),
            target_id: evidence_id.as_str().to_owned(),
        })
        .expect("valid evidence target");
        let encoded = serde_json::to_value(NavigationTargetView::from(target))
            .expect("serialize navigation target");
        assert_eq!(encoded["type"], "evidence");
        assert_eq!(encoded["evidenceId"], evidence_id.as_str());
        assert!(encoded.get("evidence_id").is_none());
    }

    #[test]
    fn intake_grants_are_globally_capped_and_host_queued() {
        let root = temporary_root("intake-cap");
        fs::create_dir_all(&root).expect("create test root");
        let artifact = root.join("sample.exe");
        fs::write(&artifact, b"not executed").expect("create test artifact");
        let state = AppState {
            cases: Arc::new(tf_case::CaseService::open(root.join("data")).expect("open cases")),
            intake_grants: Mutex::new(HashMap::new()),
            pending_intake: Mutex::new(Vec::new()),
            report_bundles: Mutex::new(HashMap::new()),
        };
        let offers = queue_intake_paths(
            &state,
            std::iter::repeat_n(artifact, MAX_OUTSTANDING_INTAKE_GRANTS + 8).collect(),
        );
        assert_eq!(offers.len(), MAX_OUTSTANDING_INTAKE_GRANTS);
        assert_eq!(
            state.intake_grants.lock().expect("grants").len(),
            MAX_OUTSTANDING_INTAKE_GRANTS
        );
        assert_eq!(
            state.pending_intake.lock().expect("pending").as_slice(),
            offers.as_slice()
        );
        drop(state);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn status_describes_worker_appcontainer_network_enforcement() {
        let status = serde_json::to_value(app_status()).expect("serialize app status");
        assert_eq!(
            status["networkPolicy"],
            "PE/YARA workers use zero-capability AppContainer network denial"
        );
        assert!(status.get("networkDuringAnalysis").is_none());
    }
}
