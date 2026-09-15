#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tf_model::{
    AnalysisRun, AnalystNote, Artifact, Bookmark, Case, CaseChronology, CaseGraph, Evidence,
    Finding, FindingEvidence, FindingExplanation, FindingExplanationAttackMapping,
    ManifestVerificationStatus, Provenance, QuickCheck, RuleRecord, YaraPack,
};
use thiserror::Error;

pub const REPORT_SCHEMA_VERSION: u32 = 4;
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const ATTACK_CONTEXT_CAVEAT: &str = "MITRE ATT&CK mappings describe static capability or contextual relevance only; they do not establish observed execution or attribution.";
pub const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EVIDENCE_ITEMS: usize = 25_000;
pub const MAX_FINDINGS: usize = 5_000;
pub const MAX_RULES: usize = 5_000;
pub const MAX_EVIDENCE_LINKS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Html,
    Pdf,
    Csv,
    Stix,
}

impl ReportFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Csv => "csv",
            Self::Stix => "stix",
        }
    }
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("report input is inconsistent: {0}")]
    InvalidInput(&'static str),
    #[error("report input exceeds the {name} limit of {limit}")]
    ItemLimit { name: &'static str, limit: usize },
    #[error("rendered report exceeds the {max_bytes} byte limit")]
    TooLarge { max_bytes: usize },
    #[error("report JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Validated report data which excludes acquisition paths, store paths, and analyzer parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReportInput {
    report_schema_version: u32,
    generated_at: String,
    case: ReportCase,
    artifact: ReportArtifact,
    analysis_run: Option<ReportAnalysisRun>,
    run_history: Vec<ReportAnalysisRun>,
    provenance: Vec<ReportProvenance>,
    rules: Vec<ReportRule>,
    findings: Vec<ReportFinding>,
    attack_mapping_caveat: String,
    evidence_by_kind: Vec<EvidenceGroup>,
    quick_check: Option<QuickCheck>,
    relationships: Vec<ReportRelationship>,
    chronology: Vec<ReportChronologyEvent>,
    chronology_reliability: BTreeMap<String, u32>,
    notes: Vec<ReportNote>,
    bookmarks: Vec<ReportBookmark>,
    yara_packs: Vec<ReportYaraPack>,
    provenance_summary: ReportProvenanceSummary,
    methodology: Vec<String>,
    limitations: Vec<String>,
    integrity: ReportIntegrityReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportCase {
    id: String,
    title: String,
    created_at: String,
    updated_at: String,
    app_version: String,
    schema_version: u32,
    status: String,
    app_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportArtifact {
    id: String,
    parent_artifact_id: Option<String>,
    original_name: String,
    kind: String,
    mime: Option<String>,
    size_bytes: u64,
    sha256: String,
    sha1: String,
    md5: String,
    created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportAnalysisRun {
    id: String,
    analyzer: String,
    analyzer_version: String,
    started_at: String,
    finished_at: Option<String>,
    status: String,
    error_code: Option<String>,
    analyzer_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportProvenance {
    id: String,
    analyzer: String,
    analyzer_version: String,
    rule_id: Option<String>,
    rule_version: Option<String>,
    rule_pack_sha256: Option<String>,
    input_sha256: String,
    parameters_redacted: bool,
    analyzer_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportRule {
    id: String,
    engine: String,
    rule_id: String,
    version: String,
    source: String,
    license: String,
    sha256: String,
    enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
struct ReportFinding {
    id: String,
    rule_id: String,
    rule_version: String,
    title: String,
    category: String,
    severity: String,
    confidence: f32,
    confidence_band: String,
    state: String,
    explanation_template_id: String,
    explanation: ReportExplanation,
    linked_evidence: Vec<ReportEvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportExplanation {
    observation: String,
    why_it_matters: String,
    limitations: String,
    attack_mappings: Vec<ReportAttackMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
struct ReportAttackMapping {
    technique_id: String,
    technique_name: String,
    tactic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportEvidenceReference {
    evidence_id: String,
    role: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
struct EvidenceGroup {
    kind: String,
    evidence: Vec<ReportEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
struct ReportEvidence {
    id: String,
    class: String,
    locator: BTreeMap<String, Value>,
    value: Value,
    preview_text: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReportSupplement<'a> {
    pub graph: Option<&'a CaseGraph>,
    pub chronology: Option<&'a CaseChronology>,
    pub notes: &'a [AnalystNote],
    pub bookmarks: &'a [Bookmark],
    pub quick_check: Option<&'a QuickCheck>,
    pub yara_packs: &'a [YaraPack],
    pub run_history: &'a [AnalysisRun],
    /// A file name only. Absolute and parent-relative references are rejected.
    pub manifest_file_name: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
struct ReportRelationship {
    edge_id: String,
    source_entity_id: String,
    source: String,
    relationship: String,
    target_entity_id: String,
    target: String,
    evidence_id: String,
    confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportChronologyEvent {
    id: String,
    timestamp_utc: String,
    timestamp_type: String,
    reliability: String,
    event_type: String,
    artifact_id: Option<String>,
    evidence_id: Option<String>,
    summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportNote {
    id: String,
    entity_id: Option<String>,
    finding_id: Option<String>,
    body: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportBookmark {
    id: String,
    target_type: String,
    target_id: String,
    label: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportYaraPack {
    id: String,
    sha256: String,
    name: String,
    version: String,
    source: String,
    license: String,
    enabled: bool,
    rule_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportProvenanceSummary {
    analyzer_count: u32,
    provenance_record_count: u32,
    rule_count: u32,
    yara_pack_count: u32,
    evidence_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct ReportIntegrityReference {
    hash_algorithm: String,
    snapshot_sha256: String,
    manifest_schema_version: u32,
    external_manifest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ManifestFile {
    pub name: String,
    pub format: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ManifestRecordDigest {
    pub record_type: String,
    pub record_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVerification {
    Verified,
    Mismatch,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityManifest {
    pub manifest_schema_version: u32,
    pub hash_algorithm: String,
    pub snapshot_sha256: String,
    pub report: ManifestFile,
    pub records: Vec<ManifestRecordDigest>,
    pub artifact_verification: ArtifactVerification,
    pub limitation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ManifestVerification {
    pub status: ManifestVerificationStatus,
    pub detail: String,
    pub snapshot_sha256: Option<String>,
}

impl ReportInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generated_at: impl Into<String>,
        case: &Case,
        artifact: &Artifact,
        analysis_run: Option<&AnalysisRun>,
        provenance: &[Provenance],
        evidence: &[Evidence],
        rules: &[RuleRecord],
        findings: &[Finding],
        finding_evidence: &[FindingEvidence],
        explanations: &[FindingExplanation],
        attack_mappings: &[FindingExplanationAttackMapping],
    ) -> Result<Self, ReportError> {
        Self::new_expanded(
            generated_at,
            case,
            artifact,
            analysis_run,
            provenance,
            evidence,
            rules,
            findings,
            finding_evidence,
            explanations,
            attack_mappings,
            ReportSupplement::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_expanded(
        generated_at: impl Into<String>,
        case: &Case,
        artifact: &Artifact,
        analysis_run: Option<&AnalysisRun>,
        provenance: &[Provenance],
        evidence: &[Evidence],
        rules: &[RuleRecord],
        findings: &[Finding],
        finding_evidence: &[FindingEvidence],
        explanations: &[FindingExplanation],
        attack_mappings: &[FindingExplanationAttackMapping],
        supplement: ReportSupplement<'_>,
    ) -> Result<Self, ReportError> {
        enforce_limit("evidence items", evidence.len(), MAX_EVIDENCE_ITEMS)?;
        enforce_limit("rules", rules.len(), MAX_RULES)?;
        enforce_limit("findings", findings.len(), MAX_FINDINGS)?;
        enforce_limit(
            "finding evidence links",
            finding_evidence.len(),
            MAX_EVIDENCE_LINKS,
        )?;

        let generated_at = generated_at.into();
        if generated_at.is_empty() || generated_at.len() > 128 {
            return Err(ReportError::InvalidInput("generated_at is invalid"));
        }
        if artifact.case_id != case.id {
            return Err(ReportError::InvalidInput(
                "artifact does not belong to the case",
            ));
        }
        if analysis_run.is_some_and(|run| run.artifact_id != artifact.id) {
            return Err(ReportError::InvalidInput(
                "analysis run does not belong to the artifact",
            ));
        }
        if supplement
            .graph
            .is_some_and(|graph| graph.case_id != case.id)
            || supplement
                .chronology
                .is_some_and(|chronology| chronology.case_id != case.id)
            || supplement.notes.iter().any(|note| note.case_id != case.id)
            || supplement
                .bookmarks
                .iter()
                .any(|bookmark| bookmark.case_id != case.id)
        {
            return Err(ReportError::InvalidInput(
                "report supplement does not belong to the case",
            ));
        }
        if supplement.manifest_file_name.is_some_and(|name| {
            name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
                || name.chars().any(char::is_control)
        }) {
            return Err(ReportError::InvalidInput(
                "manifest reference must be a safe file name",
            ));
        }
        let provenance_ids = provenance
            .iter()
            .map(|record| &record.id)
            .collect::<BTreeSet<_>>();
        if provenance_ids.len() != provenance.len()
            || provenance.iter().any(|record| {
                analysis_run.is_none_or(|run| record.analysis_run_id != run.id)
                    || !record.input_sha256.eq_ignore_ascii_case(&artifact.sha256)
            })
            || analysis_run.is_some_and(|run| {
                !provenance.iter().any(|record| {
                    record.analyzer == run.analyzer
                        && record.analyzer_version == run.analyzer_version
                })
            })
        {
            return Err(ReportError::InvalidInput(
                "provenance does not belong to the analysis run and artifact",
            ));
        }
        if evidence.iter().any(|item| {
            item.artifact_id != artifact.id || !provenance_ids.contains(&item.provenance_id)
        }) {
            return Err(ReportError::InvalidInput(
                "evidence does not belong to the artifact and provenance",
            ));
        }

        let evidence_ids = evidence
            .iter()
            .map(|item| &item.id)
            .collect::<BTreeSet<_>>();
        if evidence_ids.len() != evidence.len() {
            return Err(ReportError::InvalidInput("evidence IDs are not unique"));
        }
        let finding_ids = findings
            .iter()
            .map(|finding| &finding.id)
            .collect::<BTreeSet<_>>();
        if finding_ids.len() != findings.len() {
            return Err(ReportError::InvalidInput("finding IDs are not unique"));
        }
        let rule_keys = rules
            .iter()
            .map(|rule| (&rule.rule_id, &rule.version))
            .collect::<BTreeSet<_>>();
        if rule_keys.len() != rules.len() {
            return Err(ReportError::InvalidInput("rule identities are not unique"));
        }

        let mut links_by_finding = BTreeMap::new();
        for link in finding_evidence {
            if !finding_ids.contains(&link.finding_id) || !evidence_ids.contains(&link.evidence_id)
            {
                return Err(ReportError::InvalidInput(
                    "finding link refers to missing evidence or finding",
                ));
            }
            let links = links_by_finding
                .entry(link.finding_id.clone())
                .or_insert_with(Vec::new);
            if links
                .iter()
                .any(|existing: &FindingEvidence| existing.evidence_id == link.evidence_id)
            {
                return Err(ReportError::InvalidInput("finding links are not unique"));
            }
            links.push(link.clone());
        }
        for links in links_by_finding.values_mut() {
            links.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        }

        let explanation_by_finding = explanations
            .iter()
            .map(|explanation| (&explanation.finding_id, explanation))
            .collect::<BTreeMap<_, _>>();
        if explanation_by_finding.len() != explanations.len()
            || explanation_by_finding.len() != findings.len()
        {
            return Err(ReportError::InvalidInput(
                "each finding must have exactly one explanation",
            ));
        }
        let mut attack_by_finding = BTreeMap::<_, Vec<ReportAttackMapping>>::new();
        for record in attack_mappings {
            if !finding_ids.contains(&record.finding_id) {
                return Err(ReportError::InvalidInput(
                    "ATT&CK mapping refers to a missing finding explanation",
                ));
            }
            attack_by_finding
                .entry(record.finding_id.clone())
                .or_default()
                .push(ReportAttackMapping {
                    technique_id: record.mapping.technique_id.clone(),
                    technique_name: record.mapping.technique_name.clone(),
                    tactic: record.mapping.tactic.clone(),
                });
        }
        for mappings in attack_by_finding.values_mut() {
            mappings.sort();
            if mappings.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(ReportError::InvalidInput("ATT&CK mappings are not unique"));
            }
        }

        let run = analysis_run;
        let mut report_findings = Vec::with_capacity(findings.len());
        for finding in findings {
            if run.is_none_or(|record| finding.analysis_run_id != record.id)
                || finding.artifact_id != artifact.id
                || !rule_keys.contains(&(&finding.rule_id, &finding.rule_version))
            {
                return Err(ReportError::InvalidInput(
                    "finding does not match its run, artifact, or rule",
                ));
            }
            let explanation = explanation_by_finding
                .get(&finding.id)
                .ok_or(ReportError::InvalidInput("finding explanation is missing"))?;
            let links = links_by_finding
                .get(&finding.id)
                .ok_or(ReportError::InvalidInput("finding has no linked evidence"))?;
            let mut explanation_links = explanation.supporting_evidence.clone();
            explanation_links.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
            if explanation.template_id != finding.explanation_template_id
                || explanation_links != *links
            {
                return Err(ReportError::InvalidInput(
                    "finding explanation and exact evidence links disagree",
                ));
            }
            report_findings.push(ReportFinding {
                id: finding.id.as_str().to_owned(),
                rule_id: finding.rule_id.clone(),
                rule_version: finding.rule_version.clone(),
                title: finding.title.clone(),
                category: finding.category.clone(),
                severity: finding.severity.as_str().to_owned(),
                confidence: finding.confidence.value(),
                confidence_band: finding.confidence_band.as_str().to_owned(),
                state: finding.state.as_str().to_owned(),
                explanation_template_id: finding.explanation_template_id.clone(),
                explanation: ReportExplanation {
                    observation: explanation.observation.clone(),
                    why_it_matters: explanation.why_it_matters.clone(),
                    limitations: explanation.limitations.clone(),
                    attack_mappings: attack_by_finding.remove(&finding.id).unwrap_or_default(),
                },
                linked_evidence: links
                    .iter()
                    .map(|link| ReportEvidenceReference {
                        evidence_id: link.evidence_id.as_str().to_owned(),
                        role: link.role.as_str().to_owned(),
                    })
                    .collect(),
            });
        }
        report_findings.sort_by(|left, right| {
            (&left.rule_id, &left.rule_version, &left.id).cmp(&(
                &right.rule_id,
                &right.rule_version,
                &right.id,
            ))
        });

        let mut evidence_groups = BTreeMap::<String, Vec<ReportEvidence>>::new();
        for item in evidence {
            evidence_groups
                .entry(item.kind.clone())
                .or_default()
                .push(ReportEvidence {
                    id: item.id.as_str().to_owned(),
                    class: item.class.as_str().to_owned(),
                    locator: normalize_map(&item.locator),
                    value: normalize_value(&item.value),
                    preview_text: item.preview_text.clone(),
                });
        }
        let evidence_by_kind = evidence_groups
            .into_iter()
            .map(|(kind, mut evidence)| {
                evidence.sort_by(|left, right| left.id.cmp(&right.id));
                EvidenceGroup { kind, evidence }
            })
            .collect();

        let mut report_rules = rules
            .iter()
            .map(|rule| ReportRule {
                id: rule.id.as_str().to_owned(),
                engine: rule.engine.clone(),
                rule_id: rule.rule_id.clone(),
                version: rule.version.clone(),
                source: rule.source.clone(),
                license: rule.license.clone(),
                sha256: rule.sha256.clone(),
                enabled: rule.enabled,
            })
            .collect::<Vec<_>>();
        report_rules.sort_by(|left, right| {
            (&left.engine, &left.rule_id, &left.version, &left.id).cmp(&(
                &right.engine,
                &right.rule_id,
                &right.version,
                &right.id,
            ))
        });

        let mut report_provenance = provenance
            .iter()
            .map(|record| ReportProvenance {
                id: record.id.as_str().to_owned(),
                analyzer: record.analyzer.clone(),
                analyzer_version: record.analyzer_version.clone(),
                rule_id: record.rule_id.clone(),
                rule_version: record.rule_version.clone(),
                rule_pack_sha256: record.rule_pack_sha256.clone(),
                input_sha256: record.input_sha256.clone(),
                parameters_redacted: true,
                analyzer_identity_sha256: identity_hash(&record.analyzer, &record.analyzer_version),
            })
            .collect::<Vec<_>>();
        report_provenance.sort_by(|left, right| {
            (
                &left.analyzer,
                &left.analyzer_version,
                &left.rule_pack_sha256,
                &left.id,
            )
                .cmp(&(
                    &right.analyzer,
                    &right.analyzer_version,
                    &right.rule_pack_sha256,
                    &right.id,
                ))
        });

        let relationships = report_relationships(supplement.graph);
        let chronology = report_chronology(supplement.chronology);
        let chronology_reliability =
            chronology
                .iter()
                .fold(BTreeMap::<String, u32>::new(), |mut counts, event| {
                    let count = counts.entry(event.reliability.clone()).or_default();
                    *count = count.saturating_add(1);
                    counts
                });
        let mut notes = supplement
            .notes
            .iter()
            .map(|note| ReportNote {
                id: note.id.as_str().to_owned(),
                entity_id: note.entity_id.as_ref().map(|id| id.as_str().to_owned()),
                finding_id: note.finding_id.as_ref().map(|id| id.as_str().to_owned()),
                body: note.body.clone(),
                created_at: note.created_at.clone(),
                updated_at: note.updated_at.clone(),
            })
            .collect::<Vec<_>>();
        notes.sort_by(|left, right| {
            (&left.created_at, &left.id).cmp(&(&right.created_at, &right.id))
        });
        let mut bookmarks = supplement
            .bookmarks
            .iter()
            .map(|bookmark| ReportBookmark {
                id: bookmark.id.as_str().to_owned(),
                target_type: bookmark.target.target_type().to_owned(),
                target_id: bookmark.target.target_id().to_owned(),
                label: bookmark.label.clone(),
                created_at: bookmark.created_at.clone(),
                updated_at: bookmark.updated_at.clone(),
            })
            .collect::<Vec<_>>();
        bookmarks.sort_by(|left, right| {
            (&left.target_type, &left.target_id, &left.id).cmp(&(
                &right.target_type,
                &right.target_id,
                &right.id,
            ))
        });
        let mut yara_packs = supplement
            .yara_packs
            .iter()
            .map(|pack| ReportYaraPack {
                id: pack.id.as_str().to_owned(),
                sha256: pack.sha256.clone(),
                name: pack.name.clone(),
                version: pack.version.clone(),
                source: pack.source.clone(),
                license: pack.license.clone(),
                enabled: pack.enabled,
                rule_count: pack.rule_count,
            })
            .collect::<Vec<_>>();
        yara_packs.sort_by(|left, right| {
            (&left.name, &left.version, &left.sha256, &left.id).cmp(&(
                &right.name,
                &right.version,
                &right.sha256,
                &right.id,
            ))
        });
        let analyzer_count = provenance
            .iter()
            .map(|record| (&record.analyzer, &record.analyzer_version))
            .collect::<BTreeSet<_>>()
            .len();
        let mut run_history = supplement
            .run_history
            .iter()
            .map(report_analysis_run)
            .collect::<Vec<_>>();
        run_history.sort_by(|left, right| {
            (&left.started_at, &left.id).cmp(&(&right.started_at, &right.id))
        });
        let mut report = Self {
            report_schema_version: REPORT_SCHEMA_VERSION,
            generated_at,
            case: ReportCase {
                id: case.id.as_str().to_owned(),
                title: case.title.clone(),
                created_at: case.created_at.clone(),
                updated_at: case.updated_at.clone(),
                app_version: case.app_version.clone(),
                schema_version: case.schema_version,
                status: case.status.as_str().to_owned(),
                app_identity_sha256: identity_hash("artifacta", &case.app_version),
            },
            artifact: ReportArtifact {
                id: artifact.id.as_str().to_owned(),
                parent_artifact_id: artifact
                    .parent_artifact_id
                    .as_ref()
                    .map(|id| id.as_str().to_owned()),
                original_name: artifact.original_name.clone(),
                kind: artifact.kind.as_str().to_owned(),
                mime: artifact.mime.clone(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256.clone(),
                sha1: artifact.sha1.clone(),
                md5: artifact.md5.clone(),
                created_at: artifact.created_at.clone(),
            },
            analysis_run: analysis_run.map(|record| ReportAnalysisRun {
                id: record.id.as_str().to_owned(),
                analyzer: record.analyzer.clone(),
                analyzer_version: record.analyzer_version.clone(),
                started_at: record.started_at.clone(),
                finished_at: record.finished_at.clone(),
                status: record.status.as_str().to_owned(),
                error_code: record.error_code.clone(),
                analyzer_identity_sha256: identity_hash(
                    &record.analyzer,
                    &record.analyzer_version,
                ),
            }),
            run_history,
            provenance: report_provenance,
            rules: report_rules,
            findings: report_findings,
            attack_mapping_caveat: ATTACK_CONTEXT_CAVEAT.to_owned(),
            evidence_by_kind,
            quick_check: supplement.quick_check.cloned(),
            relationships,
            chronology,
            chronology_reliability,
            notes,
            bookmarks,
            yara_packs,
            provenance_summary: ReportProvenanceSummary {
                analyzer_count: saturating_u32(analyzer_count),
                provenance_record_count: saturating_u32(provenance.len()),
                rule_count: saturating_u32(rules.len()),
                yara_pack_count: saturating_u32(supplement.yara_packs.len()),
                evidence_count: saturating_u32(evidence.len()),
            },
            methodology: vec![
                "Static, local analysis of the stored artifact; no execution is represented.".to_owned(),
                "Findings are deterministic rule evaluations linked to exact evidence records.".to_owned(),
                "Relationships and chronology are deterministic projections of persisted evidence.".to_owned(),
                "SHA-256 provides change detection, not authorship, authenticity, or trust.".to_owned(),
            ],
            limitations: vec![
                "Static observations do not establish runtime behavior, intent, attribution, or safety.".to_owned(),
                "Parser, extraction, rule, YARA, and local trust-store coverage may be incomplete.".to_owned(),
                "Timestamps vary in reliability; attacker-controlled and filesystem metadata require corroboration.".to_owned(),
                "Manifest verification is an integrity check only and makes no safety claim.".to_owned(),
            ],
            integrity: ReportIntegrityReference {
                hash_algorithm: "sha256".to_owned(),
                snapshot_sha256: String::new(),
                manifest_schema_version: MANIFEST_SCHEMA_VERSION,
                external_manifest: supplement.manifest_file_name.map(str::to_owned),
            },
        };
        report.integrity.snapshot_sha256 = report.compute_snapshot_sha256()?;
        Ok(report)
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.integrity.snapshot_sha256
    }

    fn compute_snapshot_sha256(&self) -> Result<String, ReportError> {
        // This is the canonical snapshot contract: compact typed JSON with only
        // generation metadata and the self-referential integrity block removed.
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or(ReportError::InvalidInput(
            "report snapshot is not an object",
        ))?;
        object.remove("generated_at");
        object.remove("integrity");
        Ok(sha256_hex(&serde_json::to_vec(&value)?))
    }
}

pub fn render_json(input: &ReportInput) -> Result<Vec<u8>, ReportError> {
    let mut output = serde_json::to_vec_pretty(input)?;
    output.push(b'\n');
    enforce_output_limit(output.len())?;
    Ok(output)
}

pub fn render_csv(input: &ReportInput) -> Result<Vec<u8>, ReportError> {
    let mut output = String::with_capacity(32 * 1024);
    output.push_str("section,field,value\n");
    csv_row(&mut output, "case", "id", &input.case.id);
    csv_row(&mut output, "case", "title", &input.case.title);
    csv_row(&mut output, "case", "status", &input.case.status);
    csv_row(&mut output, "case", "created_at", &input.case.created_at);
    csv_row(&mut output, "case", "updated_at", &input.case.updated_at);
    csv_row(&mut output, "case", "app_version", &input.case.app_version);
    csv_row(
        &mut output,
        "case",
        "schema_version",
        &input.case.schema_version.to_string(),
    );
    csv_row(&mut output, "artifact", "id", &input.artifact.id);
    if let Some(parent) = &input.artifact.parent_artifact_id {
        csv_row(&mut output, "artifact", "parent_artifact_id", parent);
    }
    csv_row(
        &mut output,
        "artifact",
        "original_name",
        &input.artifact.original_name,
    );
    csv_row(&mut output, "artifact", "kind", &input.artifact.kind);
    csv_row(
        &mut output,
        "artifact",
        "size_bytes",
        &input.artifact.size_bytes.to_string(),
    );
    csv_row(&mut output, "artifact", "sha256", &input.artifact.sha256);
    csv_row(&mut output, "artifact", "sha1", &input.artifact.sha1);
    csv_row(&mut output, "artifact", "md5", &input.artifact.md5);
    csv_row(
        &mut output,
        "artifact",
        "created_at",
        &input.artifact.created_at,
    );
    if let Some(run) = &input.analysis_run {
        csv_row(&mut output, "analysis_run", "id", &run.id);
        csv_row(&mut output, "analysis_run", "analyzer", &run.analyzer);
        csv_row(
            &mut output,
            "analysis_run",
            "analyzer_version",
            &run.analyzer_version,
        );
        csv_row(&mut output, "analysis_run", "started_at", &run.started_at);
        if let Some(finished) = &run.finished_at {
            csv_row(&mut output, "analysis_run", "finished_at", finished);
        }
        csv_row(&mut output, "analysis_run", "status", &run.status);
        if let Some(error) = &run.error_code {
            csv_row(&mut output, "analysis_run", "error_code", error);
        }
    }
    if let Some(qc) = &input.quick_check {
        csv_row(
            &mut output,
            "quick_check",
            "suspicion_band",
            qc.band.as_str(),
        );
        csv_row(&mut output, "quick_check", "statement", &qc.statement);
    }
    for finding in &input.findings {
        let prefix = format!("finding:{}", finding.id);
        csv_row(&mut output, &prefix, "rule_id", &finding.rule_id);
        csv_row(&mut output, &prefix, "title", &finding.title);
        csv_row(&mut output, &prefix, "category", &finding.category);
        csv_row(&mut output, &prefix, "severity", &finding.severity);
        csv_row(&mut output, &prefix, "state", &finding.state);
        csv_row(
            &mut output,
            &prefix,
            "observation",
            &finding.explanation.observation,
        );
    }
    for group in &input.evidence_by_kind {
        for evidence in &group.evidence {
            let prefix = format!("evidence:{}:{}", group.kind, evidence.id);
            csv_row(&mut output, &prefix, "class", &evidence.class);
            csv_row(
                &mut output,
                &prefix,
                "preview_text",
                evidence.preview_text.as_deref().unwrap_or(""),
            );
        }
    }
    for event in &input.chronology {
        let prefix = format!("chronology:{}", event.id);
        csv_row(&mut output, &prefix, "timestamp_utc", &event.timestamp_utc);
        csv_row(&mut output, &prefix, "reliability", &event.reliability);
        csv_row(&mut output, &prefix, "event_type", &event.event_type);
        csv_row(&mut output, &prefix, "summary", &event.summary);
    }
    let bytes = output.into_bytes();
    enforce_output_limit(bytes.len())?;
    Ok(bytes)
}

fn csv_row(output: &mut String, section: &str, field: &str, value: &str) {
    output.push_str(section);
    output.push(',');
    output.push_str(field);
    output.push(',');
    csv_escape(output, value);
    output.push('\n');
}

fn csv_escape(output: &mut String, value: &str) {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        output.push('"');
        for ch in value.chars() {
            if ch == '"' {
                output.push_str("\"\"");
            } else {
                output.push(ch);
            }
        }
        output.push('"');
    } else {
        output.push_str(value);
    }
}

pub fn render_stix(input: &ReportInput) -> Result<Vec<u8>, ReportError> {
    let mut objects: Vec<Value> = Vec::new();
    let identity_id = format!("identity--{}", input.case.id);
    objects.push(json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": input.case.created_at,
        "modified": input.case.updated_at,
        "name": "Artifacta analysis",
        "identity_class": "system",
        "extensions": {
            "artifacta-app-version": { "value": input.case.app_version },
            "artifacta-schema-version": { "value": input.case.schema_version }
        }
    }));
    let file_id = format!("file--{}", input.artifact.id);
    objects.push(json!({
        "type": "file",
        "spec_version": "2.1",
        "id": file_id,
        "created": input.artifact.created_at,
        "modified": input.artifact.created_at,
        "name": input.artifact.original_name,
        "hashes": {
            "SHA-256": input.artifact.sha256,
            "SHA-1": input.artifact.sha1,
            "MD5": input.artifact.md5,
        },
        "size": input.artifact.size_bytes,
    }));
    for finding in &input.findings {
        let pattern_id = format!("indicator--{}", finding.id);
        let observation = &finding.explanation.observation;
        let why = &finding.explanation.why_it_matters;
        let text = if why.is_empty() {
            observation.clone()
        } else {
            format!("{observation}\n\nWhy it matters: {why}")
        };
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": pattern_id,
            "created": input.case.created_at,
            "modified": input.case.updated_at,
            "name": finding.title,
            "description": text,
            "indicator_types": ["malicious-activity"],
            "pattern": format!("file:hashes.'SHA-256' = '{}'", input.artifact.sha256),
            "pattern_type": "stix",
            "valid_from": input.case.created_at,
            "confidence": (finding.confidence * 100.0).round() as u32,
            "labels": [finding.category.as_str()],
            "extensions": {
                "artifacta-finding": {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "confidence_band": finding.confidence_band,
                    "state": finding.state,
                    "explanation": finding.explanation.observation,
                    "limitations": finding.explanation.limitations,
                    "attack_mapping_caveat": input.attack_mapping_caveat,
                }
            }
        }));
        let relationship_id = format!("relationship--{}-{}", finding.id, &file_id[7..]);
        objects.push(json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": relationship_id,
            "created": input.case.created_at,
            "modified": input.case.updated_at,
            "relationship_type": "indicates",
            "source_ref": pattern_id,
            "target_ref": file_id,
            "description": finding.title,
        }));
    }
    for event in &input.chronology {
        objects.push(json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": format!("observed-data--{}", event.id),
            "created": event.timestamp_utc,
            "modified": event.timestamp_utc,
            "first_observed": event.timestamp_utc,
            "last_observed": event.timestamp_utc,
            "number_observed": 1,
            "objects": {
                "0": { "type": "file", "name": input.artifact.original_name },
                "1": { "type": "artifact", "payload_bin": format!("SHA-256:{}", input.artifact.sha256) }
            },
            "extensions": {
                "artifacta-event": {
                    "event_type": event.event_type,
                    "reliability": event.reliability,
                    "summary": event.summary,
                }
            }
        }));
    }
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", input.case.id),
        "spec_version": "2.1",
        "created": input.generated_at,
        "objects": objects,
    });
    let mut output = serde_json::to_vec_pretty(&bundle)?;
    output.push(b'\n');
    enforce_output_limit(output.len())?;
    Ok(output)
}

pub fn build_manifest(
    input: &ReportInput,
    report_name: &str,
    format: ReportFormat,
    report_bytes: &[u8],
    artifact_verification: ArtifactVerification,
) -> Result<IntegrityManifest, ReportError> {
    if report_name.is_empty()
        || report_name.contains('/')
        || report_name.contains('\\')
        || report_name.chars().any(char::is_control)
    {
        return Err(ReportError::InvalidInput(
            "manifest report reference must be a file name",
        ));
    }
    let records = record_digests(input)?;
    Ok(IntegrityManifest {
        manifest_schema_version: MANIFEST_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_owned(),
        snapshot_sha256: input.snapshot_sha256().to_owned(),
        report: ManifestFile {
            name: report_name.to_owned(),
            format: format.as_str().to_owned(),
            size_bytes: u64::try_from(report_bytes.len()).unwrap_or(u64::MAX),
            sha256: sha256_hex(report_bytes),
        },
        records,
        artifact_verification,
        limitation: "Verification detects changes to covered bytes and records; it does not establish authenticity, intent, or safety.".to_owned(),
    })
}

fn record_digests(input: &ReportInput) -> Result<Vec<ManifestRecordDigest>, ReportError> {
    let mut records = Vec::new();
    push_digest(&mut records, "case", &input.case.id, &input.case)?;
    push_digest(
        &mut records,
        "artifact",
        &input.artifact.id,
        &input.artifact,
    )?;
    if let Some(run) = &input.analysis_run {
        push_digest(&mut records, "analysis_run", &run.id, run)?;
    }
    for run in &input.run_history {
        push_digest(&mut records, "analysis_run_history", &run.id, run)?;
    }
    for record in &input.provenance {
        push_digest(&mut records, "provenance", &record.id, record)?;
    }
    for rule in &input.rules {
        push_digest(&mut records, "rule", &rule.id, rule)?;
    }
    for pack in &input.yara_packs {
        push_digest(&mut records, "yara_pack", &pack.id, pack)?;
    }
    for group in &input.evidence_by_kind {
        for evidence in &group.evidence {
            push_digest(&mut records, "evidence", &evidence.id, evidence)?;
        }
    }
    for finding in &input.findings {
        push_digest(&mut records, "finding", &finding.id, finding)?;
    }
    for relationship in &input.relationships {
        push_digest(
            &mut records,
            "relationship",
            &relationship.edge_id,
            relationship,
        )?;
    }
    for event in &input.chronology {
        push_digest(&mut records, "chronology_event", &event.id, event)?;
    }
    for note in &input.notes {
        push_digest(&mut records, "note", &note.id, note)?;
    }
    for bookmark in &input.bookmarks {
        push_digest(&mut records, "bookmark", &bookmark.id, bookmark)?;
    }
    if let Some(quick_check) = &input.quick_check {
        push_digest(
            &mut records,
            "quick_check",
            &quick_check.policy_version,
            quick_check,
        )?;
    }
    records.sort_by(|left, right| {
        (&left.record_type, &left.record_id).cmp(&(&right.record_type, &right.record_id))
    });
    Ok(records)
}

pub fn render_manifest(manifest: &IntegrityManifest) -> Result<Vec<u8>, ReportError> {
    let mut output = serde_json::to_vec_pretty(manifest)?;
    output.push(b'\n');
    enforce_output_limit(output.len())?;
    Ok(output)
}

#[must_use]
/// Verifies internal consistency and change detection for a report/manifest pair.
///
/// A verified JSON result covers the exact report bytes, canonical snapshot, and
/// every manifest record digest. It does not establish authenticity or safety.
/// Static HTML and PDF cannot be losslessly reconstructed into report records,
/// so byte- and reference-consistent pairs using those formats are reported as
/// unsupported rather than verified.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    report_bytes: &[u8],
    expected_manifest_sha256: Option<&str>,
) -> ManifestVerification {
    if expected_manifest_sha256
        .is_some_and(|expected| !sha256_hex(manifest_bytes).eq_ignore_ascii_case(expected))
    {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "external manifest hash mismatch",
            None,
        );
    }
    let manifest_value = match serde_json::from_slice::<Value>(manifest_bytes) {
        Ok(value) => value,
        Err(_) => {
            return verification(
                ManifestVerificationStatus::Mismatch,
                "manifest is not valid JSON",
                None,
            );
        }
    };
    let snapshot_reference = manifest_value
        .get("snapshot_sha256")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(manifest_schema_version) = json_u32(&manifest_value, "manifest_schema_version") else {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "manifest schema version is missing or invalid",
            snapshot_reference,
        );
    };
    if manifest_schema_version != MANIFEST_SCHEMA_VERSION {
        return verification(
            ManifestVerificationStatus::Unsupported,
            "manifest schema version is unsupported",
            snapshot_reference,
        );
    }
    let Some(hash_algorithm) = manifest_value.get("hash_algorithm").and_then(Value::as_str) else {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "manifest hash algorithm is missing or invalid",
            snapshot_reference,
        );
    };
    if hash_algorithm != "sha256" {
        return verification(
            ManifestVerificationStatus::Unsupported,
            "manifest hash algorithm is unsupported",
            snapshot_reference,
        );
    }
    let Some(manifest) = deserialize_exact::<IntegrityManifest>(&manifest_value) else {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "manifest is not exact contract JSON",
            snapshot_reference,
        );
    };
    if manifest.report.size_bytes != u64::try_from(report_bytes.len()).unwrap_or(u64::MAX)
        || !valid_report_name(&manifest.report.name)
        || !valid_digest(&manifest.report.sha256)
        || !manifest
            .report
            .sha256
            .eq_ignore_ascii_case(&sha256_hex(report_bytes))
        || manifest.records.windows(2).any(|pair| {
            (&pair[0].record_type, &pair[0].record_id) >= (&pair[1].record_type, &pair[1].record_id)
        })
        || !valid_digest(&manifest.snapshot_sha256)
        || manifest
            .records
            .iter()
            .any(|record| !valid_digest(&record.sha256))
    {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "manifest contents or exact report bytes do not match",
            Some(manifest.snapshot_sha256),
        );
    }
    match manifest.report.format.as_str() {
        "json" => verify_json_report(&manifest, report_bytes),
        "html" => verify_html_report(&manifest, report_bytes),
        "pdf" => verification(
            ManifestVerificationStatus::Unsupported,
            "PDF report records cannot be reconstructed for verification",
            Some(manifest.snapshot_sha256),
        ),
        _ => verification(
            ManifestVerificationStatus::Unsupported,
            "report format is unsupported",
            Some(manifest.snapshot_sha256),
        ),
    }
}

fn verify_json_report(manifest: &IntegrityManifest, report_bytes: &[u8]) -> ManifestVerification {
    let report_value = match serde_json::from_slice::<Value>(report_bytes) {
        Ok(value) => value,
        Err(_) => {
            return verification(
                ManifestVerificationStatus::Mismatch,
                "report is not valid JSON",
                Some(manifest.snapshot_sha256.clone()),
            );
        }
    };
    let Some(report_schema_version) = json_u32(&report_value, "report_schema_version") else {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "report schema version is missing or invalid",
            Some(manifest.snapshot_sha256.clone()),
        );
    };
    if report_schema_version != REPORT_SCHEMA_VERSION {
        return verification(
            ManifestVerificationStatus::Unsupported,
            "report schema version is unsupported",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    let Some(report) = deserialize_exact::<ReportInput>(&report_value) else {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "report is not exact contract JSON",
            Some(manifest.snapshot_sha256.clone()),
        );
    };
    if report.integrity.manifest_schema_version != MANIFEST_SCHEMA_VERSION {
        return verification(
            ManifestVerificationStatus::Unsupported,
            "report references an unsupported manifest schema version",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    if report.integrity.hash_algorithm != "sha256" {
        return verification(
            ManifestVerificationStatus::Unsupported,
            "report snapshot hash algorithm is unsupported",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    if !valid_digest(&report.integrity.snapshot_sha256)
        || !report
            .integrity
            .snapshot_sha256
            .eq_ignore_ascii_case(&manifest.snapshot_sha256)
    {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "report does not embed the manifest snapshot reference",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    let recomputed_snapshot = match report.compute_snapshot_sha256() {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return verification(
                ManifestVerificationStatus::Mismatch,
                "report canonical snapshot could not be recomputed",
                Some(manifest.snapshot_sha256.clone()),
            );
        }
    };
    if !recomputed_snapshot.eq_ignore_ascii_case(&manifest.snapshot_sha256) {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "report canonical snapshot digest does not match",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    let expected_records = match record_digests(&report) {
        Ok(records) => records,
        Err(_) => {
            return verification(
                ManifestVerificationStatus::Mismatch,
                "report record digests could not be recomputed",
                Some(manifest.snapshot_sha256.clone()),
            );
        }
    };
    if !record_digests_match(&manifest.records, &expected_records) {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "manifest record digests do not match report records",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    verification(
        ManifestVerificationStatus::Verified,
        "exact JSON report bytes, canonical snapshot, and record digests verified; no authenticity or safety claim is made",
        Some(manifest.snapshot_sha256.clone()),
    )
}

fn verify_html_report(manifest: &IntegrityManifest, report_bytes: &[u8]) -> ManifestVerification {
    let snapshot_card = format!(
        "<div class=\"card\"><div class=\"label\">Canonical snapshot SHA-256</div><div class=\"value\">{}</div></div>",
        manifest.snapshot_sha256
    );
    let snapshot_reference_matches = std::str::from_utf8(report_bytes)
        .is_ok_and(|report| report.matches(&snapshot_card).count() == 1);
    if !snapshot_reference_matches {
        return verification(
            ManifestVerificationStatus::Mismatch,
            "HTML report does not embed the exact manifest snapshot reference",
            Some(manifest.snapshot_sha256.clone()),
        );
    }
    verification(
        ManifestVerificationStatus::Unsupported,
        "exact HTML report bytes and embedded snapshot reference match, but report schema, canonical snapshot, and record digests cannot be recomputed from static HTML; no authenticity or safety claim is made",
        Some(manifest.snapshot_sha256.clone()),
    )
}

#[must_use]
pub fn report_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(ReportInput)).expect("schema serialization")
}

#[must_use]
pub fn manifest_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(IntegrityManifest)).expect("schema serialization")
}

#[must_use]
pub fn evidence_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(Evidence)).expect("schema serialization")
}

#[must_use]
pub fn finding_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(Finding)).expect("schema serialization")
}

pub fn render_html(input: &ReportInput) -> Result<Vec<u8>, ReportError> {
    let mut output = String::with_capacity(64 * 1024);
    output.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    output.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    output.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n<title>");
    escape_html_into(&mut output, &input.case.title);
    output.push_str(" - Artifacta case report</title>\n<style>body{margin:0;background:#f4f1e8;color:#17211d;font:15px/1.55 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:2rem}header{border-bottom:4px solid #17211d;margin-bottom:2rem}h1,h2,h3{line-height:1.15}h1{font-size:2.5rem}.meta,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.75rem}.card,details{background:#fff;border:1px solid #b7b2a5;padding:1rem;margin:.75rem 0}.label{color:#59635d;font-size:.78rem;font-weight:700;text-transform:uppercase}.value,pre{overflow-wrap:anywhere;white-space:pre-wrap}pre{background:#ebe8df;padding:.75rem}.badge{display:inline-block;border:1px solid currentColor;padding:.1rem .45rem;margin-right:.35rem;font-weight:700}a{color:#075d57}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.45rem;text-align:left;vertical-align:top}@media(max-width:600px){main{padding:1rem}h1{font-size:1.8rem}}</style></head><body><main>\n");
    output.push_str("<header><p class=\"label\">Artifacta static case report</p><h1>");
    escape_html_into(&mut output, &input.case.title);
    output.push_str("</h1><p>Generated at ");
    escape_html_into(&mut output, &input.generated_at);
    output.push_str("</p></header>\n<section><h2>Case and artifact</h2><div class=\"grid\">");
    html_card(&mut output, "Case ID", &input.case.id);
    html_card(&mut output, "Case status", &input.case.status);
    html_card(&mut output, "Case created", &input.case.created_at);
    html_card(&mut output, "Case updated", &input.case.updated_at);
    html_card(&mut output, "Application version", &input.case.app_version);
    html_card(
        &mut output,
        "Application identity SHA-256",
        &input.case.app_identity_sha256,
    );
    html_card(
        &mut output,
        "Case schema version",
        &input.case.schema_version.to_string(),
    );
    html_card(&mut output, "Artifact ID", &input.artifact.id);
    if let Some(parent_id) = &input.artifact.parent_artifact_id {
        html_card(&mut output, "Parent artifact ID", parent_id);
    }
    html_card(&mut output, "Artifact name", &input.artifact.original_name);
    html_card(&mut output, "Artifact kind", &input.artifact.kind);
    html_card(
        &mut output,
        "Artifact media type",
        input.artifact.mime.as_deref().unwrap_or("Not recorded"),
    );
    html_card(&mut output, "Artifact created", &input.artifact.created_at);
    html_card(
        &mut output,
        "Artifact size",
        &input.artifact.size_bytes.to_string(),
    );
    html_card(&mut output, "SHA-256", &input.artifact.sha256);
    html_card(&mut output, "SHA-1", &input.artifact.sha1);
    html_card(&mut output, "MD5", &input.artifact.md5);
    output.push_str(
        "</div></section>\n<section><h2>Analysis and provenance</h2><div class=\"grid\">",
    );
    if let Some(run) = &input.analysis_run {
        html_card(&mut output, "Run ID", &run.id);
        html_card(
            &mut output,
            "Analyzer",
            &format!("{} {}", run.analyzer, run.analyzer_version),
        );
        html_card(
            &mut output,
            "Analyzer identity SHA-256",
            &run.analyzer_identity_sha256,
        );
        html_card(&mut output, "Run status", &run.status);
        html_card(&mut output, "Started", &run.started_at);
        html_card(
            &mut output,
            "Finished",
            run.finished_at.as_deref().unwrap_or("Not finished"),
        );
        if let Some(error) = &run.error_code {
            html_card(&mut output, "Error code", error);
        }
    } else {
        output.push_str("<p>No analysis run is recorded.</p>");
    }
    if !input.run_history.is_empty() {
        output.push_str("</div><h3>Run history</h3><table><thead><tr><th>Run</th><th>Analyzer</th><th>Status</th><th>Started</th><th>Finished</th></tr></thead><tbody>");
        for run in &input.run_history {
            output.push_str("<tr><td>");
            escape_html_into(&mut output, &run.id);
            output.push_str("</td><td>");
            escape_html_into(
                &mut output,
                &format!("{} {}", run.analyzer, run.analyzer_version),
            );
            output.push_str("</td><td>");
            escape_html_into(&mut output, &run.status);
            output.push_str("</td><td>");
            escape_html_into(&mut output, &run.started_at);
            output.push_str("</td><td>");
            escape_html_into(
                &mut output,
                run.finished_at.as_deref().unwrap_or("Not finished"),
            );
            output.push_str("</td></tr>");
        }
        output.push_str("</tbody></table><div class=\"grid\">");
    }
    for provenance in &input.provenance {
        html_card(&mut output, "Provenance ID", &provenance.id);
        html_card(
            &mut output,
            "Provenance analyzer",
            &format!("{} {}", provenance.analyzer, provenance.analyzer_version),
        );
        html_card(&mut output, "Input SHA-256", &provenance.input_sha256);
        if let Some(rule_id) = &provenance.rule_id {
            html_card(
                &mut output,
                "Provenance rule",
                &format!(
                    "{} {}",
                    rule_id,
                    provenance
                        .rule_version
                        .as_deref()
                        .unwrap_or("version not recorded")
                ),
            );
        }
        html_card(
            &mut output,
            "Rule pack SHA-256",
            provenance
                .rule_pack_sha256
                .as_deref()
                .unwrap_or("Not recorded"),
        );
        html_card(&mut output, "Parameters", "Redacted from exported reports");
    }
    output.push_str("</div><h3>Provenance summary</h3><div class=\"grid\">");
    for (label, value) in [
        ("Analyzers", input.provenance_summary.analyzer_count),
        (
            "Provenance records",
            input.provenance_summary.provenance_record_count,
        ),
        ("Rules", input.provenance_summary.rule_count),
        ("YARA packs", input.provenance_summary.yara_pack_count),
        ("Evidence records", input.provenance_summary.evidence_count),
    ] {
        html_card(&mut output, label, &value.to_string());
    }
    output.push_str("</div></section>\n<section><h2>Integrity reference</h2><div class=\"grid\">");
    html_card(
        &mut output,
        "Canonical snapshot SHA-256",
        &input.integrity.snapshot_sha256,
    );
    html_card(
        &mut output,
        "External manifest",
        input
            .integrity
            .external_manifest
            .as_deref()
            .unwrap_or("Not exported with this one-file report"),
    );
    html_card(
        &mut output,
        "Manifest schema version",
        &input.integrity.manifest_schema_version.to_string(),
    );
    output.push_str("</div><p>SHA-256 and manifest verification detect covered changes; they do not establish authenticity or safety.</p></section>\n<section><h2>Quick Check</h2>");
    if let Some(quick_check) = &input.quick_check {
        html_labeled_text(&mut output, "Band", quick_check.band.as_str());
        html_labeled_text(&mut output, "Policy version", &quick_check.policy_version);
        html_labeled_text(&mut output, "Policy SHA-256", &quick_check.policy_sha256);
        html_labeled_text(&mut output, "Statement", &quick_check.statement);
        output.push_str("<table><thead><tr><th>Family</th><th>Findings</th><th>Contributing</th><th>Strongest severity</th></tr></thead><tbody>");
        for family in &quick_check.evidence_families {
            output.push_str("<tr><td>");
            escape_html_into(&mut output, family.family.as_str());
            let _ = write!(
                output,
                "</td><td>{}</td><td>{}</td><td>",
                family.finding_count, family.contributing_finding_count
            );
            escape_html_into(
                &mut output,
                family
                    .strongest_severity
                    .map_or("none", tf_model::Severity::as_str),
            );
            output.push_str("</td></tr>");
        }
        output.push_str("</tbody></table>");
    } else {
        output.push_str("<p>Quick Check was unavailable for this snapshot.</p>");
    }
    output.push_str("</section>\n<section><h2>Relationships</h2><table><thead><tr><th>Source</th><th>Relationship</th><th>Target</th><th>Evidence</th><th>Confidence</th></tr></thead><tbody>");
    for relationship in &input.relationships {
        output.push_str("<tr><td>");
        escape_html_into(&mut output, &relationship.source);
        output.push_str("<br><span class=\"label\">");
        escape_html_into(&mut output, &relationship.source_entity_id);
        output.push_str("</span></td><td>");
        escape_html_into(&mut output, &relationship.relationship);
        output.push_str("</td><td>");
        escape_html_into(&mut output, &relationship.target);
        output.push_str("<br><span class=\"label\">");
        escape_html_into(&mut output, &relationship.target_entity_id);
        output.push_str("</span></td><td>");
        escape_html_into(&mut output, &relationship.evidence_id);
        let _ = write!(output, "</td><td>{:.2}</td></tr>", relationship.confidence);
    }
    output.push_str("</tbody></table></section>\n<section><h2>Chronology</h2><p>Timestamp reliability is reported explicitly and should guide corroboration.</p><div class=\"grid\">");
    for (reliability, count) in &input.chronology_reliability {
        html_card(&mut output, reliability, &count.to_string());
    }
    output.push_str("</div><table><thead><tr><th>Timestamp</th><th>Reliability</th><th>Type</th><th>Summary</th></tr></thead><tbody>");
    for event in &input.chronology {
        output.push_str("<tr><td>");
        escape_html_into(&mut output, &event.timestamp_utc);
        output.push_str("</td><td>");
        escape_html_into(&mut output, &event.reliability);
        output.push_str("</td><td>");
        escape_html_into(&mut output, &event.event_type);
        output.push_str("</td><td>");
        escape_html_into(&mut output, &event.summary);
        output.push_str("</td></tr>");
    }
    output.push_str("</tbody></table></section>\n<section><h2>Notes and bookmarks</h2>");
    for note in &input.notes {
        output.push_str("<article class=\"card\">");
        html_labeled_text(&mut output, "Note ID", &note.id);
        html_labeled_text(&mut output, "Note", &note.body);
        output.push_str("</article>");
    }
    for bookmark in &input.bookmarks {
        output.push_str("<article class=\"card\">");
        html_labeled_text(
            &mut output,
            "Bookmark",
            bookmark.label.as_deref().unwrap_or("Unlabelled"),
        );
        html_labeled_text(
            &mut output,
            "Target",
            &format!("{} {}", bookmark.target_type, bookmark.target_id),
        );
        output.push_str("</article>");
    }
    output.push_str("</section>\n<section><h2>Findings</h2>");
    output.push_str("<p>");
    escape_html_into(&mut output, ATTACK_CONTEXT_CAVEAT);
    output.push_str("</p>");
    if input.findings.is_empty() {
        output.push_str("<p>No findings were recorded for this analysis run.</p>");
    }
    for finding in &input.findings {
        output.push_str("<article class=\"card\"><h3>");
        escape_html_into(&mut output, &finding.title);
        output.push_str("</h3><p><span class=\"badge\">");
        escape_html_into(&mut output, &finding.severity);
        output.push_str("</span><span class=\"badge\">confidence ");
        let _ = write!(output, "{:.2}", finding.confidence);
        output.push_str(" (");
        escape_html_into(&mut output, &finding.confidence_band);
        output.push_str(")</span></p>");
        html_labeled_text(&mut output, "Finding ID", &finding.id);
        html_labeled_text(&mut output, "Category", &finding.category);
        html_labeled_text(&mut output, "State", &finding.state);
        html_labeled_text(&mut output, "Observation", &finding.explanation.observation);
        html_labeled_text(
            &mut output,
            "Why it matters",
            &finding.explanation.why_it_matters,
        );
        html_labeled_text(&mut output, "Limitations", &finding.explanation.limitations);
        if !finding.explanation.attack_mappings.is_empty() {
            output.push_str("<p class=\"label\">MITRE ATT&amp;CK static context</p><ul>");
            for mapping in &finding.explanation.attack_mappings {
                output.push_str("<li>");
                escape_html_into(
                    &mut output,
                    &format!(
                        "{} - {} ({})",
                        mapping.technique_id, mapping.technique_name, mapping.tactic
                    ),
                );
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }
        output.push_str("<p class=\"label\">Exact linked evidence</p><ul>");
        for link in &finding.linked_evidence {
            output.push_str("<li><span class=\"badge\">");
            escape_html_into(&mut output, &link.role);
            output.push_str("</span> <a href=\"#evidence-");
            escape_html_into(&mut output, &link.evidence_id);
            output.push_str("\">");
            escape_html_into(&mut output, &link.evidence_id);
            output.push_str("</a></li>");
        }
        output.push_str("</ul><p class=\"label\">Rule</p><p class=\"value\">");
        escape_html_into(
            &mut output,
            &format!("{} version {}", finding.rule_id, finding.rule_version),
        );
        output.push_str("</p></article>\n");
        enforce_output_limit(output.len())?;
    }
    output.push_str("</section>\n<section><h2>Evidence by kind</h2><p>Use your browser's find command to search IDs, kinds, locators, previews, and values.</p>");
    for group in &input.evidence_by_kind {
        output.push_str("<h3>");
        escape_html_into(&mut output, &group.kind);
        output.push_str("</h3>");
        for evidence in &group.evidence {
            output.push_str("<details open id=\"evidence-");
            escape_html_into(&mut output, &evidence.id);
            output.push_str("\"><summary>");
            escape_html_into(&mut output, &evidence.id);
            output.push_str(" <span class=\"badge\">");
            escape_html_into(&mut output, &evidence.class);
            output.push_str("</span></summary>");
            if let Some(preview) = &evidence.preview_text {
                html_labeled_text(&mut output, "Preview", preview);
            }
            html_json(&mut output, "Locator", &evidence.locator)?;
            html_json(&mut output, "Value", &evidence.value)?;
            output.push_str("</details>\n");
            enforce_output_limit(output.len())?;
        }
    }
    output.push_str("</section>\n<section><h2>Rule catalog</h2>");
    for rule in &input.rules {
        output.push_str("<details><summary>");
        escape_html_into(&mut output, &rule.rule_id);
        output.push_str(" version ");
        escape_html_into(&mut output, &rule.version);
        output.push_str("</summary>");
        html_labeled_text(&mut output, "Rule record ID", &rule.id);
        html_labeled_text(&mut output, "Engine", &rule.engine);
        html_labeled_text(&mut output, "License", &rule.license);
        html_labeled_text(&mut output, "SHA-256", &rule.sha256);
        html_labeled_text(
            &mut output,
            "Enabled",
            if rule.enabled { "true" } else { "false" },
        );
        output.push_str("<p class=\"label\">Source</p><pre>");
        escape_html_into(&mut output, &rule.source);
        output.push_str("</pre></details>");
        enforce_output_limit(output.len())?;
    }
    output.push_str(
        "</section>\n<section><h2>Methodology and limitations</h2><h3>Methodology</h3><ul>",
    );
    for item in &input.methodology {
        output.push_str("<li>");
        escape_html_into(&mut output, item);
        output.push_str("</li>");
    }
    output.push_str("</ul><h3>Limitations</h3><ul>");
    for item in &input.limitations {
        output.push_str("<li>");
        escape_html_into(&mut output, item);
        output.push_str("</li>");
    }
    output.push_str("</ul></section>\n</main></body></html>\n");
    enforce_output_limit(output.len())?;
    Ok(output.into_bytes())
}

fn report_relationships(graph: Option<&CaseGraph>) -> Vec<ReportRelationship> {
    let Some(graph) = graph else {
        return Vec::new();
    };
    let entities = graph
        .entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity.display_value.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut relationships = graph
        .edges
        .iter()
        .map(|edge| ReportRelationship {
            edge_id: edge.id.as_str().to_owned(),
            source_entity_id: edge.source_entity_id.as_str().to_owned(),
            source: entities
                .get(edge.source_entity_id.as_str())
                .copied()
                .unwrap_or("Unknown entity")
                .to_owned(),
            relationship: edge.relationship.as_str().to_owned(),
            target_entity_id: edge.target_entity_id.as_str().to_owned(),
            target: entities
                .get(edge.target_entity_id.as_str())
                .copied()
                .unwrap_or("Unknown entity")
                .to_owned(),
            evidence_id: edge.evidence_id.as_str().to_owned(),
            confidence: edge.confidence.value(),
        })
        .collect::<Vec<_>>();
    relationships.sort_by(|left, right| {
        (
            &left.relationship,
            &left.source_entity_id,
            &left.target_entity_id,
            &left.evidence_id,
            &left.edge_id,
        )
            .cmp(&(
                &right.relationship,
                &right.source_entity_id,
                &right.target_entity_id,
                &right.evidence_id,
                &right.edge_id,
            ))
    });
    relationships
}

fn report_analysis_run(record: &AnalysisRun) -> ReportAnalysisRun {
    ReportAnalysisRun {
        id: record.id.as_str().to_owned(),
        analyzer: record.analyzer.clone(),
        analyzer_version: record.analyzer_version.clone(),
        started_at: record.started_at.clone(),
        finished_at: record.finished_at.clone(),
        status: record.status.as_str().to_owned(),
        error_code: record.error_code.clone(),
        analyzer_identity_sha256: identity_hash(&record.analyzer, &record.analyzer_version),
    }
}

fn report_chronology(chronology: Option<&CaseChronology>) -> Vec<ReportChronologyEvent> {
    let Some(chronology) = chronology else {
        return Vec::new();
    };
    let mut events = chronology
        .events
        .iter()
        .map(|event| ReportChronologyEvent {
            id: event.id.as_str().to_owned(),
            timestamp_utc: event.timestamp_utc.clone(),
            timestamp_type: event.timestamp_type.clone(),
            reliability: event.reliability.as_str().to_owned(),
            event_type: event.event_type.clone(),
            artifact_id: event.artifact_id.as_ref().map(|id| id.as_str().to_owned()),
            evidence_id: event.evidence_id.as_ref().map(|id| id.as_str().to_owned()),
            summary: event.summary.clone(),
        })
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        (&left.timestamp_utc, &left.event_type, &left.id).cmp(&(
            &right.timestamp_utc,
            &right.event_type,
            &right.id,
        ))
    });
    events
}

fn identity_hash(name: &str, version: &str) -> String {
    sha256_hex(format!("name={name}\nversion={version}\n").as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_report_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
}

fn json_u32(value: &Value, field: &str) -> Option<u32> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
}

fn deserialize_exact<T>(value: &Value) -> Option<T>
where
    T: DeserializeOwned + Serialize,
{
    let parsed = serde_json::from_value::<T>(value.clone()).ok()?;
    let canonical = serde_json::to_value(&parsed).ok()?;
    json_contract_shape_matches(value, &canonical).then_some(parsed)
}

fn json_contract_shape_matches(input: &Value, typed: &Value) -> bool {
    match (input, typed) {
        (Value::Object(input), Value::Object(typed)) => {
            input.len() == typed.len()
                && input.iter().all(|(key, input_value)| {
                    typed.get(key).is_some_and(|typed_value| {
                        json_contract_shape_matches(input_value, typed_value)
                    })
                })
        }
        (Value::Array(input), Value::Array(typed)) => {
            input.len() == typed.len()
                && input
                    .iter()
                    .zip(typed)
                    .all(|(input, typed)| json_contract_shape_matches(input, typed))
        }
        (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => true,
        _ => false,
    }
}

fn record_digests_match(
    actual: &[ManifestRecordDigest],
    expected: &[ManifestRecordDigest],
) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.record_type == expected.record_type
                && actual.record_id == expected.record_id
                && actual.sha256.eq_ignore_ascii_case(&expected.sha256)
        })
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn push_digest<T: Serialize>(
    output: &mut Vec<ManifestRecordDigest>,
    record_type: &str,
    record_id: &str,
    value: &T,
) -> Result<(), ReportError> {
    output.push(ManifestRecordDigest {
        record_type: record_type.to_owned(),
        record_id: record_id.to_owned(),
        sha256: sha256_hex(&serde_json::to_vec(value)?),
    });
    Ok(())
}

fn verification(
    status: ManifestVerificationStatus,
    detail: &str,
    snapshot_sha256: Option<String>,
) -> ManifestVerification {
    ManifestVerification {
        status,
        detail: detail.to_owned(),
        snapshot_sha256,
    }
}

fn enforce_limit(name: &'static str, actual: usize, limit: usize) -> Result<(), ReportError> {
    if actual > limit {
        Err(ReportError::ItemLimit { name, limit })
    } else {
        Ok(())
    }
}

fn enforce_output_limit(actual: usize) -> Result<(), ReportError> {
    if actual > MAX_REPORT_BYTES {
        Err(ReportError::TooLarge {
            max_bytes: MAX_REPORT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn normalize_map(map: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    map.iter()
        .map(|(key, value)| (key.clone(), normalize_value(value)))
        .collect()
}

fn normalize_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(normalize_value).collect()),
        Value::Object(items) => {
            let ordered = items
                .iter()
                .map(|(key, value)| (key.clone(), normalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::to_value(ordered).expect("JSON value normalization cannot fail")
        }
        _ => value.clone(),
    }
}

fn escape_html_into(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

fn html_card(output: &mut String, label: &str, value: &str) {
    output.push_str("<div class=\"card\"><div class=\"label\">");
    escape_html_into(output, label);
    output.push_str("</div><div class=\"value\">");
    escape_html_into(output, value);
    output.push_str("</div></div>");
}

fn html_labeled_text(output: &mut String, label: &str, value: &str) {
    output.push_str("<p><span class=\"label\">");
    escape_html_into(output, label);
    output.push_str("</span><br><span class=\"value\">");
    escape_html_into(output, value);
    output.push_str("</span></p>");
}

fn html_json<T: Serialize>(output: &mut String, label: &str, value: &T) -> Result<(), ReportError> {
    let json = serde_json::to_string_pretty(value)?;
    output.push_str("<p class=\"label\">");
    escape_html_into(output, label);
    output.push_str("</p><pre>");
    escape_html_into(output, &json);
    output.push_str("</pre>");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use serde_json::json;
    use tf_model::{
        AnalysisRunId, AnalysisStatus, ArtifactId, ArtifactKind, CaseId, CaseStatus, Confidence,
        ConfidenceBand, Edge, EdgeId, Entity, EntityId, EntityType, EventId, EvidenceEvent,
        EvidenceId, EvidenceRole, FindingId, FindingState, ObservationClass, ProvenanceId,
        Relationship, RuleRecordId, Severity, TimestampReliability,
    };

    struct Fixture {
        case: Case,
        artifact: Artifact,
        run: AnalysisRun,
        provenance: Provenance,
        evidence: Vec<Evidence>,
        rules: Vec<RuleRecord>,
        findings: Vec<Finding>,
        links: Vec<FindingEvidence>,
        explanations: Vec<FindingExplanation>,
        attack_mappings: Vec<FindingExplanationAttackMapping>,
    }

    fn fixture() -> Fixture {
        let case_id = CaseId::new();
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let provenance_id = ProvenanceId::new();
        let evidence_id = tf_model::EvidenceId::new();
        let second_evidence_id = tf_model::EvidenceId::new();
        let finding_id = FindingId::new();
        let case = Case {
            id: case_id.clone(),
            title: "<script>alert('case')</script>".to_owned(),
            created_at: "2026-08-25T10:00:00Z".to_owned(),
            updated_at: "2026-08-25T10:00:02Z".to_owned(),
            app_version: "0.1.0".to_owned(),
            schema_version: 1,
            status: CaseStatus::Complete,
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            case_id,
            parent_artifact_id: None,
            sha256: "a".repeat(64),
            sha1: "b".repeat(40),
            md5: "c".repeat(32),
            size_bytes: 42,
            kind: ArtifactKind::Pe64,
            mime: Some("application/x-test".to_owned()),
            original_name: "<img src=x onerror=alert(1)>".to_owned(),
            store_path: "artifacts/secret/path".to_owned(),
            created_at: "2026-08-25T10:00:00Z".to_owned(),
        };
        let run = AnalysisRun {
            id: run_id.clone(),
            artifact_id: artifact_id.clone(),
            analyzer: "artifacta.test".to_owned(),
            analyzer_version: "1".to_owned(),
            started_at: "2026-08-25T10:00:01Z".to_owned(),
            finished_at: Some("2026-08-25T10:00:02Z".to_owned()),
            status: AnalysisStatus::Complete,
            error_code: None,
        };
        let provenance = Provenance {
            id: provenance_id.clone(),
            analysis_run_id: run_id.clone(),
            analyzer: run.analyzer.clone(),
            analyzer_version: run.analyzer_version.clone(),
            rule_id: None,
            rule_version: None,
            rule_pack_sha256: Some("d".repeat(64)),
            input_sha256: artifact.sha256.clone(),
            parameters: BTreeMap::from([
                ("artifact_path".to_owned(), json!(r"C:\secret\source.exe")),
                ("operation".to_owned(), json!("test")),
            ]),
        };
        let evidence = vec![
            Evidence {
                id: evidence_id.clone(),
                artifact_id: artifact_id.clone(),
                provenance_id: provenance_id.clone(),
                kind: "pe.<section>".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([("offset".to_owned(), json!(12))]),
                value: json!({"z": "</script><script>bad()</script>", "a": 1}),
                preview_text: Some("unsafe <b>preview</b>".to_owned()),
            },
            Evidence {
                id: second_evidence_id.clone(),
                artifact_id: artifact_id.clone(),
                provenance_id,
                kind: "analysis.context".to_owned(),
                class: ObservationClass::Inferred,
                locator: BTreeMap::from([("index".to_owned(), json!(1))]),
                value: json!({"context": true}),
                preview_text: None,
            },
        ];
        let rules = vec![RuleRecord {
            id: RuleRecordId::new(),
            engine: "test".to_owned(),
            rule_id: "TF-TEST-1".to_owned(),
            version: "1".to_owned(),
            source: "local rule".to_owned(),
            license: "Apache-2.0".to_owned(),
            sha256: "e".repeat(64),
            enabled: true,
        }];
        let findings = vec![Finding {
            id: finding_id.clone(),
            analysis_run_id: run_id,
            artifact_id,
            rule_id: "TF-TEST-1".to_owned(),
            rule_version: "1".to_owned(),
            title: "Suspicious <thing>".to_owned(),
            category: "test".to_owned(),
            severity: Severity::High,
            confidence: Confidence::new(0.9).expect("confidence"),
            confidence_band: ConfidenceBand::Strong,
            explanation_template_id: "test.v1".to_owned(),
            state: FindingState::New,
        }];
        let links = vec![
            FindingEvidence {
                finding_id: finding_id.clone(),
                evidence_id,
                role: EvidenceRole::Supports,
            },
            FindingEvidence {
                finding_id: finding_id.clone(),
                evidence_id: second_evidence_id,
                role: EvidenceRole::Context,
            },
        ];
        let explanations = vec![FindingExplanation {
            finding_id: finding_id.clone(),
            template_id: "test.v1".to_owned(),
            observation: "Observed <input>.".to_owned(),
            why_it_matters: "It may matter.".to_owned(),
            limitations: "Not a verdict.".to_owned(),
            supporting_evidence: links.clone(),
        }];
        let attack_mappings = vec![FindingExplanationAttackMapping {
            finding_id: finding_id.clone(),
            mapping: tf_model::AttackMapping {
                technique_id: "T1055".to_owned(),
                technique_name: "Process Injection".to_owned(),
                tactic: "Defense Evasion".to_owned(),
            },
        }];
        Fixture {
            case,
            artifact,
            run,
            provenance,
            evidence,
            rules,
            findings,
            links,
            explanations,
            attack_mappings,
        }
    }

    fn input(fixture: &Fixture) -> ReportInput {
        ReportInput::new(
            "2026-08-25T12:00:00Z",
            &fixture.case,
            &fixture.artifact,
            Some(&fixture.run),
            std::slice::from_ref(&fixture.provenance),
            &fixture.evidence,
            &fixture.rules,
            &fixture.findings,
            &fixture.links,
            &fixture.explanations,
            &fixture.attack_mappings,
        )
        .expect("report input")
    }

    fn refresh_report_bytes(manifest: &mut IntegrityManifest, report_bytes: &[u8]) {
        manifest.report.size_bytes = u64::try_from(report_bytes.len()).expect("report size");
        manifest.report.sha256 = sha256_hex(report_bytes);
    }

    #[test]
    fn json_is_deterministic_and_redacted() {
        let fixture = fixture();
        let report = input(&fixture);
        let first = render_json(&report).expect("JSON");
        let second = render_json(&report).expect("JSON");
        assert_eq!(first, second);
        let text = String::from_utf8(first).expect("UTF-8");
        assert!(!text.contains("store_path"));
        assert!(!text.contains("artifacts/secret/path"));
        assert!(!text.contains("C:\\\\secret"));
        assert!(text.contains("parameters_redacted"));
        assert!(text.contains(fixture.links[0].evidence_id.as_str()));
        assert!(text.contains("T1055"));
        assert!(text.contains(ATTACK_CONTEXT_CAVEAT));
    }

    #[test]
    fn privacy_canary_never_crosses_report_or_manifest_boundaries() {
        const CANARY: &str = "TRACEFORGE_PRIVATE_PATH_CANARY_7D4A9C";
        let mut fixture = fixture();
        fixture.artifact.store_path = format!(r"artifacts\private\{CANARY}.exe");
        fixture.provenance.parameters.insert(
            "source_path".to_owned(),
            json!(format!(r"C:\Users\Analyst\Evidence\{CANARY}.exe")),
        );
        let report = input(&fixture);
        let json = render_json(&report).expect("JSON report");
        let html = render_html(&report).expect("HTML report");
        let manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &json,
            ArtifactVerification::Verified,
        )
        .and_then(|manifest| render_manifest(&manifest))
        .expect("manifest");
        for (name, bytes) in [("json", json), ("html", html), ("manifest", manifest)] {
            assert!(
                !bytes
                    .windows(CANARY.len())
                    .any(|window| window == CANARY.as_bytes()),
                "privacy canary leaked into {name}"
            );
        }
    }

    #[test]
    fn html_is_static_self_contained_and_escapes_artifact_text() {
        let fixture = fixture();
        let html =
            String::from_utf8(render_html(&input(&fixture)).expect("HTML")).expect("UTF-8 HTML");
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Evidence by kind"));
        assert!(html.contains("T1055 - Process Injection (Defense Evasion)"));
        assert!(html.contains("static capability or contextual relevance only"));
        assert!(html.contains(&format!(
            "href=\"#evidence-{}\"",
            fixture.links[0].evidence_id.as_str()
        )));
    }

    #[test]
    fn ordering_does_not_depend_on_source_collection_order() {
        let fixture = fixture();
        let first = input(&fixture);
        let mut second_fixture = fixture;
        second_fixture.evidence.reverse();
        second_fixture.rules.reverse();
        second_fixture.findings.reverse();
        second_fixture.links.reverse();
        second_fixture.explanations.reverse();
        let second = input(&second_fixture);
        assert_eq!(
            render_json(&first).expect("first"),
            render_json(&second).expect("second")
        );
    }

    #[test]
    fn rejects_disagreeing_or_missing_exact_links() {
        let mut fixture = fixture();
        fixture.explanations[0].supporting_evidence[0].role = EvidenceRole::Contradicts;
        assert!(matches!(
            ReportInput::new(
                "2026-08-25T12:00:00Z",
                &fixture.case,
                &fixture.artifact,
                Some(&fixture.run),
                std::slice::from_ref(&fixture.provenance),
                &fixture.evidence,
                &fixture.rules,
                &fixture.findings,
                &fixture.links,
                &fixture.explanations,
                &fixture.attack_mappings,
            ),
            Err(ReportError::InvalidInput(_))
        ));
    }

    #[test]
    fn enforces_output_size_limit() {
        let fixture = fixture();
        let mut report = input(&fixture);
        report.case.title = "x".repeat(MAX_REPORT_BYTES);
        assert!(matches!(
            render_json(&report),
            Err(ReportError::TooLarge { .. })
        ));
        assert!(matches!(
            render_html(&report),
            Err(ReportError::TooLarge { .. })
        ));
    }

    #[test]
    fn ids_in_fixture_are_valid_ulids() {
        let fixture = fixture();
        assert!(EvidenceId::from_str(fixture.links[0].evidence_id.as_str()).is_ok());
    }

    #[test]
    fn snapshot_hash_excludes_generation_and_output_records() {
        let fixture = fixture();
        let first = ReportInput::new(
            "2026-08-25T12:00:00Z",
            &fixture.case,
            &fixture.artifact,
            Some(&fixture.run),
            std::slice::from_ref(&fixture.provenance),
            &fixture.evidence,
            &fixture.rules,
            &fixture.findings,
            &fixture.links,
            &fixture.explanations,
            &fixture.attack_mappings,
        )
        .expect("first input");
        let second = ReportInput::new(
            "2026-08-25T13:00:00Z",
            &fixture.case,
            &fixture.artifact,
            Some(&fixture.run),
            std::slice::from_ref(&fixture.provenance),
            &fixture.evidence,
            &fixture.rules,
            &fixture.findings,
            &fixture.links,
            &fixture.explanations,
            &fixture.attack_mappings,
        )
        .expect("second input");
        assert_eq!(first.snapshot_sha256(), second.snapshot_sha256());
        assert_ne!(render_json(&first).unwrap(), render_json(&second).unwrap());
    }

    #[test]
    fn manifest_hashes_exact_report_bytes_and_verifies_without_a_safety_claim() {
        let fixture = fixture();
        let report = input(&fixture);
        let report_bytes = render_json(&report).expect("report");
        let manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &report_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        let manifest_bytes = render_manifest(&manifest).expect("manifest bytes");
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        assert_eq!(manifest.report.sha256, sha256_hex(&report_bytes));
        assert_eq!(manifest.snapshot_sha256, report.snapshot_sha256());
        assert!(manifest.limitation.contains("does not establish"));
        assert_eq!(
            verify_manifest(&manifest_bytes, &report_bytes, Some(&manifest_sha256)).status,
            ManifestVerificationStatus::Verified
        );
        assert_eq!(
            verify_manifest(&manifest_bytes, &report_bytes, Some(&"0".repeat(64))).detail,
            "external manifest hash mismatch"
        );
        let mut changed = report_bytes;
        changed.push(b' ');
        assert_eq!(
            verify_manifest(&manifest_bytes, &changed, Some(&manifest_sha256)).status,
            ManifestVerificationStatus::Mismatch
        );
        let mut unsupported = manifest;
        unsupported.manifest_schema_version += 1;
        let unsupported_bytes = render_manifest(&unsupported).expect("unsupported manifest");
        assert_eq!(
            verify_manifest(
                &unsupported_bytes,
                &changed[..changed.len() - 1],
                Some(&sha256_hex(&unsupported_bytes)),
            )
            .status,
            ManifestVerificationStatus::Unsupported
        );
    }

    #[test]
    fn verification_recomputes_changed_report_records() {
        let fixture = fixture();
        let mut report = input(&fixture);
        let original_bytes = render_json(&report).expect("original report");
        let mut manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &original_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");

        report.artifact.original_name = "tampered.exe".to_owned();
        report.integrity.snapshot_sha256 = report.compute_snapshot_sha256().expect("snapshot");
        let changed_bytes = render_json(&report).expect("changed report");
        manifest.snapshot_sha256 = report.snapshot_sha256().to_owned();
        refresh_report_bytes(&mut manifest, &changed_bytes);
        let manifest_bytes = render_manifest(&manifest).expect("changed manifest");

        let verification = verify_manifest(&manifest_bytes, &changed_bytes, None);
        assert_eq!(verification.status, ManifestVerificationStatus::Mismatch);
        assert_eq!(
            verification.detail,
            "manifest record digests do not match report records"
        );
    }

    #[test]
    fn verification_rejects_forged_embedded_snapshot_and_record_digest() {
        let fixture = fixture();
        let mut report = input(&fixture);
        let original_bytes = render_json(&report).expect("report");
        let mut manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &original_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");

        report.integrity.snapshot_sha256 = "f".repeat(64);
        let forged_report_bytes = render_json(&report).expect("forged report");
        refresh_report_bytes(&mut manifest, &forged_report_bytes);
        let forged_report_manifest = render_manifest(&manifest).expect("manifest");
        let verification = verify_manifest(&forged_report_manifest, &forged_report_bytes, None);
        assert_eq!(verification.status, ManifestVerificationStatus::Mismatch);
        assert_eq!(
            verification.detail,
            "report does not embed the manifest snapshot reference"
        );

        let report = input(&fixture);
        let report_bytes = render_json(&report).expect("report");
        let mut manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &report_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        manifest.records[0].sha256 = "f".repeat(64);
        let forged_record_manifest = render_manifest(&manifest).expect("manifest");
        let verification = verify_manifest(&forged_record_manifest, &report_bytes, None);
        assert_eq!(verification.status, ManifestVerificationStatus::Mismatch);
        assert_eq!(
            verification.detail,
            "manifest record digests do not match report records"
        );
    }

    #[test]
    fn verification_rejects_unsupported_report_schema_before_recomputation() {
        let fixture = fixture();
        let mut report = input(&fixture);
        let original_bytes = render_json(&report).expect("report");
        let mut manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &original_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        report.report_schema_version += 1;
        let unsupported_bytes = render_json(&report).expect("unsupported report");
        refresh_report_bytes(&mut manifest, &unsupported_bytes);
        let manifest_bytes = render_manifest(&manifest).expect("manifest");

        let verification = verify_manifest(&manifest_bytes, &unsupported_bytes, None);
        assert_eq!(verification.status, ManifestVerificationStatus::Unsupported);
        assert_eq!(verification.detail, "report schema version is unsupported");
    }

    #[test]
    fn static_html_verification_is_honest_about_record_coverage() {
        let fixture = fixture();
        let report = input(&fixture);
        let html = render_html(&report).expect("HTML report");
        let mut manifest = build_manifest(
            &report,
            "case.html",
            ReportFormat::Html,
            &html,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        let manifest_bytes = render_manifest(&manifest).expect("manifest bytes");

        let verification = verify_manifest(&manifest_bytes, &html, None);
        assert_eq!(verification.status, ManifestVerificationStatus::Unsupported);
        assert!(verification.detail.contains("cannot be recomputed"));

        let mut forged_html = String::from_utf8(html).expect("UTF-8 HTML");
        forged_html = forged_html.replacen(report.snapshot_sha256(), &"f".repeat(64), 1);
        refresh_report_bytes(&mut manifest, forged_html.as_bytes());
        let manifest_bytes = render_manifest(&manifest).expect("manifest bytes");
        let verification = verify_manifest(&manifest_bytes, forged_html.as_bytes(), None);
        assert_eq!(verification.status, ManifestVerificationStatus::Mismatch);
        assert_eq!(
            verification.detail,
            "HTML report does not embed the exact manifest snapshot reference"
        );
    }

    #[test]
    fn checked_in_schemas_match_and_validate_contract_snapshots() {
        let schemas = [
            ("evidence.schema.json", evidence_schema()),
            ("finding.schema.json", finding_schema()),
            ("report.schema.json", report_schema()),
            ("manifest.schema.json", manifest_schema()),
        ];
        if std::env::var_os("TRACEFORGE_UPDATE_SCHEMAS").is_some() {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
            for (name, schema) in &schemas {
                let mut bytes = serde_json::to_vec_pretty(schema).expect("schema JSON");
                bytes.push(b'\n');
                std::fs::write(root.join(name), bytes).expect("schema snapshot write");
            }
            return;
        }
        let checked = [
            include_str!("../../../schemas/evidence.schema.json"),
            include_str!("../../../schemas/finding.schema.json"),
            include_str!("../../../schemas/report.schema.json"),
            include_str!("../../../schemas/manifest.schema.json"),
        ];
        for ((name, generated), checked) in schemas.iter().zip(checked) {
            let checked: Value = serde_json::from_str(checked).expect("checked schema JSON");
            assert_eq!(&checked, generated, "stale schema snapshot: {name}");
        }

        let fixture = fixture();
        let report = input(&fixture);
        let report_value = serde_json::to_value(&report).expect("report value");
        jsonschema::validator_for(&report_schema())
            .expect("report schema")
            .validate(&report_value)
            .expect("valid report snapshot");
        let report_bytes = render_json(&report).expect("report bytes");
        let manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &report_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        jsonschema::validator_for(&manifest_schema())
            .expect("manifest schema")
            .validate(&serde_json::to_value(manifest).expect("manifest value"))
            .expect("valid manifest snapshot");
        jsonschema::validator_for(&evidence_schema())
            .expect("evidence schema")
            .validate(&serde_json::to_value(&fixture.evidence[0]).expect("evidence value"))
            .expect("valid evidence snapshot");
        jsonschema::validator_for(&finding_schema())
            .expect("finding schema")
            .validate(&serde_json::to_value(&fixture.findings[0]).expect("finding value"))
            .expect("valid finding snapshot");
    }

    #[test]
    fn normalized_domain_report_and_manifest_golden_is_stable() {
        let fixture = fixture();
        let report = input(&fixture);
        let report_bytes = render_json(&report).expect("report");
        let manifest = build_manifest(
            &report,
            "case.json",
            ReportFormat::Json,
            &report_bytes,
            ArtifactVerification::Verified,
        )
        .expect("manifest");
        let artifact_entity = Entity {
            id: EntityId::from_u128(1),
            case_id: fixture.case.id.clone(),
            entity_type: EntityType::Artifact,
            canonical_value: fixture.artifact.sha256.clone(),
            display_value: fixture.artifact.original_name.clone(),
            metadata: BTreeMap::from([("kind".to_owned(), json!("pe64"))]),
        };
        let import_entity = Entity {
            id: EntityId::from_u128(2),
            case_id: fixture.case.id.clone(),
            entity_type: EntityType::ImportedApi,
            canonical_value: "kernel32.dll!createfilew".to_owned(),
            display_value: "KERNEL32.dll!CreateFileW".to_owned(),
            metadata: BTreeMap::new(),
        };
        let edge = Edge {
            id: EdgeId::from_u128(1),
            source_entity_id: artifact_entity.id.clone(),
            target_entity_id: import_entity.id.clone(),
            relationship: Relationship::Imports,
            evidence_id: fixture.evidence[0].id.clone(),
            confidence: Confidence::new(1.0).expect("confidence"),
        };
        let event = EvidenceEvent {
            id: EventId::from_u128(1),
            case_id: fixture.case.id.clone(),
            timestamp_utc: "2026-08-25T10:00:02Z".to_owned(),
            timestamp_type: "application_generated".to_owned(),
            reliability: TimestampReliability::ApplicationGenerated,
            event_type: "analysis_completed".to_owned(),
            artifact_id: Some(fixture.artifact.id.clone()),
            evidence_id: None,
            summary: "Static analysis completed".to_owned(),
        };
        let evidence = fixture
            .evidence
            .iter()
            .map(|item| {
                json!({
                    "kind": item.kind,
                    "class": item.class.as_str(),
                    "locator": item.locator,
                    "value": item.value,
                    "preview_text": item.preview_text,
                })
            })
            .collect::<Vec<_>>();
        let findings = fixture.findings.iter().map(|finding| json!({
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity.as_str(),
            "confidence": (f64::from(finding.confidence.value()) * 100.0).round() / 100.0,
            "confidence_band": finding.confidence_band.as_str(),
            "state": finding.state.as_str(),
            "evidence_roles": fixture.links.iter().filter(|link| link.finding_id == finding.id).map(|link| link.role.as_str()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>();
        let mut record_type_counts = BTreeMap::<String, u64>::new();
        for record in &manifest.records {
            *record_type_counts
                .entry(record.record_type.clone())
                .or_default() += 1;
        }
        let entities = [artifact_entity, import_entity].map(|entity| {
            json!({
                "entity_type": entity.entity_type.as_str(),
                "canonical_value": entity.canonical_value,
                "display_value": entity.display_value,
                "metadata": entity.metadata,
            })
        });
        let golden = json!({
            "evidence": evidence,
            "findings": findings,
            "entities": entities,
            "edges": [json!({
                "relationship": edge.relationship.as_str(),
                "confidence": edge.confidence.value(),
            })],
            "events": [json!({
                "timestamp_type": event.timestamp_type,
                "reliability": event.reliability.as_str(),
                "event_type": event.event_type,
                "summary": event.summary,
            })],
            "report": {
                "schema_version": report.report_schema_version,
                "case_title": report.case.title,
                "artifact_kind": report.artifact.kind,
                "evidence_kinds": report.evidence_by_kind.iter().map(|group| group.kind.as_str()).collect::<Vec<_>>(),
                "finding_rules": report.findings.iter().map(|finding| finding.rule_id.as_str()).collect::<Vec<_>>(),
                "parameters_redacted": report.provenance.iter().all(|record| record.parameters_redacted),
                "methodology": report.methodology,
                "limitations": report.limitations,
            },
            "manifest": {
                "schema_version": manifest.manifest_schema_version,
                "hash_algorithm": manifest.hash_algorithm,
                "report_name": manifest.report.name,
                "report_format": manifest.report.format,
                "artifact_verification": manifest.artifact_verification,
                "record_type_counts": record_type_counts,
                "limitation": manifest.limitation,
            }
        });
        let checked: Value =
            serde_json::from_str(include_str!("../testdata/normalized-golden.json"))
                .expect("normalized golden JSON");
        assert_eq!(golden, checked);
    }

    #[test]
    #[ignore = "measurement only; run explicitly and compare environments, never as a PR gate"]
    fn measure_report_baseline() {
        let fixture = fixture();
        let report = input(&fixture);
        let iterations = 500;
        let started = std::time::Instant::now();
        let mut bytes = 0;
        for _ in 0..iterations {
            bytes += render_json(&report).expect("report benchmark").len();
        }
        println!(
            "{{\"benchmark\":\"report\",\"iterations\":{iterations},\"bytes\":{bytes},\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }
}
