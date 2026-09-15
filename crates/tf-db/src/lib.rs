#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use tf_model::{
    AnalysisRun, AnalysisRunId, AnalysisStatus, Artifact, ArtifactLocation, AttackMapping, Case,
    CaseId, CaseStatus, Evidence, Finding, FindingEvidence, FindingExplanation,
    FindingExplanationAttackMapping, FindingId, FindingSet, Provenance, ReportManifestRecord,
    ReportRecord, RuleRecord,
};
use thiserror::Error;

mod bookmarks;
mod investigator;
mod projection;
mod yara;
pub use bookmarks::MAX_BOOKMARK_LABEL_BYTES;
pub use investigator::{
    DeletedCaseObject, DeletedObject, MAX_CASE_TITLE_BYTES, MAX_NOTE_BYTES, MAX_SEARCH_QUERY_BYTES,
    MAX_SEARCH_RESULTS,
};
pub use yara::{DeletedYaraPack, StoredYaraPack};

const SCHEMA_VERSION: u32 = 11;
const INITIAL_MIGRATION: &str = include_str!("../migrations/001_initial.sql");
const FINDINGS_MIGRATION: &str = include_str!("../migrations/002_findings.sql");
const INVESTIGATOR_MIGRATION: &str = include_str!("../migrations/003_investigator.sql");
const YARA_MIGRATION: &str = include_str!("../migrations/004_yara.sql");
const ATTACK_MAPPINGS_MIGRATION: &str = include_str!("../migrations/005_attack_mappings.sql");
const INVESTIGATION_PROJECTIONS_MIGRATION: &str =
    include_str!("../migrations/006_investigation_projections.sql");
const BOOKMARKS_MIGRATION: &str = include_str!("../migrations/007_bookmarks.sql");
const REPORT_MANIFESTS_MIGRATION: &str = include_str!("../migrations/008_report_manifests.sql");
const PROJECTION_OWNERSHIP_MIGRATION: &str =
    include_str!("../migrations/009_projection_ownership.sql");
const FOREIGN_KEY_INDEXES_MIGRATION: &str =
    include_str!("../migrations/010_foreign_key_indexes.sql");
const CANONICAL_FINDING_STATES_MIGRATION: &str =
    include_str!("../migrations/011_canonical_finding_states.sql");
const MIGRATIONS: [&str; SCHEMA_VERSION as usize] = [
    INITIAL_MIGRATION,
    FINDINGS_MIGRATION,
    INVESTIGATOR_MIGRATION,
    YARA_MIGRATION,
    ATTACK_MAPPINGS_MIGRATION,
    INVESTIGATION_PROJECTIONS_MIGRATION,
    BOOKMARKS_MIGRATION,
    REPORT_MANIFESTS_MIGRATION,
    PROJECTION_OWNERSHIP_MIGRATION,
    FOREIGN_KEY_INDEXES_MIGRATION,
    CANONICAL_FINDING_STATES_MIGRATION,
];
const REQUIRED_TABLES: [&str; 25] = [
    "analysis_runs",
    "artifact_locations",
    "artifacts",
    "blobs",
    "bookmarks",
    "cases",
    "case_projections",
    "edges",
    "entities",
    "entity_evidence",
    "events",
    "evidence",
    "finding_evidence",
    "findings",
    "notes",
    "provenance",
    "projection_edges",
    "projection_entities",
    "projection_events",
    "reports",
    "report_manifests",
    "rules",
    "search_terms",
    "yara_pack_rules",
    "yara_packs",
];

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("case database failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("case database lock was poisoned")]
    LockPoisoned,
    #[error("SQLite WAL mode is required but unavailable")]
    WalUnavailable,
    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("database migration ended at schema version {found}; expected exactly {expected}")]
    SchemaVersionMismatch { found: u32, expected: u32 },
    #[error("database schema is incomplete or invalid: {0}")]
    InvalidSchema(String),
    #[error("database {check} failed: {detail}")]
    IntegrityCheck { check: &'static str, detail: String },
    #[error("analysis records have inconsistent case, artifact, run, or provenance identity")]
    IdentityMismatch,
    #[error("finding records have inconsistent rule, run, explanation, or evidence links")]
    FindingMismatch,
    #[error("analysis run has an invalid terminal status")]
    InvalidAnalysisStatus,
    #[error("report record has inconsistent case identity or unsupported metadata")]
    ReportMismatch,
    #[error("the requested record was not found")]
    NotFound,
    #[error("the requested value is invalid: {0}")]
    Validation(&'static str),
    #[error("the requested state transition is not allowed")]
    InvalidStateTransition,
    #[error("a YARA pack with this name and version has different content")]
    YaraPackIdentityConflict,
    #[error("the case has an active analysis run")]
    ActiveAnalysis,
    #[error("stored JSON could not be encoded: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseCaseAnalysis {
    pub case: Case,
    pub artifact: Artifact,
    pub analysis_run: Option<AnalysisRun>,
    pub provenances: Vec<Provenance>,
    pub evidence: Vec<Evidence>,
    pub rules: Vec<RuleRecord>,
    pub findings: Vec<Finding>,
    pub finding_evidence: Vec<FindingEvidence>,
    pub explanations: Vec<FindingExplanation>,
    pub attack_mappings: Vec<FindingExplanationAttackMapping>,
    pub run_history: Vec<AnalysisRun>,
}

type StoredFindings = (
    Vec<RuleRecord>,
    Vec<Finding>,
    Vec<FindingEvidence>,
    Vec<FindingExplanation>,
    Vec<FindingExplanationAttackMapping>,
);

#[derive(Debug)]
pub struct CaseDatabase {
    path: std::path::PathBuf,
    connection: Mutex<Connection>,
}

impl CaseDatabase {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref().to_path_buf();
        let mut connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DatabaseError::WalUnavailable);
        }
        connection.pragma_update(None, "synchronous", "FULL")?;

        let version = schema_version(&connection)?;
        if version > SCHEMA_VERSION {
            return Err(DatabaseError::UnsupportedSchemaVersion {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version < SCHEMA_VERSION {
            apply_migrations(&mut connection, &MIGRATIONS[version as usize..])?;
        }
        verify_database(&connection)?;

        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn checkpoint(&self) -> Result<(), DatabaseError> {
        let connection = self.lock()?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .map_err(Into::into)
    }

    pub fn insert_case_artifact(
        &self,
        case: &Case,
        artifact: &Artifact,
        location: &ArtifactLocation,
    ) -> Result<(), DatabaseError> {
        if artifact.case_id != case.id || location.artifact_id != artifact.id {
            return Err(DatabaseError::IdentityMismatch);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO cases
                (id, title, created_at, updated_at, app_version, schema_version, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                case.id.as_str(),
                case.title,
                case.created_at,
                case.updated_at,
                case.app_version,
                i64::from(case.schema_version),
                case.status.as_str()
            ],
        )?;
        transaction.execute(
            "INSERT INTO artifacts
                (id, case_id, parent_artifact_id, sha256, sha1, md5, size_bytes, kind, mime,
                 original_name, store_path, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                artifact.id.as_str(),
                artifact.case_id.as_str(),
                artifact.parent_artifact_id.as_ref().map(|id| id.as_str()),
                artifact.sha256,
                artifact.sha1,
                artifact.md5,
                sqlite_integer(artifact.size_bytes)?,
                artifact.kind.as_str(),
                artifact.mime,
                artifact.original_name,
                artifact.store_path,
                artifact.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO artifact_locations
                (id, artifact_id, display_name, source_path, modified_at_utc, created_at_utc,
                 ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                location.id.as_str(),
                location.artifact_id.as_str(),
                location.display_name,
                location.source_path,
                location.modified_at_utc,
                location.created_at_utc,
                location.ingested_at,
            ],
        )?;
        investigator::index_case_artifact(&transaction, case, artifact)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_completed_analysis(
        &self,
        case_id: &CaseId,
        run: &AnalysisRun,
        provenances: &[Provenance],
        evidence: &[Evidence],
        finding_set: &FindingSet,
        updated_at: &str,
    ) -> Result<(), DatabaseError> {
        if run.status != AnalysisStatus::Complete || run.finished_at.is_none() {
            return Err(DatabaseError::InvalidAnalysisStatus);
        }
        let provenance_ids = provenances
            .iter()
            .map(|record| &record.id)
            .collect::<BTreeSet<_>>();
        let primary_present = provenances.iter().any(|record| {
            record.analyzer == run.analyzer && record.analyzer_version == run.analyzer_version
        });
        let input_sha256 = provenances
            .first()
            .map(|record| record.input_sha256.as_str());
        if provenances.is_empty()
            || provenance_ids.len() != provenances.len()
            || !primary_present
            || provenances.iter().any(|record| {
                record.analysis_run_id != run.id
                    || !record
                        .input_sha256
                        .eq_ignore_ascii_case(input_sha256.unwrap_or_default())
            })
            || evidence.iter().any(|item| {
                item.artifact_id != run.artifact_id || !provenance_ids.contains(&item.provenance_id)
            })
        {
            return Err(DatabaseError::IdentityMismatch);
        }
        validate_finding_set(run, evidence, finding_set)?;
        let encoded_provenance = provenances
            .iter()
            .map(|record| serde_json::to_string(&record.parameters))
            .collect::<Result<Vec<_>, _>>()?;
        let encoded_evidence = evidence
            .iter()
            .map(|item| {
                Ok((
                    serde_json::to_string(&item.locator)?,
                    serde_json::to_string(&item.value)?,
                ))
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard_artifact_identity(&transaction, case_id, run, input_sha256)?;
        persist_terminal_analysis_run(&transaction, run)?;
        for (provenance, parameters_json) in provenances.iter().zip(encoded_provenance) {
            transaction.execute(
                "INSERT INTO provenance
                    (id, analysis_run_id, analyzer, analyzer_version, rule_id, rule_version,
                     rule_pack_sha256, input_sha256, parameters_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    provenance.id.as_str(),
                    provenance.analysis_run_id.as_str(),
                    provenance.analyzer,
                    provenance.analyzer_version,
                    provenance.rule_id,
                    provenance.rule_version,
                    provenance.rule_pack_sha256,
                    provenance.input_sha256,
                    parameters_json,
                ],
            )?;
        }
        for (item, (locator_json, value_json)) in evidence.iter().zip(encoded_evidence) {
            transaction.execute(
                "INSERT INTO evidence
                    (id, artifact_id, provenance_id, kind, class, locator_json, value_json,
                     preview_text)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    item.id.as_str(),
                    item.artifact_id.as_str(),
                    item.provenance_id.as_str(),
                    item.kind,
                    item.class.as_str(),
                    locator_json,
                    value_json,
                    item.preview_text,
                ],
            )?;
            investigator::index_evidence(&transaction, case_id, run, item)?;
        }
        for rule in &finding_set.rules {
            transaction.execute(
                "INSERT INTO rules (id, engine, rule_id, version, source, license, sha256, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(engine, rule_id, version) DO NOTHING",
                params![
                    rule.id.as_str(),
                    rule.engine,
                    rule.rule_id,
                    rule.version,
                    rule.source,
                    rule.license,
                    rule.sha256,
                    rule.enabled,
                ],
            )?;
            let exact: bool = transaction.query_row(
                "SELECT id = ?1 AND source = ?2 AND license = ?3 AND sha256 = ?4 AND enabled = ?5
                 FROM rules WHERE engine = ?6 AND rule_id = ?7 AND version = ?8",
                params![
                    rule.id.as_str(),
                    rule.source,
                    rule.license,
                    rule.sha256,
                    rule.enabled,
                    rule.engine,
                    rule.rule_id,
                    rule.version,
                ],
                |row| row.get(0),
            )?;
            if !exact {
                return Err(DatabaseError::FindingMismatch);
            }
        }
        let explanations = finding_set
            .explanations
            .iter()
            .map(|explanation| (explanation.finding_id.clone(), explanation))
            .collect::<BTreeMap<_, _>>();
        let attack_mappings = finding_set.attack_mappings.iter().fold(
            BTreeMap::<_, Vec<_>>::new(),
            |mut grouped, record| {
                grouped
                    .entry(record.finding_id.clone())
                    .or_default()
                    .push(record.mapping.clone());
                grouped
            },
        );
        for finding in &finding_set.findings {
            let explanation = explanations
                .get(&finding.id)
                .ok_or(DatabaseError::FindingMismatch)?;
            let attack_mappings_json = serde_json::to_string(
                attack_mappings
                    .get(&finding.id)
                    .map_or(&[][..], Vec::as_slice),
            )?;
            transaction.execute(
                "INSERT INTO findings
                    (id, artifact_id, rule_id, title, category, severity, confidence,
                     confidence_band, explanation_template_id, state, analysis_run_id,
                      rule_version, observation, why_it_matters, limitations, attack_mappings_json)
                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    finding.id.as_str(),
                    finding.artifact_id.as_str(),
                    finding.rule_id,
                    finding.title,
                    finding.category,
                    finding.severity.as_str(),
                    finding.confidence.value(),
                    finding.confidence_band.as_str(),
                    finding.explanation_template_id,
                    finding.state.as_str(),
                    finding.analysis_run_id.as_str(),
                    finding.rule_version,
                    explanation.observation,
                    explanation.why_it_matters,
                    explanation.limitations,
                    attack_mappings_json,
                ],
            )?;
            investigator::index_finding(&transaction, case_id, finding)?;
        }
        for link in &finding_set.evidence_links {
            transaction.execute(
                "INSERT INTO finding_evidence (finding_id, evidence_id, role)
                 VALUES (?1, ?2, ?3)",
                params![
                    link.finding_id.as_str(),
                    link.evidence_id.as_str(),
                    link.role.as_str(),
                ],
            )?;
        }
        update_case(&transaction, case_id, updated_at, CaseStatus::Complete)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_failed_analysis(
        &self,
        case_id: &CaseId,
        run: &AnalysisRun,
        updated_at: &str,
    ) -> Result<(), DatabaseError> {
        if !matches!(
            run.status,
            AnalysisStatus::Failed | AnalysisStatus::TimedOut | AnalysisStatus::ResourceLimit
        ) || run.finished_at.is_none()
            || run.error_code.is_none()
        {
            return Err(DatabaseError::InvalidAnalysisStatus);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard_artifact_identity(&transaction, case_id, run, None)?;
        persist_terminal_analysis_run(&transaction, run)?;
        update_case(&transaction, case_id, updated_at, CaseStatus::Error)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_case_analysis(
        &self,
        case_id: &CaseId,
    ) -> Result<Option<DatabaseCaseAnalysis>, DatabaseError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let case = transaction
            .query_row(
                "SELECT id, title, created_at, updated_at, app_version, schema_version, status
                 FROM cases WHERE id = ?1",
                params![case_id.as_str()],
                map_case,
            )
            .optional()?;
        let Some(case) = case else {
            transaction.commit()?;
            return Ok(None);
        };
        let artifact = transaction
            .query_row(
                "SELECT id, case_id, parent_artifact_id, sha256, sha1, md5, size_bytes, kind,
                        mime, original_name, store_path, created_at
                 FROM artifacts WHERE case_id = ?1
                 ORDER BY created_at ASC, id ASC LIMIT 1",
                params![case_id.as_str()],
                map_artifact,
            )
            .optional()?
            .ok_or(DatabaseError::IdentityMismatch)?;
        let analysis_run = transaction
            .query_row(
                "SELECT id, artifact_id, analyzer, analyzer_version, started_at, finished_at,
                        status, error_code
                 FROM analysis_runs WHERE artifact_id = ?1
                 ORDER BY julianday(started_at) DESC, id DESC LIMIT 1",
                params![artifact.id.as_str()],
                map_analysis_run,
            )
            .optional()?;
        let (provenances, evidence) = match &analysis_run {
            Some(run) => load_provenances_and_evidence(&transaction, run)?,
            None => (Vec::new(), Vec::new()),
        };
        let (rules, findings, finding_evidence, explanations, attack_mappings) = match &analysis_run
        {
            Some(run) if run.status == AnalysisStatus::Complete => {
                load_findings(&transaction, run)?
            }
            _ => (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        };
        let run_history = investigator::load_run_history(&transaction, &artifact.id)?;
        transaction.commit()?;
        Ok(Some(DatabaseCaseAnalysis {
            case,
            artifact,
            analysis_run,
            provenances,
            evidence,
            rules,
            findings,
            finding_evidence,
            explanations,
            attack_mappings,
            run_history,
        }))
    }

    pub fn get_case_analysis_run(
        &self,
        case_id: &CaseId,
        run_id: &AnalysisRunId,
    ) -> Result<Option<DatabaseCaseAnalysis>, DatabaseError> {
        investigator::get_case_analysis_run(self, case_id, run_id)
    }

    pub fn list_cases(&self) -> Result<Vec<Case>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, title, created_at, updated_at, app_version, schema_version, status
             FROM cases
             ORDER BY updated_at DESC, id DESC",
        )?;
        let rows = statement.query_map([], map_case)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn insert_report(&self, report: &ReportRecord) -> Result<(), DatabaseError> {
        if !matches!(report.format.as_str(), "json" | "html" | "pdf")
            || report.generated_at.is_empty()
            || report.path.is_empty()
            || report.sha256.len() != 64
            || !report.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DatabaseError::ReportMismatch);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "INSERT INTO reports (id, case_id, format, generated_at, path, sha256)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6
             WHERE EXISTS (SELECT 1 FROM cases WHERE id = ?2)",
            params![
                report.id.as_str(),
                report.case_id.as_str(),
                report.format,
                report.generated_at,
                report.path,
                report.sha256,
            ],
        )?;
        if changed != 1 {
            return Err(DatabaseError::ReportMismatch);
        }
        Ok(())
    }

    pub fn insert_report_bundle(
        &self,
        report: &ReportRecord,
        manifest: &ReportManifestRecord,
    ) -> Result<(), DatabaseError> {
        validate_report(report)?;
        validate_manifest(manifest)?;
        if manifest.report_id != report.id
            || manifest.case_id != report.case_id
            || manifest.generated_at != report.generated_at
        {
            return Err(DatabaseError::ReportMismatch);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_report_row(&transaction, report)?;
        let changed = transaction.execute(
            "INSERT INTO report_manifests(
                id, report_id, case_id, generated_at, path, schema_version,
                snapshot_sha256, manifest_sha256
             ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
               WHERE EXISTS (SELECT 1 FROM reports WHERE id = ?2 AND case_id = ?3)",
            params![
                manifest.id.as_str(),
                manifest.report_id.as_str(),
                manifest.case_id.as_str(),
                manifest.generated_at,
                manifest.path,
                i64::from(manifest.schema_version),
                manifest.snapshot_sha256,
                manifest.manifest_sha256,
            ],
        )?;
        if changed != 1 {
            return Err(DatabaseError::ReportMismatch);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_report_manifests(
        &self,
        case_id: &CaseId,
    ) -> Result<Vec<ReportManifestRecord>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, report_id, case_id, generated_at, path, schema_version,
                    snapshot_sha256, manifest_sha256
             FROM report_manifests WHERE case_id = ?1
             ORDER BY generated_at DESC, id DESC",
        )?;
        statement
            .query_map(params![case_id.as_str()], map_report_manifest_record)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn list_reports(&self, case_id: &CaseId) -> Result<Vec<ReportRecord>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, case_id, format, generated_at, path, sha256
             FROM reports WHERE case_id = ?1
             ORDER BY generated_at DESC, id DESC",
        )?;
        let rows = statement.query_map(params![case_id.as_str()], map_report_record)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn case_count(&self) -> Result<u64, DatabaseError> {
        let connection = self.lock()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM cases", [], |row| row.get(0))?;
        u64::try_from(count)
            .map_err(|_| DatabaseError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, count)))
    }

    /// Terminates only non-terminal runs left behind by a prior host process.
    pub fn recover_interrupted_analyses(&self, recovered_at: &str) -> Result<u64, DatabaseError> {
        if recovered_at.is_empty()
            || recovered_at.len() > 64
            || recovered_at.chars().any(char::is_control)
        {
            return Err(DatabaseError::Validation("recovery timestamp"));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let affected: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM analysis_runs WHERE status IN ('queued', 'running')",
            [],
            |row| row.get(0),
        )?;
        if affected != 0 {
            transaction.execute(
                "UPDATE cases
                 SET status = 'error', pre_archive_status = NULL, updated_at = ?1
                 WHERE EXISTS (
                     SELECT 1 FROM artifacts a JOIN analysis_runs r ON r.artifact_id = a.id
                     WHERE a.case_id = cases.id AND r.status IN ('queued', 'running')
                 )",
                params![recovered_at],
            )?;
            transaction.execute(
                "UPDATE analysis_runs
                 SET finished_at = ?1,
                     status = CASE status WHEN 'queued' THEN 'cancelled' ELSE 'failed' END,
                     error_code = 'host_interrupted'
                 WHERE status IN ('queued', 'running')",
                params![recovered_at],
            )?;
        }
        transaction.commit()?;
        u64::try_from(affected).map_err(|_| DatabaseError::InvalidAnalysisStatus)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, DatabaseError> {
        self.connection
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned)
    }
}

fn schema_version(connection: &Connection) -> Result<u32, DatabaseError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(Into::into)
}

fn apply_migrations(connection: &mut Connection, migrations: &[&str]) -> Result<(), DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for migration in migrations {
        transaction.execute_batch(migration)?;
    }
    verify_database(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), DatabaseError> {
    let version = schema_version(connection)?;
    if version != SCHEMA_VERSION {
        return Err(DatabaseError::SchemaVersionMismatch {
            found: version,
            expected: SCHEMA_VERSION,
        });
    }

    let tables = {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?
    };
    let missing = REQUIRED_TABLES
        .iter()
        .filter(|table| !tables.contains(**table))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(DatabaseError::InvalidSchema(format!(
            "missing required tables: {}",
            missing.join(", ")
        )));
    }
    let attack_mapping_column: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('findings')
            WHERE name = 'attack_mappings_json' AND type = 'TEXT' AND \"notnull\" = 1
         )",
        [],
        |row| row.get(0),
    )?;
    if !attack_mapping_column {
        return Err(DatabaseError::InvalidSchema(
            "findings.attack_mappings_json is missing or invalid".to_owned(),
        ));
    }
    let projection_columns_valid: bool = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM pragma_table_info('case_projections')) = 3
            AND (SELECT COUNT(*) FROM pragma_table_info('entity_evidence')) = 3
            AND (SELECT COUNT(*) FROM pragma_table_info('bookmarks')) = 7",
        [],
        |row| row.get(0),
    )?;
    if !projection_columns_valid {
        return Err(DatabaseError::InvalidSchema(
            "investigation projection tables are invalid".to_owned(),
        ));
    }
    let projection_triggers: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type = 'trigger' AND name IN (
            'entities_controlled_insert', 'entities_controlled_update',
            'edges_controlled_insert', 'edges_controlled_update',
            'events_controlled_insert', 'events_controlled_update'
         )",
        [],
        |row| row.get(0),
    )?;
    if projection_triggers != 6 {
        return Err(DatabaseError::InvalidSchema(
            "investigation projection vocabulary guards are missing".to_owned(),
        ));
    }

    let foreign_key_failure = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok(format!(
                "table {}, row {}, parent {}, constraint {}",
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?
            ))
        })
        .optional()?;
    if let Some(detail) = foreign_key_failure {
        return Err(DatabaseError::IntegrityCheck {
            check: "foreign_key_check",
            detail,
        });
    }

    let quick_check = {
        let mut statement = connection.prepare("PRAGMA quick_check")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    if quick_check.as_slice() != ["ok"] {
        return Err(DatabaseError::IntegrityCheck {
            check: "quick_check",
            detail: quick_check.join("; "),
        });
    }
    Ok(())
}

fn validate_finding_set(
    run: &AnalysisRun,
    evidence: &[Evidence],
    finding_set: &FindingSet,
) -> Result<(), DatabaseError> {
    let rule_keys = finding_set
        .rules
        .iter()
        .map(|rule| (rule.rule_id.as_str(), rule.version.as_str()))
        .collect::<BTreeSet<_>>();
    let evidence_ids = evidence
        .iter()
        .map(|item| &item.id)
        .collect::<BTreeSet<_>>();
    let finding_ids = finding_set
        .findings
        .iter()
        .map(|finding| &finding.id)
        .collect::<BTreeSet<_>>();
    let link_keys = finding_set
        .evidence_links
        .iter()
        .map(|link| (&link.finding_id, &link.evidence_id))
        .collect::<BTreeSet<_>>();
    let explanation_ids = finding_set
        .explanations
        .iter()
        .map(|explanation| &explanation.finding_id)
        .collect::<BTreeSet<_>>();
    let attack_mapping_keys = finding_set
        .attack_mappings
        .iter()
        .map(|record| (&record.finding_id, &record.mapping))
        .collect::<BTreeSet<_>>();
    let ordered_rules = finding_set
        .rules
        .windows(2)
        .all(|pair| (&pair[0].rule_id, &pair[0].version) < (&pair[1].rule_id, &pair[1].version));
    let ordered_findings = finding_set
        .findings
        .windows(2)
        .all(|pair| (&pair[0].rule_id, &pair[0].id) < (&pair[1].rule_id, &pair[1].id));
    let finding_order = finding_set
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (&finding.id, index))
        .collect::<BTreeMap<_, _>>();
    let ordered_links = finding_set.evidence_links.windows(2).all(|pair| {
        let left = (finding_order.get(&pair[0].finding_id), &pair[0].evidence_id);
        let right = (finding_order.get(&pair[1].finding_id), &pair[1].evidence_id);
        left < right
    });
    if rule_keys.len() != finding_set.rules.len()
        || finding_ids.len() != finding_set.findings.len()
        || link_keys.len() != finding_set.evidence_links.len()
        || explanation_ids.len() != finding_set.explanations.len()
        || finding_ids.len() != explanation_ids.len()
        || attack_mapping_keys.len() != finding_set.attack_mappings.len()
        || finding_set.attack_mappings.iter().any(|record| {
            !finding_ids.contains(&record.finding_id) || !valid_attack_mapping(&record.mapping)
        })
        || !ordered_rules
        || !ordered_findings
        || !ordered_links
    {
        return Err(DatabaseError::FindingMismatch);
    }
    for finding in &finding_set.findings {
        if finding.analysis_run_id != run.id
            || finding.artifact_id != run.artifact_id
            || !rule_keys.contains(&(finding.rule_id.as_str(), finding.rule_version.as_str()))
        {
            return Err(DatabaseError::FindingMismatch);
        }
        let links = finding_set
            .evidence_links
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .cloned()
            .collect::<Vec<_>>();
        let explanation = finding_set
            .explanations
            .iter()
            .find(|explanation| explanation.finding_id == finding.id)
            .ok_or(DatabaseError::FindingMismatch)?;
        if links.is_empty()
            || explanation.template_id != finding.explanation_template_id
            || explanation.supporting_evidence != links
        {
            return Err(DatabaseError::FindingMismatch);
        }
    }
    if finding_set.evidence_links.iter().any(|link| {
        !finding_ids.contains(&link.finding_id) || !evidence_ids.contains(&link.evidence_id)
    }) {
        return Err(DatabaseError::FindingMismatch);
    }
    Ok(())
}

fn load_findings(
    transaction: &Transaction<'_>,
    run: &AnalysisRun,
) -> Result<StoredFindings, DatabaseError> {
    let findings = {
        let mut statement = transaction.prepare(
            "SELECT id, analysis_run_id, artifact_id, rule_id, rule_version, title, category,
                    severity, confidence, confidence_band, explanation_template_id, state
             FROM findings WHERE analysis_run_id = ?1 ORDER BY rule_id ASC, id ASC",
        )?;
        let rows = statement.query_map(params![run.id.as_str()], map_finding)?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let finding_evidence = {
        let mut statement = transaction.prepare(
            "SELECT fe.finding_id, fe.evidence_id, fe.role
             FROM finding_evidence fe
             JOIN findings f ON f.id = fe.finding_id
             WHERE f.analysis_run_id = ?1
             ORDER BY f.rule_id ASC, f.id ASC, fe.evidence_id ASC",
        )?;
        let rows = statement.query_map(params![run.id.as_str()], map_finding_evidence)?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let explanations = {
        let mut statement = transaction.prepare(
            "SELECT id, explanation_template_id, observation, why_it_matters, limitations
             FROM findings WHERE analysis_run_id = ?1 ORDER BY rule_id ASC, id ASC",
        )?;
        let rows = statement.query_map(params![run.id.as_str()], |row| {
            let finding_id = row.get::<_, String>(0)?;
            let finding_id: FindingId = parse_text(0, &finding_id)?;
            Ok(FindingExplanation {
                supporting_evidence: finding_evidence
                    .iter()
                    .filter(|link| link.finding_id == finding_id)
                    .cloned()
                    .collect(),
                finding_id,
                template_id: row.get(1)?,
                observation: row.get(2)?,
                why_it_matters: row.get(3)?,
                limitations: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let attack_mappings = {
        let mut statement = transaction.prepare(
            "SELECT id, attack_mappings_json FROM findings
             WHERE analysis_run_id = ?1 ORDER BY rule_id ASC, id ASC",
        )?;
        let rows = statement.query_map(params![run.id.as_str()], |row| {
            let finding_id = row.get::<_, String>(0)?;
            let finding_id: FindingId = parse_text(0, &finding_id)?;
            let mappings = parse_json::<Vec<AttackMapping>>(1, &row.get::<_, String>(1)?)?;
            Ok(mappings
                .into_iter()
                .map(|mapping| FindingExplanationAttackMapping {
                    finding_id: finding_id.clone(),
                    mapping,
                })
                .collect::<Vec<_>>())
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect()
    };
    let rules = {
        let mut statement = transaction.prepare(
            "SELECT id, engine, rule_id, version, source, license, sha256, enabled
             FROM rules ORDER BY rule_id ASC, version ASC",
        )?;
        let rows = statement.query_map([], map_rule_record)?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    Ok((
        rules,
        findings,
        finding_evidence,
        explanations,
        attack_mappings,
    ))
}

fn valid_attack_mapping(mapping: &AttackMapping) -> bool {
    let suffix = mapping.technique_id.strip_prefix('T');
    suffix.is_some_and(|value| {
        let mut parts = value.split('.');
        parts
            .next()
            .is_some_and(|part| part.len() == 4 && part.bytes().all(|b| b.is_ascii_digit()))
            && parts
                .next()
                .is_none_or(|part| part.len() == 3 && part.bytes().all(|b| b.is_ascii_digit()))
            && parts.next().is_none()
    }) && !mapping.technique_name.trim().is_empty()
        && !mapping.tactic.trim().is_empty()
}

fn load_provenances_and_evidence(
    transaction: &Transaction<'_>,
    run: &AnalysisRun,
) -> Result<(Vec<Provenance>, Vec<Evidence>), DatabaseError> {
    let provenances = {
        let mut statement = transaction.prepare(
            "SELECT id, analysis_run_id, analyzer, analyzer_version, rule_id, rule_version,
                    rule_pack_sha256, input_sha256, parameters_json
             FROM provenance WHERE analysis_run_id = ?1 ORDER BY analyzer, rule_pack_sha256, id",
        )?;
        statement
            .query_map(params![run.id.as_str()], map_provenance)?
            .collect::<Result<Vec<_>, _>>()?
    };
    let evidence = {
        let mut statement = transaction.prepare(
            "SELECT e.id, e.artifact_id, e.provenance_id, e.kind, e.class, e.locator_json,
                    e.value_json, e.preview_text
             FROM evidence e
             JOIN provenance p ON p.id = e.provenance_id
             WHERE p.analysis_run_id = ?1
             ORDER BY p.analyzer, p.rule_pack_sha256, e.kind, e.id",
        )?;
        statement
            .query_map(params![run.id.as_str()], map_evidence)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok((provenances, evidence))
}

fn guard_artifact_identity(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
    run: &AnalysisRun,
    input_sha256: Option<&str>,
) -> Result<(), DatabaseError> {
    let artifact_sha256 = transaction
        .query_row(
            "SELECT sha256 FROM artifacts WHERE id = ?1 AND case_id = ?2",
            params![run.artifact_id.as_str(), case_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if artifact_sha256
        .as_deref()
        .is_none_or(|stored| input_sha256.is_some_and(|input| !stored.eq_ignore_ascii_case(input)))
    {
        return Err(DatabaseError::IdentityMismatch);
    }
    Ok(())
}

fn insert_analysis_run(
    transaction: &Transaction<'_>,
    run: &AnalysisRun,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "INSERT INTO analysis_runs
            (id, artifact_id, analyzer, analyzer_version, started_at, finished_at, status,
             error_code)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            run.id.as_str(),
            run.artifact_id.as_str(),
            run.analyzer,
            run.analyzer_version,
            run.started_at,
            run.finished_at,
            run.status.as_str(),
            run.error_code,
        ],
    )?;
    Ok(())
}

fn persist_terminal_analysis_run(
    transaction: &Transaction<'_>,
    run: &AnalysisRun,
) -> Result<(), DatabaseError> {
    let existing = transaction
        .query_row(
            "SELECT artifact_id, analyzer, analyzer_version, started_at, status
             FROM analysis_runs WHERE id = ?1",
            params![run.id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((artifact_id, analyzer, version, started_at, status)) = existing {
        if artifact_id != run.artifact_id.as_str()
            || analyzer != run.analyzer
            || version != run.analyzer_version
            || started_at != run.started_at
            || status != AnalysisStatus::Running.as_str()
        {
            return Err(DatabaseError::InvalidAnalysisStatus);
        }
        let changed = transaction.execute(
            "UPDATE analysis_runs
             SET finished_at = ?1, status = ?2, error_code = ?3
             WHERE id = ?4 AND status = 'running'",
            params![
                run.finished_at,
                run.status.as_str(),
                run.error_code,
                run.id.as_str()
            ],
        )?;
        if changed != 1 {
            return Err(DatabaseError::InvalidAnalysisStatus);
        }
        Ok(())
    } else {
        insert_analysis_run(transaction, run)?;
        Ok(())
    }
}

fn update_case(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
    updated_at: &str,
    status: CaseStatus,
) -> Result<(), DatabaseError> {
    let changed = transaction.execute(
        "UPDATE cases SET updated_at = ?1, status = ?2 WHERE id = ?3",
        params![updated_at, status.as_str(), case_id.as_str()],
    )?;
    if changed != 1 {
        return Err(DatabaseError::IdentityMismatch);
    }
    Ok(())
}

fn map_case(row: &Row<'_>) -> Result<Case, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let schema_version = row.get::<_, i64>(5)?;
    let status = row.get::<_, String>(6)?;
    Ok(Case {
        id: parse_text(0, &id)?,
        title: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
        app_version: row.get(4)?,
        schema_version: u32::try_from(schema_version)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, schema_version))?,
        status: parse_text(6, &status)?,
    })
}

fn map_artifact(row: &Row<'_>) -> Result<Artifact, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let case_id = row.get::<_, String>(1)?;
    let parent_id = row.get::<_, Option<String>>(2)?;
    let size_bytes = row.get::<_, i64>(6)?;
    let kind = row.get::<_, String>(7)?;
    Ok(Artifact {
        id: parse_text(0, &id)?,
        case_id: parse_text(1, &case_id)?,
        parent_artifact_id: parent_id
            .as_deref()
            .map(|value| parse_text(2, value))
            .transpose()?,
        sha256: row.get(3)?,
        sha1: row.get(4)?,
        md5: row.get(5)?,
        size_bytes: u64::try_from(size_bytes)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, size_bytes))?,
        kind: parse_text(7, &kind)?,
        mime: row.get(8)?,
        original_name: row.get(9)?,
        store_path: row.get(10)?,
        created_at: row.get(11)?,
    })
}

fn map_analysis_run(row: &Row<'_>) -> Result<AnalysisRun, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let artifact_id = row.get::<_, String>(1)?;
    let status = row.get::<_, String>(6)?;
    Ok(AnalysisRun {
        id: parse_text(0, &id)?,
        artifact_id: parse_text(1, &artifact_id)?,
        analyzer: row.get(2)?,
        analyzer_version: row.get(3)?,
        started_at: row.get(4)?,
        finished_at: row.get(5)?,
        status: parse_text(6, &status)?,
        error_code: row.get(7)?,
    })
}

fn map_provenance(row: &Row<'_>) -> Result<Provenance, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let analysis_run_id = row.get::<_, String>(1)?;
    let parameters = row.get::<_, String>(8)?;
    Ok(Provenance {
        id: parse_text(0, &id)?,
        analysis_run_id: parse_text(1, &analysis_run_id)?,
        analyzer: row.get(2)?,
        analyzer_version: row.get(3)?,
        rule_id: row.get(4)?,
        rule_version: row.get(5)?,
        rule_pack_sha256: row.get(6)?,
        input_sha256: row.get(7)?,
        parameters: parse_json(8, &parameters)?,
    })
}

fn map_evidence(row: &Row<'_>) -> Result<Evidence, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let artifact_id = row.get::<_, String>(1)?;
    let provenance_id = row.get::<_, String>(2)?;
    let class = row.get::<_, String>(4)?;
    let locator = row.get::<_, String>(5)?;
    let value = row.get::<_, String>(6)?;
    Ok(Evidence {
        id: parse_text(0, &id)?,
        artifact_id: parse_text(1, &artifact_id)?,
        provenance_id: parse_text(2, &provenance_id)?,
        kind: row.get(3)?,
        class: parse_text(4, &class)?,
        locator: parse_json(5, &locator)?,
        value: parse_json(6, &value)?,
        preview_text: row.get(7)?,
    })
}

fn map_finding(row: &Row<'_>) -> Result<Finding, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let analysis_run_id = row.get::<_, String>(1)?;
    let artifact_id = row.get::<_, String>(2)?;
    let severity = row.get::<_, String>(7)?;
    let confidence = row.get::<_, f32>(8)?;
    let confidence_band = row.get::<_, String>(9)?;
    let state = row.get::<_, String>(11)?;
    Ok(Finding {
        id: parse_text(0, &id)?,
        analysis_run_id: parse_text(1, &analysis_run_id)?,
        artifact_id: parse_text(2, &artifact_id)?,
        rule_id: row.get(3)?,
        rule_version: row.get(4)?,
        title: row.get(5)?,
        category: row.get(6)?,
        severity: parse_text(7, &severity)?,
        confidence: tf_model::Confidence::new(confidence).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Real,
                Box::new(error),
            )
        })?,
        confidence_band: parse_text(9, &confidence_band)?,
        explanation_template_id: row.get(10)?,
        state: parse_text(11, &state)?,
    })
}

fn map_finding_evidence(row: &Row<'_>) -> Result<FindingEvidence, rusqlite::Error> {
    let finding_id = row.get::<_, String>(0)?;
    let evidence_id = row.get::<_, String>(1)?;
    let role = row.get::<_, String>(2)?;
    Ok(FindingEvidence {
        finding_id: parse_text(0, &finding_id)?,
        evidence_id: parse_text(1, &evidence_id)?,
        role: parse_text(2, &role)?,
    })
}

fn map_rule_record(row: &Row<'_>) -> Result<RuleRecord, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    Ok(RuleRecord {
        id: parse_text(0, &id)?,
        engine: row.get(1)?,
        rule_id: row.get(2)?,
        version: row.get(3)?,
        source: row.get(4)?,
        license: row.get(5)?,
        sha256: row.get(6)?,
        enabled: row.get(7)?,
    })
}

fn map_report_record(row: &Row<'_>) -> Result<ReportRecord, rusqlite::Error> {
    let id = row.get::<_, String>(0)?;
    let case_id = row.get::<_, String>(1)?;
    Ok(ReportRecord {
        id: parse_text(0, &id)?,
        case_id: parse_text(1, &case_id)?,
        format: row.get(2)?,
        generated_at: row.get(3)?,
        path: row.get(4)?,
        sha256: row.get(5)?,
    })
}

fn map_report_manifest_record(row: &Row<'_>) -> Result<ReportManifestRecord, rusqlite::Error> {
    let schema_version = row.get::<_, i64>(5)?;
    Ok(ReportManifestRecord {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        report_id: parse_text(1, &row.get::<_, String>(1)?)?,
        case_id: parse_text(2, &row.get::<_, String>(2)?)?,
        generated_at: row.get(3)?,
        path: row.get(4)?,
        schema_version: u32::try_from(schema_version)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, schema_version))?,
        snapshot_sha256: row.get(6)?,
        manifest_sha256: row.get(7)?,
    })
}

fn validate_report(report: &ReportRecord) -> Result<(), DatabaseError> {
    if !matches!(report.format.as_str(), "json" | "html" | "pdf")
        || report.generated_at.is_empty()
        || report.path.is_empty()
        || !valid_sha256(&report.sha256)
    {
        Err(DatabaseError::ReportMismatch)
    } else {
        Ok(())
    }
}

fn validate_manifest(manifest: &ReportManifestRecord) -> Result<(), DatabaseError> {
    if manifest.generated_at.is_empty()
        || manifest.path.is_empty()
        || manifest.schema_version == 0
        || !valid_sha256(&manifest.snapshot_sha256)
        || !valid_sha256(&manifest.manifest_sha256)
    {
        Err(DatabaseError::ReportMismatch)
    } else {
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn insert_report_row(
    transaction: &Transaction<'_>,
    report: &ReportRecord,
) -> Result<(), DatabaseError> {
    let changed = transaction.execute(
        "INSERT INTO reports (id, case_id, format, generated_at, path, sha256)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6
         WHERE EXISTS (SELECT 1 FROM cases WHERE id = ?2)",
        params![
            report.id.as_str(),
            report.case_id.as_str(),
            report.format,
            report.generated_at,
            report.path,
            report.sha256,
        ],
    )?;
    if changed != 1 {
        return Err(DatabaseError::ReportMismatch);
    }
    Ok(())
}

fn sqlite_integer(value: u64) -> Result<i64, rusqlite::Error> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::ToSqlConversionFailure(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact size exceeds SQLite INTEGER range",
            )
            .into(),
        )
    })
}

fn parse_text<T>(column: usize, value: &str) -> Result<T, rusqlite::Error>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_json<T>(column: usize, value: &str) -> Result<T, rusqlite::Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use serde_json::json;
    use tf_model::{
        AnalysisRunId, AnalystNote, ArtifactId, ArtifactKind, ArtifactLocationId,
        CaseSearchRequest, EdgeId, EntityId, EventId, EvidenceId, FindingAction, FindingId,
        FindingState, NoteId, ObservationClass, ProvenanceId, ReportId, ReportManifestId,
        SearchField, YaraPack, YaraPackId, YaraRuleMetadata,
    };

    fn fixture() -> (Case, Artifact, ArtifactLocation) {
        let case_id = CaseId::new();
        let artifact_id = ArtifactId::new();
        let case = Case {
            id: case_id.clone(),
            title: "sample.exe".to_owned(),
            created_at: "2026-08-25T12:00:00Z".to_owned(),
            updated_at: "2026-08-25T12:00:00Z".to_owned(),
            app_version: "0.1.0".to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            case_id,
            parent_artifact_id: None,
            sha256: "a".repeat(64),
            sha1: "b".repeat(40),
            md5: "c".repeat(32),
            size_bytes: 128,
            kind: ArtifactKind::Pe64,
            mime: Some("application/vnd.microsoft.portable-executable".to_owned()),
            original_name: "sample.exe".to_owned(),
            store_path: "artifacts/objects/aa/aaaa".to_owned(),
            created_at: "2026-08-25T12:00:00Z".to_owned(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id,
            display_name: "sample.exe".to_owned(),
            source_path: Some(r"C:\evidence\sample.exe".to_owned()),
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: "2026-08-25T12:00:00Z".to_owned(),
        };
        (case, artifact, location)
    }

    fn analysis(artifact: &Artifact) -> (AnalysisRun, Provenance, Vec<Evidence>) {
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: "traceforge.pe".to_owned(),
            analyzer_version: "0.1.0".to_owned(),
            started_at: "2026-08-25T12:00:01Z".to_owned(),
            finished_at: Some("2026-08-25T12:00:02Z".to_owned()),
            status: AnalysisStatus::Complete,
            error_code: None,
        };
        let provenance = Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: run.id.clone(),
            analyzer: run.analyzer.clone(),
            analyzer_version: run.analyzer_version.clone(),
            rule_id: None,
            rule_version: None,
            rule_pack_sha256: None,
            input_sha256: artifact.sha256.clone(),
            parameters: BTreeMap::from([("operation".to_owned(), json!("pe_static"))]),
        };
        let evidence = vec![Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact.id.clone(),
            provenance_id: provenance.id.clone(),
            kind: "pe.header".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::from([("file_offset".to_owned(), json!(64))]),
            value: json!({"machine": 34404}),
            preview_text: Some("PE32+".to_owned()),
        }];
        (run, provenance, evidence)
    }

    #[test]
    #[ignore = "measurement only; run explicitly and compare environments, never as a PR gate"]
    fn measure_search_baseline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let request = CaseSearchRequest {
            query: "sample".to_owned(),
            fields: vec![SearchField::CaseTitle],
            include_archived: false,
            limit: 100,
        };
        let iterations = 1_000;
        let started = std::time::Instant::now();
        let mut hits = 0;
        for _ in 0..iterations {
            hits += database
                .search_cases(&request)
                .expect("search benchmark")
                .len();
        }
        println!(
            "{{\"benchmark\":\"search\",\"iterations\":{iterations},\"hits\":{hits},\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }

    #[test]
    fn completed_analysis_round_trips_multiple_analyzer_provenance_and_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, pe_provenance, mut evidence) = analysis(&artifact);
        let yara_provenance = Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: run.id.clone(),
            analyzer: "traceforge.yara-x".to_owned(),
            analyzer_version: "0.1.0".to_owned(),
            rule_id: None,
            rule_version: Some("2026.08".to_owned()),
            rule_pack_sha256: Some("d".repeat(64)),
            input_sha256: artifact.sha256.clone(),
            parameters: BTreeMap::new(),
        };
        evidence.push(Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact.id.clone(),
            provenance_id: yara_provenance.id.clone(),
            kind: "yara.match".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::new(),
            value: json!({"rule_identifier": "Demo"}),
            preview_text: Some("YARA rule matched".to_owned()),
        });
        database
            .persist_completed_analysis(
                &case.id,
                &run,
                &[pe_provenance.clone(), yara_provenance.clone()],
                &evidence,
                &FindingSet::default(),
                run.finished_at.as_deref().expect("finished"),
            )
            .expect("analysis");

        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("case");
        assert_eq!(stored.provenances.len(), 2);
        assert!(stored.provenances.contains(&pe_provenance));
        assert!(stored.provenances.contains(&yara_provenance));
        assert_eq!(stored.evidence, evidence);
    }

    #[test]
    fn yara_pack_crud_rejects_identity_conflicts_and_tracks_shared_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let rule = YaraRuleMetadata {
            namespace: "default".to_owned(),
            identifier: "Demo".to_owned(),
            tags: vec!["triage".to_owned()],
            metadata: json!({"author": "Artifacta"}),
        };
        let pack = YaraPack {
            id: YaraPackId::new(),
            sha256: "a".repeat(64),
            name: "demo".to_owned(),
            version: "1".to_owned(),
            source: "unit test".to_owned(),
            license: "Apache-2.0".to_owned(),
            imported_at: "2026-08-25T12:00:00Z".to_owned(),
            enabled: true,
            rule_count: 1,
        };
        let storage_path = format!("yara-packs/aa/{}.yar", pack.sha256);
        database
            .insert_yara_pack(&pack, std::slice::from_ref(&rule), &storage_path, 100)
            .expect("pack");
        let mut conflict = pack.clone();
        conflict.id = YaraPackId::new();
        conflict.sha256 = "b".repeat(64);
        assert!(matches!(
            database.insert_yara_pack(&conflict, std::slice::from_ref(&rule), "other", 100),
            Err(DatabaseError::YaraPackIdentityConflict)
        ));
        let mut shared = pack.clone();
        shared.id = YaraPackId::new();
        shared.name = "another-demo".to_owned();
        database
            .insert_yara_pack(&shared, std::slice::from_ref(&rule), &storage_path, 100)
            .expect("shared pack");
        assert_eq!(database.list_yara_packs().expect("packs").len(), 2);
        assert!(database.delete_yara_pack(&pack.id).expect("delete").shared);
        let deleted = database
            .delete_yara_pack(&shared.id)
            .expect("delete shared");
        assert!(!deleted.shared);
    }

    #[test]
    fn migration_enables_wal_and_transactional_intake() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();

        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("transaction");

        assert_eq!(database.case_count().expect("count"), 1);
        assert_eq!(database.list_cases().expect("cases"), vec![case]);
    }

    #[test]
    fn v11_canonicalizes_legacy_finding_states_and_adds_remaining_child_indexes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let database = CaseDatabase::open(&path).expect("current database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("case insert");
        drop(database);

        let finding_id = FindingId::new();
        let entity_id = EntityId::new();
        let connection = Connection::open(&path).expect("raw database");
        connection
            .execute(
                "INSERT INTO findings(
                    id, artifact_id, rule_id, title, category, severity, confidence,
                    confidence_band, explanation_template_id, state, analysis_run_id,
                    rule_version, observation, why_it_matters, limitations
                 ) VALUES (?1, ?2, 'legacy.rule', 'Legacy finding', 'legacy', 'low',
                           0.5, 'tentative', 'legacy', 'acknowledged', NULL, 'legacy',
                           'observation', 'why', 'limits')",
                params![finding_id.as_str(), artifact.id.as_str()],
            )
            .expect("legacy finding");
        connection
            .execute(
                "INSERT INTO entities(
                    id, case_id, entity_type, canonical_value, display_value, metadata_json
                 ) VALUES (?1, ?2, 'finding', ?3, 'Legacy finding', ?4)",
                params![
                    entity_id.as_str(),
                    case.id.as_str(),
                    finding_id.as_str(),
                    json!({"finding_id": finding_id.as_str(), "state": "acknowledged"}).to_string()
                ],
            )
            .expect("legacy finding entity");
        connection
            .pragma_update(None, "user_version", 10_u32)
            .expect("downgrade version marker");
        drop(connection);

        drop(CaseDatabase::open(&path).expect("v11 migration"));
        let connection = Connection::open(&path).expect("inspect migrated database");
        let state: String = connection
            .query_row(
                "SELECT state FROM findings WHERE id = ?1",
                [finding_id.as_str()],
                |row| row.get(0),
            )
            .expect("finding state");
        let entity_state: String = connection
            .query_row(
                "SELECT json_extract(metadata_json, '$.state') FROM entities WHERE id = ?1",
                [entity_id.as_str()],
                |row| row.get(0),
            )
            .expect("entity state");
        assert_eq!(state, "reviewed");
        assert_eq!(entity_state, "reviewed");
        for index in [
            "artifacts_parent_artifact_id",
            "case_projections_source_analysis_run_id",
            "reports_case_id",
        ] {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                    [index],
                    |row| row.get(0),
                )
                .expect("index lookup");
            assert_eq!(count, 1, "missing index {index}");
        }
    }

    #[test]
    fn migrates_a_version_four_database_to_attack_mapping_storage() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        connection.execute_batch(INITIAL_MIGRATION).expect("v1");
        connection.execute_batch(FINDINGS_MIGRATION).expect("v2");
        connection
            .execute_batch(INVESTIGATOR_MIGRATION)
            .expect("v3");
        connection.execute_batch(YARA_MIGRATION).expect("v4");
        drop(connection);

        let database = CaseDatabase::open(path).expect("current migration");
        let version: u32 = database
            .lock()
            .expect("connection")
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version");
        assert_eq!(version, SCHEMA_VERSION);
        let default_value: String = database
            .lock()
            .expect("connection")
            .query_row(
                "SELECT dflt_value FROM pragma_table_info('findings') WHERE name = 'attack_mappings_json'",
                [],
                |row| row.get(0),
            )
            .expect("mapping column");
        assert_eq!(default_value, "'[]'");
    }

    #[test]
    fn migrates_0_2_2_v5_without_discarding_legacy_investigation_rows() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        for migration in [
            INITIAL_MIGRATION,
            FINDINGS_MIGRATION,
            INVESTIGATOR_MIGRATION,
            YARA_MIGRATION,
            ATTACK_MAPPINGS_MIGRATION,
        ] {
            connection.execute_batch(migration).expect("v5 schema");
        }
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("foreign keys");
        let (mut case, artifact, _) = fixture();
        case.app_version = "0.2.2".to_owned();
        case.status = CaseStatus::Complete;
        let run_id = AnalysisRunId::new();
        let provenance_id = ProvenanceId::new();
        let evidence_id = EvidenceId::new();
        let finding_id = FindingId::new();
        let source_entity = EntityId::new();
        let target_entity = EntityId::new();
        let edge_id = EdgeId::new();
        let event_id = EventId::new();
        let note_id = NoteId::new();
        connection
            .execute(
                "INSERT INTO cases(
                    id, title, created_at, updated_at, app_version, schema_version, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    case.id.as_str(),
                    case.title,
                    case.created_at,
                    case.updated_at,
                    case.app_version,
                    case.schema_version,
                    case.status.as_str(),
                ],
            )
            .expect("legacy case");
        connection
            .execute(
                "INSERT INTO artifacts(
                    id, case_id, sha256, sha1, md5, size_bytes, kind, original_name,
                    store_path, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    artifact.id.as_str(),
                    artifact.case_id.as_str(),
                    artifact.sha256,
                    artifact.sha1,
                    artifact.md5,
                    artifact.size_bytes as i64,
                    artifact.kind.as_str(),
                    artifact.original_name,
                    artifact.store_path,
                    artifact.created_at,
                ],
            )
            .expect("legacy artifact");
        connection
            .execute(
                "INSERT INTO analysis_runs(
                    id, artifact_id, analyzer, analyzer_version, started_at, finished_at, status
                 ) VALUES (?1, ?2, 'traceforge.pe', '0.2.2', ?3, ?4, 'complete')",
                params![
                    run_id.as_str(),
                    artifact.id.as_str(),
                    "2026-08-25T12:00:01Z",
                    "2026-08-25T12:00:02Z"
                ],
            )
            .expect("legacy analysis run");
        connection
            .execute(
                "INSERT INTO provenance(
                    id, analysis_run_id, analyzer, analyzer_version, input_sha256, parameters_json
                 ) VALUES (?1, ?2, 'traceforge.pe', '0.2.2', ?3, '{}')",
                params![provenance_id.as_str(), run_id.as_str(), artifact.sha256],
            )
            .expect("legacy provenance");
        connection
            .execute(
                "INSERT INTO evidence(
                    id, artifact_id, provenance_id, kind, class, locator_json, value_json
                 ) VALUES (?1, ?2, ?3, 'legacy.observation', 'observed', '{}', '{\"value\":1}')",
                params![
                    evidence_id.as_str(),
                    artifact.id.as_str(),
                    provenance_id.as_str()
                ],
            )
            .expect("legacy evidence");
        connection
            .execute(
                "INSERT INTO findings(
                    id, artifact_id, rule_id, title, category, severity, confidence,
                    confidence_band, explanation_template_id, state, analysis_run_id,
                    rule_version, observation, why_it_matters, limitations, attack_mappings_json
                 ) VALUES (
                    ?1, ?2, 'legacy.rule', 'Legacy finding', 'legacy', 'low', 0.5,
                    'tentative', 'legacy.v1', 'open', ?3, '0.2.2', 'observed', 'matters',
                    'limited', '[]'
                 )",
                params![finding_id.as_str(), artifact.id.as_str(), run_id.as_str()],
            )
            .expect("legacy finding");
        connection
            .execute(
                "INSERT INTO finding_evidence(finding_id, evidence_id, role)
                 VALUES (?1, ?2, 'supports')",
                params![finding_id.as_str(), evidence_id.as_str()],
            )
            .expect("legacy finding evidence");
        connection
            .execute(
                "INSERT INTO entities(
                    id, case_id, entity_type, canonical_value, display_value, metadata_json
                 ) VALUES (?1, ?2, 'host', 'legacy-host', 'Legacy host', '{}'),
                          (?3, ?2, 'process', 'legacy-process', 'Legacy process', '{}')",
                params![
                    source_entity.as_str(),
                    case.id.as_str(),
                    target_entity.as_str()
                ],
            )
            .expect("legacy entities");
        connection
            .execute(
                "INSERT INTO edges(
                    id, source_entity_id, target_entity_id, relationship, evidence_id, confidence
                 ) VALUES (?1, ?2, ?3, 'derived_from', ?4, 0.75)",
                params![
                    edge_id.as_str(),
                    source_entity.as_str(),
                    target_entity.as_str(),
                    evidence_id.as_str()
                ],
            )
            .expect("legacy edge");
        connection
            .execute(
                "INSERT INTO notes(id, case_id, entity_id, finding_id, body, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'retain me', ?5, ?5)",
                params![
                    note_id.as_str(),
                    case.id.as_str(),
                    source_entity.as_str(),
                    finding_id.as_str(),
                    case.created_at,
                ],
            )
            .expect("legacy note");
        connection
            .execute(
                "INSERT INTO events(
                    id, case_id, timestamp_utc, timestamp_type, reliability, event_type, summary
                  ) VALUES (?1, ?2, ?3, 'legacy', 'application_recorded', 'legacy', 'retained')",
                params![event_id.as_str(), case.id.as_str(), case.created_at],
            )
            .expect("legacy event");
        drop(connection);

        let database = CaseDatabase::open(path).expect("current migration");
        assert_eq!(database.case_count().expect("raw case retained"), 1);
        assert_eq!(
            database
                .projection_cases_needing_rebuild(2)
                .expect("backfill candidates"),
            vec![case.id.clone()]
        );
        let connection = database.lock().expect("connection");
        for (table, expected) in [
            ("entities", 2_i64),
            ("edges", 1),
            ("events", 1),
            ("projection_entities", 0),
            ("projection_edges", 0),
            ("projection_events", 0),
            ("case_projections", 0),
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("migrated row count");
            assert_eq!(count, expected, "unexpected migrated rows in {table}");
        }
        let note_links: (Option<String>, Option<String>) = connection
            .query_row(
                "SELECT entity_id, finding_id FROM notes WHERE id = ?1",
                params![note_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("retained note");
        assert_eq!(note_links.0.as_deref(), Some(source_entity.as_str()));
        assert_eq!(note_links.1.as_deref(), Some(finding_id.as_str()));
        let finding_link: (String, String) = connection
            .query_row(
                "SELECT finding_id, evidence_id FROM finding_evidence",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("retained finding evidence");
        assert_eq!(finding_link.0, finding_id.as_str());
        assert_eq!(finding_link.1, evidence_id.as_str());
        assert!(
            connection
                .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
                .optional()
                .expect("foreign key check")
                .is_none()
        );
        drop(connection);
        let analysis = database
            .get_case_analysis(&case.id)
            .expect("analysis query")
            .expect("migrated case");
        assert_eq!(analysis.evidence.len(), 1);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.finding_evidence.len(), 1);
    }

    #[test]
    fn migrates_v6_projection_rows_and_marks_old_projection_versions_for_backfill() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        for migration in &MIGRATIONS[..6] {
            connection.execute_batch(migration).expect("v6 schema");
        }
        let (case, artifact, _) = fixture();
        connection
            .execute(
                "INSERT INTO cases(
                    id, title, created_at, updated_at, app_version, schema_version, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    case.id.as_str(),
                    case.title,
                    case.created_at,
                    case.updated_at,
                    case.app_version,
                    case.schema_version,
                    case.status.as_str(),
                ],
            )
            .expect("v6 case");
        connection
            .execute(
                "INSERT INTO artifacts(
                    id, case_id, sha256, sha1, md5, size_bytes, kind, original_name,
                    store_path, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    artifact.id.as_str(),
                    artifact.case_id.as_str(),
                    artifact.sha256,
                    artifact.sha1,
                    artifact.md5,
                    artifact.size_bytes as i64,
                    artifact.kind.as_str(),
                    artifact.original_name,
                    artifact.store_path,
                    artifact.created_at,
                ],
            )
            .expect("v6 artifact");
        let entity_id = EntityId::new();
        connection
            .execute(
                "INSERT INTO entities(
                    id, case_id, entity_type, canonical_value, display_value, metadata_json
                 ) VALUES (?1, ?2, 'artifact', ?3, 'sample.exe', '{}')",
                params![entity_id.as_str(), case.id.as_str(), artifact.sha256],
            )
            .expect("v6 projection entity");
        connection
            .execute(
                "INSERT INTO case_projections(case_id, projection_version)
                 VALUES (?1, 1)",
                params![case.id.as_str()],
            )
            .expect("v6 projection state");
        drop(connection);

        let database = CaseDatabase::open(path).expect("v7 migration");
        let graph = database
            .get_case_graph(&case.id)
            .expect("v6 graph query")
            .expect("v6 graph retained");
        assert_eq!(graph.entities[0].id, entity_id);
        let owned: i64 = database
            .lock()
            .expect("connection")
            .query_row(
                "SELECT COUNT(*) FROM projection_entities WHERE entity_id = ?1",
                params![entity_id.as_str()],
                |row| row.get(0),
            )
            .expect("projection ownership");
        assert_eq!(owned, 1);
        assert_eq!(
            database
                .projection_cases_needing_rebuild(2)
                .expect("projection backfill"),
            vec![case.id]
        );
        let bookmark_table: bool = database
            .lock()
            .expect("connection")
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'bookmarks'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("bookmark table");
        assert!(bookmark_table);
    }

    #[test]
    fn migrates_v7_to_report_manifest_storage_without_changing_existing_reports() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        for migration in &MIGRATIONS[..7] {
            connection.execute_batch(migration).expect("v7 schema");
        }
        let (case, artifact, _) = fixture();
        connection
            .execute(
                "INSERT INTO cases(
                    id, title, created_at, updated_at, app_version, schema_version, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    case.id.as_str(),
                    case.title,
                    case.created_at,
                    case.updated_at,
                    case.app_version,
                    case.schema_version,
                    case.status.as_str(),
                ],
            )
            .expect("v7 case");
        connection
            .execute(
                "INSERT INTO artifacts(
                    id, case_id, sha256, sha1, md5, size_bytes, kind, original_name,
                    store_path, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    artifact.id.as_str(),
                    artifact.case_id.as_str(),
                    artifact.sha256,
                    artifact.sha1,
                    artifact.md5,
                    artifact.size_bytes as i64,
                    artifact.kind.as_str(),
                    artifact.original_name,
                    artifact.store_path,
                    artifact.created_at,
                ],
            )
            .expect("v7 artifact");
        let report = ReportRecord {
            id: ReportId::new(),
            case_id: case.id.clone(),
            format: "json".to_owned(),
            generated_at: case.updated_at.clone(),
            path: "case.json".to_owned(),
            sha256: "d".repeat(64),
        };
        connection
            .execute(
                "INSERT INTO reports(id, case_id, format, generated_at, path, sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    report.id.as_str(),
                    report.case_id.as_str(),
                    report.format,
                    report.generated_at,
                    report.path,
                    report.sha256,
                ],
            )
            .expect("v7 report");
        drop(connection);

        let database = CaseDatabase::open(path).expect("v8 migration");
        assert_eq!(
            database.list_reports(&case.id).expect("reports"),
            vec![report]
        );
        assert!(
            database
                .list_report_manifests(&case.id)
                .expect("manifests")
                .is_empty()
        );
        assert_eq!(
            schema_version(&database.lock().unwrap()).unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn report_and_manifest_records_persist_atomically() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("case");
        let report = ReportRecord {
            id: ReportId::new(),
            case_id: case.id.clone(),
            format: "html".to_owned(),
            generated_at: case.created_at.clone(),
            path: "case.html".to_owned(),
            sha256: "a".repeat(64),
        };
        let manifest = ReportManifestRecord {
            id: ReportManifestId::new(),
            report_id: report.id.clone(),
            case_id: case.id.clone(),
            generated_at: report.generated_at.clone(),
            path: "case.manifest.json".to_owned(),
            schema_version: 1,
            snapshot_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
        };
        database
            .insert_report_bundle(&report, &manifest)
            .expect("bundle records");
        assert_eq!(database.list_reports(&case.id).unwrap(), vec![report]);
        assert_eq!(
            database.list_report_manifests(&case.id).unwrap(),
            vec![manifest]
        );
    }

    #[test]
    fn reopens_a_version_one_smoke_test_database() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        connection
            .execute_batch(INITIAL_MIGRATION)
            .expect("version one schema");
        drop(connection);

        let database = CaseDatabase::open(path).expect("compatible database");
        assert_eq!(database.case_count().expect("count"), 0);
        let version: u32 = database
            .lock()
            .expect("connection")
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version");
        assert_eq!(version, SCHEMA_VERSION);
        verify_database(&database.lock().expect("connection")).expect("integrity checks");
        for table in REQUIRED_TABLES {
            let present: bool = database
                .lock()
                .expect("connection")
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .expect("schema query");
            assert!(present, "missing migrated table {table}");
        }
    }

    #[test]
    fn migration_batch_rolls_back_a_deliberately_failed_fixture() {
        let mut connection = Connection::open_in_memory().expect("raw database");
        connection.execute_batch(INITIAL_MIGRATION).expect("v1");
        let failed = apply_migrations(
            &mut connection,
            &[
                FINDINGS_MIGRATION,
                "CREATE TABLE migration_fixture(value TEXT);\nINSERT INTO missing_table VALUES (1);\nPRAGMA user_version = 5;",
            ],
        );
        assert!(failed.is_err());
        assert_eq!(schema_version(&connection).expect("version"), 1);
        let added_column: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('findings') WHERE name = 'analysis_run_id')",
                [],
                |row| row.get(0),
            )
            .expect("column query");
        assert!(!added_column);
        let fixture_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'migration_fixture')",
                [],
                |row| row.get(0),
            )
            .expect("table query");
        assert!(!fixture_table);
    }

    #[test]
    fn open_rejects_unsupported_and_incomplete_current_schemas_clearly() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let newer_path = directory.path().join("newer.db");
        Connection::open(&newer_path)
            .expect("newer database")
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("newer version");
        assert!(matches!(
            CaseDatabase::open(newer_path),
            Err(DatabaseError::UnsupportedSchemaVersion { .. })
        ));

        let incomplete_path = directory.path().join("incomplete.db");
        Connection::open(&incomplete_path)
            .expect("incomplete database")
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .expect("current version marker");
        assert!(matches!(
            CaseDatabase::open(incomplete_path),
            Err(DatabaseError::InvalidSchema(_))
        ));
    }

    #[test]
    fn open_rejects_foreign_key_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("foreign-key.db");
        drop(CaseDatabase::open(&path).expect("database"));
        let connection = Connection::open(&path).expect("raw database");
        connection
            .pragma_update(None, "foreign_keys", false)
            .expect("disable fixture enforcement");
        connection
            .execute(
                "INSERT INTO artifact_locations(
                    id, artifact_id, display_name, source_path, modified_at_utc, created_at_utc,
                    ingested_at
                 ) VALUES (?1, ?2, 'dangling', NULL, NULL, NULL, '2026-08-25T12:00:00Z')",
                params![
                    ArtifactLocationId::new().as_str(),
                    ArtifactId::new().as_str()
                ],
            )
            .expect("dangling fixture");
        drop(connection);

        assert!(matches!(
            CaseDatabase::open(path),
            Err(DatabaseError::IntegrityCheck {
                check: "foreign_key_check",
                ..
            })
        ));
    }

    #[test]
    fn startup_recovery_is_transactional_and_preserves_terminal_runs() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (complete, provenance, evidence) = analysis(&artifact);
        database
            .persist_completed_analysis(
                &case.id,
                &complete,
                std::slice::from_ref(&provenance),
                &evidence,
                &FindingSet::default(),
                complete.finished_at.as_deref().expect("finished"),
            )
            .expect("terminal history");
        let queued_id = AnalysisRunId::new();
        let running_id = AnalysisRunId::new();
        database
            .lock()
            .expect("connection")
            .execute_batch(&format!(
                "INSERT INTO analysis_runs(id, artifact_id, analyzer, analyzer_version, started_at, status)
                 VALUES ('{}', '{}', 'queued-test', '1', '2026-08-25T12:01:00Z', 'queued');
                 INSERT INTO analysis_runs(id, artifact_id, analyzer, analyzer_version, started_at, status)
                 VALUES ('{}', '{}', 'running-test', '1', '2026-08-25T12:02:00Z', 'running');
                 UPDATE cases SET status = 'active' WHERE id = '{}';",
                queued_id.as_str(),
                artifact.id.as_str(),
                running_id.as_str(),
                artifact.id.as_str(),
                case.id.as_str(),
            ))
            .expect("interrupted fixtures");

        assert_eq!(
            database
                .recover_interrupted_analyses("2026-08-25T12:03:00Z")
                .expect("recovery"),
            2
        );
        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("case");
        assert_eq!(stored.case.status, CaseStatus::Error);
        assert_eq!(stored.case.updated_at, "2026-08-25T12:03:00Z");
        let queued = stored
            .run_history
            .iter()
            .find(|run| run.id == queued_id)
            .expect("queued history");
        assert_eq!(queued.status, AnalysisStatus::Cancelled);
        assert_eq!(queued.error_code.as_deref(), Some("host_interrupted"));
        let running = stored
            .run_history
            .iter()
            .find(|run| run.id == running_id)
            .expect("running history");
        assert_eq!(running.status, AnalysisStatus::Failed);
        assert_eq!(running.error_code.as_deref(), Some("host_interrupted"));
        let preserved = stored
            .run_history
            .iter()
            .find(|run| run.id == complete.id)
            .expect("terminal history");
        assert_eq!(preserved, &complete);
        assert_eq!(
            database
                .recover_interrupted_analyses("2026-08-25T12:04:00Z")
                .expect("idempotent recovery"),
            0
        );
    }

    #[test]
    fn migration_scopes_v1_findings_to_latest_completed_run_with_stable_ties() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        connection
            .execute_batch(INITIAL_MIGRATION)
            .expect("version one schema");
        let (case, artifact, _) = fixture();
        let older_run_id = AnalysisRunId::from_u128(1);
        let selected_run_id = AnalysisRunId::from_u128(2);
        let incomplete_run_id = AnalysisRunId::from_u128(3);
        let finding_id = FindingId::new();
        connection
            .execute(
                "INSERT INTO cases
                    (id, title, created_at, updated_at, app_version, schema_version, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    case.id.as_str(),
                    case.title,
                    case.created_at,
                    case.updated_at,
                    case.app_version,
                    case.schema_version,
                    CaseStatus::Complete.as_str(),
                ],
            )
            .expect("legacy case");
        connection
            .execute(
                "INSERT INTO artifacts
                    (id, case_id, sha256, sha1, md5, size_bytes, kind, mime, original_name,
                     store_path, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    artifact.id.as_str(),
                    artifact.case_id.as_str(),
                    artifact.sha256,
                    artifact.sha1,
                    artifact.md5,
                    i64::try_from(artifact.size_bytes).expect("fixture size"),
                    artifact.kind.as_str(),
                    artifact.mime,
                    artifact.original_name,
                    artifact.store_path,
                    artifact.created_at,
                ],
            )
            .expect("legacy artifact");
        connection
            .execute(
                "INSERT INTO analysis_runs
                    (id, artifact_id, analyzer, analyzer_version, started_at, finished_at,
                     status, error_code)
                 VALUES (?1, ?2, 'legacy', '1', ?3, ?4, 'complete', NULL),
                        (?5, ?2, 'legacy', '1', ?3, ?4, 'complete', NULL),
                        (?6, ?2, 'legacy', '1', ?7, NULL, 'running', NULL)",
                params![
                    older_run_id.as_str(),
                    artifact.id.as_str(),
                    "2026-08-25T12:00:01Z",
                    "2026-08-25T12:00:02Z",
                    selected_run_id.as_str(),
                    incomplete_run_id.as_str(),
                    "2026-08-25T13:00:00Z",
                ],
            )
            .expect("legacy runs");
        connection
            .execute(
                "INSERT INTO findings
                    (id, artifact_id, rule_id, title, category, severity, confidence,
                     confidence_band, explanation_template_id, state)
                 VALUES (?1, ?2, 'legacy.rule', 'Legacy observation', 'legacy', 'low', 0.5,
                         'tentative', 'legacy.v1', 'open')",
                params![finding_id.as_str(), artifact.id.as_str()],
            )
            .expect("legacy finding");
        drop(connection);

        let database = CaseDatabase::open(path).expect("migrated database");
        let stored = database
            .get_case_analysis_run(&case.id, &selected_run_id)
            .expect("query")
            .expect("case");
        assert_eq!(stored.findings.len(), 1);
        assert_eq!(stored.findings[0].id, finding_id);
        assert_eq!(stored.findings[0].analysis_run_id, selected_run_id);
        assert_eq!(stored.findings[0].rule_version, "legacy");
        assert_eq!(stored.explanations.len(), 1);
    }

    #[test]
    fn foreign_keys_and_identity_guards_roll_back_intake() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, mut artifact, location) = fixture();
        artifact.case_id = CaseId::new();

        assert!(matches!(
            database.insert_case_artifact(&case, &artifact, &location),
            Err(DatabaseError::IdentityMismatch)
        ));
        assert_eq!(database.case_count().expect("count"), 0);
    }

    #[test]
    fn completed_analysis_round_trips_exact_models() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, evidence) = analysis(&artifact);

        database
            .persist_completed_analysis(
                &case.id,
                &run,
                std::slice::from_ref(&provenance),
                &evidence,
                &FindingSet::default(),
                "2026-08-25T12:00:02Z",
            )
            .expect("analysis transaction");

        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("case analysis");
        assert_eq!(stored.artifact, artifact);
        assert_eq!(stored.analysis_run, Some(run));
        assert_eq!(stored.provenances, vec![provenance]);
        assert_eq!(stored.evidence, evidence);
        assert!(stored.rules.is_empty());
        assert!(stored.findings.is_empty());
        assert!(stored.finding_evidence.is_empty());
        assert!(stored.explanations.is_empty());
        assert_eq!(stored.case.status, CaseStatus::Complete);
        assert_eq!(stored.case.updated_at, "2026-08-25T12:00:02Z");
    }

    #[test]
    fn evidence_failure_rolls_back_the_whole_analysis_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence.push(evidence[0].clone());

        assert!(
            database
                .persist_completed_analysis(
                    &case.id,
                    &run,
                    std::slice::from_ref(&provenance),
                    &evidence,
                    &FindingSet::default(),
                    "2026-08-25T12:00:02Z",
                )
                .is_err()
        );
        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("acquired case remains");
        assert_eq!(stored.case.status, CaseStatus::Active);
        assert!(stored.analysis_run.is_none());
        assert!(stored.provenances.is_empty());
        assert!(stored.evidence.is_empty());
    }

    #[test]
    fn findings_rules_explanations_and_exact_links_round_trip() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence[0].kind = "pe.section".to_owned();
        evidence[0].value = json!({"name":"UPX0","entropy":7.8,"characteristics":0x60000020_u64});
        let finding_set = tf_rules::evaluate(&run.id, &artifact.id, &evidence);

        database
            .persist_completed_analysis(
                &case.id,
                &run,
                std::slice::from_ref(&provenance),
                &evidence,
                &finding_set,
                "2026-08-25T12:00:02Z",
            )
            .expect("analysis transaction");
        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("case analysis");

        assert_eq!(stored.rules, finding_set.rules);
        assert_eq!(stored.findings, finding_set.findings);
        assert_eq!(stored.finding_evidence, finding_set.evidence_links);
        assert_eq!(stored.explanations, finding_set.explanations);
    }

    #[test]
    fn finding_insert_failure_rolls_back_evidence_run_and_rule_registration() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence[0].kind = "pe.section".to_owned();
        evidence[0].value = json!({"name":"UPX0","entropy":7.8,"characteristics":0x60000020_u64});
        let mut finding_set = tf_rules::evaluate(&run.id, &artifact.id, &evidence);
        finding_set.rules[0].sha256 = "invalid".to_owned();

        assert!(
            database
                .persist_completed_analysis(
                    &case.id,
                    &run,
                    std::slice::from_ref(&provenance),
                    &evidence,
                    &finding_set,
                    "2026-08-25T12:00:02Z",
                )
                .is_err()
        );
        let stored = database
            .get_case_analysis(&case.id)
            .expect("query")
            .expect("case remains");
        assert_eq!(stored.case.status, CaseStatus::Active);
        assert!(stored.analysis_run.is_none());
        assert!(stored.evidence.is_empty());
        let rule_count: i64 = database
            .lock()
            .expect("connection")
            .query_row("SELECT COUNT(*) FROM rules", [], |row| row.get(0))
            .expect("rule count");
        assert_eq!(rule_count, 0);
    }

    #[test]
    fn report_records_insert_and_list_in_stable_order() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let older = ReportRecord {
            id: ReportId::new(),
            case_id: case.id.clone(),
            format: "json".to_owned(),
            generated_at: "2026-08-25T12:00:00Z".to_owned(),
            path: r"C:\reports\case.json".to_owned(),
            sha256: "a".repeat(64),
        };
        let newer = ReportRecord {
            id: ReportId::new(),
            case_id: case.id.clone(),
            format: "html".to_owned(),
            generated_at: "2026-08-25T13:00:00Z".to_owned(),
            path: r"C:\reports\case.html".to_owned(),
            sha256: "b".repeat(64),
        };
        database.insert_report(&older).expect("older report");
        database.insert_report(&newer).expect("newer report");

        assert_eq!(
            database.list_reports(&case.id).expect("reports"),
            vec![newer, older]
        );
    }

    #[test]
    fn invalid_report_insert_is_rejected_without_a_partial_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let report = ReportRecord {
            id: ReportId::new(),
            case_id: CaseId::new(),
            format: "pdf".to_owned(),
            generated_at: "2026-08-25T12:00:00Z".to_owned(),
            path: "case.pdf".to_owned(),
            sha256: "invalid".to_owned(),
        };

        assert!(matches!(
            database.insert_report(&report),
            Err(DatabaseError::ReportMismatch)
        ));
        assert!(
            database
                .list_reports(&report.case_id)
                .expect("reports")
                .is_empty()
        );
    }

    #[test]
    fn migrates_a_version_two_database_to_current_schema() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("case.db");
        let connection = Connection::open(&path).expect("raw database");
        connection
            .execute_batch(INITIAL_MIGRATION)
            .expect("version one schema");
        connection
            .execute_batch(FINDINGS_MIGRATION)
            .expect("version two schema");
        let (case, artifact, _) = fixture();
        connection
            .execute(
                "INSERT INTO cases(id, title, created_at, updated_at, app_version, schema_version, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    case.id.as_str(), case.title, case.created_at, case.updated_at,
                    case.app_version, case.schema_version, case.status.as_str()
                ],
            )
            .expect("legacy case");
        connection
            .execute(
                "INSERT INTO artifacts(id, case_id, sha256, sha1, md5, size_bytes, kind,
                                       original_name, store_path, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    artifact.id.as_str(),
                    artifact.case_id.as_str(),
                    artifact.sha256,
                    artifact.sha1,
                    artifact.md5,
                    artifact.size_bytes as i64,
                    artifact.kind.as_str(),
                    artifact.original_name,
                    artifact.store_path,
                    artifact.created_at
                ],
            )
            .expect("legacy artifact");
        drop(connection);

        let database = CaseDatabase::open(path).expect("v3 migration");
        let hits = database
            .search_cases(&CaseSearchRequest {
                query: "sample".to_owned(),
                fields: vec![SearchField::CaseTitle],
                include_archived: false,
                limit: 10,
            })
            .expect("materialized title search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].case_id, case.id);
        let version: u32 = database
            .lock()
            .expect("connection")
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version");
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn reanalysis_history_preserves_each_complete_run() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (first, first_provenance, first_evidence) = analysis(&artifact);
        database
            .persist_completed_analysis(
                &case.id,
                &first,
                std::slice::from_ref(&first_provenance),
                &first_evidence,
                &FindingSet::default(),
                "2026-08-25T12:00:02Z",
            )
            .expect("first run");
        let (mut second, mut second_provenance, mut second_evidence) = analysis(&artifact);
        second.started_at = "2026-08-25T13:00:01Z".to_owned();
        second.finished_at = Some("2026-08-25T13:00:02Z".to_owned());
        second_provenance.analysis_run_id = second.id.clone();
        second_evidence[0].provenance_id = second_provenance.id.clone();
        second_evidence[0].value = json!({"machine": 332});
        database
            .persist_completed_analysis(
                &case.id,
                &second,
                std::slice::from_ref(&second_provenance),
                &second_evidence,
                &FindingSet::default(),
                "2026-08-25T13:00:02Z",
            )
            .expect("second run");

        let latest = database
            .get_case_analysis(&case.id)
            .expect("latest")
            .expect("case");
        assert_eq!(
            latest.analysis_run.as_ref().map(|run| &run.id),
            Some(&second.id)
        );
        assert_eq!(latest.run_history, vec![second.clone(), first.clone()]);
        let historical = database
            .get_case_analysis_run(&case.id, &first.id)
            .expect("history query")
            .expect("historical run");
        assert_eq!(historical.analysis_run, Some(first));
        assert_eq!(historical.evidence, first_evidence);
    }

    #[test]
    fn deletion_refuses_active_runs_and_tracks_shared_objects() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let active = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: "traceforge.pe".to_owned(),
            analyzer_version: "1".to_owned(),
            started_at: "2026-08-25T12:00:01Z".to_owned(),
            finished_at: None,
            status: AnalysisStatus::Running,
            error_code: None,
        };
        database
            .start_analysis(&case.id, &active, &active.started_at)
            .expect("active run");
        assert!(matches!(
            database.delete_case_transactional(&case.id),
            Err(DatabaseError::ActiveAnalysis)
        ));
        let mut failed = active;
        failed.finished_at = Some("2026-08-25T12:00:02Z".to_owned());
        failed.status = AnalysisStatus::Failed;
        failed.error_code = Some("test".to_owned());
        database
            .persist_failed_analysis(&case.id, &failed, "2026-08-25T12:00:02Z")
            .expect("terminal run");

        let (mut other_case, mut other_artifact, mut other_location) = fixture();
        other_case.title = "copy.exe".to_owned();
        other_artifact.sha256 = artifact.sha256.clone();
        other_artifact.sha1 = artifact.sha1.clone();
        other_artifact.md5 = artifact.md5.clone();
        other_artifact.store_path = artifact.store_path.clone();
        other_location.artifact_id = other_artifact.id.clone();
        database
            .insert_case_artifact(&other_case, &other_artifact, &other_location)
            .expect("deduplicated case");
        let first = database
            .delete_case_transactional(&case.id)
            .expect("first delete");
        assert!(first.objects[0].shared);
        let second = database
            .delete_case_transactional(&other_case.id)
            .expect("last delete");
        assert!(!second.objects[0].shared);
        assert_eq!(database.case_count().expect("count"), 0);
    }

    #[test]
    fn materialized_search_covers_hash_import_indicator_and_evidence_values() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence[0].kind = "pe.import".to_owned();
        evidence[0].value = json!({"dll":"KERNEL32.dll","function":"CreateProcessW"});
        evidence.push(Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact.id.clone(),
            provenance_id: provenance.id.clone(),
            kind: "pe.indicator".to_owned(),
            class: ObservationClass::Inferred,
            locator: BTreeMap::new(),
            value: json!({"category":"domain","canonical_value":"example.test"}),
            preview_text: Some("example.test".to_owned()),
        });
        evidence.push(Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact.id.clone(),
            provenance_id: provenance.id.clone(),
            kind: "pe.authenticode".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::new(),
            value: json!({
                "pkcs7": {
                    "certificates": [{"subject":"CN=Artifacta Test CA"}],
                    "signers": [{"subject":"CN=Example Publisher"}]
                }
            }),
            preview_text: None,
        });
        database
            .persist_completed_analysis(
                &case.id,
                &run,
                std::slice::from_ref(&provenance),
                &evidence,
                &FindingSet::default(),
                "2026-08-25T12:00:02Z",
            )
            .expect("analysis");

        for (query, field) in [
            (&artifact.sha256[..12], SearchField::Sha256),
            ("kernel32", SearchField::Import),
            ("example.test", SearchField::Indicator),
            ("createprocess", SearchField::Import),
            ("cn=artifacta", SearchField::Certificate),
            ("cn=example", SearchField::Signer),
        ] {
            let hits = database
                .search_cases(&CaseSearchRequest {
                    query: query.to_owned(),
                    fields: vec![field],
                    include_archived: false,
                    limit: 10,
                })
                .expect("search");
            assert!(!hits.is_empty(), "missing {field:?} hit for {query}");
            assert_eq!(hits[0].case_id, case.id);
        }
        assert!(matches!(
            database.search_cases(&CaseSearchRequest {
                query: "x".repeat(257),
                fields: Vec::new(),
                include_archived: false,
                limit: 10,
            }),
            Err(DatabaseError::Validation(_))
        ));
    }

    #[test]
    fn indexed_search_and_materialized_record_growth_remain_bounded() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence[0].kind = "pe.string".to_owned();
        evidence[0].value = json!({
            "moderate_fixture": (0..512).map(|index| format!("bounded-{index:04}")).collect::<Vec<_>>()
        });
        database
            .persist_completed_analysis(
                &case.id,
                &run,
                std::slice::from_ref(&provenance),
                &evidence,
                &FindingSet::default(),
                "2026-08-25T12:00:02Z",
            )
            .expect("analysis");
        let indexed: i64 = database
            .lock()
            .expect("connection")
            .query_row(
                "SELECT COUNT(*) FROM search_terms WHERE evidence_id = ?1",
                params![evidence[0].id.as_str()],
                |row| row.get(0),
            )
            .expect("index count");
        assert_eq!(indexed, investigator::MAX_SCALARS_PER_EVIDENCE as i64);
        let hits = database
            .search_cases(&CaseSearchRequest {
                query: "bounded-".to_owned(),
                fields: vec![SearchField::EvidenceValue],
                include_archived: false,
                limit: MAX_SEARCH_RESULTS,
            })
            .expect("bounded search");
        assert_eq!(hits.len(), MAX_SEARCH_RESULTS as usize);

        let plan = {
            let connection = database.lock().expect("connection");
            let mut statement = connection
                .prepare(
                    "EXPLAIN QUERY PLAN
                     SELECT s.case_id FROM search_terms s JOIN cases c ON c.id = s.case_id
                     WHERE s.normalized_value >= ?1 AND s.normalized_value < ?2
                       AND s.field IN ('evidence_value') ORDER BY s.normalized_value LIMIT 100",
                )
                .expect("query plan");
            statement
                .query_map(params!["bounded-", "bounded-\u{10ffff}"], |row| {
                    row.get::<_, String>(3)
                })
                .expect("plan rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("plan details")
        };
        assert!(
            plan.iter()
                .any(|detail| detail.contains("search_terms_lookup")),
            "search index was not selected: {plan:?}"
        );
    }

    #[test]
    fn finding_transitions_and_note_crud_enforce_state_and_limits() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let (run, provenance, mut evidence) = analysis(&artifact);
        evidence[0].kind = "pe.section".to_owned();
        evidence[0].value = json!({"name":"UPX0","entropy":7.8,"characteristics":0x60000020_u64});
        let finding_set = tf_rules::evaluate(&run.id, &artifact.id, &evidence);
        database
            .persist_completed_analysis(
                &case.id,
                &run,
                std::slice::from_ref(&provenance),
                &evidence,
                &finding_set,
                "2026-08-25T12:00:02Z",
            )
            .expect("analysis");
        let finding_id = finding_set.findings[0].id.clone();
        let rule_hits = database
            .search_cases(&CaseSearchRequest {
                query: finding_set.findings[0].rule_id.clone(),
                fields: vec![SearchField::RuleId],
                include_archived: false,
                limit: 10,
            })
            .expect("rule search");
        assert!(!rule_hits.is_empty());
        let reviewed = database
            .transition_finding(
                &case.id,
                &finding_id,
                FindingAction::Review,
                "2026-08-25T12:01:00Z",
            )
            .expect("review");
        assert_eq!(reviewed.state, FindingState::Reviewed);
        assert!(matches!(
            database.transition_finding(
                &case.id,
                &finding_id,
                FindingAction::Review,
                "2026-08-25T12:02:00Z"
            ),
            Err(DatabaseError::InvalidStateTransition)
        ));
        let accepted = database
            .transition_finding(
                &case.id,
                &finding_id,
                FindingAction::Accept,
                "2026-08-25T12:03:00Z",
            )
            .expect("accept");
        assert_eq!(accepted.state, FindingState::Accepted);
        let dismissed = database
            .transition_finding(
                &case.id,
                &finding_id,
                FindingAction::Dismiss,
                "2026-08-25T12:04:00Z",
            )
            .expect("dismiss");
        assert_eq!(dismissed.state, FindingState::Dismissed);
        let reopened = database
            .transition_finding(
                &case.id,
                &finding_id,
                FindingAction::Reopen,
                "2026-08-25T12:05:00Z",
            )
            .expect("reopen");
        assert_eq!(reopened.state, FindingState::New);

        let note = AnalystNote {
            id: NoteId::new(),
            case_id: case.id.clone(),
            entity_id: None,
            finding_id: Some(finding_id),
            body: "reviewed evidence".to_owned(),
            created_at: "2026-08-25T12:05:00Z".to_owned(),
            updated_at: "2026-08-25T12:05:00Z".to_owned(),
        };
        database.create_note(&note).expect("create note");
        assert_eq!(
            database.list_notes(&case.id).expect("notes"),
            vec![note.clone()]
        );
        let updated = database
            .update_note(&case.id, &note.id, "updated", "2026-08-25T12:06:00Z")
            .expect("update note");
        assert_eq!(updated.body, "updated");
        database
            .delete_note(&case.id, &note.id, "2026-08-25T12:07:00Z")
            .expect("delete note");
        assert!(database.list_notes(&case.id).expect("notes").is_empty());
        let mut oversized = note;
        oversized.id = NoteId::new();
        oversized.body = "x".repeat(tf_db_max_note_bytes_for_test() + 1);
        assert!(matches!(
            database.create_note(&oversized),
            Err(DatabaseError::Validation(_))
        ));
    }

    fn tf_db_max_note_bytes_for_test() -> usize {
        crate::MAX_NOTE_BYTES
    }

    #[test]
    fn rename_archive_and_unarchive_validate_and_preserve_prior_status() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = CaseDatabase::open(directory.path().join("case.db")).expect("database");
        let (case, artifact, location) = fixture();
        database
            .insert_case_artifact(&case, &artifact, &location)
            .expect("intake");
        let renamed = database
            .rename_case(&case.id, "  Investigation 42  ", "2026-08-25T12:01:00Z")
            .expect("rename");
        assert_eq!(renamed.title, "Investigation 42");
        assert!(matches!(
            database.rename_case(&case.id, "   ", "2026-08-25T12:02:00Z"),
            Err(DatabaseError::Validation(_))
        ));
        let archived = database
            .archive_case(&case.id, "2026-08-25T12:03:00Z")
            .expect("archive");
        assert_eq!(archived.status, CaseStatus::Archived);
        assert!(matches!(
            database.archive_case(&case.id, "2026-08-25T12:04:00Z"),
            Err(DatabaseError::InvalidStateTransition)
        ));
        let restored = database
            .unarchive_case(&case.id, "2026-08-25T12:05:00Z")
            .expect("unarchive");
        assert_eq!(restored.status, CaseStatus::Active);
        assert!(matches!(
            database.unarchive_case(&case.id, "2026-08-25T12:06:00Z"),
            Err(DatabaseError::InvalidStateTransition)
        ));
    }
}
