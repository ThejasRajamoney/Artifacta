#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, TryLockError};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tf_db::{CaseDatabase, DatabaseCaseAnalysis, DatabaseError};
use tf_model::{
    AnalysisRun, AnalysisRunId, AnalysisStatus, AnalystNote, Artifact, ArtifactComparison,
    ArtifactId, ArtifactKind, ArtifactLocation, ArtifactLocationId, ArtifactSummary, Bookmark,
    BookmarkId, Case, CaseChronology, CaseGraph, CaseId, CaseSearchHit, CaseSearchRequest,
    CaseStatus, CleanupStatus, ComparisonDelta, ComparisonEntry, ComparisonGroup, ComparisonValue,
    DeleteCaseResult, EntityId, Evidence, Finding, FindingAction, FindingEvidence,
    FindingExplanation, FindingExplanationAttackMapping, FindingId, FindingSet,
    ManifestVerificationStatus, NavigationTarget, NoteId, ObjectCleanupResult, Provenance,
    ProvenanceId, QuickCheck, ReportId, ReportManifestId, ReportManifestRecord, ReportRecord,
    RuleRecord, YaraPack, YaraPackId,
};
use tf_pe::{ANALYZER_NAME, ANALYZER_VERSION, HostError, PeAnalysis, run_pe_analysis};
pub use tf_protocol::{
    AnalysisStage, Operation, PROTOCOL_VERSION, WorkerLimits, WorkerRequest, YaraOperation,
    YaraPackInput, YaraWorkerRequest,
};
pub use tf_report::ReportFormat;
use tf_report::{
    ArtifactVerification, ReportError, ReportInput, ReportSupplement, build_manifest, render_csv,
    render_html, render_json, render_manifest, render_stix, verify_manifest,
};
use tf_store::{ArtifactStore, CleanupOutcome, PeError, PeKind, StoreError, detect_pe};
use tf_yara::{
    MAX_RULE_MATCHES, MAX_STRING_INSTANCES_PER_MATCH, ValidatedPack, YaraAnalysis, YaraError,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod projection;

const PE_MIME_TYPE: &str = "application/vnd.microsoft.portable-executable";

type Analyzer = fn(WorkerRequest) -> Result<PeAnalysis, HostError>;
type YaraAnalyzer = fn(&YaraWorkerRequest) -> Result<YaraAnalysis, YaraError>;
type YaraValidator = fn(&YaraWorkerRequest) -> Result<ValidatedPack, YaraError>;

#[derive(Debug, Error)]
pub enum IntakeError {
    #[error("the selected file has no usable file name")]
    MissingFileName,
    #[error(transparent)]
    InvalidPe(#[from] PeError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("the source changed while it was being acquired")]
    SourceChanged,
    #[error("case service initialization failed: {0}")]
    Io(#[from] io::Error),
    #[error("a UTC timestamp could not be formatted")]
    Timestamp,
    #[error("case was not found")]
    CaseNotFound,
    #[error("stored artifact metadata is invalid")]
    InvalidStoredArtifact,
    #[error("stored YARA rule-pack metadata is invalid")]
    InvalidStoredYaraPack,
    #[error(transparent)]
    Yara(#[from] YaraError),
    #[error("case workflow lock was poisoned")]
    LockPoisoned,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("archive error: {0}")]
    Archive(String),
    #[error("structured log error: {0}")]
    StructuredLog(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportExportOptions {
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportBundleRecord {
    pub report: ReportRecord,
    pub manifest: ReportManifestRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportBundleVerification {
    pub status: ManifestVerificationStatus,
    pub detail: String,
    pub snapshot_sha256: Option<String>,
    pub artifact_verification: ArtifactVerification,
    pub safety_claim: bool,
}

#[derive(Debug, Error)]
pub enum ReportServiceError {
    #[error("case was not found")]
    CaseNotFound,
    #[error("report destination is invalid: {0}")]
    InvalidDestination(&'static str),
    #[error("report destination already exists")]
    DestinationExists,
    #[error("report destination contains a symbolic link or reparse point")]
    ReparsePoint,
    #[error("report destination cannot be represented as Unicode")]
    NonUnicodeDestination,
    #[error("the selected report format requires desktop rendering")]
    DesktopRenderingRequired,
    #[error("rendered report bytes do not match the selected format")]
    InvalidRenderedReport,
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    Report(#[from] ReportError),
    #[error("report file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("database persistence failed and file rollback also failed: {rollback}")]
    Rollback {
        database: DatabaseError,
        rollback: io::Error,
    },
    #[error("report file finalization failed and rollback also failed: {rollback}")]
    FileRollback {
        operation: io::Error,
        rollback: io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
    pub analysis_run: AnalysisRun,
}

#[derive(Debug)]
pub struct ArchiveIntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
    pub listing: tf_archive::ArchiveListing,
    pub child_cases: Vec<IntakeResult>,
}

#[derive(Debug)]
pub struct EvtxIntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
    pub analysis_run: AnalysisRun,
    pub evtx: tf_evtx::EvtxAnalysis,
}

#[derive(Debug)]
pub struct PcapIntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
    pub analysis_run: AnalysisRun,
    pub pcap: tf_pcap::PcapAnalysis,
}

#[derive(Debug)]
pub struct LogIntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
    pub analysis_run: AnalysisRun,
    pub log: tf_log::LogAnalysis,
}

#[derive(Debug)]
pub struct GenericIntakeResult {
    pub case: Case,
    pub artifact: Artifact,
    pub location: ArtifactLocation,
}

/// Persisted analysis details safe for host APIs. Original acquisition paths are not included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseAnalysis {
    pub case: Case,
    pub artifact: Artifact,
    pub analysis_run: Option<AnalysisRun>,
    /// Primary analyzer provenance retained for existing host projections.
    pub provenance: Option<Provenance>,
    pub provenances: Vec<Provenance>,
    pub evidence: Vec<Evidence>,
    pub rules: Vec<RuleRecord>,
    pub findings: Vec<Finding>,
    pub finding_evidence: Vec<FindingEvidence>,
    pub explanations: Vec<FindingExplanation>,
    pub attack_mappings: Vec<FindingExplanationAttackMapping>,
    pub run_history: Vec<AnalysisRun>,
    pub graph: Option<CaseGraph>,
    pub chronology: Option<CaseChronology>,
    pub notes: Vec<AnalystNote>,
    pub bookmarks: Vec<Bookmark>,
    pub quick_check: QuickCheck,
    pub yara_packs: Vec<YaraPack>,
}

impl From<DatabaseCaseAnalysis> for CaseAnalysis {
    fn from(value: DatabaseCaseAnalysis) -> Self {
        let provenance = value.analysis_run.as_ref().and_then(|run| {
            value
                .provenances
                .iter()
                .find(|record| {
                    record.analyzer == run.analyzer
                        && record.analyzer_version == run.analyzer_version
                })
                .cloned()
        });
        let quick_check =
            tf_rules::quick_check(&value.findings, &value.finding_evidence, &value.evidence);
        Self {
            case: value.case,
            artifact: value.artifact,
            analysis_run: value.analysis_run,
            provenance,
            provenances: value.provenances,
            evidence: value.evidence,
            rules: value.rules,
            findings: value.findings,
            finding_evidence: value.finding_evidence,
            explanations: value.explanations,
            attack_mappings: value.attack_mappings,
            run_history: value.run_history,
            graph: None,
            chronology: None,
            notes: Vec::new(),
            bookmarks: Vec::new(),
            quick_check,
            yara_packs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct CaseService {
    database: CaseDatabase,
    store: ArtifactStore,
    data_root: PathBuf,
    analyzer: Analyzer,
    yara_analyzer: YaraAnalyzer,
    yara_validator: YaraValidator,
    workflow: Mutex<()>,
}

impl CaseService {
    pub fn open(data_root: impl AsRef<Path>) -> Result<Self, IntakeError> {
        Self::open_with_analyzer(data_root, run_pe_analysis)
    }

    fn open_with_analyzer(
        data_root: impl AsRef<Path>,
        analyzer: Analyzer,
    ) -> Result<Self, IntakeError> {
        Self::open_with_analyzers(data_root, analyzer, tf_yara::scan, tf_yara::validate_pack)
    }

    fn open_with_analyzers(
        data_root: impl AsRef<Path>,
        analyzer: Analyzer,
        yara_analyzer: YaraAnalyzer,
        yara_validator: YaraValidator,
    ) -> Result<Self, IntakeError> {
        let data_root = data_root.as_ref().to_path_buf();
        fs::create_dir_all(&data_root)?;
        ensure_regular_directory(&data_root)?;
        prepare_staging_directory(&data_root.join("yara-staging"))?;
        prepare_staging_directory(&data_root.join("report-staging"))?;
        let database = CaseDatabase::open(data_root.join("traceforge.db"))?;
        let store = ArtifactStore::open(data_root.join("artifacts"))?;
        database.recover_interrupted_analyses(&now_rfc3339()?)?;
        let service = Self {
            database,
            store,
            data_root,
            analyzer,
            yara_analyzer,
            yara_validator,
            workflow: Mutex::new(()),
        };
        service.rebuild_stale_case_projections()?;
        Ok(service)
    }

    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn list_archive_entries(
        &self,
        source: impl AsRef<Path>,
    ) -> Result<tf_archive::ArchiveListing, IntakeError> {
        let source = source.as_ref();
        let bytes = fs::read(source)?;
        if !tf_archive::is_archive(&bytes) {
            return Err(IntakeError::InvalidPe(PeError::InvalidFormat));
        }
        let cursor = std::io::Cursor::new(bytes);
        tf_archive::list_archive(cursor).map_err(|e| IntakeError::Archive(e.to_string()))
    }

    pub fn ingest_archive(
        &self,
        source: impl AsRef<Path>,
    ) -> Result<ArchiveIntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let source = fs::canonicalize(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;

        let bytes = fs::read(&source)?;
        if !tf_archive::is_archive(&bytes) {
            return Err(IntakeError::InvalidPe(PeError::InvalidFormat));
        }

        let stored = self.store.ingest(&source)?;
        let archive_case_id = CaseId::new();
        let observed_at = now_rfc3339()?;
        let archive_case = Case {
            id: archive_case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let archive_artifact = Artifact {
            id: ArtifactId::new(),
            case_id: archive_case_id.clone(),
            parent_artifact_id: None,
            original_name: original_name.clone(),
            kind: ArtifactKind::Archive,
            mime: Some("application/zip".to_owned()),
            size_bytes: bytes.len() as u64,
            sha256: stored.sha256.clone(),
            sha1: stored.sha1.clone(),
            md5: stored.md5.clone(),
            store_path: stored.relative_path.clone(),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: archive_artifact.id.clone(),
            display_name: original_name.clone(),
            source_path: Some(source.to_string_lossy().into_owned()),
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: observed_at.clone(),
        };
        self.database
            .insert_case_artifact(&archive_case, &archive_artifact, &location)?;

        let mut pe_entries: Vec<(String, Vec<u8>)> = Vec::new();
        let cursor = std::io::Cursor::new(&bytes);
        let listing = tf_archive::extract_archive(cursor, |name, entry_bytes| {
            if entry_bytes.len() >= 4 && entry_bytes[0] == b'M' && entry_bytes[1] == b'Z' {
                pe_entries.push((name.to_owned(), entry_bytes.to_vec()));
            }
        })
        .map_err(|e| IntakeError::Archive(e.to_string()))?;
        drop(_workflow);

        let mut child_cases = Vec::new();
        for (_name, entry_bytes) in pe_entries {
            let temp = NamedTempFile::new();
            if let Ok(mut f) = temp {
                let _ = std::io::Write::write_all(&mut f, &entry_bytes);
                if let Ok(result) = self.ingest_pe(f.path()) {
                    child_cases.push(result);
                }
            }
        }

        Ok(ArchiveIntakeResult {
            case: archive_case,
            artifact: archive_artifact,
            location,
            listing,
            child_cases,
        })
    }

    pub fn ingest_evtx(&self, source: impl AsRef<Path>) -> Result<EvtxIntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let source = fs::canonicalize(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;

        let bytes = fs::read(&source)?;
        if !tf_evtx::is_evtx_bytes(&bytes) {
            return Err(IntakeError::InvalidPe(PeError::InvalidFormat));
        }

        let stored = self.store.ingest(&source)?;
        let case_id = CaseId::new();
        let observed_at = now_rfc3339()?;
        let case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            original_name: original_name.clone(),
            kind: ArtifactKind::WindowsEventLog,
            mime: Some("application/vnd.evtx".to_owned()),
            size_bytes: bytes.len() as u64,
            sha256: stored.sha256.clone(),
            sha1: stored.sha1.clone(),
            md5: stored.md5.clone(),
            store_path: stored.relative_path.clone(),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: original_name,
            source_path: Some(source.to_string_lossy().into_owned()),
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: observed_at,
        };
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;

        let analysis =
            tf_evtx::analyze_evtx_file(&source).map_err(|e| IntakeError::Archive(e.to_string()))?;

        let started_at = now_rfc3339()?;
        let finished_at = Some(now_rfc3339()?);
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: "tf-evtx".to_owned(),
            analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at,
            finished_at,
            status: AnalysisStatus::Complete,
            error_code: None,
        };
        self.database
            .start_analysis(&case_id, &run, &now_rfc3339()?)?;

        Ok(EvtxIntakeResult {
            case,
            artifact,
            location,
            analysis_run: run,
            evtx: analysis,
        })
    }

    pub fn ingest_pcap(&self, source: impl AsRef<Path>) -> Result<PcapIntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let source = fs::canonicalize(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;

        let bytes = fs::read(&source)?;
        if !tf_pcap::is_pcap_bytes(&bytes) {
            return Err(IntakeError::InvalidPe(PeError::InvalidFormat));
        }
        let is_pcapng = tf_pcap::is_pcapng_magic(&bytes);

        let stored = self.store.ingest(&source)?;
        let case_id = CaseId::new();
        let observed_at = now_rfc3339()?;
        let case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            original_name: original_name.clone(),
            kind: if is_pcapng {
                ArtifactKind::PcapNg
            } else {
                ArtifactKind::Pcap
            },
            mime: if is_pcapng {
                Some("application/vnd.tcpdump-pcap-ng".to_owned())
            } else {
                Some("application/vnd.tcpdump.pcap".to_owned())
            },
            size_bytes: bytes.len() as u64,
            sha256: stored.sha256.clone(),
            sha1: stored.sha1.clone(),
            md5: stored.md5.clone(),
            store_path: stored.relative_path.clone(),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: original_name,
            source_path: Some(source.to_string_lossy().into_owned()),
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: observed_at,
        };
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;

        let analysis =
            tf_pcap::analyze_pcap_file(&source).map_err(|e| IntakeError::Archive(e.to_string()))?;

        let started_at = now_rfc3339()?;
        let finished_at = Some(now_rfc3339()?);
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: "tf-pcap".to_owned(),
            analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at,
            finished_at,
            status: AnalysisStatus::Complete,
            error_code: None,
        };
        self.database
            .start_analysis(&case_id, &run, &now_rfc3339()?)?;

        Ok(PcapIntakeResult {
            case,
            artifact,
            location,
            analysis_run: run,
            pcap: analysis,
        })
    }

    pub fn ingest_log(&self, source: impl AsRef<Path>) -> Result<LogIntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let source = fs::canonicalize(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;

        let bytes = fs::read(&source)?;
        if bytes.is_empty() {
            return Err(IntakeError::StructuredLog("log file is empty".to_owned()));
        }

        let stored = self.store.ingest(&source)?;
        let case_id = CaseId::new();
        let observed_at = now_rfc3339()?;
        let case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            original_name: original_name.clone(),
            kind: ArtifactKind::StructuredLog,
            mime: Some("text/plain".to_owned()),
            size_bytes: bytes.len() as u64,
            sha256: stored.sha256.clone(),
            sha1: stored.sha1.clone(),
            md5: stored.md5.clone(),
            store_path: stored.relative_path.clone(),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: original_name,
            source_path: Some(source.to_string_lossy().into_owned()),
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: observed_at,
        };
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;

        let analysis = tf_log::analyze_log(bytes.as_slice(), None)
            .map_err(|e| IntakeError::StructuredLog(e.to_string()))?;

        let started_at = now_rfc3339()?;
        let finished_at = Some(now_rfc3339()?);
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: "tf-log".to_owned(),
            analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at,
            finished_at,
            status: AnalysisStatus::Complete,
            error_code: None,
        };
        self.database
            .start_analysis(&case_id, &run, &now_rfc3339()?)?;

        Ok(LogIntakeResult {
            case,
            artifact,
            location,
            analysis_run: run,
            log: analysis,
        })
    }

    pub fn ingest_generic(
        &self,
        source: impl AsRef<Path>,
    ) -> Result<GenericIntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let source = fs::canonicalize(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;

        let metadata = fs::metadata(&source)?;
        let stored = self.store.ingest(&source)?;
        let case_id = CaseId::new();
        let observed_at = now_rfc3339()?;
        let created_at = format_file_time(metadata.created().ok());
        let modified_at = format_file_time(metadata.modified().ok());

        let case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            original_name: original_name.clone(),
            kind: ArtifactKind::Other,
            mime: None,
            size_bytes: stored.size_bytes,
            sha256: stored.sha256.clone(),
            sha1: stored.sha1.clone(),
            md5: stored.md5.clone(),
            store_path: stored.relative_path.clone(),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: original_name,
            source_path: Some(source.to_string_lossy().into_owned()),
            modified_at_utc: modified_at,
            created_at_utc: created_at,
            ingested_at: observed_at,
        };
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;

        Ok(GenericIntakeResult {
            case,
            artifact,
            location,
        })
    }

    pub fn ingest_pe(&self, source: impl AsRef<Path>) -> Result<IntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let source = source.as_ref();
        let initial_kind = detect_pe(source)?;
        let source_path = fs::canonicalize(source)?;
        let metadata = fs::metadata(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;
        let observed_at = now_rfc3339()?;
        let created_at = format_file_time(metadata.created().ok());
        let modified_at = format_file_time(metadata.modified().ok());

        let stored = self.store.ingest(source)?;
        let immutable_path = self.store.absolute_path(&stored);
        let stored_kind = detect_pe(&immutable_path)?;
        if initial_kind != stored_kind {
            return Err(IntakeError::SourceChanged);
        }

        let case_id = CaseId::new();
        let artifact_id = ArtifactId::new();
        let mut case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            case_id,
            parent_artifact_id: None,
            sha256: stored.sha256,
            sha1: stored.sha1,
            md5: stored.md5,
            size_bytes: stored.size_bytes,
            kind: map_pe_kind(stored_kind),
            mime: Some(PE_MIME_TYPE.to_owned()),
            original_name: original_name.clone(),
            store_path: format!("artifacts/{}", stored.relative_path),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id,
            display_name: original_name,
            source_path: Some(source_path.to_string_lossy().into_owned()),
            modified_at_utc: modified_at,
            created_at_utc: created_at,
            ingested_at: observed_at,
        };

        // Acquisition is durable before untrusted parsing starts, so worker failure cannot erase it.
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;
        self.refresh_case_projection(&case.id)?;

        let started_at = now_rfc3339()?;
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            started_at,
            finished_at: None,
            status: AnalysisStatus::Running,
            error_code: None,
        };
        let run = self.execute_analysis(&case.id, &artifact, &immutable_path, run, &|_| {})?;
        case.updated_at = run
            .finished_at
            .clone()
            .ok_or(IntakeError::InvalidStoredArtifact)?;
        case.status = if run.status == AnalysisStatus::Complete {
            CaseStatus::Complete
        } else {
            CaseStatus::Error
        };

        Ok(IntakeResult {
            case,
            artifact,
            location,
            analysis_run: run,
        })
    }

    /// Ingests a PE file and reports analysis stage transitions via the callback.
    ///
    /// This is identical to [`ingest_pe`](Self::ingest_pe) but calls `on_stage` at each
    /// analysis transition so the host can display granular progress.
    pub fn ingest_pe_with_stages(
        &self,
        source: impl AsRef<Path>,
        on_stage: &dyn Fn(AnalysisStage),
    ) -> Result<IntakeResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        on_stage(AnalysisStage::Ingesting);
        let source = source.as_ref();
        let initial_kind = detect_pe(source)?;
        let source_path = fs::canonicalize(source)?;
        let metadata = fs::metadata(source)?;
        let original_name = source
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(IntakeError::MissingFileName)?;
        let observed_at = now_rfc3339()?;
        let created_at = format_file_time(metadata.created().ok());
        let modified_at = format_file_time(metadata.modified().ok());

        let stored = self.store.ingest(source)?;
        let immutable_path = self.store.absolute_path(&stored);
        let stored_kind = detect_pe(&immutable_path)?;
        if initial_kind != stored_kind {
            return Err(IntakeError::SourceChanged);
        }

        let case_id = CaseId::new();
        let artifact_id = ArtifactId::new();
        let mut case = Case {
            id: case_id.clone(),
            title: original_name.clone(),
            created_at: observed_at.clone(),
            updated_at: observed_at.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: 1,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            case_id,
            parent_artifact_id: None,
            sha256: stored.sha256,
            sha1: stored.sha1,
            md5: stored.md5,
            size_bytes: stored.size_bytes,
            kind: map_pe_kind(stored_kind),
            mime: Some(PE_MIME_TYPE.to_owned()),
            original_name: original_name.clone(),
            store_path: format!("artifacts/{}", stored.relative_path),
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id,
            display_name: original_name,
            source_path: Some(source_path.to_string_lossy().into_owned()),
            modified_at_utc: modified_at,
            created_at_utc: created_at,
            ingested_at: observed_at,
        };

        self.database
            .insert_case_artifact(&case, &artifact, &location)?;
        self.refresh_case_projection(&case.id)?;

        let started_at = now_rfc3339()?;
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            started_at,
            finished_at: None,
            status: AnalysisStatus::Running,
            error_code: None,
        };
        let run = self.execute_analysis(&case.id, &artifact, &immutable_path, run, on_stage)?;
        case.updated_at = run
            .finished_at
            .clone()
            .ok_or(IntakeError::InvalidStoredArtifact)?;
        case.status = if run.status == AnalysisStatus::Complete {
            CaseStatus::Complete
        } else {
            CaseStatus::Error
        };
        on_stage(AnalysisStage::Complete);

        Ok(IntakeResult {
            case,
            artifact,
            location,
            analysis_run: run,
        })
    }

    pub fn get_case_analysis(
        &self,
        case_id: &CaseId,
    ) -> Result<Option<CaseAnalysis>, DatabaseError> {
        self.database
            .get_case_analysis(case_id)?
            .map(|record| self.enrich_analysis(record))
            .transpose()
    }

    pub fn get_case_analysis_run(
        &self,
        case_id: &CaseId,
        run_id: &AnalysisRunId,
    ) -> Result<Option<CaseAnalysis>, DatabaseError> {
        self.database
            .get_case_analysis_run(case_id, run_id)?
            .map(|record| self.enrich_analysis(record))
            .transpose()
    }

    pub fn get_case_graph(&self, case_id: &CaseId) -> Result<Option<CaseGraph>, DatabaseError> {
        self.database.get_case_graph(case_id)
    }

    pub fn get_case_chronology(
        &self,
        case_id: &CaseId,
    ) -> Result<Option<CaseChronology>, DatabaseError> {
        self.database.get_case_chronology(case_id)
    }

    fn enrich_analysis(&self, record: DatabaseCaseAnalysis) -> Result<CaseAnalysis, DatabaseError> {
        let case_id = record.case.id.clone();
        let run_id = record.analysis_run.as_ref().map(|run| run.id.clone());
        let mut analysis = CaseAnalysis::from(record);
        analysis.graph = self
            .database
            .get_case_graph(&case_id)?
            .filter(|graph| graph.source_analysis_run_id.as_ref() == run_id.as_ref());
        analysis.chronology = self
            .database
            .get_case_chronology(&case_id)?
            .filter(|chronology| chronology.source_analysis_run_id.as_ref() == run_id.as_ref());
        analysis.notes = self.database.list_notes(&case_id)?;
        analysis.bookmarks = self.database.list_bookmarks(&case_id)?;
        let relevant_hashes = analysis
            .provenances
            .iter()
            .filter_map(|record| record.rule_pack_sha256.as_deref())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        analysis.yara_packs = self
            .database
            .list_yara_packs()?
            .into_iter()
            .filter(|pack| relevant_hashes.contains(&pack.sha256.to_ascii_lowercase()))
            .collect();
        Ok(analysis)
    }

    pub fn rebuild_case_projection(&self, case_id: &CaseId) -> Result<(), IntakeError> {
        self.refresh_case_projection(case_id).map_err(Into::into)
    }

    pub fn rename_case(&self, case_id: &CaseId, title: &str) -> Result<Case, IntakeError> {
        self.database
            .rename_case(case_id, title, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn archive_case(&self, case_id: &CaseId) -> Result<Case, IntakeError> {
        self.database
            .archive_case(case_id, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn unarchive_case(&self, case_id: &CaseId) -> Result<Case, IntakeError> {
        self.database
            .unarchive_case(case_id, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn delete_case(&self, case_id: &CaseId) -> Result<DeleteCaseResult, IntakeError> {
        let _workflow = match self.workflow.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(IntakeError::Database(DatabaseError::ActiveAnalysis));
            }
            Err(TryLockError::Poisoned(_)) => return Err(IntakeError::LockPoisoned),
        };
        let deleted = self.database.delete_case_transactional(case_id)?;
        let mut objects = Vec::with_capacity(deleted.objects.len());
        for object in deleted.objects {
            let (cleanup, cleanup_message) = if object.shared {
                (CleanupStatus::RetainedShared, None)
            } else if let Some(relative_path) = object.store_path.strip_prefix("artifacts/") {
                match self.store.remove_object(relative_path, &object.sha256) {
                    CleanupOutcome::Removed => (CleanupStatus::Removed, None),
                    CleanupOutcome::AlreadyMissing => (CleanupStatus::AlreadyMissing, None),
                    CleanupOutcome::Deferred(message) => (CleanupStatus::Deferred, Some(message)),
                }
            } else {
                (
                    CleanupStatus::Deferred,
                    Some("stored object path was not recognized".to_owned()),
                )
            };
            objects.push(ObjectCleanupResult {
                sha256: object.sha256,
                cleanup,
                cleanup_message,
            });
        }
        Ok(DeleteCaseResult {
            case_id: deleted.case_id,
            objects,
        })
    }

    pub fn transition_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
        action: FindingAction,
    ) -> Result<Finding, IntakeError> {
        self.database
            .transition_finding(case_id, finding_id, action, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn acknowledge_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
    ) -> Result<Finding, IntakeError> {
        self.transition_finding(case_id, finding_id, FindingAction::Review)
    }

    pub fn accept_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
    ) -> Result<Finding, IntakeError> {
        self.transition_finding(case_id, finding_id, FindingAction::Accept)
    }

    pub fn dismiss_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
    ) -> Result<Finding, IntakeError> {
        self.transition_finding(case_id, finding_id, FindingAction::Dismiss)
    }

    pub fn reopen_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
    ) -> Result<Finding, IntakeError> {
        self.transition_finding(case_id, finding_id, FindingAction::Reopen)
    }

    pub fn create_note(
        &self,
        case_id: &CaseId,
        entity_id: Option<EntityId>,
        finding_id: Option<FindingId>,
        body: impl Into<String>,
    ) -> Result<AnalystNote, IntakeError> {
        let timestamp = now_rfc3339()?;
        let note = AnalystNote {
            id: NoteId::new(),
            case_id: case_id.clone(),
            entity_id,
            finding_id,
            body: body.into(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
        };
        self.database.create_note(&note)?;
        Ok(note)
    }

    pub fn update_note(
        &self,
        case_id: &CaseId,
        note_id: &NoteId,
        body: &str,
    ) -> Result<AnalystNote, IntakeError> {
        self.database
            .update_note(case_id, note_id, body, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn delete_note(&self, case_id: &CaseId, note_id: &NoteId) -> Result<(), IntakeError> {
        self.database
            .delete_note(case_id, note_id, &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn list_notes(&self, case_id: &CaseId) -> Result<Vec<AnalystNote>, DatabaseError> {
        self.database.list_notes(case_id)
    }

    pub fn create_bookmark(
        &self,
        case_id: &CaseId,
        target: NavigationTarget,
        label: Option<String>,
    ) -> Result<Bookmark, IntakeError> {
        let timestamp = now_rfc3339()?;
        let bookmark = Bookmark {
            id: BookmarkId::new(),
            case_id: case_id.clone(),
            target,
            label: normalize_bookmark_label(label),
            created_at: timestamp.clone(),
            updated_at: timestamp,
        };
        self.database.insert_bookmark(&bookmark)?;
        Ok(bookmark)
    }

    pub fn get_bookmark(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
    ) -> Result<Option<Bookmark>, DatabaseError> {
        self.database.get_bookmark(case_id, bookmark_id)
    }

    pub fn list_bookmarks(&self, case_id: &CaseId) -> Result<Vec<Bookmark>, DatabaseError> {
        self.database.list_bookmarks(case_id)
    }

    pub fn update_bookmark_label(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
        label: Option<String>,
    ) -> Result<Bookmark, IntakeError> {
        let label = normalize_bookmark_label(label);
        self.database
            .update_bookmark_label(case_id, bookmark_id, label.as_deref(), &now_rfc3339()?)
            .map_err(Into::into)
    }

    pub fn delete_bookmark(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
    ) -> Result<(), IntakeError> {
        self.database
            .delete_bookmark(case_id, bookmark_id)
            .map_err(Into::into)
    }

    pub fn search_cases(
        &self,
        request: &CaseSearchRequest,
    ) -> Result<Vec<CaseSearchHit>, DatabaseError> {
        self.database.search_cases(request)
    }

    pub fn reanalyze_case(&self, case_id: &CaseId) -> Result<AnalysisRun, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let artifact = self
            .database
            .artifact_for_case(case_id)?
            .ok_or(IntakeError::CaseNotFound)?;
        let relative_path = artifact
            .store_path
            .strip_prefix("artifacts/")
            .ok_or(IntakeError::InvalidStoredArtifact)?;
        let immutable_path =
            self.store
                .resolve_object(relative_path, &artifact.sha256, artifact.size_bytes)?;
        let started_at = now_rfc3339()?;
        let run = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            started_at: started_at.clone(),
            finished_at: None,
            status: AnalysisStatus::Running,
            error_code: None,
        };
        self.execute_analysis(case_id, &artifact, &immutable_path, run, &|_| {})
    }

    /// Imports a local YARA source file after compiling it in a contained disposable worker.
    pub fn import_yara_pack(
        &self,
        source_path: impl AsRef<Path>,
        name: impl Into<String>,
        version: impl Into<String>,
        source: impl Into<String>,
        license: impl Into<String>,
    ) -> Result<YaraPack, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let bytes = read_bounded_yara_source(source_path.as_ref())?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let staging_root = self.data_root.join("yara-staging");
        fs::create_dir_all(&staging_root)?;
        let mut staging = NamedTempFile::new_in(&staging_root)?;
        staging.write_all(&bytes)?;
        staging.as_file_mut().sync_all()?;
        let id = YaraPackId::new();
        let input = YaraPackInput {
            id: id.clone(),
            sha256: sha256.clone(),
            source_path: staging.path().to_string_lossy().into_owned(),
            name: name.into(),
            version: version.into(),
            source: source.into(),
            license: license.into(),
        };
        let validation_request = YaraWorkerRequest {
            protocol: PROTOCOL_VERSION,
            job_id: id.as_str().to_owned(),
            operation: YaraOperation::Validate,
            analysis_run_id: AnalysisRunId::new(),
            artifact_id: ArtifactId::new(),
            artifact_path: None,
            input_sha256: None,
            packs: vec![input.clone()],
            limits: WorkerLimits::default(),
            max_rule_matches: MAX_RULE_MATCHES,
            max_string_instances_per_match: MAX_STRING_INSTANCES_PER_MATCH,
        };
        let validated = (self.yara_validator)(&validation_request)?;
        if validated.pack_sha256 != sha256 || validated.rules.is_empty() {
            return Err(IntakeError::InvalidStoredYaraPack);
        }

        let relative_path = format!("yara-packs/{}/{sha256}.yar", &sha256[..2]);
        let final_path = self
            .data_root
            .join(relative_path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let parent = final_path
            .parent()
            .ok_or(IntakeError::InvalidStoredYaraPack)?;
        fs::create_dir_all(parent)?;
        let created = if final_path.exists() {
            let existing = read_bounded_yara_source(&final_path)?;
            if existing != bytes {
                return Err(IntakeError::InvalidStoredYaraPack);
            }
            false
        } else {
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.write_all(&bytes)?;
            temporary.as_file_mut().sync_all()?;
            match temporary.persist_noclobber(&final_path) {
                Ok(_) => true,
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = read_bounded_yara_source(&final_path)?;
                    if existing != bytes {
                        return Err(IntakeError::InvalidStoredYaraPack);
                    }
                    false
                }
                Err(error) => return Err(IntakeError::Io(error.error)),
            }
        };
        let pack = YaraPack {
            id,
            sha256,
            name: input.name,
            version: input.version,
            source: input.source,
            license: input.license,
            imported_at: now_rfc3339()?,
            enabled: true,
            rule_count: u32::try_from(validated.rules.len())
                .map_err(|_| IntakeError::InvalidStoredYaraPack)?,
        };
        if let Err(error) = self.database.insert_yara_pack(
            &pack,
            &validated.rules,
            &relative_path,
            bytes.len() as u64,
        ) {
            if created {
                let _ = fs::remove_file(&final_path);
            }
            return Err(error.into());
        }
        Ok(pack)
    }

    pub fn list_yara_packs(&self) -> Result<Vec<YaraPack>, DatabaseError> {
        self.database.list_yara_packs()
    }

    pub fn set_yara_pack_enabled(
        &self,
        pack_id: &YaraPackId,
        enabled: bool,
    ) -> Result<YaraPack, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        self.database
            .set_yara_pack_enabled(pack_id, enabled)
            .map_err(Into::into)
    }

    pub fn delete_yara_pack(
        &self,
        pack_id: &YaraPackId,
    ) -> Result<ObjectCleanupResult, IntakeError> {
        let _workflow = self
            .workflow
            .lock()
            .map_err(|_| IntakeError::LockPoisoned)?;
        let deleted = self.database.delete_yara_pack(pack_id)?;
        if deleted.shared {
            return Ok(ObjectCleanupResult {
                sha256: deleted.sha256,
                cleanup: CleanupStatus::RetainedShared,
                cleanup_message: None,
            });
        }
        let path = match yara_storage_path(&self.data_root, &deleted.storage_path, &deleted.sha256)
        {
            Some(path) => path,
            None => {
                return Ok(ObjectCleanupResult {
                    sha256: deleted.sha256,
                    cleanup: CleanupStatus::Deferred,
                    cleanup_message: Some("stored YARA pack path was not recognized".to_owned()),
                });
            }
        };
        let (cleanup, cleanup_message) = secure_remove_rule_source(&path);
        Ok(ObjectCleanupResult {
            sha256: deleted.sha256,
            cleanup,
            cleanup_message,
        })
    }

    fn rebuild_stale_case_projections(&self) -> Result<(), DatabaseError> {
        for case_id in self
            .database
            .projection_cases_needing_rebuild(projection::INVESTIGATION_PROJECTION_VERSION)?
        {
            self.refresh_case_projection(&case_id)?;
        }
        Ok(())
    }

    fn refresh_case_projection(&self, case_id: &CaseId) -> Result<(), DatabaseError> {
        let analysis = self
            .database
            .get_case_analysis(case_id)?
            .ok_or(DatabaseError::NotFound)?;
        let locations = self.database.artifact_locations_for_case(case_id)?;
        let finding_history = self.database.projection_finding_history(case_id)?;
        let (graph, chronology) = projection::build(projection::ProjectionInput {
            case_id,
            artifact: &analysis.artifact,
            locations: &locations,
            analysis_run: analysis.analysis_run.as_ref(),
            run_history: &analysis.run_history,
            evidence: &analysis.evidence,
            findings: &analysis.findings,
            finding_evidence: &analysis.finding_evidence,
            finding_history: &finding_history,
        });
        self.database.replace_case_projection(&graph, &chronology)
    }

    fn execute_analysis(
        &self,
        case_id: &CaseId,
        artifact: &Artifact,
        immutable_path: &Path,
        mut run: AnalysisRun,
        on_stage: &dyn Fn(AnalysisStage),
    ) -> Result<AnalysisRun, IntakeError> {
        on_stage(AnalysisStage::VerifyingIdentity);
        let stored_packs = self.database.enabled_yara_packs()?;
        let mut packs = Vec::with_capacity(stored_packs.len());
        for stored in stored_packs {
            let source_path =
                yara_storage_path(&self.data_root, &stored.storage_path, &stored.pack.sha256)
                    .ok_or(IntakeError::InvalidStoredYaraPack)?;
            packs.push(YaraPackInput {
                id: stored.pack.id,
                sha256: stored.pack.sha256,
                source_path: source_path.to_string_lossy().into_owned(),
                name: stored.pack.name,
                version: stored.pack.version,
                source: stored.pack.source,
                license: stored.pack.license,
            });
        }
        self.database
            .start_analysis(case_id, &run, &run.started_at)?;
        let request = WorkerRequest {
            protocol: PROTOCOL_VERSION,
            job_id: run.id.as_str().to_owned(),
            analysis_run_id: run.id.clone(),
            operation: Operation::PeStatic,
            artifact_id: artifact.id.clone(),
            artifact_path: immutable_path.to_string_lossy().into_owned(),
            input_sha256: artifact.sha256.clone(),
            limits: WorkerLimits::default(),
        };
        on_stage(AnalysisStage::ParsingPe);
        let pe_analysis = match (self.analyzer)(request) {
            Ok(analysis) if analysis_matches(&run, artifact, &analysis) => analysis,
            outcome => {
                let (status, code) = match outcome {
                    Err(error) => classify_worker_failure(&error),
                    Ok(_) => (AnalysisStatus::Failed, "worker_identity_mismatch"),
                };
                return self.finish_failed_analysis(case_id, run, status, code);
            }
        };

        let yara_analysis = if packs.is_empty() {
            on_stage(AnalysisStage::RunningRules);
            None
        } else {
            on_stage(AnalysisStage::RunningYara);
            let request = YaraWorkerRequest {
                protocol: PROTOCOL_VERSION,
                job_id: run.id.as_str().to_owned(),
                operation: YaraOperation::Scan,
                analysis_run_id: run.id.clone(),
                artifact_id: artifact.id.clone(),
                artifact_path: Some(immutable_path.to_string_lossy().into_owned()),
                input_sha256: Some(artifact.sha256.clone()),
                packs: packs.clone(),
                limits: WorkerLimits::default(),
                max_rule_matches: MAX_RULE_MATCHES,
                max_string_instances_per_match: MAX_STRING_INSTANCES_PER_MATCH,
            };
            match (self.yara_analyzer)(&request) {
                Ok(analysis) if yara_analysis_matches(&run, artifact, &packs, &analysis) => {
                    Some(analysis)
                }
                outcome => {
                    let (status, code) = match outcome {
                        Err(error) => classify_yara_failure(&error),
                        Ok(_) => (AnalysisStatus::Failed, "yara_worker_identity_mismatch"),
                    };
                    return self.finish_failed_analysis(case_id, run, status, code);
                }
            }
        };

        let mut provenances = vec![pe_analysis.provenance];
        let mut evidence = pe_analysis.evidence;
        let mut yara_findings = None;
        if let Some(yara) = yara_analysis {
            yara_findings = Some(tf_yara::findings_for_matches(
                &run.id,
                &artifact.id,
                &yara.evidence,
            ));
            provenances.extend(yara.provenances);
            evidence.extend(yara.evidence);
        }
        on_stage(AnalysisStage::RunningRules);
        let rule_engine_params = tf_rules::rule_engine_parameters();
        provenances.push(Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: run.id.clone(),
            analyzer: tf_rules::ENGINE_NAME.to_owned(),
            analyzer_version: tf_rules::ENGINE_VERSION.to_owned(),
            rule_id: None,
            rule_version: None,
            rule_pack_sha256: None,
            input_sha256: artifact.sha256.clone(),
            parameters: rule_engine_params,
        });
        let mut finding_set = tf_rules::evaluate(&run.id, &artifact.id, &evidence);
        if let Some(yara_findings) = yara_findings {
            merge_finding_sets(&mut finding_set, yara_findings);
        }
        on_stage(AnalysisStage::BuildingGraph);
        let finished_at = now_rfc3339()?;
        run.finished_at = Some(finished_at.clone());
        run.status = AnalysisStatus::Complete;
        self.database.persist_completed_analysis(
            case_id,
            &run,
            &provenances,
            &evidence,
            &finding_set,
            &finished_at,
        )?;
        on_stage(AnalysisStage::BuildingChronology);
        self.refresh_case_projection(case_id)?;
        on_stage(AnalysisStage::FinalizingQuickCheck);
        Ok(run)
    }

    fn finish_failed_analysis(
        &self,
        case_id: &CaseId,
        mut run: AnalysisRun,
        status: AnalysisStatus,
        code: &str,
    ) -> Result<AnalysisRun, IntakeError> {
        let finished_at = now_rfc3339()?;
        run.finished_at = Some(finished_at.clone());
        run.status = status;
        run.error_code = Some(code.to_owned());
        self.database
            .persist_failed_analysis(case_id, &run, &finished_at)?;
        self.refresh_case_projection(case_id)?;
        Ok(run)
    }

    pub fn compare_cases(
        &self,
        left_case_id: &CaseId,
        right_case_id: &CaseId,
    ) -> Result<ArtifactComparison, IntakeError> {
        let left = self
            .get_case_analysis(left_case_id)?
            .ok_or(IntakeError::CaseNotFound)?;
        let right = self
            .get_case_analysis(right_case_id)?
            .ok_or(IntakeError::CaseNotFound)?;
        Ok(compare_analyses(&left, &right))
    }

    pub fn list_cases(&self) -> Result<Vec<Case>, DatabaseError> {
        self.database.list_cases()
    }

    pub fn render_report_bytes(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
    ) -> Result<Vec<u8>, ReportServiceError> {
        let analysis = self
            .get_case_analysis(case_id)?
            .ok_or(ReportServiceError::CaseNotFound)?;
        let input = analysis.report_input(generated_at)?;
        match format {
            ReportFormat::Json => render_json(&input).map_err(Into::into),
            ReportFormat::Html => render_html(&input).map_err(Into::into),
            ReportFormat::Csv => render_csv(&input).map_err(Into::into),
            ReportFormat::Stix => render_stix(&input).map_err(Into::into),
            ReportFormat::Pdf => Err(ReportServiceError::DesktopRenderingRequired),
        }
    }

    pub fn export_report(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        destination: impl AsRef<Path>,
    ) -> Result<ReportRecord, ReportServiceError> {
        self.export_report_with_options(
            case_id,
            format,
            generated_at,
            destination,
            ReportExportOptions::default(),
        )
    }

    pub fn export_report_with_options(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        destination: impl AsRef<Path>,
        options: ReportExportOptions,
    ) -> Result<ReportRecord, ReportServiceError> {
        let generated_at = generated_at.into();
        let bytes = self.render_report_bytes(case_id, format, generated_at.clone())?;
        self.export_rendered_report_with_options(
            case_id,
            format,
            generated_at,
            destination,
            &bytes,
            options,
        )
    }

    pub fn export_rendered_report(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        destination: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<ReportRecord, ReportServiceError> {
        self.export_rendered_report_with_options(
            case_id,
            format,
            generated_at,
            destination,
            bytes,
            ReportExportOptions::default(),
        )
    }

    fn export_rendered_report_with_options(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        destination: impl AsRef<Path>,
        bytes: &[u8],
        options: ReportExportOptions,
    ) -> Result<ReportRecord, ReportServiceError> {
        validate_rendered_report(format, bytes)?;
        let generated_at = generated_at.into();
        let destination = validate_destination(destination.as_ref())?;
        let path = destination
            .to_str()
            .ok_or(ReportServiceError::NonUnicodeDestination)?
            .to_owned();
        let report = ReportRecord {
            id: ReportId::new(),
            case_id: case_id.clone(),
            format: format.as_str().to_owned(),
            generated_at,
            path,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        write_and_persist_report(
            &self.data_root.join("report-staging"),
            &destination,
            bytes,
            options.overwrite,
            || self.database.insert_report(&report),
        )?;
        Ok(report)
    }

    pub fn export_report_bundle(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        report_destination: impl AsRef<Path>,
        manifest_destination: impl AsRef<Path>,
    ) -> Result<ReportBundleRecord, ReportServiceError> {
        self.export_report_bundle_with_options(
            case_id,
            format,
            generated_at,
            report_destination,
            manifest_destination,
            ReportExportOptions::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_report_bundle_with_options(
        &self,
        case_id: &CaseId,
        format: ReportFormat,
        generated_at: impl Into<String>,
        report_destination: impl AsRef<Path>,
        manifest_destination: impl AsRef<Path>,
        options: ReportExportOptions,
    ) -> Result<ReportBundleRecord, ReportServiceError> {
        let generated_at = generated_at.into();
        let manifest_name = file_name(manifest_destination.as_ref())?;
        let analysis = self
            .get_case_analysis(case_id)?
            .ok_or(ReportServiceError::CaseNotFound)?;
        let input = analysis.report_input_with_manifest(&generated_at, Some(&manifest_name))?;
        let report_bytes = match format {
            ReportFormat::Json => render_json(&input)?,
            ReportFormat::Html => render_html(&input)?,
            ReportFormat::Csv => render_csv(&input)?,
            ReportFormat::Stix => render_stix(&input)?,
            ReportFormat::Pdf => return Err(ReportServiceError::DesktopRenderingRequired),
        };
        self.export_rendered_report_bundle_with_options(
            &analysis,
            format,
            generated_at,
            report_destination,
            manifest_destination,
            &report_bytes,
            options,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_rendered_report_bundle(
        &self,
        analysis: &CaseAnalysis,
        format: ReportFormat,
        generated_at: impl Into<String>,
        report_destination: impl AsRef<Path>,
        manifest_destination: impl AsRef<Path>,
        report_bytes: &[u8],
    ) -> Result<ReportBundleRecord, ReportServiceError> {
        self.export_rendered_report_bundle_with_options(
            analysis,
            format,
            generated_at,
            report_destination,
            manifest_destination,
            report_bytes,
            ReportExportOptions::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn export_rendered_report_bundle_with_options(
        &self,
        analysis: &CaseAnalysis,
        format: ReportFormat,
        generated_at: impl Into<String>,
        report_destination: impl AsRef<Path>,
        manifest_destination: impl AsRef<Path>,
        report_bytes: &[u8],
        options: ReportExportOptions,
    ) -> Result<ReportBundleRecord, ReportServiceError> {
        validate_rendered_report(format, report_bytes)?;
        let generated_at = generated_at.into();
        let report_destination = validate_destination(report_destination.as_ref())?;
        let manifest_destination = validate_destination(manifest_destination.as_ref())?;
        if report_destination == manifest_destination {
            return Err(ReportServiceError::InvalidDestination(
                "report and manifest destinations must differ",
            ));
        }
        let report_name = file_name(&report_destination)?;
        let manifest_name = file_name(&manifest_destination)?;
        let input = analysis.report_input_with_manifest(&generated_at, Some(&manifest_name))?;
        let artifact_verification = self.verify_stored_artifact(&analysis.artifact);
        let manifest = build_manifest(
            &input,
            &report_name,
            format,
            report_bytes,
            artifact_verification,
        )?;
        let manifest_bytes = render_manifest(&manifest)?;
        let report = ReportRecord {
            id: ReportId::new(),
            case_id: analysis.case.id.clone(),
            format: format.as_str().to_owned(),
            generated_at: generated_at.clone(),
            path: path_string(&report_destination)?,
            sha256: format!("{:x}", Sha256::digest(report_bytes)),
        };
        let manifest_record = ReportManifestRecord {
            id: ReportManifestId::new(),
            report_id: report.id.clone(),
            case_id: analysis.case.id.clone(),
            generated_at,
            path: path_string(&manifest_destination)?,
            schema_version: tf_report::MANIFEST_SCHEMA_VERSION,
            snapshot_sha256: input.snapshot_sha256().to_owned(),
            manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
        };
        write_and_persist_bundle(
            &report_destination,
            report_bytes,
            &manifest_destination,
            &manifest_bytes,
            options.overwrite,
            || {
                self.database
                    .insert_report_bundle(&report, &manifest_record)
            },
        )?;
        Ok(ReportBundleRecord {
            report,
            manifest: manifest_record,
        })
    }

    pub fn verify_report_bundle(&self, bundle: &ReportBundleRecord) -> ReportBundleVerification {
        if bundle.report.id != bundle.manifest.report_id
            || bundle.report.case_id != bundle.manifest.case_id
            || bundle.report.generated_at != bundle.manifest.generated_at
        {
            return bundle_verification(
                ManifestVerificationStatus::Mismatch,
                "persisted report and manifest identities disagree",
                None,
                ArtifactVerification::Unavailable,
            );
        }
        if bundle.manifest.schema_version != tf_report::MANIFEST_SCHEMA_VERSION {
            return bundle_verification(
                ManifestVerificationStatus::Unsupported,
                "persisted manifest schema version is unsupported",
                Some(bundle.manifest.snapshot_sha256.clone()),
                ArtifactVerification::Unavailable,
            );
        }
        let report_bytes = match read_bundle_file(Path::new(&bundle.report.path)) {
            Ok(bytes) => bytes,
            Err(detail) => {
                return bundle_verification(
                    ManifestVerificationStatus::Unavailable,
                    &detail,
                    Some(bundle.manifest.snapshot_sha256.clone()),
                    ArtifactVerification::Unavailable,
                );
            }
        };
        let manifest_bytes = match read_bundle_file(Path::new(&bundle.manifest.path)) {
            Ok(bytes) => bytes,
            Err(detail) => {
                return bundle_verification(
                    ManifestVerificationStatus::Unavailable,
                    &detail,
                    Some(bundle.manifest.snapshot_sha256.clone()),
                    ArtifactVerification::Unavailable,
                );
            }
        };
        let artifact_verification = self
            .database
            .artifact_for_case(&bundle.report.case_id)
            .ok()
            .flatten()
            .map_or(ArtifactVerification::Unavailable, |artifact| {
                self.verify_stored_artifact(&artifact)
            });
        let verification = verify_manifest(
            &manifest_bytes,
            &report_bytes,
            Some(&bundle.manifest.manifest_sha256),
        );
        if verification.status != ManifestVerificationStatus::Verified
            || verification.snapshot_sha256.as_deref()
                != Some(bundle.manifest.snapshot_sha256.as_str())
            || !bundle
                .report
                .sha256
                .eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(&report_bytes)))
        {
            return bundle_verification(
                if verification.status == ManifestVerificationStatus::Verified {
                    ManifestVerificationStatus::Mismatch
                } else {
                    verification.status
                },
                if verification.status == ManifestVerificationStatus::Verified {
                    "persisted snapshot or report hash disagrees with verified manifest"
                } else {
                    &verification.detail
                },
                verification.snapshot_sha256,
                artifact_verification,
            );
        }
        bundle_verification(
            ManifestVerificationStatus::Verified,
            "JSON manifest, canonical snapshot, record digests, exact report bytes, persisted hashes, and artifact status checked; no authenticity or safety claim is made",
            verification.snapshot_sha256,
            artifact_verification,
        )
    }

    fn verify_stored_artifact(&self, artifact: &Artifact) -> ArtifactVerification {
        let Some(relative) = artifact.store_path.strip_prefix("artifacts/") else {
            return ArtifactVerification::Mismatch;
        };
        match self
            .store
            .resolve_object(relative, &artifact.sha256, artifact.size_bytes)
        {
            Ok(_) => ArtifactVerification::Verified,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                ArtifactVerification::Unavailable
            }
            Err(StoreError::Io(_)) => ArtifactVerification::Unavailable,
            Err(_) => ArtifactVerification::Mismatch,
        }
    }

    pub fn list_reports(&self, case_id: &CaseId) -> Result<Vec<ReportRecord>, DatabaseError> {
        self.database.list_reports(case_id)
    }

    pub fn list_report_manifests(
        &self,
        case_id: &CaseId,
    ) -> Result<Vec<ReportManifestRecord>, DatabaseError> {
        self.database.list_report_manifests(case_id)
    }

    pub fn export_case_bundle(
        &self,
        case_id: &CaseId,
        destination: impl AsRef<Path>,
    ) -> Result<CaseBundleExport, IntakeError> {
        let analysis = self
            .get_case_analysis(case_id)?
            .ok_or(IntakeError::CaseNotFound)?;
        let destination = destination.as_ref();
        fs::create_dir_all(destination)?;

        let db_dest = destination.join("traceforge.db");
        self.database.checkpoint()?;
        fs::copy(self.database.path(), &db_dest)?;

        let wal_path = self.database.path().with_extension("db-wal");
        let shm_path = self.database.path().with_extension("db-shm");
        if wal_path.exists() {
            fs::copy(&wal_path, destination.join("traceforge.db-wal"))?;
        }
        if shm_path.exists() {
            fs::copy(&shm_path, destination.join("traceforge.db-shm"))?;
        }

        let mut artifacts = Vec::new();
        let store_path = analysis.artifact.store_path.clone();
        let source = self.data_root.join(&store_path);
        if source.exists() {
            let dest = destination.join("artifacts").join(&store_path);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::copy(&source, &dest)?;
            artifacts.push(CaseBundleEntry {
                store_path,
                sha256: analysis.artifact.sha256.clone(),
                size_bytes: analysis.artifact.size_bytes,
            });
        }

        let manifest = CaseBundleManifest {
            schema_version: 1,
            case_id: case_id.as_str().to_owned(),
            case_title: analysis.case.title.clone(),
            artifact_name: analysis.artifact.original_name.clone(),
            artifact_sha256: analysis.artifact.sha256.clone(),
            artifacts,
            exported_at: now_rfc3339()?,
        };
        let manifest_json = serde_json::to_vec_pretty(&manifest)?;
        fs::write(destination.join("bundle-manifest.json"), manifest_json)?;

        Ok(CaseBundleExport {
            destination: destination.to_path_buf(),
            manifest,
        })
    }

    pub fn import_case_bundle(&self, source: impl AsRef<Path>) -> Result<CaseId, IntakeError> {
        let source = source.as_ref();
        let manifest_path = source.join("bundle-manifest.json");
        let manifest_bytes = fs::read(&manifest_path)?;
        let manifest: CaseBundleManifest = serde_json::from_slice(&manifest_bytes)?;

        let db_path = source.join("traceforge.db");
        if !db_path.exists() {
            return Err(IntakeError::Archive("bundle database not found".to_owned()));
        }
        let case_id: CaseId = manifest
            .case_id
            .parse()
            .map_err(|_| IntakeError::Archive("invalid case ID in manifest".to_owned()))?;

        // Restore WAL/SHM if present so the copied DB is usable
        for wal_name in &["traceforge.db-wal", "traceforge.db-shm"] {
            let src = source.join(wal_name);
            if src.exists() {
                let dest = self.data_root.join(wal_name);
                fs::copy(&src, &dest)?;
            }
        }

        // Copy artifact files into our store and recompute all hashes via the store
        let mut stored_sha1 = String::new();
        let mut stored_md5 = String::new();
        let mut stored_size: u64 = 0;
        let mut stored_path_str = String::new();
        for entry in &manifest.artifacts {
            let source_path = source.join("artifacts").join(&entry.store_path);
            if source_path.exists() {
                let stored = self.store.ingest(&source_path)?;
                stored_sha1 = stored.sha1;
                stored_md5 = stored.md5;
                stored_size = stored.size_bytes;
                stored_path_str = stored.relative_path;
            }
        }

        let observed_at = now_rfc3339()?;
        let case = Case {
            id: case_id.clone(),
            title: manifest.case_title,
            created_at: manifest.exported_at.clone(),
            updated_at: manifest.exported_at,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: manifest.schema_version,
            status: CaseStatus::Active,
        };
        let artifact = Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            original_name: manifest.artifact_name,
            kind: ArtifactKind::Unknown,
            mime: None,
            size_bytes: stored_size,
            sha256: manifest.artifact_sha256,
            sha1: stored_sha1,
            md5: stored_md5,
            store_path: stored_path_str,
            created_at: observed_at.clone(),
        };
        let location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: artifact.original_name.clone(),
            source_path: None,
            modified_at_utc: None,
            created_at_utc: None,
            ingested_at: observed_at,
        };
        self.database
            .insert_case_artifact(&case, &artifact, &location)?;

        Ok(case_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBundleExport {
    pub destination: PathBuf,
    pub manifest: CaseBundleManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBundleManifest {
    pub schema_version: u32,
    pub case_id: String,
    pub case_title: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub artifacts: Vec<CaseBundleEntry>,
    pub exported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBundleEntry {
    pub store_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

impl CaseAnalysis {
    pub fn report_input(
        &self,
        generated_at: impl Into<String>,
    ) -> Result<ReportInput, ReportError> {
        self.report_input_with_manifest(generated_at, None)
    }

    pub fn report_input_with_manifest(
        &self,
        generated_at: impl Into<String>,
        manifest_file_name: Option<&str>,
    ) -> Result<ReportInput, ReportError> {
        ReportInput::new_expanded(
            generated_at,
            &self.case,
            &self.artifact,
            self.analysis_run.as_ref(),
            &self.provenances,
            &self.evidence,
            &self.rules,
            &self.findings,
            &self.finding_evidence,
            &self.explanations,
            &self.attack_mappings,
            ReportSupplement {
                graph: self.graph.as_ref(),
                chronology: self.chronology.as_ref(),
                notes: &self.notes,
                bookmarks: &self.bookmarks,
                quick_check: Some(&self.quick_check),
                yara_packs: &self.yara_packs,
                run_history: &self.run_history,
                manifest_file_name,
            },
        )
    }
}

fn compare_analyses(left: &CaseAnalysis, right: &CaseAnalysis) -> ArtifactComparison {
    ArtifactComparison {
        left: ArtifactSummary::from(&left.artifact),
        right: ArtifactSummary::from(&right.artifact),
        hashes: compare_maps(hash_values(&left.artifact), hash_values(&right.artifact)),
        headers: compare_maps(
            header_values(&left.evidence),
            header_values(&right.evidence),
        ),
        sections: compare_maps(
            evidence_values(&left.evidence, "pe.section", evidence_key),
            evidence_values(&right.evidence, "pe.section", evidence_key),
        ),
        imports: compare_maps(
            import_values(&left.evidence),
            import_values(&right.evidence),
        ),
        strings: compare_maps(
            evidence_values(&left.evidence, "pe.string", string_key),
            evidence_values(&right.evidence, "pe.string", string_key),
        ),
        signatures: compare_maps(
            signature_values(&left.evidence),
            signature_values(&right.evidence),
        ),
        findings: compare_maps(finding_values(left), finding_values(right)),
    }
}

fn hash_values(artifact: &Artifact) -> BTreeMap<String, ComparisonValue> {
    [
        ("md5", artifact.md5.as_str()),
        ("sha1", artifact.sha1.as_str()),
        ("sha256", artifact.sha256.as_str()),
    ]
    .into_iter()
    .map(|(key, value)| {
        (
            key.to_owned(),
            ComparisonValue {
                key: key.to_owned(),
                value: serde_json::Value::String(value.to_owned()),
                evidence_ids: Vec::new(),
            },
        )
    })
    .collect()
}

fn header_values(evidence: &[Evidence]) -> BTreeMap<String, ComparisonValue> {
    let mut values = BTreeMap::new();
    for item in evidence.iter().filter(|item| item.kind == "pe.header") {
        if let Some(fields) = item.value.as_object() {
            for (key, value) in fields {
                values.insert(
                    key.clone(),
                    ComparisonValue {
                        key: key.clone(),
                        value: value.clone(),
                        evidence_ids: vec![item.id.clone()],
                    },
                );
            }
        }
    }
    for (index, item) in evidence
        .iter()
        .filter(|item| item.kind == "pe.rich_header")
        .enumerate()
    {
        let key = format!("rich_header:{index}");
        values.insert(
            key.clone(),
            ComparisonValue {
                key,
                value: item.value.clone(),
                evidence_ids: vec![item.id.clone()],
            },
        );
    }
    values
}

fn import_values(evidence: &[Evidence]) -> BTreeMap<String, ComparisonValue> {
    let mut values = BTreeMap::new();
    for item in evidence
        .iter()
        .filter(|item| matches!(item.kind.as_str(), "pe.import" | "pe.delay_import"))
    {
        let key = import_key(item);
        let value = serde_json::json!({
            "kind": item.kind.as_str(),
            "dll": item.value.get("dll"),
            "function": item.value.get("function"),
            "ordinal": item.value.get("ordinal"),
        });
        values
            .entry(key.clone())
            .and_modify(|existing: &mut ComparisonValue| {
                existing.evidence_ids.push(item.id.clone());
                existing.evidence_ids.sort();
                existing.evidence_ids.dedup();
            })
            .or_insert_with(|| ComparisonValue {
                key,
                value,
                evidence_ids: vec![item.id.clone()],
            });
    }
    values
}

fn evidence_values(
    evidence: &[Evidence],
    kind: &str,
    key_fn: fn(&Evidence) -> String,
) -> BTreeMap<String, ComparisonValue> {
    let mut values = BTreeMap::new();
    for item in evidence.iter().filter(|item| item.kind == kind) {
        let key = key_fn(item);
        let value = if kind == "pe.string" {
            serde_json::json!({
                "text": item.value.get("text"),
                "encoding": item.value.get("encoding"),
                "length_chars": item.value.get("length_chars"),
                "truncated": item.value.get("truncated"),
            })
        } else {
            item.value.clone()
        };
        values
            .entry(key.clone())
            .and_modify(|existing: &mut ComparisonValue| {
                existing.evidence_ids.push(item.id.clone());
                existing.evidence_ids.sort();
                existing.evidence_ids.dedup();
            })
            .or_insert_with(|| ComparisonValue {
                key,
                value,
                evidence_ids: vec![item.id.clone()],
            });
    }
    values
}

fn evidence_key(evidence: &Evidence) -> String {
    evidence
        .value
        .get("index")
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| evidence.id.as_str().to_owned())
}

fn import_key(evidence: &Evidence) -> String {
    let dll = evidence
        .value
        .get("dll")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let symbol = evidence
        .value
        .get("function")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .or_else(|| {
            evidence
                .value
                .get("ordinal")
                .map(serde_json::Value::to_string)
        })
        .unwrap_or_default();
    format!(
        "{}!{}",
        dll.to_ascii_lowercase(),
        symbol.to_ascii_lowercase()
    )
}

fn string_key(evidence: &Evidence) -> String {
    let encoding = evidence
        .value
        .get("encoding")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let text = evidence
        .value
        .get("text")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    format!("{encoding}:{text}")
}

fn signature_values(evidence: &[Evidence]) -> BTreeMap<String, ComparisonValue> {
    let mut occurrence = BTreeMap::<String, usize>::new();
    let mut values = BTreeMap::new();
    for item in evidence
        .iter()
        .filter(|item| item.kind.starts_with("pe.authenticode"))
    {
        let base = if item.kind == "pe.authenticode.trust" {
            "trust".to_owned()
        } else {
            format!(
                "{}:entry:{}",
                item.kind,
                item.value
                    .get("entry_index")
                    .map(serde_json::Value::to_string)
                    .unwrap_or_else(|| "none".to_owned())
            )
        };
        let index = occurrence.entry(base.clone()).or_default();
        let key = if *index == 0 {
            base
        } else {
            format!("{base}:{}", *index)
        };
        *index += 1;
        values.insert(
            key.clone(),
            ComparisonValue {
                key,
                value: item.value.clone(),
                evidence_ids: vec![item.id.clone()],
            },
        );
    }
    values
}

fn finding_values(analysis: &CaseAnalysis) -> BTreeMap<String, ComparisonValue> {
    let mut links = BTreeMap::<FindingId, Vec<tf_model::EvidenceId>>::new();
    for link in &analysis.finding_evidence {
        links
            .entry(link.finding_id.clone())
            .or_default()
            .push(link.evidence_id.clone());
    }
    let mut values = BTreeMap::new();
    for finding in &analysis.findings {
        let mut evidence_ids = links.remove(&finding.id).unwrap_or_default();
        evidence_ids.sort();
        evidence_ids.dedup();
        let key = finding.rule_id.clone();
        values.insert(
            key.clone(),
            ComparisonValue {
                key,
                value: serde_json::json!({
                    "rule_id": finding.rule_id,
                    "rule_version": finding.rule_version,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence.value(),
                    "confidence_band": finding.confidence_band,
                    "state": finding.state,
                }),
                evidence_ids,
            },
        );
    }
    values
}

fn compare_maps(
    left: BTreeMap<String, ComparisonValue>,
    right: BTreeMap<String, ComparisonValue>,
) -> ComparisonGroup {
    let mut group = ComparisonGroup::default();
    for (key, left_value) in &left {
        match right.get(key) {
            None => group.removed.push(ComparisonEntry {
                delta: ComparisonDelta::Removed,
                key: key.clone(),
                left: Some(left_value.clone()),
                right: None,
            }),
            Some(right_value) if left_value.value != right_value.value => {
                group.changed.push(ComparisonEntry {
                    delta: ComparisonDelta::Changed,
                    key: key.clone(),
                    left: Some(left_value.clone()),
                    right: Some(right_value.clone()),
                });
            }
            Some(_) => {}
        }
    }
    for (key, right_value) in right {
        if !left.contains_key(&key) {
            group.added.push(ComparisonEntry {
                delta: ComparisonDelta::Added,
                key,
                left: None,
                right: Some(right_value),
            });
        }
    }
    group
}

fn validate_destination(destination: &Path) -> Result<PathBuf, ReportServiceError> {
    if destination.file_name().is_none() {
        return Err(ReportServiceError::InvalidDestination(
            "a file name is required",
        ));
    }
    let absolute = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    if absolute
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(ReportServiceError::InvalidDestination(
            "parent traversal is not allowed",
        ));
    }
    let parent = absolute
        .parent()
        .ok_or(ReportServiceError::InvalidDestination(
            "a destination directory is required",
        ))?;
    for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if is_reparse_point(&metadata) {
            return Err(ReportServiceError::ReparsePoint);
        }
        if !metadata.is_dir() {
            return Err(ReportServiceError::InvalidDestination(
                "an ancestor is not a directory",
            ));
        }
    }
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            if is_reparse_point(&metadata) {
                return Err(ReportServiceError::ReparsePoint);
            }
            if !metadata.is_file() {
                return Err(ReportServiceError::InvalidDestination(
                    "the existing destination is not a regular file",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(absolute)
}

fn validate_rendered_report(format: ReportFormat, bytes: &[u8]) -> Result<(), ReportServiceError> {
    if bytes.is_empty() || bytes.len() > tf_report::MAX_REPORT_BYTES {
        return Err(ReportServiceError::InvalidRenderedReport);
    }
    let matches_format = match format {
        ReportFormat::Json => serde_json::from_slice::<serde_json::Value>(bytes).is_ok(),
        ReportFormat::Html => bytes.starts_with(b"<!doctype html>"),
        ReportFormat::Pdf => {
            bytes.starts_with(b"%PDF-") && bytes.windows(5).any(|window| window == b"%%EOF")
        }
        ReportFormat::Csv => {
            let text = std::str::from_utf8(bytes).is_ok();
            let has_header = bytes.starts_with(b"section,field,value");
            text && has_header
        }
        ReportFormat::Stix => serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| {
                v.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t == "bundle")
            })
            .unwrap_or(false),
    };
    if matches_format {
        Ok(())
    } else {
        Err(ReportServiceError::InvalidRenderedReport)
    }
}

fn file_name(path: &Path) -> Result<String, ReportServiceError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or(ReportServiceError::NonUnicodeDestination)
}

fn path_string(path: &Path) -> Result<String, ReportServiceError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ReportServiceError::NonUnicodeDestination)
}

fn read_bundle_file(path: &Path) -> Result<Vec<u8>, String> {
    let path = validate_destination(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err("bundle component is unavailable as a regular file".to_owned());
    }
    if metadata.len() > tf_report::MAX_REPORT_BYTES as u64 {
        return Err("bundle component exceeds the verification size limit".to_owned());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn bundle_verification(
    status: ManifestVerificationStatus,
    detail: &str,
    snapshot_sha256: Option<String>,
    artifact_verification: ArtifactVerification,
) -> ReportBundleVerification {
    ReportBundleVerification {
        status,
        detail: detail.to_owned(),
        snapshot_sha256,
        artifact_verification,
        safety_claim: false,
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn write_and_persist_report<F>(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
    overwrite: bool,
    persist: F,
) -> Result<(), ReportServiceError>
where
    F: FnOnce() -> Result<(), DatabaseError>,
{
    ensure_regular_directory(staging_root)?;
    let mut rendered = NamedTempFile::new_in(staging_root)?;
    rendered.write_all(bytes)?;
    rendered.as_file_mut().sync_all()?;
    rendered.as_file_mut().rewind()?;

    let parent = destination
        .parent()
        .ok_or(ReportServiceError::InvalidDestination(
            "a destination directory is required",
        ))?;
    let mut staged = NamedTempFile::new_in(parent)?;
    io::copy(rendered.as_file_mut(), staged.as_file_mut())?;
    staged.as_file_mut().sync_all()?;

    let mut backup = None;
    if overwrite {
        match fs::symlink_metadata(destination) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) || !metadata.is_file() {
                    return Err(ReportServiceError::ReparsePoint);
                }
                let prior = NamedTempFile::new_in(parent)?;
                fs::copy(destination, prior.path())?;
                prior.as_file().sync_all()?;
                backup = Some(prior);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    let persistence = if overwrite {
        staged.persist(destination)
    } else {
        staged.persist_noclobber(destination)
    };
    let persisted = match persistence {
        Ok(file) => file,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ReportServiceError::DestinationExists);
        }
        Err(error) => {
            let primary = error.error;
            return Err(primary.into());
        }
    };
    let finalization = persisted
        .sync_all()
        .and_then(|()| sync_parent_directory(parent));
    drop(persisted);
    if let Err(operation) = finalization {
        return match rollback_report_file(destination, backup, parent) {
            Ok(()) => Err(ReportServiceError::Io(operation)),
            Err(rollback) => Err(ReportServiceError::FileRollback {
                operation,
                rollback,
            }),
        };
    }

    if let Err(database) = persist() {
        return match rollback_report_file(destination, backup, parent) {
            Ok(()) => Err(ReportServiceError::Database(database)),
            Err(rollback) => Err(ReportServiceError::Rollback { database, rollback }),
        };
    }
    drop(backup);
    Ok(())
}

fn write_and_persist_bundle<F>(
    report_destination: &Path,
    report_bytes: &[u8],
    manifest_destination: &Path,
    manifest_bytes: &[u8],
    overwrite: bool,
    persist: F,
) -> Result<(), ReportServiceError>
where
    F: FnOnce() -> Result<(), DatabaseError>,
{
    let report_parent =
        report_destination
            .parent()
            .ok_or(ReportServiceError::InvalidDestination(
                "a destination directory is required",
            ))?;
    let manifest_parent =
        manifest_destination
            .parent()
            .ok_or(ReportServiceError::InvalidDestination(
                "a destination directory is required",
            ))?;
    let mut report_staged = NamedTempFile::new_in(report_parent)?;
    report_staged.write_all(report_bytes)?;
    report_staged.as_file_mut().sync_all()?;
    let mut manifest_staged = NamedTempFile::new_in(manifest_parent)?;
    manifest_staged.write_all(manifest_bytes)?;
    manifest_staged.as_file_mut().sync_all()?;

    let report_backup = prepare_backup(report_destination, report_parent, overwrite)?;
    let manifest_backup = prepare_backup(manifest_destination, manifest_parent, overwrite)?;
    let report_file = persist_staged(report_staged, report_destination, overwrite)?;
    let manifest_file = match persist_staged(manifest_staged, manifest_destination, overwrite) {
        Ok(file) => file,
        Err(operation) => {
            return match rollback_bundle_files(
                report_destination,
                report_backup,
                report_parent,
                manifest_destination,
                manifest_backup,
                manifest_parent,
            ) {
                Ok(()) => Err(operation),
                Err(rollback) => Err(ReportServiceError::FileRollback {
                    operation: io::Error::other(operation.to_string()),
                    rollback,
                }),
            };
        }
    };
    let finalization = report_file
        .sync_all()
        .and_then(|()| manifest_file.sync_all())
        .and_then(|()| sync_parent_directory(report_parent))
        .and_then(|()| {
            if manifest_parent == report_parent {
                Ok(())
            } else {
                sync_parent_directory(manifest_parent)
            }
        });
    drop(report_file);
    drop(manifest_file);
    if let Err(operation) = finalization {
        return match rollback_bundle_files(
            report_destination,
            report_backup,
            report_parent,
            manifest_destination,
            manifest_backup,
            manifest_parent,
        ) {
            Ok(()) => Err(ReportServiceError::Io(operation)),
            Err(rollback) => Err(ReportServiceError::FileRollback {
                operation,
                rollback,
            }),
        };
    }
    if let Err(database) = persist() {
        return match rollback_bundle_files(
            report_destination,
            report_backup,
            report_parent,
            manifest_destination,
            manifest_backup,
            manifest_parent,
        ) {
            Ok(()) => Err(ReportServiceError::Database(database)),
            Err(rollback) => Err(ReportServiceError::Rollback { database, rollback }),
        };
    }
    drop(report_backup);
    drop(manifest_backup);
    Ok(())
}

fn prepare_backup(
    destination: &Path,
    parent: &Path,
    overwrite: bool,
) -> Result<Option<NamedTempFile>, ReportServiceError> {
    match fs::symlink_metadata(destination) {
        Ok(_) if !overwrite => Err(ReportServiceError::DestinationExists),
        Ok(metadata) => {
            if is_reparse_point(&metadata) || !metadata.is_file() {
                return Err(ReportServiceError::ReparsePoint);
            }
            let backup = NamedTempFile::new_in(parent)?;
            fs::copy(destination, backup.path())?;
            backup.as_file().sync_all()?;
            Ok(Some(backup))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn persist_staged(
    staged: NamedTempFile,
    destination: &Path,
    overwrite: bool,
) -> Result<fs::File, ReportServiceError> {
    let result = if overwrite {
        staged.persist(destination)
    } else {
        staged.persist_noclobber(destination)
    };
    result.map_err(|error| {
        if error.error.kind() == io::ErrorKind::AlreadyExists {
            ReportServiceError::DestinationExists
        } else {
            ReportServiceError::Io(error.error)
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn rollback_bundle_files(
    report_destination: &Path,
    report_backup: Option<NamedTempFile>,
    report_parent: &Path,
    manifest_destination: &Path,
    manifest_backup: Option<NamedTempFile>,
    manifest_parent: &Path,
) -> Result<(), io::Error> {
    let report_result = rollback_report_file(report_destination, report_backup, report_parent);
    let manifest_result =
        rollback_report_file(manifest_destination, manifest_backup, manifest_parent);
    report_result.and(manifest_result)
}

fn rollback_report_file(
    destination: &Path,
    backup: Option<NamedTempFile>,
    parent: &Path,
) -> Result<(), io::Error> {
    if let Some(backup) = backup {
        let restored = backup.persist(destination).map_err(|error| error.error)?;
        restored.sync_all()?;
    } else {
        match fs::remove_file(destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    sync_parent_directory(parent)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), io::Error> {
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<(), io::Error> {
    Ok(())
}

fn analysis_matches(run: &AnalysisRun, artifact: &Artifact, analysis: &PeAnalysis) -> bool {
    analysis.analyzer.name == run.analyzer
        && analysis.analyzer.version == run.analyzer_version
        && analysis.provenance.analysis_run_id == run.id
        && analysis.provenance.analyzer == run.analyzer
        && analysis.provenance.analyzer_version == run.analyzer_version
        && analysis
            .provenance
            .input_sha256
            .eq_ignore_ascii_case(&artifact.sha256)
        && analysis.evidence.iter().all(|item| {
            item.artifact_id == artifact.id && item.provenance_id == analysis.provenance.id
        })
}

fn yara_analysis_matches(
    run: &AnalysisRun,
    artifact: &Artifact,
    packs: &[YaraPackInput],
    analysis: &YaraAnalysis,
) -> bool {
    let expected_hashes = packs
        .iter()
        .map(|pack| pack.sha256.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let actual_hashes = analysis
        .provenances
        .iter()
        .filter_map(|record| record.rule_pack_sha256.as_deref())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let provenance_ids = analysis
        .provenances
        .iter()
        .map(|record| &record.id)
        .collect::<BTreeSet<_>>();
    analysis.analyzer.name == tf_yara::ANALYZER_NAME
        && analysis.analyzer.version == tf_yara::ANALYZER_VERSION
        && analysis.provenances.len() == packs.len()
        && provenance_ids.len() == packs.len()
        && actual_hashes == expected_hashes
        && analysis.provenances.iter().all(|record| {
            record.analysis_run_id == run.id
                && record.analyzer == tf_yara::ANALYZER_NAME
                && record.analyzer_version == tf_yara::ANALYZER_VERSION
                && record.input_sha256.eq_ignore_ascii_case(&artifact.sha256)
        })
        && analysis.evidence.iter().all(|item| {
            item.artifact_id == artifact.id
                && item.kind == "yara.match"
                && provenance_ids.contains(&item.provenance_id)
        })
}

fn merge_finding_sets(target: &mut FindingSet, additional: FindingSet) {
    target.rules.extend(additional.rules);
    target.findings.extend(additional.findings);
    target.evidence_links.extend(additional.evidence_links);
    target.explanations.extend(additional.explanations);
    target.attack_mappings.extend(additional.attack_mappings);
    target.rules.sort_by(|left, right| {
        (&left.rule_id, &left.version).cmp(&(&right.rule_id, &right.version))
    });
    target
        .rules
        .dedup_by(|left, right| left.rule_id == right.rule_id && left.version == right.version);
    target
        .findings
        .sort_by(|left, right| (&left.rule_id, &left.id).cmp(&(&right.rule_id, &right.id)));
    let order = target
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (finding.id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    target.evidence_links.sort_by(|left, right| {
        (order.get(&left.finding_id), &left.evidence_id)
            .cmp(&(order.get(&right.finding_id), &right.evidence_id))
    });
    target
        .explanations
        .sort_by_key(|record| order.get(&record.finding_id).copied());
    target.attack_mappings.sort_by(|left, right| {
        (order.get(&left.finding_id), &left.mapping)
            .cmp(&(order.get(&right.finding_id), &right.mapping))
    });
}

fn classify_worker_failure(error: &HostError) -> (AnalysisStatus, &'static str) {
    match error {
        HostError::TimedOut(_) => (AnalysisStatus::TimedOut, "worker_timeout"),
        HostError::OutputLimit { .. } => (AnalysisStatus::ResourceLimit, "worker_output_limit"),
        HostError::WorkerReported { code, .. }
            if matches!(
                code.as_str(),
                "section_limit" | "record_limit" | "message_limit" | "result_limit"
            ) =>
        {
            (AnalysisStatus::ResourceLimit, "worker_resource_limit")
        }
        HostError::WorkerReported { code, .. } if code == "invalid_section_bounds" => {
            (AnalysisStatus::Failed, "invalid_section_bounds")
        }
        HostError::WorkerReported { code, .. } if code == "invalid_pe" => {
            (AnalysisStatus::Failed, "invalid_pe")
        }
        HostError::Spawn(_) => (AnalysisStatus::Failed, "worker_spawn_failure"),
        HostError::Containment(_) => (AnalysisStatus::Failed, "worker_containment_failure"),
        HostError::Io(_) => (AnalysisStatus::Failed, "worker_io_failure"),
        HostError::InvalidOutput(_) => (AnalysisStatus::Failed, "worker_invalid_output"),
        HostError::InvalidTranscript(_) => (AnalysisStatus::Failed, "worker_protocol_failure"),
        HostError::ProcessFailed { .. } => (AnalysisStatus::Failed, "worker_process_failure"),
        _ => (AnalysisStatus::Failed, "worker_failure"),
    }
}

fn classify_yara_failure(error: &YaraError) -> (AnalysisStatus, &'static str) {
    match error {
        YaraError::TimedOut(_) => (AnalysisStatus::TimedOut, "yara_worker_timeout"),
        YaraError::OutputLimit { .. } => {
            (AnalysisStatus::ResourceLimit, "yara_worker_output_limit")
        }
        YaraError::WorkerReported { code, .. }
            if matches!(
                code.as_str(),
                "record_limit" | "message_limit" | "result_limit" | "match_limit"
            ) =>
        {
            (AnalysisStatus::ResourceLimit, "yara_worker_resource_limit")
        }
        _ => (AnalysisStatus::Failed, "yara_worker_failure"),
    }
}

fn read_bounded_yara_source(path: &Path) -> Result<Vec<u8>, IntakeError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > tf_protocol::MAX_YARA_PACK_BYTES as u64
    {
        return Err(IntakeError::Yara(YaraError::PackTooLarge));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(tf_protocol::MAX_YARA_PACK_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > tf_protocol::MAX_YARA_PACK_BYTES {
        return Err(IntakeError::Yara(YaraError::PackTooLarge));
    }
    Ok(bytes)
}

fn yara_storage_path(data_root: &Path, relative: &str, sha256: &str) -> Option<PathBuf> {
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let hash = sha256.to_ascii_lowercase();
    let expected = format!("yara-packs/{}/{hash}.yar", &hash[..2]);
    if relative != expected {
        return None;
    }
    let path = data_root.join(expected.replace('/', std::path::MAIN_SEPARATOR_STR));
    for component in [
        data_root.join("yara-packs"),
        data_root.join("yara-packs").join(&hash[..2]),
        path.clone(),
    ] {
        match fs::symlink_metadata(component) {
            Ok(metadata) if is_reparse_point(&metadata) => return None,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(path)
}

fn ensure_regular_directory(path: &Path) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !is_reparse_point(&metadata) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staging path is not a regular directory",
        ))
    }
}

fn prepare_staging_directory(path: &Path) -> Result<(), io::Error> {
    fs::create_dir_all(path)?;
    ensure_regular_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_file() && !is_reparse_point(&metadata) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn secure_remove_rule_source(path: &Path) -> (CleanupStatus, Option<String>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !is_reparse_point(&metadata) => metadata,
        Ok(_) => {
            return (
                CleanupStatus::Deferred,
                Some("stored YARA source is not a regular file".to_owned()),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (CleanupStatus::AlreadyMissing, None);
        }
        Err(error) => return (CleanupStatus::Deferred, Some(error.to_string())),
    };
    let operation = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        let zeros = [0_u8; 8192];
        let mut remaining = metadata.len();
        while remaining != 0 {
            let count = usize::try_from(remaining.min(zeros.len() as u64)).unwrap_or(zeros.len());
            file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
        drop(file);
        fs::remove_file(path)
    })();
    match operation {
        Ok(()) => (CleanupStatus::Removed, None),
        Err(error) => (CleanupStatus::Deferred, Some(error.to_string())),
    }
}

fn map_pe_kind(kind: PeKind) -> ArtifactKind {
    match kind {
        PeKind::Pe32 => ArtifactKind::Pe32,
        PeKind::Pe64 => ArtifactKind::Pe64,
    }
}

fn now_rfc3339() -> Result<String, IntakeError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| IntakeError::Timestamp)
}

fn normalize_bookmark_label(label: Option<String>) -> Option<String> {
    label.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn format_file_time(value: Option<SystemTime>) -> Option<String> {
    value.and_then(|timestamp| OffsetDateTime::from(timestamp).format(&Rfc3339).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tf_model::{EvidenceId, ObservationClass, ProvenanceId};
    use tf_protocol::{AnalyzerIdentity, WorkerStats};

    fn pe_fixture(magic: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[84..86].copy_from_slice(&2_u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&magic.to_le_bytes());
        bytes
    }

    fn successful_analyzer(request: WorkerRequest) -> Result<PeAnalysis, HostError> {
        assert_eq!(request.protocol, PROTOCOL_VERSION);
        assert_eq!(request.operation, Operation::PeStatic);
        assert_eq!(request.limits, WorkerLimits::default());
        assert_eq!(request.job_id, request.analysis_run_id.as_str());
        assert!(request.artifact_path.contains("artifacts"));
        assert!(
            fs::metadata(&request.artifact_path)
                .expect("stored artifact")
                .permissions()
                .readonly()
        );
        let provenance = Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: request.analysis_run_id,
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            rule_id: None,
            rule_version: None,
            rule_pack_sha256: None,
            input_sha256: request.input_sha256,
            parameters: BTreeMap::from([("operation".to_owned(), json!("pe_static"))]),
        };
        Ok(PeAnalysis {
            analyzer: AnalyzerIdentity {
                name: ANALYZER_NAME.to_owned(),
                version: ANALYZER_VERSION.to_owned(),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new(),
                artifact_id: request.artifact_id,
                provenance_id: provenance.id.clone(),
                kind: "pe.header".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([("file_offset".to_owned(), json!(64))]),
                value: json!({"pe_kind": "pe32", "entry_point_rva": 4096}),
                preview_text: None,
            }],
            provenance,
            stats: WorkerStats {
                records_emitted: 4,
                bytes_emitted: 256,
                elapsed_ms: 1,
                truncated: false,
            },
        })
    }

    fn timed_out_analyzer(_: WorkerRequest) -> Result<PeAnalysis, HostError> {
        Err(HostError::TimedOut(Duration::from_secs(15)))
    }

    fn projection_analyzer(request: WorkerRequest) -> Result<PeAnalysis, HostError> {
        let mut analysis = successful_analyzer(request)?;
        let artifact_id = analysis.evidence[0].artifact_id.clone();
        let provenance_id = analysis.provenance.id.clone();
        analysis.evidence.push(Evidence {
            id: EvidenceId::new(),
            artifact_id,
            provenance_id,
            kind: "pe.import".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::from([("thunk_index".to_owned(), json!(0))]),
            value: json!({
                "dll": "KERNEL32.dll",
                "function": "CreateFileW",
                "ordinal": null,
                "iat_rva": 4096
            }),
            preview_text: None,
        });
        Ok(analysis)
    }

    static DISAPPEARING_PROJECTION_RUNS: AtomicUsize = AtomicUsize::new(0);

    fn disappearing_projection_analyzer(request: WorkerRequest) -> Result<PeAnalysis, HostError> {
        let mut analysis = successful_analyzer(request)?;
        if DISAPPEARING_PROJECTION_RUNS.fetch_add(1, Ordering::SeqCst) == 0 {
            analysis.evidence.push(Evidence {
                id: EvidenceId::new(),
                artifact_id: analysis.evidence[0].artifact_id.clone(),
                provenance_id: analysis.provenance.id.clone(),
                kind: "pe.import".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([("thunk_index".to_owned(), json!(0))]),
                value: json!({
                    "dll": "KERNEL32.dll",
                    "function": "CreateFileW",
                    "ordinal": null,
                    "iat_rva": 4096
                }),
                preview_text: None,
            });
        }
        Ok(analysis)
    }

    fn successful_yara_validator(request: &YaraWorkerRequest) -> Result<ValidatedPack, YaraError> {
        assert_eq!(request.operation, YaraOperation::Validate);
        assert_eq!(request.packs.len(), 1);
        assert!(request.packs[0].source_path.contains("yara-staging"));
        Ok(ValidatedPack {
            analyzer: AnalyzerIdentity {
                name: tf_yara::ANALYZER_NAME.to_owned(),
                version: tf_yara::ANALYZER_VERSION.to_owned(),
            },
            pack_sha256: request.packs[0].sha256.clone(),
            rules: vec![tf_model::YaraRuleMetadata {
                namespace: "default".to_owned(),
                identifier: "Demo".to_owned(),
                tags: vec!["triage".to_owned()],
                metadata: json!({"author": "Artifacta"}),
            }],
            stats: WorkerStats {
                records_emitted: 3,
                bytes_emitted: 100,
                elapsed_ms: 1,
                truncated: false,
            },
        })
    }

    fn successful_yara_analyzer(request: &YaraWorkerRequest) -> Result<YaraAnalysis, YaraError> {
        assert_eq!(request.operation, YaraOperation::Scan);
        assert!(
            request
                .artifact_path
                .as_deref()
                .is_some_and(|path| path.contains("artifacts"))
        );
        let pack = &request.packs[0];
        assert!(pack.source_path.contains("yara-packs"));
        let provenance = Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: request.analysis_run_id.clone(),
            analyzer: tf_yara::ANALYZER_NAME.to_owned(),
            analyzer_version: tf_yara::ANALYZER_VERSION.to_owned(),
            rule_id: None,
            rule_version: Some(pack.version.clone()),
            rule_pack_sha256: Some(pack.sha256.clone()),
            input_sha256: request.input_sha256.clone().expect("hash"),
            parameters: BTreeMap::new(),
        };
        Ok(YaraAnalysis {
            analyzer: AnalyzerIdentity {
                name: tf_yara::ANALYZER_NAME.to_owned(),
                version: tf_yara::ANALYZER_VERSION.to_owned(),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new(),
                artifact_id: request.artifact_id.clone(),
                provenance_id: provenance.id.clone(),
                kind: "yara.match".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([
                    ("namespace".to_owned(), json!("default")),
                    ("rule_identifier".to_owned(), json!("Demo")),
                ]),
                value: json!({
                    "pack_sha256": pack.sha256,
                    "pack_name": pack.name,
                    "pack_version": pack.version,
                    "pack_source": pack.source,
                    "pack_license": pack.license,
                    "namespace": "default",
                    "rule_identifier": "Demo",
                    "tags": ["triage"],
                    "metadata": {"author": "Artifacta"},
                    "matched_strings": [{
                        "identifier": "$a",
                        "instances": [{"offset": 2, "length": 4, "hex_preview": "44454d4f"}]
                    }],
                    "string_instances_truncated": false
                }),
                preview_text: Some("YARA rule default:Demo matched".to_owned()),
            }],
            provenances: vec![provenance],
            stats: WorkerStats {
                records_emitted: 4,
                bytes_emitted: 300,
                elapsed_ms: 1,
                truncated: false,
            },
        })
    }

    #[test]
    fn yara_pack_lifecycle_and_analysis_are_path_free_and_preserve_pe_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let data_root = directory.path().join("data");
        let artifact_source = directory.path().join("sample.exe");
        let rule_source = directory.path().join("private-rule-name.yar");
        fs::write(&artifact_source, pe_fixture(0x10b)).expect("PE fixture");
        fs::write(
            &rule_source,
            b"rule Demo { strings: $a = \"DEMO\" condition: $a }",
        )
        .expect("rule fixture");
        let service = CaseService::open_with_analyzers(
            &data_root,
            successful_analyzer,
            successful_yara_analyzer,
            successful_yara_validator,
        )
        .expect("service");
        let pack = service
            .import_yara_pack(&rule_source, "demo", "1", "unit test", "Apache-2.0")
            .expect("import");
        assert_eq!(
            service.list_yara_packs().expect("packs"),
            vec![pack.clone()]
        );

        let intake = service.ingest_pe(&artifact_source).expect("intake");
        let analysis = service
            .get_case_analysis(&intake.case.id)
            .expect("query")
            .expect("analysis");
        assert_eq!(analysis.provenances.len(), 3);
        assert!(
            analysis
                .evidence
                .iter()
                .any(|item| item.kind == "pe.header")
        );
        assert!(
            analysis
                .evidence
                .iter()
                .any(|item| item.kind == "yara.match")
        );
        assert!(analysis.findings.iter().any(|finding| {
            finding.category == "yara_match" && finding.severity == tf_model::Severity::Contextual
        }));
        let serialized = serde_json::to_string(&analysis).expect("serialize");
        assert!(!serialized.contains("private-rule-name.yar"));
        assert!(!serialized.contains("yara-packs"));
        let report = service
            .render_report_bytes(&intake.case.id, ReportFormat::Json, "2026-08-25T12:00:00Z")
            .expect("report");
        let report = String::from_utf8(report).expect("UTF-8 report");
        assert!(!report.contains("private-rule-name.yar"));
        assert!(!report.contains("yara-packs"));
        assert!(report.contains("yara.match"));

        let cleanup = service.delete_yara_pack(&pack.id).expect("delete pack");
        assert_eq!(cleanup.cleanup, CleanupStatus::Removed);
        assert!(service.list_yara_packs().expect("packs").is_empty());
    }

    #[test]
    fn intake_to_retrieval_persists_complete_analysis_without_source_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("misleading.txt");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");

        let result = service.ingest_pe(&source).expect("intake");
        let analysis = service
            .get_case_analysis(&result.case.id)
            .expect("query")
            .expect("analysis");

        assert_eq!(result.artifact.kind, ArtifactKind::Pe32);
        assert_eq!(result.location.display_name, "misleading.txt");
        assert_eq!(result.analysis_run.status, AnalysisStatus::Complete);
        assert_eq!(analysis.case, result.case);
        assert_eq!(analysis.artifact, result.artifact);
        assert_eq!(analysis.analysis_run, Some(result.analysis_run.clone()));
        assert_eq!(analysis.evidence.len(), 1);
        assert_eq!(analysis.rules, tf_rules::rule_catalog());
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.finding_evidence.len(), 1);
        assert_eq!(analysis.explanations.len(), 1);
        assert_eq!(analysis.findings[0].rule_id, "TF-PE-003");
        assert_eq!(
            analysis.finding_evidence[0].evidence_id,
            analysis.evidence[0].id
        );
        assert!(
            !serde_json::to_string(&analysis)
                .expect("serialize DTO")
                .contains("sourcePath")
        );
        let intake_json = serde_json::to_string(&result).expect("serialize intake DTO");
        assert!(!intake_json.contains(source.to_string_lossy().as_ref()));
        assert!(!intake_json.contains(&result.artifact.store_path));
        assert!(
            directory
                .path()
                .join("data")
                .join(&analysis.artifact.store_path)
                .is_file()
        );
    }

    #[test]
    fn worker_timeout_keeps_case_and_persists_safe_terminal_run() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x20b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), timed_out_analyzer)
                .expect("service");

        let result = service.ingest_pe(&source).expect("useful intake result");
        assert_eq!(result.case.status, CaseStatus::Error);
        assert_eq!(result.analysis_run.status, AnalysisStatus::TimedOut);
        assert_eq!(
            result.analysis_run.error_code.as_deref(),
            Some("worker_timeout")
        );

        let stored = service
            .get_case_analysis(&result.case.id)
            .expect("query")
            .expect("acquired case remains");
        assert_eq!(stored.case, result.case);
        assert_eq!(stored.analysis_run, Some(result.analysis_run));
        assert!(stored.provenances.is_empty());
        assert!(stored.evidence.is_empty());
        assert!(stored.rules.is_empty());
        assert!(stored.findings.is_empty());
        assert!(stored.finding_evidence.is_empty());
        assert!(stored.explanations.is_empty());
        let chronology = service
            .get_case_chronology(&result.case.id)
            .expect("chronology query")
            .expect("chronology");
        for event_type in ["analysis_started", "analysis_failed"] {
            let event = chronology
                .events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("analysis lifecycle event");
            assert_eq!(
                event.reliability,
                tf_model::TimestampReliability::ApplicationGenerated
            );
            assert!(event.evidence_id.is_none());
        }
        assert!(
            service
                .data_root()
                .join(&stored.artifact.store_path)
                .is_file()
        );
    }

    #[test]
    fn worker_failure_codes_preserve_parser_and_host_failure_categories() {
        assert_eq!(
            classify_worker_failure(&HostError::WorkerReported {
                code: "invalid_section_bounds".to_owned(),
                message: "section 0 raw range lies outside the artifact".to_owned(),
            }),
            (AnalysisStatus::Failed, "invalid_section_bounds")
        );
        assert_eq!(
            classify_worker_failure(&HostError::InvalidTranscript("missing terminal record")),
            (AnalysisStatus::Failed, "worker_protocol_failure")
        );
    }

    #[test]
    fn reanalysis_uses_the_immutable_object_and_preserves_run_history() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        fs::remove_file(&source).expect("remove original source");

        let rerun = service.reanalyze_case(&intake.case.id).expect("reanalysis");
        assert_eq!(rerun.status, AnalysisStatus::Complete);
        assert_ne!(rerun.id, intake.analysis_run.id);
        let latest = service
            .get_case_analysis(&intake.case.id)
            .expect("latest query")
            .expect("case");
        assert_eq!(
            latest.analysis_run.as_ref().map(|run| &run.id),
            Some(&rerun.id)
        );
        assert_eq!(latest.run_history.len(), 2);
        assert_eq!(latest.run_history[0].id, rerun.id);
        let historical = service
            .get_case_analysis_run(&intake.case.id, &intake.analysis_run.id)
            .expect("history query")
            .expect("historical run");
        assert_eq!(historical.analysis_run, Some(intake.analysis_run));
        assert_eq!(historical.evidence.len(), 1);
        assert_ne!(historical.evidence[0].id, latest.evidence[0].id);
    }

    #[test]
    fn projection_reanalysis_preserves_stable_ids_and_refreshes_raw_links() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), projection_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let first_graph = service
            .get_case_graph(&intake.case.id)
            .expect("graph query")
            .expect("graph");
        let first_chronology = service
            .get_case_chronology(&intake.case.id)
            .expect("chronology query")
            .expect("chronology");
        assert!(
            first_graph
                .entities
                .iter()
                .any(|entity| entity.entity_type == tf_model::EntityType::Finding)
        );
        assert!(
            first_graph
                .edges
                .iter()
                .any(|edge| { edge.relationship == tf_model::Relationship::SupportsFinding })
        );
        assert!(
            first_chronology
                .events
                .iter()
                .any(|event| event.event_type == "analysis_started")
        );
        assert!(
            first_chronology
                .events
                .iter()
                .any(|event| event.event_type == "analysis_completed")
        );
        assert!(
            first_chronology
                .events
                .iter()
                .any(|event| event.event_type == "rule_finding_generated")
        );
        assert_eq!(
            first_graph.source_analysis_run_id.as_ref(),
            Some(&intake.analysis_run.id)
        );
        let finding = service
            .get_case_analysis(&intake.case.id)
            .expect("analysis query")
            .expect("analysis")
            .findings[0]
            .clone();
        service
            .acknowledge_finding(&intake.case.id, &finding.id)
            .expect("acknowledge finding");
        let refreshed_state = service
            .get_case_graph(&intake.case.id)
            .expect("refreshed graph query")
            .expect("refreshed graph")
            .entities
            .into_iter()
            .find(|entity| entity.metadata.get("finding_id") == Some(&json!(finding.id.as_str())))
            .and_then(|entity| entity.metadata.get("state").cloned());
        assert_eq!(refreshed_state, Some(json!("reviewed")));
        let rerun = service.reanalyze_case(&intake.case.id).expect("reanalysis");
        let second_graph = service
            .get_case_graph(&intake.case.id)
            .expect("graph query")
            .expect("graph");
        let second_chronology = service
            .get_case_chronology(&intake.case.id)
            .expect("chronology query")
            .expect("chronology");
        assert_eq!(
            first_graph
                .entities
                .iter()
                .map(|entity| &entity.id)
                .collect::<Vec<_>>(),
            second_graph
                .entities
                .iter()
                .map(|entity| &entity.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first_graph
                .edges
                .iter()
                .map(|edge| &edge.id)
                .collect::<Vec<_>>(),
            second_graph
                .edges
                .iter()
                .map(|edge| &edge.id)
                .collect::<Vec<_>>()
        );
        assert!(
            first_graph
                .edges
                .iter()
                .zip(&second_graph.edges)
                .all(|(first, second)| first.evidence_id != second.evidence_id)
        );
        assert!(first_chronology.events.iter().all(|first| {
            second_chronology
                .events
                .iter()
                .any(|second| second.id == first.id)
        }));
        assert!(
            second_chronology
                .events
                .iter()
                .any(|event| event.event_type == "reanalysis_started")
        );
        assert!(
            second_chronology
                .events
                .iter()
                .any(|event| event.event_type == "reanalysis_completed")
        );
        assert!(second_chronology.events.iter().all(|event| {
            !matches!(
                event.event_type.as_str(),
                "analysis_started"
                    | "analysis_completed"
                    | "reanalysis_started"
                    | "reanalysis_completed"
                    | "rule_finding_generated"
            ) || event.reliability == tf_model::TimestampReliability::ApplicationGenerated
        }));
        assert_eq!(
            second_chronology
                .events
                .iter()
                .filter(|event| event.event_type == "rule_finding_generated")
                .count(),
            2
        );
        assert_eq!(second_graph.source_analysis_run_id, Some(rerun.id.clone()));
        assert_eq!(
            second_chronology.source_analysis_run_id,
            Some(rerun.id.clone())
        );
        service
            .rebuild_case_projection(&intake.case.id)
            .expect("explicit rebuild");
        assert_eq!(
            service
                .get_case_graph(&intake.case.id)
                .expect("rebuilt graph query")
                .expect("rebuilt graph"),
            second_graph
        );
    }

    #[test]
    fn reanalysis_removes_bookmarks_for_disappearing_derived_targets() {
        DISAPPEARING_PROJECTION_RUNS.store(0, Ordering::SeqCst);
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service = CaseService::open_with_analyzer(
            directory.path().join("data"),
            disappearing_projection_analyzer,
        )
        .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let first_graph = service
            .get_case_graph(&intake.case.id)
            .expect("graph query")
            .expect("graph");
        let stable_entity = first_graph
            .entities
            .iter()
            .find(|entity| entity.entity_type == tf_model::EntityType::Artifact)
            .expect("artifact entity");
        let disappearing_entity = first_graph
            .entities
            .iter()
            .find(|entity| entity.entity_type == tf_model::EntityType::ImportedApi)
            .expect("import entity");
        let disappearing_edge = first_graph
            .edges
            .iter()
            .find(|edge| edge.target_entity_id == disappearing_entity.id)
            .expect("import edge");
        let stable_bookmark = service
            .create_bookmark(
                &intake.case.id,
                NavigationTarget::Entity {
                    entity_id: stable_entity.id.clone(),
                },
                Some("stable".to_owned()),
            )
            .expect("stable bookmark");
        service
            .create_bookmark(
                &intake.case.id,
                NavigationTarget::Entity {
                    entity_id: disappearing_entity.id.clone(),
                },
                Some("derived entity".to_owned()),
            )
            .expect("entity bookmark");
        service
            .create_bookmark(
                &intake.case.id,
                NavigationTarget::Edge {
                    edge_id: disappearing_edge.id.clone(),
                },
                Some("derived edge".to_owned()),
            )
            .expect("edge bookmark");

        service.reanalyze_case(&intake.case.id).expect("reanalysis");

        assert_eq!(
            service
                .list_bookmarks(&intake.case.id)
                .expect("bookmarks after reanalysis")
                .into_iter()
                .map(|bookmark| bookmark.id)
                .collect::<Vec<_>>(),
            vec![stable_bookmark.id]
        );
        let second_graph = service
            .get_case_graph(&intake.case.id)
            .expect("graph query")
            .expect("graph");
        assert!(
            second_graph
                .entities
                .iter()
                .all(|entity| entity.id != disappearing_entity.id)
        );
        assert!(
            second_graph
                .edges
                .iter()
                .all(|edge| edge.id != disappearing_edge.id)
        );
    }

    #[test]
    fn bookmarks_cover_all_navigation_targets_persist_and_validate_case_identity() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let data_root = directory.path().join("data");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(&data_root, projection_analyzer).expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let analysis = service
            .get_case_analysis(&intake.case.id)
            .expect("analysis query")
            .expect("analysis");
        let graph = service
            .get_case_graph(&intake.case.id)
            .expect("graph query")
            .expect("graph");
        let chronology = service
            .get_case_chronology(&intake.case.id)
            .expect("chronology query")
            .expect("chronology");
        let targets = vec![
            NavigationTarget::Evidence {
                evidence_id: analysis.evidence[0].id.clone(),
            },
            NavigationTarget::Finding {
                finding_id: analysis.findings[0].id.clone(),
            },
            NavigationTarget::Entity {
                entity_id: graph.entities[0].id.clone(),
            },
            NavigationTarget::Edge {
                edge_id: graph.edges[0].id.clone(),
            },
            NavigationTarget::Event {
                event_id: chronology.events[0].id.clone(),
            },
        ];
        let mut bookmarks = Vec::new();
        for (index, target) in targets.into_iter().enumerate() {
            bookmarks.push(
                service
                    .create_bookmark(&intake.case.id, target, Some(format!("Bookmark {index}")))
                    .expect("bookmark"),
            );
        }
        assert_eq!(
            service
                .list_bookmarks(&intake.case.id)
                .expect("bookmarks")
                .len(),
            5
        );
        assert!(matches!(
            service.create_bookmark(
                &intake.case.id,
                NavigationTarget::Evidence {
                    evidence_id: analysis.evidence[0].id.clone(),
                },
                Some("x".repeat(tf_db::MAX_BOOKMARK_LABEL_BYTES + 1)),
            ),
            Err(IntakeError::Database(DatabaseError::Validation(
                "bookmark label"
            )))
        ));
        let updated = service
            .update_bookmark_label(
                &intake.case.id,
                &bookmarks[0].id,
                Some("  Important evidence  ".to_owned()),
            )
            .expect("updated bookmark");
        assert_eq!(updated.label.as_deref(), Some("Important evidence"));
        assert_eq!(
            service
                .get_bookmark(&intake.case.id, &updated.id)
                .expect("bookmark query"),
            Some(updated)
        );

        let second = service.ingest_pe(&source).expect("second case");
        let cross_case = service.create_bookmark(
            &second.case.id,
            NavigationTarget::Entity {
                entity_id: graph.entities[0].id.clone(),
            },
            None,
        );
        assert!(matches!(
            cross_case,
            Err(IntakeError::Database(DatabaseError::IdentityMismatch))
        ));
        service
            .delete_bookmark(&intake.case.id, &bookmarks[4].id)
            .expect("delete bookmark");
        drop(service);

        let reopened = CaseService::open_with_analyzer(&data_root, projection_analyzer)
            .expect("reopened service");
        assert_eq!(
            reopened
                .list_bookmarks(&intake.case.id)
                .expect("persisted bookmarks")
                .len(),
            4
        );
    }

    #[test]
    fn startup_recovers_an_interrupted_run_then_allows_successful_reanalysis() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let data_root = directory.path().join("data");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(&data_root, successful_analyzer).expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let interrupted = AnalysisRun {
            id: AnalysisRunId::new(),
            artifact_id: intake.artifact.id.clone(),
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            started_at: "2020-01-01T00:00:00Z".to_owned(),
            finished_at: None,
            status: AnalysisStatus::Running,
            error_code: None,
        };
        service
            .database
            .start_analysis(&intake.case.id, &interrupted, &interrupted.started_at)
            .expect("interrupted run");
        drop(service);

        let service = CaseService::open_with_analyzer(&data_root, successful_analyzer)
            .expect("restarted service");
        let recovered = service
            .get_case_analysis_run(&intake.case.id, &interrupted.id)
            .expect("recovery query")
            .expect("recovered run")
            .analysis_run
            .expect("analysis run");
        assert_eq!(recovered.status, AnalysisStatus::Failed);
        assert_eq!(recovered.error_code.as_deref(), Some("host_interrupted"));
        assert!(recovered.finished_at.is_some());
        let rerun = service
            .reanalyze_case(&intake.case.id)
            .expect("successful reanalysis");
        assert_eq!(rerun.status, AnalysisStatus::Complete);
        let history = service
            .get_case_analysis(&intake.case.id)
            .expect("history query")
            .expect("case");
        assert_eq!(history.case.status, CaseStatus::Complete);
        assert!(
            history
                .run_history
                .iter()
                .any(|run| run == &intake.analysis_run)
        );
        assert!(history.run_history.iter().any(|run| run == &recovered));
        assert!(history.run_history.iter().any(|run| run == &rerun));
    }

    #[test]
    fn startup_cleans_validated_staging_roots_without_touching_objects_or_nested_entries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let data_root = directory.path().join("data");
        for staging in ["artifacts/staging", "yara-staging", "report-staging"] {
            fs::create_dir_all(data_root.join(staging).join("nested")).expect("staging root");
            fs::write(data_root.join(staging).join("stale.tmp"), b"stale").expect("stale fixture");
            fs::write(
                data_root.join(staging).join("nested/keep.tmp"),
                b"do not recurse",
            )
            .expect("nested fixture");
        }
        let object = data_root.join("artifacts/objects/aa/immutable");
        fs::create_dir_all(object.parent().expect("object parent")).expect("object directory");
        fs::write(&object, b"immutable").expect("object fixture");

        CaseService::open_with_analyzer(&data_root, successful_analyzer).expect("service");

        for staging in ["artifacts/staging", "yara-staging", "report-staging"] {
            assert!(!data_root.join(staging).join("stale.tmp").exists());
            assert!(data_root.join(staging).join("nested/keep.tmp").is_file());
        }
        assert_eq!(fs::read(object).expect("object bytes"), b"immutable");
    }

    #[test]
    fn deletion_retains_shared_content_then_removes_the_last_object() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let first = service.ingest_pe(&source).expect("first intake");
        let second = service.ingest_pe(&source).expect("second intake");
        let object = service.data_root().join(&first.artifact.store_path);

        let first_delete = service.delete_case(&first.case.id).expect("first delete");
        assert_eq!(first_delete.objects.len(), 1);
        assert_eq!(
            first_delete.objects[0].cleanup,
            CleanupStatus::RetainedShared
        );
        assert!(object.is_file());
        let second_delete = service.delete_case(&second.case.id).expect("last delete");
        assert_eq!(second_delete.objects[0].cleanup, CleanupStatus::Removed);
        assert!(!object.exists());
    }

    #[test]
    fn comparison_is_ordered_contains_evidence_ids_and_serializes_without_paths() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let left = service
            .get_case_analysis(&intake.case.id)
            .expect("query")
            .expect("case");
        let mut right = left.clone();
        right.artifact.sha256 = "f".repeat(64);
        right.evidence[0].value["entry_point_rva"] = json!(8192);
        let section_id = EvidenceId::new();
        right.evidence.push(Evidence {
            id: section_id.clone(),
            artifact_id: right.artifact.id.clone(),
            provenance_id: right.provenances.first().expect("provenance").id.clone(),
            kind: "pe.section".to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::from([("section_index".to_owned(), json!(0))]),
            value: json!({"index":0,"name":".text","virtual_size":4096}),
            preview_text: None,
        });

        let comparison = compare_analyses(&left, &right);
        assert_eq!(comparison.hashes.changed.len(), 1);
        assert_eq!(comparison.hashes.changed[0].key, "sha256");
        assert_eq!(comparison.headers.changed[0].key, "entry_point_rva");
        assert_eq!(
            comparison.sections.added[0]
                .right
                .as_ref()
                .expect("right")
                .evidence_ids,
            vec![section_id]
        );
        let encoded = serde_json::to_string(&comparison).expect("comparison JSON");
        assert!(!encoded.contains("store_path"));
        assert!(!encoded.contains("storePath"));
        assert!(!encoded.contains(source.to_string_lossy().as_ref()));
        let analysis_json = serde_json::to_string(&left).expect("analysis JSON");
        assert!(!analysis_json.contains(&left.artifact.store_path));
    }

    #[test]
    #[ignore = "measurement only; run explicitly and compare environments, never as a PR gate"]
    fn measure_comparison_baseline() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let left = service
            .get_case_analysis(&intake.case.id)
            .expect("query")
            .expect("case");
        let mut right = left.clone();
        for index in 0..1_000 {
            right.evidence.push(Evidence {
                id: EvidenceId::from_u128(index + 10),
                artifact_id: right.artifact.id.clone(),
                provenance_id: right.provenances[0].id.clone(),
                kind: "pe.string".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([("file_offset".to_owned(), json!(index))]),
                value: json!({"text": format!("value-{index}"), "encoding":"ascii", "length_chars": 8, "truncated": false}),
                preview_text: None,
            });
        }
        let iterations = 100;
        let started = std::time::Instant::now();
        let mut changes = 0;
        for _ in 0..iterations {
            changes += compare_analyses(&left, &right).strings.added.len();
        }
        println!(
            "{{\"benchmark\":\"comparison\",\"iterations\":{iterations},\"changes\":{changes},\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }

    #[test]
    fn rejects_non_pe_without_creating_a_case() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("fake.exe");
        fs::write(&source, b"not a PE image").expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");

        assert!(matches!(
            service.ingest_pe(&source),
            Err(IntakeError::InvalidPe(PeError::InvalidFormat))
        ));
        assert!(service.list_cases().expect("cases").is_empty());
    }

    #[test]
    fn renders_and_exports_report_then_persists_its_hash() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let generated_at = "2026-08-25T14:00:00Z";
        let expected = service
            .render_report_bytes(&intake.case.id, ReportFormat::Json, generated_at)
            .expect("render");
        let destination = directory.path().join("reports");
        fs::create_dir(&destination).expect("report directory");
        let destination = destination.join("case.json");

        let record = service
            .export_report(
                &intake.case.id,
                ReportFormat::Json,
                generated_at,
                &destination,
            )
            .expect("export");

        assert_eq!(fs::read(&destination).expect("report bytes"), expected);
        assert_eq!(record.sha256, format!("{:x}", Sha256::digest(&expected)));
        assert_eq!(record.generated_at, generated_at);
        assert_eq!(
            service.list_reports(&intake.case.id).expect("reports"),
            vec![record]
        );
        let report_text = String::from_utf8(expected).expect("JSON UTF-8");
        assert!(!report_text.contains(&intake.artifact.store_path));
        assert!(!report_text.contains(source.to_string_lossy().as_ref()));
    }

    #[test]
    fn core_report_service_never_writes_html_bytes_as_pdf() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");

        assert!(matches!(
            service.render_report_bytes(&intake.case.id, ReportFormat::Pdf, "2026-08-25T14:00:00Z"),
            Err(ReportServiceError::DesktopRenderingRequired)
        ));

        let destination = directory.path().join("mismatched.pdf");
        assert!(matches!(
            service.export_rendered_report(
                &intake.case.id,
                ReportFormat::Pdf,
                "2026-08-25T14:00:00Z",
                &destination,
                b"<!doctype html><html></html>"
            ),
            Err(ReportServiceError::InvalidRenderedReport)
        ));
        assert!(!destination.exists());
        assert!(
            service
                .list_reports(&intake.case.id)
                .expect("reports")
                .is_empty()
        );
    }

    #[test]
    fn rendered_pdf_and_manifest_are_persisted_and_verified() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let analysis = service
            .get_case_analysis(&intake.case.id)
            .expect("analysis query")
            .expect("analysis");
        let generated_at = "2026-08-25T14:00:00Z";
        let pdf = b"%PDF-1.7\nArtifacta inert test PDF\n%%EOF";
        let report_destination = directory.path().join("case.pdf");

        let report = service
            .export_rendered_report(
                &intake.case.id,
                ReportFormat::Pdf,
                generated_at,
                &report_destination,
                pdf,
            )
            .expect("rendered PDF export");
        assert_eq!(report.format, "pdf");
        assert_eq!(fs::read(&report_destination).expect("PDF bytes"), pdf);

        let bundle_destination = directory.path().join("case-bundle.pdf");
        let manifest_destination = directory.path().join("case-bundle.pdf.manifest.json");
        let bundle = service
            .export_rendered_report_bundle(
                &analysis,
                ReportFormat::Pdf,
                generated_at,
                &bundle_destination,
                &manifest_destination,
                pdf,
            )
            .expect("rendered PDF bundle export");

        assert_eq!(
            service
                .list_reports(&intake.case.id)
                .expect("reports")
                .len(),
            2
        );
        assert_eq!(
            service
                .list_report_manifests(&intake.case.id)
                .expect("manifests"),
            vec![bundle.manifest.clone()]
        );
        let verification = service.verify_report_bundle(&bundle);
        assert_eq!(verification.status, ManifestVerificationStatus::Unsupported);
        assert_eq!(
            verification.artifact_verification,
            ArtifactVerification::Verified
        );
        assert!(!verification.safety_claim);
    }

    #[test]
    fn export_refuses_overwrite_by_default_without_recording_a_report() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let destination = directory.path().join("case.html");
        fs::write(&destination, b"keep me").expect("existing report");

        assert!(matches!(
            service.export_report(
                &intake.case.id,
                ReportFormat::Html,
                "2026-08-25T14:00:00Z",
                &destination,
            ),
            Err(ReportServiceError::DestinationExists)
        ));
        assert_eq!(fs::read(&destination).expect("existing bytes"), b"keep me");
        assert!(
            service
                .list_reports(&intake.case.id)
                .expect("reports")
                .is_empty()
        );
    }

    #[test]
    fn persistence_failure_rolls_back_new_file_and_restores_overwritten_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).expect("staging directory");
        let destination = directory.path().join("case.json");
        fs::write(&destination, b"prior report").expect("existing report");

        let result = write_and_persist_report(&staging, &destination, b"replacement", true, || {
            assert_eq!(fs::read_dir(&staging).expect("staging entries").count(), 1);
            Err(DatabaseError::ReportMismatch)
        });
        assert!(
            matches!(
                result,
                Err(ReportServiceError::Database(DatabaseError::ReportMismatch))
            ),
            "unexpected rollback result: {result:?}"
        );
        assert_eq!(
            fs::read(&destination).expect("restored report"),
            b"prior report"
        );

        let new_destination = directory.path().join("new.json");
        assert!(matches!(
            write_and_persist_report(&staging, &new_destination, b"new report", false, || {
                Err(DatabaseError::ReportMismatch)
            }),
            Err(ReportServiceError::Database(DatabaseError::ReportMismatch))
        ));
        assert!(!new_destination.exists());
    }

    #[test]
    fn exports_verifies_and_persists_a_deterministic_report_bundle() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let report_path = directory.path().join("case.json");
        let manifest_path = directory.path().join("case.manifest.json");
        let bundle = service
            .export_report_bundle(
                &intake.case.id,
                ReportFormat::Json,
                "2026-08-25T14:00:00Z",
                &report_path,
                &manifest_path,
            )
            .expect("bundle");

        let report_bytes = fs::read(&report_path).expect("report bytes");
        let manifest_bytes = fs::read(&manifest_path).expect("manifest bytes");
        assert_eq!(
            bundle.report.sha256,
            format!("{:x}", Sha256::digest(&report_bytes))
        );
        assert_eq!(
            bundle.manifest.manifest_sha256,
            format!("{:x}", Sha256::digest(&manifest_bytes))
        );
        assert!(
            String::from_utf8(report_bytes.clone())
                .unwrap()
                .contains("case.manifest.json")
        );
        assert_eq!(
            service
                .list_report_manifests(&intake.case.id)
                .expect("manifests"),
            vec![bundle.manifest.clone()]
        );
        let verified = service.verify_report_bundle(&bundle);
        assert_eq!(verified.status, ManifestVerificationStatus::Verified);
        assert_eq!(
            verified.artifact_verification,
            ArtifactVerification::Verified
        );
        assert!(!verified.safety_claim);

        let second_directory = directory.path().join("second");
        fs::create_dir(&second_directory).expect("second bundle directory");
        service
            .export_report_bundle(
                &intake.case.id,
                ReportFormat::Json,
                "2026-08-25T14:00:00Z",
                second_directory.join("case.json"),
                second_directory.join("case.manifest.json"),
            )
            .expect("second bundle");
        assert_eq!(
            fs::read(second_directory.join("case.json")).unwrap(),
            report_bytes
        );
        assert_eq!(
            fs::read(second_directory.join("case.manifest.json")).unwrap(),
            manifest_bytes
        );

        fs::write(&report_path, [report_bytes, b"changed".to_vec()].concat())
            .expect("tampered report");
        assert_eq!(
            service.verify_report_bundle(&bundle).status,
            ManifestVerificationStatus::Mismatch
        );
        fs::remove_file(&manifest_path).expect("remove manifest");
        assert_eq!(
            service.verify_report_bundle(&bundle).status,
            ManifestVerificationStatus::Unavailable
        );
    }

    #[test]
    fn bundle_database_failure_restores_both_overwritten_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let report = directory.path().join("case.json");
        let manifest = directory.path().join("case.manifest.json");
        fs::write(&report, b"prior report").expect("prior report");
        fs::write(&manifest, b"prior manifest").expect("prior manifest");
        let result = write_and_persist_bundle(
            &report,
            b"new report",
            &manifest,
            b"new manifest",
            true,
            || Err(DatabaseError::ReportMismatch),
        );
        assert!(matches!(
            result,
            Err(ReportServiceError::Database(DatabaseError::ReportMismatch))
        ));
        assert_eq!(fs::read(report).unwrap(), b"prior report");
        assert_eq!(fs::read(manifest).unwrap(), b"prior manifest");
    }

    #[test]
    fn destination_rejects_parent_traversal() {
        assert!(matches!(
            validate_destination(Path::new("reports/../case.json")),
            Err(ReportServiceError::InvalidDestination(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn destination_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real = directory.path().join("real");
        let linked = directory.path().join("linked");
        fs::create_dir(&real).expect("real directory");
        symlink(&real, &linked).expect("directory symlink");
        assert!(matches!(
            validate_destination(&linked.join("case.json")),
            Err(ReportServiceError::ReparsePoint)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn destination_rejects_symlinked_parent_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real = directory.path().join("real");
        let linked = directory.path().join("linked");
        fs::create_dir(&real).expect("real directory");
        if let Err(error) = symlink_dir(&real, &linked) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("directory symlink: {error}");
        }
        assert!(matches!(
            validate_destination(&linked.join("case.json")),
            Err(ReportServiceError::ReparsePoint)
        ));
    }

    #[test]
    fn provenance_includes_rule_engine_parameters_after_analysis() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("sample.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");
        let intake = service.ingest_pe(&source).expect("intake");
        let analysis = service
            .get_case_analysis(&intake.case.id)
            .expect("query")
            .expect("analysis");

        let rule_engine_provenance = analysis
            .provenances
            .iter()
            .find(|p| p.analyzer == tf_rules::ENGINE_NAME)
            .expect("rule engine provenance");

        assert_eq!(
            rule_engine_provenance.analyzer_version,
            tf_rules::ENGINE_VERSION
        );
        assert!(!rule_engine_provenance.parameters.is_empty());

        let expected = tf_rules::rule_engine_parameters();
        for (key, expected_value) in &expected {
            assert_eq!(
                rule_engine_provenance.parameters.get(key),
                Some(expected_value),
                "parameter {key} mismatch"
            );
        }
    }

    #[test]
    fn ingest_pe_with_stages_reports_stages_in_order() {
        use std::sync::{Arc, Mutex};
        use tf_protocol::ALL_STAGES;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("staged.exe");
        fs::write(&source, pe_fixture(0x10b)).expect("fixture write");
        let service =
            CaseService::open_with_analyzer(directory.path().join("data"), successful_analyzer)
                .expect("service");

        let stages: Arc<Mutex<Vec<AnalysisStage>>> = Arc::new(Mutex::new(Vec::new()));
        let stages_clone = stages.clone();
        let result = service
            .ingest_pe_with_stages(&source, &|stage| {
                stages_clone.lock().unwrap().push(stage);
            })
            .expect("intake with stages");

        assert_eq!(result.analysis_run.status, AnalysisStatus::Complete);
        let recorded = stages.lock().unwrap().clone();

        assert!(
            recorded.len() >= 4,
            "expected at least 4 stages, got {}",
            recorded.len()
        );

        assert_eq!(recorded[0], AnalysisStage::Ingesting);
        assert_eq!(recorded[1], AnalysisStage::VerifyingIdentity);
        assert_eq!(recorded[2], AnalysisStage::ParsingPe);

        assert!(recorded.contains(&AnalysisStage::RunningRules));
        assert!(recorded.contains(&AnalysisStage::BuildingGraph));
        assert!(recorded.contains(&AnalysisStage::BuildingChronology));
        assert!(recorded.contains(&AnalysisStage::FinalizingQuickCheck));
        assert!(recorded.contains(&AnalysisStage::Complete));

        let stage_indices: Vec<(AnalysisStage, usize)> = ALL_STAGES
            .iter()
            .filter_map(|stage| {
                recorded
                    .iter()
                    .position(|recorded| recorded == stage)
                    .map(|index| (*stage, index))
            })
            .collect();
        for window in stage_indices.windows(2) {
            assert!(
                window[0].1 < window[1].1,
                "stage {:?} (index {}) should precede {:?} (index {})",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1,
            );
        }
    }
}
