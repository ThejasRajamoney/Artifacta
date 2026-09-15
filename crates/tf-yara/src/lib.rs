#![deny(unsafe_code)]

//! YARA-X compilation and scanning isolated in bounded disposable processes.

#[cfg(windows)]
#[allow(unsafe_code)]
mod job_windows;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tf_model::{
    Confidence, ConfidenceBand, Evidence, EvidenceId, EvidenceRole, Finding, FindingEvidence,
    FindingExplanation, FindingId, FindingSet, FindingState, ObservationClass, Provenance,
    ProvenanceId, RuleRecord, RuleRecordId, Severity, YaraRuleMetadata,
};
use tf_protocol::{
    AnalyzerIdentity, MAX_IPC_MESSAGE_BYTES, MAX_YARA_PACK_BYTES, PROTOCOL_VERSION, WorkerStats,
    YaraOperation, YaraPackInput, YaraWorkerRecord, YaraWorkerRequest, decode_ndjson,
    encode_ndjson,
};
use thiserror::Error;

pub const ANALYZER_NAME: &str = "traceforge.yara-x";
pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ENGINE_NAME: &str = "yara-x";
pub const MAX_RULES_PER_PACK: usize = 10_000;
pub const MAX_ENABLED_PACKS: usize = 64;
pub const MAX_RULE_MATCHES: u32 = 1_024;
pub const MAX_STRING_INSTANCES_PER_MATCH: u32 = 128;
pub const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
pub const MAX_HEX_PREVIEW_BYTES: usize = 64;
pub const MAX_YARA_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const COMPILER_ERRORS_MAX_WIDTH: usize = 100;
const COMPILER_MAX_WARNINGS: usize = 8;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const IO_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_JOB_ID_BYTES: usize = 256;
const MAX_REQUEST_PATH_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct YaraAnalysis {
    pub analyzer: AnalyzerIdentity,
    pub provenances: Vec<Provenance>,
    pub evidence: Vec<Evidence>,
    pub stats: WorkerStats,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedPack {
    pub analyzer: AnalyzerIdentity,
    pub pack_sha256: String,
    pub rules: Vec<YaraRuleMetadata>,
    pub stats: WorkerStats,
}

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("invalid YARA request: {0}")]
    InvalidRequest(&'static str),
    #[error("YARA rule pack exceeds the {MAX_YARA_PACK_BYTES}-byte limit")]
    PackTooLarge,
    #[error("YARA rule pack is not valid UTF-8")]
    InvalidUtf8,
    #[error("YARA rule pack compilation failed: {diagnostic}")]
    Compilation { diagnostic: String },
    #[error("YARA rule pack includes and modules are not allowed")]
    NonLocalFeature,
    #[error("failed to start the YARA worker: {0}")]
    Spawn(#[source] io::Error),
    #[error("failed to communicate with the YARA worker: {0}")]
    Io(#[source] io::Error),
    #[error("failed to contain the YARA worker before request delivery: {0}")]
    Containment(#[source] io::Error),
    #[error("YARA worker exceeded its {0:?} deadline")]
    TimedOut(Duration),
    #[error("YARA worker output exceeded the {limit}-byte {kind} limit")]
    OutputLimit { kind: &'static str, limit: u64 },
    #[error("YARA worker emitted invalid output: {0}")]
    InvalidOutput(String),
    #[error("YARA worker transcript violated the protocol: {0}")]
    InvalidTranscript(&'static str),
    #[error("YARA worker reported {code}: {message}")]
    WorkerReported { code: String, message: String },
    #[error("YARA worker exited with {status}; stderr: {stderr}")]
    ProcessFailed { status: ExitStatus, stderr: String },
}

#[derive(Debug)]
enum WorkerFailure {
    Coded { code: &'static str, message: String },
    Io(io::Error),
}

impl From<io::Error> for WorkerFailure {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl WorkerFailure {
    fn code(&self) -> &'static str {
        match self {
            Self::Coded { code, .. } => code,
            Self::Io(_) => "worker_io",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Coded { message, .. } => truncate(message, MAX_DIAGNOSTIC_BYTES),
            Self::Io(error) => truncate(&error.to_string(), MAX_DIAGNOSTIC_BYTES),
        }
    }
}

struct Emitter<W> {
    output: W,
    max_message: usize,
    max_total: u64,
    max_records: u32,
    records: u32,
    bytes: u64,
}

impl<W: Write> Emitter<W> {
    fn new(output: W, request: &YaraWorkerRequest) -> Self {
        Self {
            output,
            max_message: usize::try_from(request.limits.max_message_bytes)
                .unwrap_or(MAX_IPC_MESSAGE_BYTES)
                .min(MAX_IPC_MESSAGE_BYTES),
            max_total: request.limits.max_total_result_bytes.min(64 * 1024 * 1024),
            max_records: request.limits.max_records,
            records: 0,
            bytes: 0,
        }
    }

    fn emit(&mut self, record: &YaraWorkerRecord) -> Result<(), WorkerFailure> {
        if self.records >= self.max_records {
            return Err(coded("record_limit", "worker record limit reached"));
        }
        let encoded =
            encode_ndjson(record).map_err(|error| coded("message_limit", error.to_string()))?;
        if encoded.len() > self.max_message {
            return Err(coded("message_limit", "worker record is too large"));
        }
        let length = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        if self.bytes.saturating_add(length) > self.max_total {
            return Err(coded("result_limit", "worker result byte limit reached"));
        }
        self.output.write_all(&encoded)?;
        self.output.flush()?;
        self.records += 1;
        self.bytes += length;
        Ok(())
    }
}

/// Entry point used only by the desktop executable's exact `--yara-worker` mode.
#[must_use]
pub fn run_worker() -> i32 {
    #[cfg(windows)]
    if job_windows::harden_worker_dll_search().is_err() {
        return 3;
    }
    run_worker_io(io::stdin().lock(), io::stdout().lock())
}

/// Runs the trusted Windows broker used by the exact `--yara-broker` mode.
#[must_use]
pub fn run_broker() -> i32 {
    #[cfg(windows)]
    {
        job_windows::run_broker()
            .ok()
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or(3)
    }
    #[cfg(not(windows))]
    {
        3
    }
}

/// Removes the stable worker profile during uninstall when it is not in use.
pub fn cleanup_appcontainer_profile() {
    #[cfg(windows)]
    job_windows::cleanup_profile();
}

fn run_worker_io<R: Read, W: Write>(mut input: R, output: W) -> i32 {
    let started = Instant::now();
    let request: YaraWorkerRequest = match read_one_line(&mut input) {
        Ok(request) => request,
        Err(_) => return 2,
    };
    let mut emitter = Emitter::new(output, &request);
    if emitter
        .emit(&YaraWorkerRecord::Hello {
            protocol: PROTOCOL_VERSION,
            analyzer: identity(),
        })
        .is_err()
    {
        return 1;
    }
    let records = match worker_records(&request) {
        Ok(records) => records,
        Err(error) => {
            let _ = emitter.emit(&YaraWorkerRecord::Error {
                code: error.code().to_owned(),
                message: redact_request_paths(error.message(), &request),
            });
            return 1;
        }
    };
    for record in records {
        if let Err(error) = emitter.emit(&record) {
            let _ = emitter.emit(&YaraWorkerRecord::Error {
                code: error.code().to_owned(),
                message: redact_request_paths(error.message(), &request),
            });
            return 1;
        }
    }
    let complete = YaraWorkerRecord::Complete {
        stats: WorkerStats {
            records_emitted: emitter.records.saturating_add(1),
            bytes_emitted: emitter.bytes,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            truncated: false,
        },
    };
    if emitter.emit(&complete).is_err() {
        1
    } else {
        0
    }
}

fn worker_records(request: &YaraWorkerRequest) -> Result<Vec<YaraWorkerRecord>, WorkerFailure> {
    validate_worker_request(request)?;
    match request.operation {
        YaraOperation::Validate => validate_pack_worker(&request.packs[0]),
        YaraOperation::Scan => scan_worker(request),
    }
}

fn validate_pack_worker(pack: &YaraPackInput) -> Result<Vec<YaraWorkerRecord>, WorkerFailure> {
    let (_, rules) = compile_pack(pack)?;
    Ok(vec![YaraWorkerRecord::Validated {
        pack_sha256: pack.sha256.to_ascii_lowercase(),
        rules,
    }])
}

fn scan_worker(request: &YaraWorkerRequest) -> Result<Vec<YaraWorkerRecord>, WorkerFailure> {
    let artifact_path = request
        .artifact_path
        .as_deref()
        .ok_or_else(|| coded("invalid_request", "scan artifact path is missing"))?;
    let expected = normalized_hash(
        request
            .input_sha256
            .as_deref()
            .ok_or_else(|| coded("invalid_request", "scan input hash is missing"))?,
    )
    .ok_or_else(|| coded("invalid_request", "scan input hash is invalid"))?;
    let mut artifact = VerifiedArtifact::open(artifact_path, &expected)?;

    let mut output = Vec::new();
    let mut match_count = 0_u32;
    for pack in &request.packs {
        let (rules, _) = compile_pack(pack)?;
        let provenance = Provenance {
            id: ProvenanceId::new(),
            analysis_run_id: request.analysis_run_id.clone(),
            analyzer: ANALYZER_NAME.to_owned(),
            analyzer_version: ANALYZER_VERSION.to_owned(),
            rule_id: None,
            rule_version: Some(pack.version.clone()),
            rule_pack_sha256: Some(pack.sha256.to_ascii_lowercase()),
            input_sha256: expected.clone(),
            parameters: BTreeMap::from([
                ("operation".to_owned(), json!("yara_scan")),
                ("includes_enabled".to_owned(), json!(false)),
                ("modules_enabled".to_owned(), json!(false)),
                ("network_access".to_owned(), json!(false)),
                ("mmap_enabled".to_owned(), json!(false)),
                ("compiler_error_on_slow_pattern".to_owned(), json!(true)),
                ("compiler_error_on_slow_loop".to_owned(), json!(true)),
                (
                    "compiler_errors_max_width".to_owned(),
                    json!(COMPILER_ERRORS_MAX_WIDTH),
                ),
                (
                    "compiler_max_warnings".to_owned(),
                    json!(COMPILER_MAX_WARNINGS),
                ),
                ("max_rules_per_pack".to_owned(), json!(MAX_RULES_PER_PACK)),
                ("max_rule_pack_bytes".to_owned(), json!(MAX_YARA_PACK_BYTES)),
                (
                    "max_rule_matches".to_owned(),
                    json!(request.max_rule_matches),
                ),
                (
                    "max_string_instances_per_match".to_owned(),
                    json!(request.max_string_instances_per_match),
                ),
                (
                    "scanner_max_matches_per_pattern".to_owned(),
                    json!(MAX_STRING_INSTANCES_PER_MATCH),
                ),
                (
                    "max_hex_preview_bytes".to_owned(),
                    json!(MAX_HEX_PREVIEW_BYTES),
                ),
                (
                    "worker_limits".to_owned(),
                    json!({
                        "wall_time_ms": request.limits.wall_time_ms,
                        "memory_bytes": request.limits.memory_bytes,
                        "max_records": request.limits.max_records,
                        "max_message_bytes": request.limits.max_message_bytes,
                        "max_total_result_bytes": request.limits.max_total_result_bytes,
                    }),
                ),
            ]),
        };
        let provenance_id = provenance.id.clone();
        output.push(YaraWorkerRecord::Provenance { provenance });

        let mut scanner = yara_x::Scanner::new(&rules);
        scanner
            .use_mmap(false)
            .set_timeout(Duration::from_millis(request.limits.wall_time_ms))
            .max_matches_per_pattern(MAX_STRING_INSTANCES_PER_MATCH as usize);
        let results = scanner
            .scan(&artifact.bytes)
            .map_err(|error| coded("scan_failed", error.to_string()))?;
        for rule in results.matching_rules() {
            if match_count >= request.max_rule_matches {
                return Err(coded("match_limit", "YARA rule match limit reached"));
            }
            match_count += 1;
            let namespace = rule.namespace().to_owned();
            let identifier = rule.identifier().to_owned();
            let tags = rule
                .tags()
                .map(|tag| tag.identifier().to_owned())
                .collect::<Vec<_>>();
            let metadata = rule.metadata().into_json();
            let mut strings = Vec::new();
            let mut instance_count = 0_u32;
            let mut instances_truncated = false;
            for pattern in rule.patterns() {
                let mut instances = Vec::new();
                for matched in pattern.matches() {
                    if instance_count >= request.max_string_instances_per_match {
                        instances_truncated = true;
                        break;
                    }
                    instance_count += 1;
                    let range = matched.range();
                    instances.push(json!({
                        "offset": range.start,
                        "length": range.end.saturating_sub(range.start),
                        "hex_preview": hex_preview(matched.data()),
                        "preview_truncated": matched.data().len() > MAX_HEX_PREVIEW_BYTES,
                    }));
                }
                if !instances.is_empty() {
                    strings.push(json!({
                        "identifier": pattern.identifier(),
                        "instances": instances,
                    }));
                }
                if instance_count >= request.max_string_instances_per_match {
                    break;
                }
            }
            let evidence = Evidence {
                id: EvidenceId::new(),
                artifact_id: request.artifact_id.clone(),
                provenance_id: provenance_id.clone(),
                kind: "yara.match".to_owned(),
                class: ObservationClass::Observed,
                locator: BTreeMap::from([
                    ("namespace".to_owned(), json!(namespace)),
                    ("rule_identifier".to_owned(), json!(identifier)),
                ]),
                value: json!({
                    "pack_sha256": pack.sha256.to_ascii_lowercase(),
                    "pack_name": pack.name,
                    "pack_version": pack.version,
                    "pack_source": pack.source,
                    "pack_license": pack.license,
                    "namespace": namespace,
                    "rule_identifier": identifier,
                    "tags": tags,
                    "metadata": metadata,
                    "matched_strings": strings,
                    "string_instances_truncated": instances_truncated
                        || instance_count >= request.max_string_instances_per_match,
                }),
                preview_text: Some(format!("YARA rule {namespace}:{identifier} matched")),
            };
            output.push(YaraWorkerRecord::Evidence { evidence });
        }
    }
    artifact.verify_unchanged(&expected)?;
    Ok(output)
}

struct VerifiedArtifact {
    file: File,
    bytes: Vec<u8>,
    initial_len: u64,
}

impl VerifiedArtifact {
    fn open(path: &str, expected: &str) -> Result<Self, WorkerFailure> {
        let mut file = File::open(path)?;
        let initial_len = file.metadata()?.len();
        if initial_len > MAX_YARA_SCAN_BYTES {
            return Err(coded(
                "input_size",
                "artifact exceeds the YARA scan byte limit",
            ));
        }

        let mut bytes = Vec::with_capacity(
            usize::try_from(initial_len).unwrap_or(MAX_YARA_SCAN_BYTES as usize),
        );
        Read::by_ref(&mut file)
            .take(MAX_YARA_SCAN_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_YARA_SCAN_BYTES {
            return Err(coded(
                "input_size",
                "artifact exceeds the YARA scan byte limit",
            ));
        }
        if bytes.len() as u64 != initial_len {
            return Err(coded("input_changed", "artifact changed while being read"));
        }
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(coded("input_hash_mismatch", "artifact hash does not match"));
        }
        Ok(Self {
            file,
            bytes,
            initial_len,
        })
    }

    fn verify_unchanged(&mut self, expected: &str) -> Result<(), WorkerFailure> {
        if self.file.metadata()?.len() != self.initial_len || hash_file(&mut self.file)? != expected
        {
            return Err(coded(
                "input_changed",
                "artifact changed while being scanned",
            ));
        }
        Ok(())
    }
}

fn compile_pack(
    pack: &YaraPackInput,
) -> Result<(yara_x::Rules, Vec<YaraRuleMetadata>), WorkerFailure> {
    let mut file = File::open(&pack.source_path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_YARA_PACK_BYTES as u64 {
        return Err(coded(
            "pack_size",
            "rule pack size is outside the allowed range",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(MAX_YARA_PACK_BYTES));
    Read::by_ref(&mut file)
        .take(MAX_YARA_PACK_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_YARA_PACK_BYTES {
        return Err(coded(
            "pack_size",
            "rule pack size is outside the allowed range",
        ));
    }
    if format!("{:x}", Sha256::digest(&bytes)) != pack.sha256.to_ascii_lowercase() {
        return Err(coded("pack_hash_mismatch", "rule pack hash does not match"));
    }
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| coded("invalid_utf8", "rule pack must be valid UTF-8"))?;
    if contains_non_local_directive(source) {
        return Err(coded(
            "non_local_feature",
            "includes and imported modules are not allowed",
        ));
    }
    let mut compiler = yara_x::Compiler::new();
    compiler
        .enable_includes(false)
        .error_on_slow_pattern(true)
        .error_on_slow_loop(true)
        .errors_max_width(COMPILER_ERRORS_MAX_WIDTH)
        .max_warnings(COMPILER_MAX_WARNINGS);
    if let Err(error) = compiler.add_source(source) {
        return Err(coded(
            "compile_error",
            truncate(&error.to_string(), MAX_DIAGNOSTIC_BYTES),
        ));
    }
    let rules = compiler.build();
    let metadata = rules
        .iter()
        .map(|rule| YaraRuleMetadata {
            namespace: rule.namespace().to_owned(),
            identifier: rule.identifier().to_owned(),
            tags: rule.tags().map(|tag| tag.identifier().to_owned()).collect(),
            metadata: rule.metadata().into_json(),
        })
        .collect::<Vec<_>>();
    if metadata.is_empty() || metadata.len() > MAX_RULES_PER_PACK {
        return Err(coded(
            "rule_limit",
            "rule pack rule count is outside the allowed range",
        ));
    }
    let identities = metadata
        .iter()
        .map(|rule| (&rule.namespace, &rule.identifier))
        .collect::<BTreeSet<_>>();
    if identities.len() != metadata.len() {
        return Err(coded("duplicate_rule", "rule identities must be unique"));
    }
    Ok((rules, metadata))
}

/// Produces deterministic contextual findings linked one-to-one with YARA match evidence.
#[must_use]
pub fn findings_for_matches(
    run_id: &tf_model::AnalysisRunId,
    artifact_id: &tf_model::ArtifactId,
    evidence: &[Evidence],
) -> FindingSet {
    let mut matches = evidence
        .iter()
        .filter(|item| item.kind == "yara.match")
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        yara_key(left)
            .cmp(&yara_key(right))
            .then(left.id.cmp(&right.id))
    });
    let mut output = FindingSet::default();
    for item in matches {
        let pack_hash = string_value(&item.value, "pack_sha256").unwrap_or("unknown");
        let pack_version = string_value(&item.value, "pack_version").unwrap_or("unknown");
        let pack_source = string_value(&item.value, "pack_source").unwrap_or("not recorded");
        let pack_license = string_value(&item.value, "pack_license").unwrap_or("not recorded");
        let namespace = string_value(&item.value, "namespace").unwrap_or("default");
        let identifier = string_value(&item.value, "rule_identifier").unwrap_or("unknown");
        let rule_id = format!("yara:{pack_hash}:{namespace}:{identifier}");
        let record_id = deterministic_rule_id(&rule_id, pack_version);
        output.rules.push(RuleRecord {
            id: record_id,
            engine: ENGINE_NAME.to_owned(),
            rule_id: rule_id.clone(),
            version: pack_version.to_owned(),
            source: pack_source.to_owned(),
            license: pack_license.to_owned(),
            sha256: pack_hash.to_owned(),
            enabled: true,
        });
        let finding_id = deterministic_finding_id(run_id, artifact_id, &rule_id, &item.id);
        let link = FindingEvidence {
            finding_id: finding_id.clone(),
            evidence_id: item.id.clone(),
            role: EvidenceRole::Context,
        };
        output.findings.push(Finding {
            id: finding_id.clone(),
            analysis_run_id: run_id.clone(),
            artifact_id: artifact_id.clone(),
            rule_id,
            rule_version: pack_version.to_owned(),
            title: format!("YARA rule match: {namespace}:{identifier}"),
            category: "yara_match".to_owned(),
            severity: Severity::Contextual,
            confidence: Confidence::new(1.0).expect("constant confidence is valid"),
            confidence_band: ConfidenceBand::Strong,
            explanation_template_id: "yara.match.context.v1".to_owned(),
            state: FindingState::New,
        });
        output.explanations.push(FindingExplanation {
            finding_id,
            template_id: "yara.match.context.v1".to_owned(),
            observation: format!(
                "The local YARA rule {namespace}:{identifier} matched. Pack source: {pack_source}; version: {pack_version}; license: {pack_license}."
            ),
            why_it_matters: "The rule match identifies exact bytes and rule-authored context for investigator review.".to_owned(),
            limitations: "A rule match is not a malware verdict. Rule quality, scope, age, and false positives must be assessed against the exact matched evidence.".to_owned(),
            supporting_evidence: vec![link.clone()],
        });
        output.evidence_links.push(link);
    }
    output.rules.sort_by(|left, right| {
        (&left.rule_id, &left.version).cmp(&(&right.rule_id, &right.version))
    });
    output
        .rules
        .dedup_by(|left, right| left.rule_id == right.rule_id && left.version == right.version);
    output
}

pub fn validate_pack(request: &YaraWorkerRequest) -> Result<ValidatedPack, YaraError> {
    if request.operation != YaraOperation::Validate {
        return Err(YaraError::InvalidRequest("operation must be validate"));
    }
    let output = run_host(request)?;
    parse_validation(request, output)
}

pub fn scan(request: &YaraWorkerRequest) -> Result<YaraAnalysis, YaraError> {
    if request.operation != YaraOperation::Scan {
        return Err(YaraError::InvalidRequest("operation must be scan"));
    }
    let output = run_host(request)?;
    parse_scan(request, output)
}

fn run_host(request: &YaraWorkerRequest) -> Result<DecodedOutput, YaraError> {
    validate_host_request(request)?;
    // `request` is only reassigned inside the Windows containment block below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut request = request.clone();
    let executable = std::env::current_exe().map_err(YaraError::Spawn)?;
    let mut command = Command::new(&executable);
    #[cfg(windows)]
    let _staged = {
        let staged = job_windows::StagedWorker::new(&executable, request.limits.memory_bytes)
            .map_err(YaraError::Containment)?;
        if let Some(artifact_path) = request.artifact_path.as_deref() {
            let artifact = staged
                .copy_file(std::path::Path::new(artifact_path), "artifact.bin")
                .map_err(YaraError::Containment)?;
            request.artifact_path = Some(artifact.to_string_lossy().into_owned());
        }
        for (index, pack) in request.packs.iter_mut().enumerate() {
            let staged_pack = staged
                .copy_file(
                    std::path::Path::new(&pack.source_path),
                    &format!("pack-{index}.yar"),
                )
                .map_err(YaraError::Containment)?;
            pack.source_path = staged_pack.to_string_lossy().into_owned();
        }
        staged.configure_broker(&mut command);
        staged
    };
    #[cfg(not(windows))]
    command.arg("--yara-worker");
    let encoded =
        encode_ndjson(&request).map_err(|error| YaraError::InvalidOutput(error.to_string()))?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(YaraError::Spawn)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(YaraError::InvalidTranscript("stdout is not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(YaraError::InvalidTranscript("stderr is not piped"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or(YaraError::InvalidTranscript("stdin is not piped"))?;
    let max_line = usize::try_from(request.limits.max_message_bytes)
        .unwrap_or(MAX_IPC_MESSAGE_BYTES)
        .min(MAX_IPC_MESSAGE_BYTES);
    let max_total = request.limits.max_total_result_bytes.min(64 * 1024 * 1024);
    let max_records = request.limits.max_records;
    let (out_tx, out_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = out_tx.send(read_output(stdout, max_line, max_total, max_records));
    });
    let (err_tx, err_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = err_tx.send(capture_stderr(stderr));
    });
    let stdin_rx = spawn_request_writer(stdin, encoded);
    let deadline = Duration::from_millis(request.limits.wall_time_ms.min(15_000));
    let started = Instant::now();
    let mut output = None;
    let mut request_sent = false;
    let status = loop {
        if !request_sent {
            match stdin_rx.try_recv() {
                Ok(Ok(())) => request_sent = true,
                Ok(Err(error)) => {
                    terminate(&mut child);
                    return Err(YaraError::Io(error));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate(&mut child);
                    return Err(YaraError::InvalidTranscript("stdin writer terminated"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if output.is_none() {
            match out_rx.try_recv() {
                Ok(result) => match result {
                    Ok(value) => output = Some(value),
                    Err(error) => {
                        terminate(&mut child);
                        return Err(error);
                    }
                },
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate(&mut child);
                    return Err(YaraError::InvalidTranscript("stdout reader terminated"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                terminate(&mut child);
                return Err(YaraError::TimedOut(deadline));
            }
            Err(error) => {
                terminate(&mut child);
                return Err(YaraError::Io(error));
            }
        }
    };
    let output = match output {
        Some(output) => output,
        None => out_rx
            .recv()
            .map_err(|_| YaraError::InvalidTranscript("stdout reader terminated"))??,
    };
    let stderr = err_rx.recv().unwrap_or_default();
    if !status.success() {
        if let Some(YaraWorkerRecord::Error { code, message }) = output.records.last() {
            return Err(map_worker_error(code, message));
        }
        return Err(YaraError::ProcessFailed {
            status,
            stderr: redact_request_paths(stderr, &request),
        });
    }
    Ok(output)
}

fn spawn_request_writer<W: Write + Send + 'static>(
    mut stdin: W,
    encoded: Vec<u8>,
) -> mpsc::Receiver<io::Result<()>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(stdin.write_all(&encoded));
    });
    receiver
}

#[derive(Debug)]
struct DecodedOutput {
    records: Vec<YaraWorkerRecord>,
    line_bytes: Vec<u64>,
}

fn read_output<R: Read>(
    mut input: R,
    max_line: usize,
    max_total: u64,
    max_records: u32,
) -> Result<DecodedOutput, YaraError> {
    let mut records = Vec::new();
    let mut line_bytes = Vec::new();
    let mut line = Vec::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input.read(&mut buffer).map_err(YaraError::Io)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if total > max_total {
            return Err(YaraError::OutputLimit {
                kind: "total output",
                limit: max_total,
            });
        }
        for byte in &buffer[..count] {
            if line.len() == max_line {
                return Err(YaraError::OutputLimit {
                    kind: "record",
                    limit: max_line as u64,
                });
            }
            line.push(*byte);
            if *byte == b'\n' {
                if records.len() >= usize::try_from(max_records).unwrap_or(usize::MAX) {
                    return Err(YaraError::OutputLimit {
                        kind: "record count",
                        limit: u64::from(max_records),
                    });
                }
                records.push(
                    decode_ndjson(&line)
                        .map_err(|error| YaraError::InvalidOutput(error.to_string()))?,
                );
                line_bytes.push(u64::try_from(line.len()).unwrap_or(u64::MAX));
                line.clear();
            }
        }
    }
    if !line.is_empty() {
        return Err(YaraError::InvalidTranscript(
            "output ended without a newline",
        ));
    }
    Ok(DecodedOutput {
        records,
        line_bytes,
    })
}

fn parse_validation(
    request: &YaraWorkerRequest,
    output: DecodedOutput,
) -> Result<ValidatedPack, YaraError> {
    validate_envelope(&output)?;
    let [
        YaraWorkerRecord::Hello { analyzer, .. },
        YaraWorkerRecord::Validated { pack_sha256, rules },
        YaraWorkerRecord::Complete { stats },
    ] = output.records.as_slice()
    else {
        return Err(YaraError::InvalidTranscript(
            "validation transcript shape is invalid",
        ));
    };
    if *analyzer != identity() || *pack_sha256 != request.packs[0].sha256.to_ascii_lowercase() {
        return Err(YaraError::InvalidTranscript(
            "validation identity does not match",
        ));
    }
    Ok(ValidatedPack {
        analyzer: analyzer.clone(),
        pack_sha256: pack_sha256.clone(),
        rules: rules.clone(),
        stats: stats.clone(),
    })
}

fn parse_scan(
    request: &YaraWorkerRequest,
    output: DecodedOutput,
) -> Result<YaraAnalysis, YaraError> {
    validate_envelope(&output)?;
    let analyzer = match output.records.first() {
        Some(YaraWorkerRecord::Hello { analyzer, .. }) if *analyzer == identity() => {
            analyzer.clone()
        }
        _ => {
            return Err(YaraError::InvalidTranscript(
                "hello identity does not match",
            ));
        }
    };
    let last = output.records.len() - 1;
    let YaraWorkerRecord::Complete { stats } = &output.records[last] else {
        return Err(YaraError::InvalidTranscript("complete record is missing"));
    };
    let mut provenances = Vec::new();
    let mut evidence = Vec::new();
    let mut current = None;
    for record in &output.records[1..last] {
        match record {
            YaraWorkerRecord::Provenance { provenance }
                if provenance.analysis_run_id == request.analysis_run_id
                    && provenance.analyzer == ANALYZER_NAME
                    && provenance.analyzer_version == ANALYZER_VERSION
                    && request.input_sha256.as_deref()
                        == Some(provenance.input_sha256.as_str()) =>
            {
                current = Some(provenance.id.clone());
                provenances.push(provenance.clone());
            }
            YaraWorkerRecord::Evidence { evidence: item }
                if current.as_ref() == Some(&item.provenance_id)
                    && item.artifact_id == request.artifact_id
                    && item.kind == "yara.match"
                    && item.class == ObservationClass::Observed =>
            {
                evidence.push(item.clone());
            }
            _ => {
                return Err(YaraError::InvalidTranscript(
                    "scan record identity or order is invalid",
                ));
            }
        }
    }
    if provenances.len() != request.packs.len() {
        return Err(YaraError::InvalidTranscript(
            "pack provenance count does not match",
        ));
    }
    Ok(YaraAnalysis {
        analyzer,
        provenances,
        evidence,
        stats: stats.clone(),
    })
}

fn validate_envelope(output: &DecodedOutput) -> Result<(), YaraError> {
    if output.records.len() < 3 {
        return Err(YaraError::InvalidTranscript("transcript is incomplete"));
    }
    let Some(YaraWorkerRecord::Hello { protocol, .. }) = output.records.first() else {
        return Err(YaraError::InvalidTranscript("hello must be first"));
    };
    let Some(YaraWorkerRecord::Complete { stats }) = output.records.last() else {
        return Err(YaraError::InvalidTranscript("complete must be last"));
    };
    let last = output.records.len() - 1;
    let bytes = output.line_bytes[..last].iter().sum::<u64>();
    if *protocol != PROTOCOL_VERSION
        || stats.truncated
        || usize::try_from(stats.records_emitted).ok() != Some(output.records.len())
        || stats.bytes_emitted != bytes
    {
        return Err(YaraError::InvalidTranscript(
            "envelope statistics do not match",
        ));
    }
    Ok(())
}

fn validate_host_request(request: &YaraWorkerRequest) -> Result<(), YaraError> {
    validate_worker_request(request).map_err(|error| match error {
        WorkerFailure::Coded { message, .. } => YaraError::InvalidOutput(message),
        WorkerFailure::Io(error) => YaraError::Io(error),
    })
}

fn validate_worker_request(request: &YaraWorkerRequest) -> Result<(), WorkerFailure> {
    if request.protocol != PROTOCOL_VERSION
        || request.packs.is_empty()
        || request.packs.len() > MAX_ENABLED_PACKS
    {
        return Err(coded("invalid_request", "protocol or pack list is invalid"));
    }
    if request.limits.wall_time_ms == 0
        || request.limits.wall_time_ms > 15_000
        || request.limits.memory_bytes == 0
        || request.limits.memory_bytes > 512 * 1024 * 1024
        || request.limits.max_message_bytes == 0
        || request.limits.max_message_bytes as usize > MAX_IPC_MESSAGE_BYTES
        || request.limits.max_total_result_bytes == 0
        || request.limits.max_total_result_bytes > 64 * 1024 * 1024
        || request.limits.max_records == 0
        || request.max_rule_matches == 0
        || request.max_rule_matches > MAX_RULE_MATCHES
        || request.max_string_instances_per_match == 0
        || request.max_string_instances_per_match > MAX_STRING_INSTANCES_PER_MATCH
    {
        return Err(coded("invalid_request", "worker limits are invalid"));
    }
    if !valid_label(&request.job_id, MAX_JOB_ID_BYTES)
        || request
            .artifact_path
            .as_deref()
            .is_some_and(|path| !valid_path(path))
    {
        return Err(coded("invalid_request", "request metadata is invalid"));
    }
    if request.operation == YaraOperation::Validate
        && (request.packs.len() != 1
            || request.artifact_path.is_some()
            || request.input_sha256.is_some())
    {
        return Err(coded(
            "invalid_request",
            "validation request shape is invalid",
        ));
    }
    if request.operation == YaraOperation::Scan
        && (request.artifact_path.is_none()
            || request
                .input_sha256
                .as_deref()
                .and_then(normalized_hash)
                .is_none())
    {
        return Err(coded("invalid_request", "scan request shape is invalid"));
    }
    if usize::try_from(request.limits.max_records).unwrap_or(usize::MAX) < request.packs.len() + 2 {
        return Err(coded(
            "invalid_request",
            "record limit cannot hold the minimum worker transcript",
        ));
    }
    for pack in &request.packs {
        if normalized_hash(&pack.sha256).is_none()
            || !valid_path(&pack.source_path)
            || !valid_label(&pack.name, 256)
            || !valid_label(&pack.version, 128)
            || !valid_label(&pack.source, 1024)
            || !valid_label(&pack.license, 256)
        {
            return Err(coded("invalid_request", "pack metadata is invalid"));
        }
    }
    let encoded_len = serde_json::to_vec(request)
        .map_err(|error| coded("invalid_request", error.to_string()))?
        .len()
        .checked_add(1)
        .ok_or_else(|| coded("invalid_request", "encoded request size overflow"))?;
    let max_request = usize::try_from(request.limits.max_message_bytes)
        .unwrap_or(MAX_IPC_MESSAGE_BYTES)
        .min(MAX_IPC_MESSAGE_BYTES);
    if encoded_len > max_request {
        return Err(coded(
            "invalid_request",
            "encoded request exceeds the worker message limit",
        ));
    }
    Ok(())
}

fn read_one_line<R: Read, T: DeserializeOwned>(input: &mut R) -> Result<T, WorkerFailure> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if input.read(&mut byte)? == 0 || line.len() >= MAX_IPC_MESSAGE_BYTES {
            return Err(coded("protocol", "request is missing or too large"));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if input.read(&mut byte)? != 0 {
        return Err(coded("protocol", "worker accepts exactly one request"));
    }
    decode_ndjson(&line).map_err(|error| coded("protocol", error.to_string()))
}

fn contains_non_local_directive(source: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("include ") || trimmed.starts_with("import ")
    })
}

fn hash_file(file: &mut File) -> Result<String, io::Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; IO_CHUNK_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn identity() -> AnalyzerIdentity {
    AnalyzerIdentity {
        name: ANALYZER_NAME.to_owned(),
        version: ANALYZER_VERSION.to_owned(),
    }
}

fn coded(code: &'static str, message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::Coded {
        code,
        message: message.into(),
    }
}

fn normalized_hash(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn valid_label(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
}

fn valid_path(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_PATH_BYTES && !value.contains('\0')
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn redact_request_paths(mut message: String, request: &YaraWorkerRequest) -> String {
    if let Some(path) = &request.artifact_path {
        message = message.replace(path, "[redacted artifact path]");
    }
    for pack in &request.packs {
        message = message.replace(&pack.source_path, "[redacted rule-pack path]");
    }
    truncate(&message, MAX_DIAGNOSTIC_BYTES)
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_HEX_PREVIEW_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn capture_stderr<R: Read>(mut input: R) -> String {
    let mut output = Vec::with_capacity(MAX_STDERR_BYTES);
    let mut buffer = [0_u8; 8192];
    loop {
        match input.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let keep = count.min(MAX_STDERR_BYTES.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn map_worker_error(code: &str, message: &str) -> YaraError {
    match code {
        "pack_size" => YaraError::PackTooLarge,
        "invalid_utf8" => YaraError::InvalidUtf8,
        "compile_error" => YaraError::Compilation {
            diagnostic: truncate(message, MAX_DIAGNOSTIC_BYTES),
        },
        "non_local_feature" => YaraError::NonLocalFeature,
        _ => YaraError::WorkerReported {
            code: code.to_owned(),
            message: truncate(message, MAX_DIAGNOSTIC_BYTES),
        },
    }
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn yara_key(evidence: &Evidence) -> (String, String, String) {
    (
        string_value(&evidence.value, "pack_sha256")
            .unwrap_or("")
            .to_owned(),
        string_value(&evidence.value, "namespace")
            .unwrap_or("")
            .to_owned(),
        string_value(&evidence.value, "rule_identifier")
            .unwrap_or("")
            .to_owned(),
    )
}

fn deterministic_rule_id(rule_id: &str, version: &str) -> RuleRecordId {
    let digest = Sha256::digest([rule_id.as_bytes(), b"\0", version.as_bytes()].concat());
    RuleRecordId::from(ulid_from_digest(&digest))
}

fn deterministic_finding_id(
    run_id: &tf_model::AnalysisRunId,
    artifact_id: &tf_model::ArtifactId,
    rule_id: &str,
    evidence_id: &EvidenceId,
) -> FindingId {
    let digest = Sha256::digest(
        [
            run_id.as_str().as_bytes(),
            b"\0",
            artifact_id.as_str().as_bytes(),
            b"\0",
            rule_id.as_bytes(),
            b"\0",
            evidence_id.as_str().as_bytes(),
        ]
        .concat(),
    );
    FindingId::from(ulid_from_digest(&digest))
}

fn ulid_from_digest(digest: &[u8]) -> ulid::Ulid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    ulid::Ulid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::mpsc::{Receiver, Sender};
    use tf_model::{AnalysisRunId, ArtifactId, YaraPackId};
    use tf_protocol::WorkerLimits;

    fn pack(path: &Path, source: &[u8]) -> YaraPackInput {
        std::fs::write(path, source).expect("write pack");
        YaraPackInput {
            id: YaraPackId::new(),
            sha256: format!("{:x}", Sha256::digest(source)),
            source_path: path.to_string_lossy().into_owned(),
            name: "test-pack".to_owned(),
            version: "1".to_owned(),
            source: "unit test".to_owned(),
            license: "Apache-2.0".to_owned(),
        }
    }

    fn request(operation: YaraOperation, pack: YaraPackInput) -> YaraWorkerRequest {
        YaraWorkerRequest {
            protocol: PROTOCOL_VERSION,
            job_id: "test".to_owned(),
            operation,
            analysis_run_id: AnalysisRunId::new(),
            artifact_id: ArtifactId::new(),
            artifact_path: None,
            input_sha256: None,
            packs: vec![pack],
            limits: WorkerLimits::default(),
            max_rule_matches: MAX_RULE_MATCHES,
            max_string_instances_per_match: MAX_STRING_INSTANCES_PER_MATCH,
        }
    }

    fn invoke(request: &YaraWorkerRequest) -> (i32, Vec<YaraWorkerRecord>) {
        let input = encode_ndjson(request).expect("request");
        let mut output = Vec::new();
        let status = run_worker_io(input.as_slice(), &mut output);
        let records = output
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| decode_ndjson(line).expect("record"))
            .collect();
        (status, records)
    }

    #[test]
    fn validates_and_scans_with_exact_bounded_match_evidence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rule = br#"rule Demo : inert { meta: author = "Artifacta" strings: $a = "DEMO" condition: $a }"#;
        let pack = pack(&directory.path().join("demo.yar"), rule);
        let validation = request(YaraOperation::Validate, pack.clone());
        let (status, records) = invoke(&validation);
        assert_eq!(status, 0);
        let YaraWorkerRecord::Validated { rules, .. } = &records[1] else {
            panic!("validated")
        };
        assert_eq!(rules[0].identifier, "Demo");

        let artifact = b"xxDEMOyyDEMO";
        let artifact_path = directory.path().join("artifact.bin");
        std::fs::write(&artifact_path, artifact).expect("artifact");
        let mut scan = request(YaraOperation::Scan, pack);
        scan.artifact_path = Some(artifact_path.to_string_lossy().into_owned());
        scan.input_sha256 = Some(format!("{:x}", Sha256::digest(artifact)));
        let (status, records) = invoke(&scan);
        assert_eq!(status, 0);
        let evidence = records
            .iter()
            .find_map(|record| match record {
                YaraWorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .expect("match evidence");
        assert_eq!(evidence.kind, "yara.match");
        assert_eq!(
            evidence.value["matched_strings"][0]["instances"][0]["offset"],
            2
        );
        assert_eq!(
            evidence.value["matched_strings"][0]["instances"][0]["length"],
            4
        );
        assert_eq!(
            evidence.value["matched_strings"][0]["instances"][0]["hex_preview"],
            "44454d4f"
        );
        let findings = findings_for_matches(
            &scan.analysis_run_id,
            &scan.artifact_id,
            std::slice::from_ref(evidence),
        );
        assert_eq!(findings.findings[0].severity, Severity::Contextual);
        assert!(
            findings.explanations[0]
                .limitations
                .contains("not a malware verdict")
        );
    }

    #[test]
    fn verified_buffer_binds_scan_bytes_and_detects_same_length_changes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rule = b"rule Original { strings: $a = \"ORIGINAL\" condition: $a }";
        let pack = pack(&directory.path().join("exact.yar"), rule);
        let (rules, _) = compile_pack(&pack).expect("compile pack");
        let artifact_path = directory.path().join("artifact.bin");
        let original = b"ORIGINAL";
        std::fs::write(&artifact_path, original).expect("write original artifact");
        let expected = format!("{:x}", Sha256::digest(original));
        let mut artifact =
            VerifiedArtifact::open(artifact_path.to_str().expect("UTF-8 test path"), &expected)
                .expect("verify artifact");

        std::fs::write(&artifact_path, b"REPLACED").expect("replace artifact bytes");
        {
            let mut scanner = yara_x::Scanner::new(&rules);
            let results = scanner.scan(&artifact.bytes).expect("scan verified bytes");
            let identifiers = results
                .matching_rules()
                .map(|matched| matched.identifier())
                .collect::<Vec<_>>();
            assert_eq!(identifiers, ["Original"]);
        }
        assert!(matches!(
            artifact.verify_unchanged(&expected),
            Err(WorkerFailure::Coded {
                code: "input_changed",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_utf8_includes_modules_and_compile_errors_with_bounded_messages() {
        let directory = tempfile::tempdir().expect("tempdir");
        for (name, source, code) in [
            ("utf8.yar", &[0xff, 0xfe][..], "invalid_utf8"),
            (
                "include.yar",
                b"include \"other.yar\"".as_slice(),
                "non_local_feature",
            ),
            (
                "module.yar",
                b"import \"pe\"\nrule x { condition: true }".as_slice(),
                "non_local_feature",
            ),
            (
                "bad.yar",
                b"rule broken { condition:".as_slice(),
                "compile_error",
            ),
        ] {
            let request = request(
                YaraOperation::Validate,
                pack(&directory.path().join(name), source),
            );
            let (status, records) = invoke(&request);
            assert_eq!(status, 1);
            assert!(
                matches!(&records[1], YaraWorkerRecord::Error { code: actual, message } if actual == code && message.len() <= MAX_DIAGNOSTIC_BYTES)
            );
        }
    }

    #[test]
    fn caps_string_instances_and_rejects_oversized_packs() {
        let directory = tempfile::tempdir().expect("tempdir");
        let oversized = vec![b' '; MAX_YARA_PACK_BYTES + 1];
        let oversized_request = request(
            YaraOperation::Validate,
            pack(&directory.path().join("large.yar"), &oversized),
        );
        let (_, records) = invoke(&oversized_request);
        assert!(matches!(&records[1], YaraWorkerRecord::Error { code, .. } if code == "pack_size"));

        let rule = b"rule cap { strings: $a = \"ABCD\" condition: $a }";
        let pack = pack(&directory.path().join("cap.yar"), rule);
        let artifact = b"ABCD".repeat(100);
        let artifact_path = directory.path().join("artifact.bin");
        std::fs::write(&artifact_path, &artifact).expect("artifact");
        let mut request = request(YaraOperation::Scan, pack);
        request.artifact_path = Some(artifact_path.to_string_lossy().into_owned());
        request.input_sha256 = Some(format!("{:x}", Sha256::digest(&artifact)));
        request.max_string_instances_per_match = 3;
        let (_, records) = invoke(&request);
        let evidence = records
            .iter()
            .find_map(|record| match record {
                YaraWorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .expect("evidence");
        assert_eq!(
            evidence.value["matched_strings"][0]["instances"]
                .as_array()
                .expect("instances")
                .len(),
            3
        );
        assert_eq!(evidence.value["string_instances_truncated"], true);
    }

    #[test]
    fn rejects_oversized_artifacts_pack_aggregates_and_requests() {
        let directory = tempfile::tempdir().expect("tempdir");
        let artifact_path = directory.path().join("oversized.bin");
        File::create(&artifact_path)
            .expect("create sparse artifact")
            .set_len(MAX_YARA_SCAN_BYTES + 1)
            .expect("size sparse artifact");
        assert!(matches!(
            VerifiedArtifact::open(
                artifact_path.to_str().expect("UTF-8 test path"),
                &"00".repeat(32),
            ),
            Err(WorkerFailure::Coded {
                code: "input_size",
                ..
            })
        ));

        let input = pack(
            &directory.path().join("aggregate.yar"),
            b"rule Aggregate { condition: true }",
        );
        let mut too_many = request(YaraOperation::Validate, input.clone());
        too_many.packs = vec![input.clone(); MAX_ENABLED_PACKS + 1];
        assert!(matches!(
            validate_worker_request(&too_many),
            Err(WorkerFailure::Coded {
                code: "invalid_request",
                ..
            })
        ));

        let mut invalid_metadata = request(YaraOperation::Validate, input.clone());
        invalid_metadata.packs[0].source = "x".repeat(1025);
        assert!(matches!(
            validate_worker_request(&invalid_metadata),
            Err(WorkerFailure::Coded {
                code: "invalid_request",
                ..
            })
        ));

        let mut impossible_transcript = request(YaraOperation::Validate, input.clone());
        impossible_transcript.limits.max_records = 2;
        assert!(matches!(
            validate_worker_request(&impossible_transcript),
            Err(WorkerFailure::Coded {
                code: "invalid_request",
                message,
            }) if message.contains("minimum worker transcript")
        ));

        let mut aggregate = request(YaraOperation::Scan, input);
        aggregate.artifact_path = Some("artifact.bin".to_owned());
        aggregate.input_sha256 = Some("00".repeat(32));
        aggregate.packs = (0..MAX_ENABLED_PACKS)
            .map(|index| {
                let mut input = aggregate.packs[0].clone();
                input.source_path = format!("{index}-{}", "p".repeat(20 * 1024));
                input
            })
            .collect();
        assert!(matches!(
            validate_worker_request(&aggregate),
            Err(WorkerFailure::Coded {
                code: "invalid_request",
                message,
            }) if message.contains("encoded request")
        ));

        let mut requested_cap = request(YaraOperation::Validate, aggregate.packs[0].clone());
        requested_cap.limits.max_message_bytes = 128;
        assert!(matches!(
            validate_worker_request(&requested_cap),
            Err(WorkerFailure::Coded {
                code: "invalid_request",
                message,
            }) if message.contains("encoded request")
        ));
    }

    struct BlockingWriter {
        started: Sender<()>,
        release: Receiver<()>,
    }

    impl Write for BlockingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.started.send(()).expect("signal writer start");
            self.release.recv().expect("release writer");
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_writer_is_monitorable_while_delivery_is_blocked() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let result_rx = spawn_request_writer(
            BlockingWriter {
                started: started_tx,
                release: release_rx,
            },
            b"request\n".to_vec(),
        );

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer should start");
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).expect("release writer");
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("writer result")
                .is_ok()
        );
    }

    #[test]
    fn moderate_inert_local_scan_honors_match_record_and_byte_caps() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source = (0..8)
            .map(|index| format!("rule Inert{index} {{ strings: $a = \"ABCD\" condition: $a }}\n"))
            .collect::<String>();
        let pack = pack(&directory.path().join("moderate.yar"), source.as_bytes());
        let artifact = b"ABCD\0".repeat(400_000);
        let artifact_path = directory.path().join("artifact.bin");
        std::fs::write(&artifact_path, &artifact).expect("artifact");
        let mut request = request(YaraOperation::Scan, pack);
        request.artifact_path = Some(artifact_path.to_string_lossy().into_owned());
        request.input_sha256 = Some(format!("{:x}", Sha256::digest(&artifact)));
        request.limits.wall_time_ms = 15_000;
        request.limits.max_records = 32;
        request.limits.max_total_result_bytes = 1024 * 1024;
        request.max_rule_matches = 8;
        request.max_string_instances_per_match = 16;

        let (status, records) = invoke(&request);
        assert_eq!(status, 0);
        let evidence = records
            .iter()
            .filter_map(|record| match record {
                YaraWorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(evidence.len(), 8);
        assert!(evidence.iter().all(|item| {
            item.value["matched_strings"][0]["instances"]
                .as_array()
                .is_some_and(|instances| instances.len() <= 16)
        }));
        assert!(records.len() <= 32);
        let output_bytes: usize = records
            .iter()
            .map(|record| encode_ndjson(record).expect("record encoding").len())
            .sum();
        assert!(output_bytes <= 1024 * 1024);
        let YaraWorkerRecord::Provenance { provenance } = &records[1] else {
            panic!("provenance expected");
        };
        assert_eq!(provenance.parameters["includes_enabled"], false);
        assert_eq!(provenance.parameters["modules_enabled"], false);
        assert_eq!(provenance.parameters["network_access"], false);
        assert_eq!(provenance.parameters["compiler_errors_max_width"], 100);
        assert_eq!(provenance.parameters["max_rule_matches"], 8);
        assert_eq!(provenance.parameters["max_string_instances_per_match"], 16);
    }

    #[test]
    fn bounded_output_reader_rejects_hostile_output() {
        assert!(matches!(
            read_output(vec![b'x'; 17].as_slice(), 16, 100, 10),
            Err(YaraError::OutputLimit { kind: "record", .. })
        ));
        assert!(matches!(
            read_output(b"{}".as_slice(), 16, 100, 10),
            Err(YaraError::InvalidTranscript(_))
        ));
        assert!(matches!(
            read_output(b"{}\n{}\n".as_slice(), 16, 5, 10),
            Err(YaraError::OutputLimit {
                kind: "total output",
                ..
            })
        ));
    }
}
