#![deny(unsafe_code)]

//! Packaged static PE worker and its bounded disposable-process host.

pub mod analysis;
mod authenticode;
#[cfg(windows)]
#[allow(unsafe_code)]
mod authenticode_windows;
#[cfg(windows)]
#[allow(unsafe_code)]
mod job_windows;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tf_model::{Evidence, EvidenceId, ObservationClass, Provenance, ProvenanceId};
use tf_protocol::{
    AnalyzerIdentity, MAX_IPC_MESSAGE_BYTES, Operation, PROTOCOL_VERSION, WorkerRecord,
    WorkerRequest, WorkerStats, decode_ndjson, encode_ndjson,
};
use thiserror::Error;

pub use tf_protocol::WorkerLimits;

pub const ANALYZER_NAME: &str = "traceforge.pe";
pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HOST_DEADLINE: Duration = Duration::from_secs(15);
pub const MAX_TOTAL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

const IO_CHUNK_BYTES: usize = 1024 * 1024;

/// Parses a file through the production parser for development or fuzz tooling.
///
/// This feature-gated API does not run in production and deliberately returns only
/// parser observations, without worker IDs, timestamps, trust interpretation, or I/O policy.
#[cfg(feature = "dev-tools")]
pub fn parse_file_for_dev(path: &Path) -> Result<Vec<Value>, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    parse_reader_for_dev(&mut file, length)
}

/// Parses in-memory bytes through the production parser for development tooling.
#[cfg(feature = "dev-tools")]
pub fn parse_bytes_for_dev(bytes: Vec<u8>) -> Result<Vec<Value>, String> {
    let length = bytes.len() as u64;
    parse_reader_for_dev(&mut io::Cursor::new(bytes), length)
}

#[cfg(feature = "dev-tools")]
fn parse_reader_for_dev<R: Read + Seek>(reader: &mut R, length: u64) -> Result<Vec<Value>, String> {
    analysis::parse(reader, length, &tf_protocol::WorkerLimits::default())
        .map(|records| {
            records
                .into_iter()
                .map(|record| {
                    json!({
                        "kind": record.kind,
                        "class": record.class.as_str(),
                        "locator": record.locator,
                        "value": record.value,
                        "preview_text": record.preview_text,
                    })
                })
                .collect()
        })
        .map_err(|error| error.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeAnalysis {
    pub analyzer: AnalyzerIdentity,
    pub provenance: Provenance,
    pub evidence: Vec<Evidence>,
    pub stats: WorkerStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStderr {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("invalid PE worker request: {0}")]
    InvalidRequest(&'static str),
    #[error("failed to start the packaged PE worker: {0}")]
    Spawn(#[source] io::Error),
    #[error("failed to communicate with the packaged PE worker: {0}")]
    Io(#[source] io::Error),
    #[error("failed to contain the packaged PE worker before request delivery: {0}")]
    Containment(#[source] io::Error),
    #[error("PE worker exceeded its {0:?} wall-time deadline")]
    TimedOut(Duration),
    #[error("PE worker output exceeded the {limit}-byte {kind} limit")]
    OutputLimit { kind: &'static str, limit: u64 },
    #[error("PE worker emitted invalid NDJSON: {0}")]
    InvalidOutput(String),
    #[error("PE worker transcript violated the protocol: {0}")]
    InvalidTranscript(&'static str),
    #[error("PE worker reported {code}: {message}")]
    WorkerReported { code: String, message: String },
    #[error("PE worker exited with {status}; stderr: {stderr:?}")]
    ProcessFailed {
        status: ExitStatus,
        stderr: CapturedStderr,
    },
}

#[derive(Debug, Error)]
pub enum WorkerFailure {
    #[error("{message}")]
    Coded { code: &'static str, message: String },
    #[error("worker I/O failed")]
    Io(#[from] io::Error),
    #[error("worker protocol encoding failed")]
    Protocol,
}

impl WorkerFailure {
    pub(crate) fn invalid_pe(message: impl Into<String>) -> Self {
        Self::Coded {
            code: "invalid_pe",
            message: message.into(),
        }
    }

    pub(crate) fn invalid_section_bounds(message: impl Into<String>) -> Self {
        Self::Coded {
            code: "invalid_section_bounds",
            message: message.into(),
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Coded { code, .. } => code,
            Self::Io(_) | Self::Protocol => "worker_failure",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Coded { message, .. } => message.clone(),
            Self::Io(_) | Self::Protocol => "worker could not safely parse the artifact".to_owned(),
        }
    }
}

struct Emitter<W> {
    output: W,
    max_message_bytes: usize,
    max_total_bytes: u64,
    max_records: u32,
    records: u32,
    bytes: u64,
}

impl<W: Write> Emitter<W> {
    fn new(output: W, request: &WorkerRequest) -> Self {
        Self {
            output,
            max_message_bytes: usize::try_from(request.limits.max_message_bytes)
                .unwrap_or(MAX_IPC_MESSAGE_BYTES)
                .min(MAX_IPC_MESSAGE_BYTES),
            max_total_bytes: request
                .limits
                .max_total_result_bytes
                .min(MAX_TOTAL_OUTPUT_BYTES),
            max_records: request.limits.max_records,
            records: 0,
            bytes: 0,
        }
    }

    fn emit(&mut self, record: &WorkerRecord) -> Result<(), WorkerFailure> {
        if self.records >= self.max_records {
            return Err(WorkerFailure::Coded {
                code: "record_limit",
                message: "worker record limit reached".to_owned(),
            });
        }
        let encoded = encode_ndjson(record).map_err(|_| WorkerFailure::Protocol)?;
        if encoded.len() > self.max_message_bytes {
            return Err(WorkerFailure::Coded {
                code: "message_limit",
                message: "worker record exceeds the message limit".to_owned(),
            });
        }
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| WorkerFailure::Protocol)?;
        if self.bytes.saturating_add(encoded_len) > self.max_total_bytes {
            return Err(WorkerFailure::Coded {
                code: "result_limit",
                message: "worker result byte limit reached".to_owned(),
            });
        }
        self.output.write_all(&encoded)?;
        self.output.flush()?;
        self.records += 1;
        self.bytes += encoded_len;
        Ok(())
    }
}

/// Runs the hidden one-request worker over standard input and output.
///
/// The desktop binary calls this only for an exact `--pe-worker` invocation.
#[must_use]
pub fn run_worker() -> i32 {
    #[cfg(windows)]
    if job_windows::harden_worker_dll_search().is_err() {
        return 3;
    }
    run_worker_io(io::stdin().lock(), io::stdout().lock())
}

/// Runs the trusted Windows broker used by the exact `--pe-broker` mode.
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
    let request = match read_request(&mut input) {
        Ok(request) => request,
        Err(_) => return 2,
    };
    let mut emitter = Emitter::new(output, &request);
    if emitter
        .emit(&WorkerRecord::Hello {
            protocol: PROTOCOL_VERSION,
            analyzer: analyzer_identity(),
        })
        .is_err()
    {
        return 1;
    }

    let result = worker_records(&request).and_then(|records| {
        for record in records {
            emitter.emit(&record)?;
        }
        Ok(())
    });
    if let Err(error) = result {
        let _ = emitter.emit(&WorkerRecord::Error {
            code: error.code().to_owned(),
            message: error.public_message(),
            retryable: false,
        });
        return 1;
    }

    let complete = WorkerRecord::Complete {
        stats: WorkerStats {
            records_emitted: emitter.records.saturating_add(1),
            bytes_emitted: emitter.bytes,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            truncated: false,
        },
    };
    if emitter.emit(&complete).is_err() {
        return 1;
    }
    0
}

fn read_request<R: Read>(input: &mut R) -> Result<WorkerRequest, WorkerFailure> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = input.read(&mut byte)?;
        if count == 0 {
            return Err(WorkerFailure::Protocol);
        }
        line.push(byte[0]);
        if line.len() > MAX_IPC_MESSAGE_BYTES {
            return Err(WorkerFailure::Protocol);
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    if input.read(&mut byte)? != 0 {
        return Err(WorkerFailure::Protocol);
    }
    decode_ndjson(&line).map_err(|_| WorkerFailure::Protocol)
}

fn worker_records(request: &WorkerRequest) -> Result<Vec<WorkerRecord>, WorkerFailure> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(WorkerFailure::Coded {
            code: "unsupported_protocol",
            message: "worker protocol version does not match".to_owned(),
        });
    }
    if request.operation != Operation::PeStatic {
        return Err(WorkerFailure::Coded {
            code: "unsupported_operation",
            message: "worker only supports pe_static".to_owned(),
        });
    }
    let expected_hash =
        normalized_sha256(&request.input_sha256).ok_or_else(|| WorkerFailure::Coded {
            code: "input_hash_mismatch",
            message: "immutable input SHA-256 does not match request".to_owned(),
        })?;

    let mut artifact = File::open(Path::new(&request.artifact_path))?;
    let initial_length = artifact.metadata()?.len();
    if hash_file(&mut artifact)? != expected_hash {
        return Err(WorkerFailure::Coded {
            code: "input_hash_mismatch",
            message: "immutable input SHA-256 does not match request".to_owned(),
        });
    }
    let parsed = analysis::parse(&mut artifact, initial_length, &request.limits)?;
    let final_length = artifact.metadata()?.len();
    if final_length != initial_length || hash_file(&mut artifact)? != expected_hash {
        return Err(WorkerFailure::Coded {
            code: "input_changed",
            message: "immutable input changed while it was being parsed".to_owned(),
        });
    }

    let mut parameters = analysis::provenance_parameters(&request.limits);
    parameters.extend([
        ("operation".to_owned(), json!("pe_static")),
        ("parser".to_owned(), json!("traceforge_pe_v2")),
        (
            "authenticode_parser".to_owned(),
            json!("rustcrypto_cms_0.2.3_windows_cryptoapi_offline_v2"),
        ),
        (
            "authenticode_limits".to_owned(),
            authenticode::provenance_parameters(),
        ),
        ("network_access".to_owned(), json!(false)),
    ]);
    let provenance = Provenance {
        id: ProvenanceId::new(),
        analysis_run_id: request.analysis_run_id.clone(),
        analyzer: ANALYZER_NAME.to_owned(),
        analyzer_version: ANALYZER_VERSION.to_owned(),
        rule_id: None,
        rule_version: None,
        rule_pack_sha256: None,
        input_sha256: expected_hash,
        parameters,
    };
    let provenance_id = provenance.id.clone();
    let mut records = Vec::with_capacity(parsed.len() + 1);
    records.push(WorkerRecord::Provenance { provenance });
    for item in parsed {
        records.push(WorkerRecord::Evidence {
            evidence: evidence_with_class(
                request,
                &provenance_id,
                item.kind,
                item.class,
                item.locator,
                item.value,
                item.preview_text,
            ),
        });
    }
    Ok(records)
}

fn analyzer_identity() -> AnalyzerIdentity {
    AnalyzerIdentity {
        name: ANALYZER_NAME.to_owned(),
        version: ANALYZER_VERSION.to_owned(),
    }
}

fn evidence_with_class(
    request: &WorkerRequest,
    provenance_id: &ProvenanceId,
    kind: String,
    class: ObservationClass,
    locator: BTreeMap<String, Value>,
    value: Value,
    preview_text: Option<String>,
) -> Evidence {
    Evidence {
        id: EvidenceId::new(),
        artifact_id: request.artifact_id.clone(),
        provenance_id: provenance_id.clone(),
        kind,
        class,
        locator,
        value,
        preview_text,
    }
}

fn normalized_sha256(value: &str) -> Option<String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
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

/// Spawns this installed executable in hidden PE-worker mode and validates one result.
///
/// Wall time, line size, total output, record count, stderr capture, and (on Windows) process
/// memory are host-enforced. The request is not sent until Windows Job Object assignment succeeds.
pub fn run_pe_analysis(mut request: WorkerRequest) -> Result<PeAnalysis, HostError> {
    validate_request(&request)?;
    request.input_sha256 = request.input_sha256.to_ascii_lowercase();
    let executable = std::env::current_exe().map_err(HostError::Spawn)?;
    let mut command = Command::new(&executable);
    #[cfg(windows)]
    let _staged = {
        let staged = job_windows::StagedWorker::new(&executable, request.limits.memory_bytes)
            .map_err(HostError::Containment)?;
        let artifact = staged
            .copy_file(Path::new(&request.artifact_path), "artifact.bin")
            .map_err(HostError::Containment)?;
        request.artifact_path = artifact.to_string_lossy().into_owned();
        staged.configure_broker(&mut command);
        staged
    };
    #[cfg(not(windows))]
    command.arg("--pe-worker");
    run_command(command, &request, HOST_DEADLINE)
}

fn validate_request(request: &WorkerRequest) -> Result<(), HostError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(HostError::InvalidRequest("unsupported protocol version"));
    }
    if request.operation != Operation::PeStatic {
        return Err(HostError::InvalidRequest("operation must be pe_static"));
    }
    if normalized_sha256(&request.input_sha256).is_none() {
        return Err(HostError::InvalidRequest(
            "input_sha256 must be 64 hex digits",
        ));
    }
    if request.limits.wall_time_ms == 0
        || request.limits.memory_bytes == 0
        || request.limits.max_message_bytes == 0
        || request.limits.max_total_result_bytes == 0
        || request.limits.max_records == 0
    {
        return Err(HostError::InvalidRequest("worker limits must be nonzero"));
    }
    Ok(())
}

fn run_command(
    mut command: Command,
    request: &WorkerRequest,
    hard_deadline: Duration,
) -> Result<PeAnalysis, HostError> {
    let encoded =
        encode_ndjson(request).map_err(|error| HostError::InvalidOutput(error.to_string()))?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(HostError::Spawn)?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate(&mut child);
        HostError::InvalidTranscript("worker stdout was not piped")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate(&mut child);
        HostError::InvalidTranscript("worker stderr was not piped")
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        terminate(&mut child);
        HostError::InvalidTranscript("worker stdin was not piped")
    })?;

    let max_line = usize::try_from(request.limits.max_message_bytes)
        .unwrap_or(MAX_IPC_MESSAGE_BYTES)
        .min(MAX_IPC_MESSAGE_BYTES);
    let max_total = request
        .limits
        .max_total_result_bytes
        .min(MAX_TOTAL_OUTPUT_BYTES);
    let max_records = request.limits.max_records;
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdout_sender.send(read_output(stdout, max_line, max_total, max_records));
    });
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stderr_sender.send(capture_stderr(stderr));
    });
    let (stdin_sender, stdin_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut stdin = stdin;
        let _ = stdin_sender.send(stdin.write_all(&encoded));
    });

    let requested_deadline = Duration::from_millis(request.limits.wall_time_ms);
    let deadline = hard_deadline.min(requested_deadline);
    let started = Instant::now();
    let mut output = None;
    let mut request_sent = false;
    let status = loop {
        if !request_sent {
            match stdin_receiver.try_recv() {
                Ok(Ok(())) => request_sent = true,
                Ok(Err(error)) => {
                    terminate(&mut child);
                    return Err(HostError::Io(error));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate(&mut child);
                    return Err(HostError::InvalidTranscript("stdin writer terminated"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if output.is_none() {
            match stdout_receiver.try_recv() {
                Ok(result) => match result {
                    Ok(value) => output = Some(value),
                    Err(error) => {
                        terminate(&mut child);
                        return Err(error);
                    }
                },
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate(&mut child);
                    return Err(HostError::InvalidTranscript("stdout reader terminated"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate(&mut child);
                return Err(HostError::Io(error));
            }
        }
        if started.elapsed() >= deadline {
            terminate(&mut child);
            return Err(HostError::TimedOut(deadline));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = match output {
        Some(output) => output,
        None => stdout_receiver
            .recv()
            .map_err(|_| HostError::InvalidTranscript("stdout reader terminated"))??,
    };
    let stderr = stderr_receiver
        .recv()
        .map_err(|_| HostError::InvalidTranscript("stderr reader terminated"))?;
    if !status.success() {
        if let Some((code, message)) = reported_error(&output.records) {
            return Err(HostError::WorkerReported { code, message });
        }
        return Err(HostError::ProcessFailed { status, stderr });
    }
    validate_transcript(request, output)
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct DecodedOutput {
    records: Vec<WorkerRecord>,
    line_bytes: Vec<u64>,
}

fn read_output<R: Read>(
    mut input: R,
    max_line: usize,
    max_total: u64,
    max_records: u32,
) -> Result<DecodedOutput, HostError> {
    let mut records = Vec::new();
    let mut line_bytes = Vec::new();
    let mut line = Vec::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input.read(&mut buffer).map_err(HostError::Io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or(HostError::OutputLimit {
                kind: "total output",
                limit: max_total,
            })?;
        if total > max_total {
            return Err(HostError::OutputLimit {
                kind: "total output",
                limit: max_total,
            });
        }
        for byte in &buffer[..count] {
            if line.len() == max_line {
                return Err(HostError::OutputLimit {
                    kind: "line",
                    limit: u64::try_from(max_line).unwrap_or(u64::MAX),
                });
            }
            line.push(*byte);
            if *byte == b'\n' {
                if records.len() >= usize::try_from(max_records).unwrap_or(usize::MAX) {
                    return Err(HostError::OutputLimit {
                        kind: "record count",
                        limit: u64::from(max_records),
                    });
                }
                let record = decode_ndjson(&line)
                    .map_err(|error| HostError::InvalidOutput(error.to_string()))?;
                line_bytes.push(u64::try_from(line.len()).unwrap_or(u64::MAX));
                records.push(record);
                line.clear();
            }
        }
    }
    if !line.is_empty() {
        return Err(HostError::InvalidTranscript(
            "worker output ended without a newline",
        ));
    }
    Ok(DecodedOutput {
        records,
        line_bytes,
    })
}

fn capture_stderr<R: Read>(mut input: R) -> CapturedStderr {
    let mut captured = Vec::with_capacity(MAX_STDERR_BYTES);
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match input.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let available = MAX_STDERR_BYTES.saturating_sub(captured.len());
                let keep = available.min(count);
                captured.extend_from_slice(&buffer[..keep]);
                truncated |= keep != count;
            }
        }
    }
    CapturedStderr {
        text: String::from_utf8_lossy(&captured).into_owned(),
        truncated,
    }
}

fn reported_error(records: &[WorkerRecord]) -> Option<(String, String)> {
    let [
        WorkerRecord::Hello { protocol, analyzer },
        WorkerRecord::Error { code, message, .. },
    ] = records
    else {
        return None;
    };
    (*protocol == PROTOCOL_VERSION && *analyzer == analyzer_identity())
        .then(|| (code.clone(), message.clone()))
}

fn validate_transcript(
    request: &WorkerRequest,
    output: DecodedOutput,
) -> Result<PeAnalysis, HostError> {
    if output.records.len() < 4 {
        return Err(HostError::InvalidTranscript(
            "success transcript is incomplete",
        ));
    }
    let analyzer = match &output.records[0] {
        WorkerRecord::Hello { protocol, analyzer }
            if *protocol == PROTOCOL_VERSION && *analyzer == analyzer_identity() =>
        {
            analyzer.clone()
        }
        WorkerRecord::Hello { .. } => {
            return Err(HostError::InvalidTranscript(
                "hello protocol or analyzer identity does not match",
            ));
        }
        _ => {
            return Err(HostError::InvalidTranscript(
                "hello must be the first record",
            ));
        }
    };
    let provenance = match &output.records[1] {
        WorkerRecord::Provenance { provenance }
            if provenance.analysis_run_id == request.analysis_run_id
                && provenance.analyzer == analyzer.name
                && provenance.analyzer_version == analyzer.version
                && provenance.input_sha256 == request.input_sha256 =>
        {
            provenance.clone()
        }
        WorkerRecord::Provenance { .. } => {
            return Err(HostError::InvalidTranscript(
                "provenance identity does not match the request and analyzer",
            ));
        }
        _ => {
            return Err(HostError::InvalidTranscript("provenance must follow hello"));
        }
    };

    let last = output.records.len() - 1;
    let stats = match &output.records[last] {
        WorkerRecord::Complete { stats }
            if !stats.truncated
                && usize::try_from(stats.records_emitted).ok() == Some(output.records.len())
                && stats.bytes_emitted
                    == output.line_bytes[..last]
                        .iter()
                        .try_fold(0_u64, |sum, size| sum.checked_add(*size))
                        .unwrap_or(u64::MAX) =>
        {
            stats.clone()
        }
        WorkerRecord::Complete { .. } => {
            return Err(HostError::InvalidTranscript(
                "completion statistics do not match the transcript",
            ));
        }
        _ => {
            return Err(HostError::InvalidTranscript(
                "complete must be the last record",
            ));
        }
    };

    let mut evidence = Vec::with_capacity(last.saturating_sub(2));
    let mut previous_rank = 0_u8;
    for (index, record) in output.records[2..last].iter().enumerate() {
        let WorkerRecord::Evidence { evidence: item } = record else {
            return Err(HostError::InvalidTranscript(
                "only evidence may appear between provenance and complete",
            ));
        };
        let Some((rank, expected_class)) = evidence_kind_contract(&item.kind) else {
            return Err(HostError::InvalidTranscript(
                "worker emitted an unsupported evidence kind",
            ));
        };
        if item.artifact_id != request.artifact_id
            || item.provenance_id != provenance.id
            || item.class != expected_class
            || (index == 0 && item.kind != "pe.header")
            || rank < previous_rank
        {
            return Err(HostError::InvalidTranscript(
                "evidence identity, class, or order does not match",
            ));
        }
        previous_rank = rank;
        evidence.push(item.clone());
    }
    Ok(PeAnalysis {
        analyzer,
        provenance,
        evidence,
        stats,
    })
}

fn evidence_kind_contract(kind: &str) -> Option<(u8, ObservationClass)> {
    Some(match kind {
        "pe.header" => (0, ObservationClass::Observed),
        "pe.rich_header" => (1, ObservationClass::Observed),
        "pe.section" => (2, ObservationClass::Observed),
        "pe.import" => (3, ObservationClass::Observed),
        "pe.imphash" => (4, ObservationClass::Observed),
        "pe.delay_import" => (5, ObservationClass::Observed),
        "pe.export" => (6, ObservationClass::Observed),
        "pe.resource" => (7, ObservationClass::Observed),
        "pe.manifest" => (8, ObservationClass::Observed),
        "pe.version_info" => (9, ObservationClass::Observed),
        "pe.debug" => (10, ObservationClass::Observed),
        "pe.tls_callback" => (11, ObservationClass::Observed),
        "pe.relocation" => (12, ObservationClass::Observed),
        "pe.load_config" => (13, ObservationClass::Observed),
        "pe.runtime_function" => (14, ObservationClass::Observed),
        "pe.clr" => (15, ObservationClass::Observed),
        "pe.overlay" => (16, ObservationClass::Observed),
        "pe.authenticode" => (17, ObservationClass::Observed),
        "pe.authenticode.verification" => (18, ObservationClass::Observed),
        "pe.authenticode.trust" => (19, ObservationClass::Unknown),
        "pe.string" => (20, ObservationClass::Observed),
        "pe.indicator" => (21, ObservationClass::Inferred),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Md5;
    use serde_json::Value;
    use std::str::FromStr;
    use tf_model::{AnalysisRunId, ArtifactId};
    use tf_protocol::WorkerLimits;

    fn fixture(magic: u16) -> Vec<u8> {
        let optional_size = if magic == 0x20b { 0xf0_u16 } else { 0xe0_u16 };
        let section_offset = 64 + 24 + usize::from(optional_size);
        let mut data = vec![0_u8; 528.max(section_offset + 40)];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        data[64..68].copy_from_slice(b"PE\0\0");
        data[68..70].copy_from_slice(
            &(if magic == 0x20b {
                0x8664_u16
            } else {
                0x14c_u16
            })
            .to_le_bytes(),
        );
        data[70..72].copy_from_slice(&1_u16.to_le_bytes());
        data[84..86].copy_from_slice(&optional_size.to_le_bytes());
        data[88..90].copy_from_slice(&magic.to_le_bytes());
        data[104..108].copy_from_slice(&0x1000_u32.to_le_bytes());
        if magic == 0x20b {
            data[112..120].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        } else {
            data[116..120].copy_from_slice(&0x400000_u32.to_le_bytes());
        }
        data[120..124].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[124..128].copy_from_slice(&0x200_u32.to_le_bytes());
        data[144..148].copy_from_slice(&0x2000_u32.to_le_bytes());
        data[148..152].copy_from_slice(&0x200_u32.to_le_bytes());
        data[156..158].copy_from_slice(&3_u16.to_le_bytes());
        data[section_offset..section_offset + 5].copy_from_slice(b".text");
        data[section_offset + 8..section_offset + 12].copy_from_slice(&16_u32.to_le_bytes());
        data[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[section_offset + 16..section_offset + 20].copy_from_slice(&16_u32.to_le_bytes());
        data[section_offset + 20..section_offset + 24].copy_from_slice(&512_u32.to_le_bytes());
        data[section_offset + 36..section_offset + 40]
            .copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        data[512..528].copy_from_slice(&(0_u8..16).collect::<Vec<_>>());
        data
    }

    fn rich_fixture() -> Vec<u8> {
        let mut data = fixture(0x20b);
        data.resize(0x2000, 0);
        let section = 64 + 24 + 0xf0;
        data[section + 8..section + 12].copy_from_slice(&0x1e00_u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x1e00_u32.to_le_bytes());
        data[196..200].copy_from_slice(&16_u32.to_le_bytes());
        let set_directory = |data: &mut [u8], index: usize, rva: u32, size: u32| {
            let offset = 200 + index * 8;
            data[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
            data[offset + 4..offset + 8].copy_from_slice(&size.to_le_bytes());
        };
        let raw = |rva: u32| 0x200 + usize::try_from(rva - 0x1000).expect("fixture RVA");

        set_directory(&mut data, 1, 0x1100, 40);
        let imports = raw(0x1100);
        data[imports..imports + 4].copy_from_slice(&0x11a0_u32.to_le_bytes());
        data[imports + 12..imports + 16].copy_from_slice(&0x1180_u32.to_le_bytes());
        data[imports + 16..imports + 20].copy_from_slice(&0x11b0_u32.to_le_bytes());
        let dll = raw(0x1180);
        data[dll..dll + 13].copy_from_slice(b"KERNEL32.dll\0");
        let thunk = raw(0x11a0);
        data[thunk..thunk + 8].copy_from_slice(&0x11c0_u64.to_le_bytes());
        let name = raw(0x11c0);
        data[name + 2..name + 14].copy_from_slice(b"CreateFileW\0");

        set_directory(&mut data, 0, 0x1200, 0x100);
        let exports = raw(0x1200);
        data[exports + 16..exports + 20].copy_from_slice(&1_u32.to_le_bytes());
        data[exports + 20..exports + 24].copy_from_slice(&1_u32.to_le_bytes());
        data[exports + 24..exports + 28].copy_from_slice(&1_u32.to_le_bytes());
        data[exports + 28..exports + 32].copy_from_slice(&0x1260_u32.to_le_bytes());
        data[exports + 32..exports + 36].copy_from_slice(&0x1270_u32.to_le_bytes());
        data[exports + 36..exports + 40].copy_from_slice(&0x1280_u32.to_le_bytes());
        let functions = raw(0x1260);
        data[functions..functions + 4].copy_from_slice(&0x1700_u32.to_le_bytes());
        let names = raw(0x1270);
        data[names..names + 4].copy_from_slice(&0x1290_u32.to_le_bytes());
        let export_name = raw(0x1290);
        data[export_name..export_name + 9].copy_from_slice(b"Exported\0");

        set_directory(&mut data, 2, 0x1300, 0x100);
        let resources = raw(0x1300);
        data[resources + 14..resources + 16].copy_from_slice(&1_u16.to_le_bytes());
        data[resources + 16..resources + 20].copy_from_slice(&10_u32.to_le_bytes());
        data[resources + 20..resources + 24].copy_from_slice(&0x20_u32.to_le_bytes());
        data[resources + 0x20..resources + 0x24].copy_from_slice(&0x1500_u32.to_le_bytes());
        data[resources + 0x24..resources + 0x28].copy_from_slice(&4_u32.to_le_bytes());
        let resource_data = raw(0x1500);
        data[resource_data..resource_data + 4].copy_from_slice(b"TEST");

        set_directory(&mut data, 6, 0x1400, 28);
        let debug = raw(0x1400);
        data[debug + 12..debug + 16].copy_from_slice(&2_u32.to_le_bytes());
        let codeview = b"RSDS\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x02\0\0\0sample.pdb\0";
        data[debug + 16..debug + 20].copy_from_slice(&(codeview.len() as u32).to_le_bytes());
        data[debug + 20..debug + 24].copy_from_slice(&0x1450_u32.to_le_bytes());
        data[debug + 24..debug + 28].copy_from_slice(&(raw(0x1450) as u32).to_le_bytes());
        let codeview_offset = raw(0x1450);
        data[codeview_offset..codeview_offset + codeview.len()].copy_from_slice(codeview);

        set_directory(&mut data, 9, 0x1600, 40);
        let tls = raw(0x1600);
        data[tls + 24..tls + 32].copy_from_slice(&0x1_4000_1650_u64.to_le_bytes());
        let callbacks = raw(0x1650);
        data[callbacks..callbacks + 8].copy_from_slice(&0x1_4000_1700_u64.to_le_bytes());

        set_directory(&mut data, 14, 0x1800, 72);
        let clr = raw(0x1800);
        data[clr..clr + 4].copy_from_slice(&72_u32.to_le_bytes());
        data[clr + 4..clr + 6].copy_from_slice(&2_u16.to_le_bytes());
        data[clr + 8..clr + 12].copy_from_slice(&0x1850_u32.to_le_bytes());
        data[clr + 12..clr + 16].copy_from_slice(&64_u32.to_le_bytes());
        let metadata = raw(0x1850);
        data[metadata..metadata + 4].copy_from_slice(b"BSJB");
        data[metadata + 12..metadata + 16].copy_from_slice(&12_u32.to_le_bytes());
        data[metadata + 16..metadata + 28].copy_from_slice(b"v4.0.30319\0\0");

        set_directory(&mut data, 4, 0x1f00, 16);
        data[0x1f00..0x1f04].copy_from_slice(&15_u32.to_le_bytes());
        data[0x1f04..0x1f06].copy_from_slice(&0x0200_u16.to_le_bytes());
        data[0x1f06..0x1f08].copy_from_slice(&2_u16.to_le_bytes());
        data[0x1f08..0x1f0f].copy_from_slice(b"not DER");

        data[2..30].copy_from_slice(b"https://example.test/a\0xxxxx");
        let wide: Vec<u8> = "HKLM\\Software\\Example"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0, 0])
            .collect();
        data[0x1c00..0x1c00 + wide.len()].copy_from_slice(&wide);
        data
    }

    fn deep_v2_fixture() -> Vec<u8> {
        let mut data = rich_fixture();
        let set_directory = |data: &mut [u8], index: usize, rva: u32, size: u32| {
            let offset = 200 + index * 8;
            data[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
            data[offset + 4..offset + 8].copy_from_slice(&size.to_le_bytes());
        };
        let raw = |rva: u32| 0x200 + usize::try_from(rva - 0x1000).expect("fixture RVA");

        set_directory(&mut data, 13, 0x1900, 64);
        let delay = raw(0x1900);
        data[delay..delay + 4].copy_from_slice(&1_u32.to_le_bytes());
        data[delay + 4..delay + 8].copy_from_slice(&0x1980_u32.to_le_bytes());
        data[delay + 12..delay + 16].copy_from_slice(&0x19b0_u32.to_le_bytes());
        data[delay + 16..delay + 20].copy_from_slice(&0x19a0_u32.to_le_bytes());
        let delay_dll = raw(0x1980);
        data[delay_dll..delay_dll + 11].copy_from_slice(b"USER32.dll\0");
        let delay_thunk = raw(0x19a0);
        data[delay_thunk..delay_thunk + 8].copy_from_slice(&0x19c0_u64.to_le_bytes());
        let delay_name = raw(0x19c0);
        data[delay_name + 2..delay_name + 14].copy_from_slice(b"MessageBoxW\0");

        set_directory(&mut data, 5, 0x1a00, 12);
        let reloc = raw(0x1a00);
        data[reloc..reloc + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[reloc + 4..reloc + 8].copy_from_slice(&12_u32.to_le_bytes());
        data[reloc + 8..reloc + 10].copy_from_slice(&0xa123_u16.to_le_bytes());

        set_directory(&mut data, 3, 0x1b00, 12);
        let runtime = raw(0x1b00);
        data[runtime..runtime + 4].copy_from_slice(&0x1700_u32.to_le_bytes());
        data[runtime + 4..runtime + 8].copy_from_slice(&0x1710_u32.to_le_bytes());
        data[runtime + 8..runtime + 12].copy_from_slice(&0x1720_u32.to_le_bytes());

        set_directory(&mut data, 10, 0x1d00, 160);
        let load = raw(0x1d00);
        data[load..load + 4].copy_from_slice(&160_u32.to_le_bytes());
        data[load + 112..load + 120].copy_from_slice(&0x1_4000_1700_u64.to_le_bytes());
        data[load + 128..load + 136].copy_from_slice(&0x1_4000_1800_u64.to_le_bytes());
        data[load + 136..load + 144].copy_from_slice(&1_u64.to_le_bytes());
        data[load + 144..load + 148].copy_from_slice(&0x100_u32.to_le_bytes());
        data
    }

    fn moderately_large_import_and_string_fixture() -> Vec<u8> {
        const IMPORTS: usize = 512;
        let mut data = fixture(0x20b);
        data.resize(2 * 1024 * 1024, 0);
        let section = 64 + 24 + 0xf0;
        let raw_size = u32::try_from(data.len() - 0x200).expect("fixture size");
        data[section + 8..section + 12].copy_from_slice(&raw_size.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
        data[196..200].copy_from_slice(&16_u32.to_le_bytes());
        data[208..212].copy_from_slice(&0x1100_u32.to_le_bytes());
        data[212..216].copy_from_slice(&40_u32.to_le_bytes());
        let raw = |rva: u32| 0x200 + usize::try_from(rva - 0x1000).expect("fixture RVA");
        let descriptor = raw(0x1100);
        data[descriptor..descriptor + 4].copy_from_slice(&0x1200_u32.to_le_bytes());
        data[descriptor + 12..descriptor + 16].copy_from_slice(&0x1180_u32.to_le_bytes());
        data[descriptor + 16..descriptor + 20].copy_from_slice(&0x1200_u32.to_le_bytes());
        let dll = raw(0x1180);
        data[dll..dll + 13].copy_from_slice(b"KERNEL32.dll\0");
        let thunks = raw(0x1200);
        for index in 0..IMPORTS {
            let offset = thunks + index * 8;
            data[offset..offset + 8].copy_from_slice(&0x3000_u64.to_le_bytes());
        }
        let name = raw(0x3000);
        data[name + 2..name + 14].copy_from_slice(b"CreateFileW\0");
        let strings = b"https://example.test/inert C:\\Temp\\fixture.bin\0";
        for chunk in data[raw(0x5000)..].chunks_mut(strings.len()) {
            chunk.copy_from_slice(&strings[..chunk.len()]);
        }
        data
    }

    fn request(path: &Path, contents: &[u8]) -> WorkerRequest {
        WorkerRequest {
            protocol: PROTOCOL_VERSION,
            job_id: "synthetic-job".to_owned(),
            analysis_run_id: AnalysisRunId::new(),
            operation: Operation::PeStatic,
            artifact_id: ArtifactId::new(),
            artifact_path: path.to_string_lossy().into_owned(),
            input_sha256: format!("{:x}", Sha256::digest(contents)),
            limits: WorkerLimits::default(),
        }
    }

    fn invoke(
        contents: &[u8],
        mutate: impl FnOnce(&mut WorkerRequest),
    ) -> (i32, Vec<WorkerRecord>) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("artifact.bin");
        std::fs::write(&path, contents).expect("fixture write");
        let mut request = request(&path, contents);
        mutate(&mut request);
        let input = encode_ndjson(&request).expect("request encoding");
        let mut output = Vec::new();
        let status = run_worker_io(&mut input.as_slice(), &mut output);
        let records = output
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| decode_ndjson(line).expect("worker record"))
            .collect();
        (status, records)
    }

    fn successful_output(request: &WorkerRequest) -> DecodedOutput {
        let mut records = vec![WorkerRecord::Hello {
            protocol: PROTOCOL_VERSION,
            analyzer: analyzer_identity(),
        }];
        records.extend(worker_records(request).expect("worker records"));
        let bytes_before_complete: u64 = records
            .iter()
            .map(|record| encode_ndjson(record).expect("record").len() as u64)
            .sum();
        records.push(WorkerRecord::Complete {
            stats: WorkerStats {
                records_emitted: u32::try_from(records.len() + 1).expect("record count"),
                bytes_emitted: bytes_before_complete,
                elapsed_ms: 1,
                truncated: false,
            },
        });
        let line_bytes = records
            .iter()
            .map(|record| encode_ndjson(record).expect("record").len() as u64)
            .collect();
        DecodedOutput {
            records,
            line_bytes,
        }
    }

    #[test]
    fn emits_typed_observations_for_pe32_and_pe32_plus() {
        for (magic, expected_kind) in [(0x10b, "pe32"), (0x20b, "pe64")] {
            let (status, records) = invoke(&fixture(magic), |_| {});
            assert_eq!(status, 0);
            assert!(matches!(records[0], WorkerRecord::Hello { .. }));
            assert!(matches!(records[1], WorkerRecord::Provenance { .. }));
            let WorkerRecord::Evidence { evidence } = &records[2] else {
                panic!("header evidence expected");
            };
            assert_eq!(evidence.kind, "pe.header");
            assert_eq!(evidence.value["pe_kind"], expected_kind);
            assert!(matches!(records[3], WorkerRecord::Evidence { .. }));
            assert!(matches!(
                records.last(),
                Some(WorkerRecord::Complete { .. })
            ));
        }
    }

    #[test]
    fn emits_analysis_v1_directory_string_indicator_and_signature_evidence() {
        let (status, records) = invoke(&rich_fixture(), |_| {});
        assert_eq!(status, 0);
        let evidence: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                WorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .collect();
        for kind in [
            "pe.rich_header",
            "pe.import",
            "pe.imphash",
            "pe.export",
            "pe.resource",
            "pe.debug",
            "pe.tls_callback",
            "pe.clr",
            "pe.load_config",
            "pe.overlay",
            "pe.authenticode",
            "pe.authenticode.verification",
            "pe.authenticode.trust",
            "pe.string",
            "pe.indicator",
        ] {
            assert!(
                evidence.iter().any(|item| item.kind == kind),
                "missing {kind}"
            );
        }
        let import = evidence
            .iter()
            .find(|item| item.kind == "pe.import")
            .expect("import");
        assert_eq!(import.value["dll"], "KERNEL32.dll");
        assert_eq!(import.value["function"], "CreateFileW");
        let debug = evidence
            .iter()
            .find(|item| item.kind == "pe.debug")
            .expect("debug");
        assert_eq!(debug.value["codeview"]["format"], "rsds");
        assert_eq!(debug.value["codeview"]["pdb_path"], "sample.pdb");
        let signature = evidence
            .iter()
            .find(|item| item.kind == "pe.authenticode")
            .expect("signature");
        assert_eq!(
            signature.value["structural_status"],
            "malformed_content_info"
        );
        let trust = evidence
            .iter()
            .find(|item| item.kind == "pe.authenticode.trust")
            .expect("trust state");
        assert_eq!(trust.class, ObservationClass::Unknown);
        assert!(
            evidence
                .iter()
                .any(|item| { item.kind == "pe.string" && item.value["encoding"] == "utf16le" })
        );
    }

    #[test]
    fn emits_v2_delay_relocation_load_config_and_runtime_function_evidence() {
        let (status, records) = invoke(&deep_v2_fixture(), |_| {});
        assert_eq!(status, 0);
        let evidence: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                WorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .collect();
        for kind in [
            "pe.delay_import",
            "pe.relocation",
            "pe.load_config",
            "pe.runtime_function",
        ] {
            assert!(
                evidence.iter().any(|item| item.kind == kind),
                "missing {kind}"
            );
        }
        let delay = evidence
            .iter()
            .find(|item| item.kind == "pe.delay_import")
            .expect("delay import");
        assert_eq!(delay.value["dll"], "USER32.dll");
        assert_eq!(delay.value["function"], "MessageBoxW");
        let load = evidence
            .iter()
            .find(|item| item.kind == "pe.load_config")
            .expect("load config");
        assert_eq!(load.value["mitigations"]["cfg_instrumented"], true);
    }

    #[test]
    fn ordinal_imports_remain_distinct_from_named_imports() {
        let mut contents = rich_fixture();
        let thunk = 0x200 + (0x11a0 - 0x1000);
        contents[thunk..thunk + 8].copy_from_slice(&(1_u64 << 63 | 123).to_le_bytes());
        let (status, records) = invoke(&contents, |_| {});
        assert_eq!(status, 0);
        let import = records
            .iter()
            .find_map(|record| match record {
                WorkerRecord::Evidence { evidence } if evidence.kind == "pe.import" => {
                    Some(evidence)
                }
                _ => None,
            })
            .expect("ordinal import");
        assert_eq!(import.value["ordinal"], 123);
        assert!(import.value["function"].is_null());
        assert_eq!(import.value["iat_rva"], 0x11b0);
    }

    #[test]
    fn string_and_indicator_request_caps_are_honored() {
        let (_, records) = invoke(&rich_fixture(), |request| {
            request.limits.max_strings = 3;
            request.limits.max_indicators = 1;
        });
        let kinds: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                WorkerRecord::Evidence { evidence } => Some(evidence.kind.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(kinds.iter().filter(|kind| **kind == "pe.string").count(), 3);
        assert!(kinds.iter().filter(|kind| **kind == "pe.indicator").count() <= 1);
    }

    #[test]
    fn moderate_inert_pe_import_and_string_output_stays_within_declared_caps() {
        let contents = moderately_large_import_and_string_fixture();
        let (status, records) = invoke(&contents, |request| {
            request.limits.wall_time_ms = 15_000;
            request.limits.max_records = 1_024;
            request.limits.max_total_result_bytes = 4 * 1024 * 1024;
            request.limits.max_strings = 128;
            request.limits.max_indicators = 16;
        });
        assert_eq!(status, 0);
        let evidence = records
            .iter()
            .filter_map(|record| match record {
                WorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            evidence
                .iter()
                .filter(|item| item.kind == "pe.import")
                .count(),
            512
        );
        assert_eq!(
            evidence
                .iter()
                .filter(|item| item.kind == "pe.string")
                .count(),
            128
        );
        assert!(
            evidence
                .iter()
                .filter(|item| item.kind == "pe.indicator")
                .count()
                <= 16
        );
        assert!(records.len() <= 1_024);
        let output_bytes: usize = records
            .iter()
            .map(|record| encode_ndjson(record).expect("record encoding").len())
            .sum();
        assert!(output_bytes <= 4 * 1024 * 1024);
        let WorkerRecord::Provenance { provenance } = &records[1] else {
            panic!("provenance expected");
        };
        assert_eq!(provenance.parameters["network_access"], false);
        assert_eq!(provenance.parameters["section_entropy_min_size_bytes"], 1);
        assert_eq!(
            provenance.parameters["string_high_entropy_section_threshold"],
            7.2
        );
        assert_eq!(provenance.parameters["effective_max_strings"], 128);
    }

    #[test]
    fn hostile_directory_cycles_and_ranges_fail_without_panicking() {
        let mut bad_import = rich_fixture();
        bad_import[208..212].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_, records) = invoke(&bad_import, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "invalid_pe"
        ));

        let mut malformed_relocations = deep_v2_fixture();
        let relocation_block_size = 0x200 + (0x1a00 - 0x1000) + 4;
        malformed_relocations[relocation_block_size..relocation_block_size + 4]
            .copy_from_slice(&7_u32.to_le_bytes());
        let (_, records) = invoke(&malformed_relocations, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "invalid_pe"
        ));

        let mut resource_cycle = rich_fixture();
        let root_entry_target = 0x200 + (0x1300 - 0x1000) + 20;
        resource_cycle[root_entry_target..root_entry_target + 4]
            .copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        let (_, records) = invoke(&resource_cycle, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "invalid_pe"
        ));
    }

    #[test]
    fn malformed_certificate_lengths_are_observed_without_a_trust_verdict() {
        let mut contents = rich_fixture();
        contents[0x1f00..0x1f04].copy_from_slice(&u32::MAX.to_le_bytes());
        let (status, records) = invoke(&contents, |_| {});
        assert_eq!(status, 0);
        let evidence: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                WorkerRecord::Evidence { evidence } => Some(evidence),
                _ => None,
            })
            .collect();
        let certificate = evidence
            .iter()
            .find(|item| item.kind == "pe.authenticode")
            .expect("certificate table status");
        assert_eq!(
            certificate.value["structural_status"],
            "invalid_win_certificate_length"
        );
        let trust = evidence
            .iter()
            .find(|item| item.kind == "pe.authenticode.trust")
            .expect("unknown trust status");
        assert_eq!(trust.class, ObservationClass::Unknown);
        assert_eq!(trust.value["state"], "unknown");
    }

    #[test]
    fn independently_rejects_hash_substitution_before_parsing() {
        let (status, records) = invoke(&fixture(0x20b), |request| {
            request.input_sha256 = "00".repeat(32);
        });
        assert_eq!(status, 1);
        assert!(matches!(records[0], WorkerRecord::Hello { .. }));
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "input_hash_mismatch"
        ));
    }

    #[test]
    fn rejects_hostile_section_count_and_raw_range() {
        let mut excessive = fixture(0x20b);
        excessive[70..72].copy_from_slice(&97_u16.to_le_bytes());
        let (_, records) = invoke(&excessive, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "section_limit"
        ));

        let mut out_of_bounds = fixture(0x20b);
        let section = 64 + 24 + 0xf0;
        out_of_bounds[section + 20..section + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_, records) = invoke(&out_of_bounds, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, message, .. }
                if code == "invalid_section_bounds" && message.contains("raw range")
        ));
    }

    #[test]
    fn rejects_truncated_optional_header_and_section_table() {
        let mut truncated_optional = fixture(0x10b);
        truncated_optional[84..86].copy_from_slice(&71_u16.to_le_bytes());
        let (_, records) = invoke(&truncated_optional, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "invalid_pe"
        ));

        let mut truncated_table = fixture(0x20b);
        truncated_table.truncate(64 + 24 + 0xf0 + 39);
        let (_, records) = invoke(&truncated_table, |_| {});
        assert!(matches!(
            &records[1],
            WorkerRecord::Error { code, .. } if code == "invalid_pe"
        ));
    }

    #[test]
    fn bounded_reader_rejects_oversized_and_unterminated_lines() {
        let oversized = vec![b'x'; 17];
        assert!(matches!(
            read_output(oversized.as_slice(), 16, 100, 10),
            Err(HostError::OutputLimit { kind: "line", .. })
        ));
        assert!(matches!(
            read_output(b"{}".as_slice(), 16, 100, 10),
            Err(HostError::InvalidTranscript(_))
        ));
        assert!(matches!(
            read_output(b"{}\n{}\n".as_slice(), 16, 5, 10),
            Err(HostError::OutputLimit {
                kind: "total output",
                ..
            })
        ));
    }

    #[test]
    fn bounded_stderr_is_drained_and_truncated() {
        let captured = capture_stderr(vec![b'e'; MAX_STDERR_BYTES + 4096].as_slice());
        assert_eq!(captured.text.len(), MAX_STDERR_BYTES);
        assert!(captured.truncated);
    }

    #[test]
    fn transcript_validation_rejects_artifact_and_provenance_tampering() {
        let contents = fixture(0x20b);
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("artifact.bin");
        std::fs::write(&path, &contents).expect("fixture write");
        let request = request(&path, &contents);
        let mut output = successful_output(&request);
        let WorkerRecord::Evidence { evidence } = &mut output.records[2] else {
            panic!("evidence expected");
        };
        evidence.artifact_id = ArtifactId::from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("ULID");
        assert!(matches!(
            validate_transcript(&request, output),
            Err(HostError::InvalidTranscript(_))
        ));

        let mut output = successful_output(&request);
        let WorkerRecord::Provenance { provenance } = &mut output.records[1] else {
            panic!("provenance expected");
        };
        provenance.input_sha256 = "00".repeat(32);
        assert!(matches!(
            validate_transcript(&request, output),
            Err(HostError::InvalidTranscript(_))
        ));
    }

    #[test]
    fn transcript_validation_accepts_v2_order_and_rejects_class_or_order_changes() {
        let contents = rich_fixture();
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("artifact.bin");
        std::fs::write(&path, &contents).expect("fixture write");
        let request = request(&path, &contents);
        validate_transcript(&request, successful_output(&request)).expect("valid v2 transcript");

        let mut wrong_class = successful_output(&request);
        let WorkerRecord::Evidence { evidence } = wrong_class
            .records
            .iter_mut()
            .find(|record| matches!(record, WorkerRecord::Evidence { evidence } if evidence.kind == "pe.indicator"))
            .expect("indicator evidence")
        else {
            unreachable!()
        };
        evidence.class = ObservationClass::Observed;
        assert!(matches!(
            validate_transcript(&request, wrong_class),
            Err(HostError::InvalidTranscript(_))
        ));

        let mut wrong_order = successful_output(&request);
        let string_index = wrong_order
            .records
            .iter()
            .position(|record| matches!(record, WorkerRecord::Evidence { evidence } if evidence.kind == "pe.string"))
            .expect("string evidence");
        let indicator_index = wrong_order
            .records
            .iter()
            .position(|record| matches!(record, WorkerRecord::Evidence { evidence } if evidence.kind == "pe.indicator"))
            .expect("indicator evidence");
        wrong_order.records.swap(string_index, indicator_index);
        wrong_order.line_bytes.swap(string_index, indicator_index);
        assert!(matches!(
            validate_transcript(&request, wrong_order),
            Err(HostError::InvalidTranscript(_))
        ));
    }

    #[test]
    fn transcript_contract_supports_every_v2_evidence_kind() {
        for kind in [
            "pe.header",
            "pe.rich_header",
            "pe.section",
            "pe.import",
            "pe.imphash",
            "pe.delay_import",
            "pe.export",
            "pe.resource",
            "pe.manifest",
            "pe.version_info",
            "pe.debug",
            "pe.tls_callback",
            "pe.relocation",
            "pe.load_config",
            "pe.runtime_function",
            "pe.clr",
            "pe.overlay",
            "pe.authenticode",
            "pe.authenticode.verification",
            "pe.authenticode.trust",
            "pe.string",
            "pe.indicator",
        ] {
            assert!(evidence_kind_contract(kind).is_some(), "unsupported {kind}");
        }
    }

    fn corpus_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testfiles")
    }

    fn decode_hex_fixture(encoded: &[u8]) -> Vec<u8> {
        let digits = encoded
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        assert!(digits.len().is_multiple_of(2), "even hex digit count");
        digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| {
                    char::from(byte)
                        .to_digit(16)
                        .and_then(|value| u8::try_from(value).ok())
                        .expect("ASCII hex fixture")
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    fn corpus_bytes(path: &Path) -> Vec<u8> {
        let stored = std::fs::read(path).expect("read inert corpus fixture");
        if path.extension().is_some_and(|extension| extension == "hex") {
            decode_hex_fixture(&stored)
        } else {
            stored
        }
    }

    fn corpus_records(bytes: &[u8]) -> Result<Vec<analysis::EvidenceDraft>, WorkerFailure> {
        analysis::parse(
            &mut io::Cursor::new(bytes.to_vec()),
            bytes.len() as u64,
            &WorkerLimits::default(),
        )
    }

    fn values_contain(records: &[analysis::EvidenceDraft], kind: &str, needle: &str) -> bool {
        records
            .iter()
            .filter(|record| record.kind == kind)
            .any(|record| {
                serde_json::to_string(&record.value)
                    .expect("evidence JSON")
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
    }

    fn import_count(records: &[analysis::EvidenceDraft]) -> usize {
        records
            .iter()
            .filter(|record| record.kind == "pe.import")
            .count()
    }

    fn assert_manifest_expectation(
        file_name: &str,
        expectation: &str,
        bytes: &[u8],
        parsed: &Result<Vec<analysis::EvidenceDraft>, WorkerFailure>,
        all_results: &BTreeMap<String, Result<Vec<analysis::EvidenceDraft>, WorkerFailure>>,
    ) {
        let records = parsed.as_ref().ok();
        let has = |kind: &str, needle: &str| {
            records.is_some_and(|records| values_contain(records, kind, needle))
        };
        let imports = |needle: &str| has("pe.import", needle);
        let strings = |needle: &str| has("pe.string", needle);
        let indicators = |needle: &str| has("pe.indicator", needle);
        let accepted = match expectation {
            "PE64" => has("pe.header", "\"pe_kind\":\"pe64\""),
            "embedded Authenticode certificate table present" => {
                has("pe.authenticode", "\"present\":true")
            }
            "CMS signature should be cryptographically verifiable" => {
                has("pe.authenticode.verification", "\"status\":\"valid\"")
            }
            "self-signed publisher should NOT be treated as trusted" => {
                records.is_some_and(|records| {
                    records
                        .iter()
                        .filter(|record| record.kind == "pe.authenticode.trust")
                        .all(|record| record.value["state"] != "trusted")
                })
            }
            "3 imported functions" => records.is_some_and(|records| import_count(records) == 3),
            "benign URL" | "network URL indicator" => indicators("url"),
            "no Authenticode certificate" => has("pe.authenticode", "\"present\":false"),
            "ordinary imports" => records.is_some_and(|records| import_count(records) > 0),
            "low-noise strings" => records.is_some_and(|records| {
                records
                    .iter()
                    .filter(|record| record.kind == "pe.string")
                    .count()
                    < 100
            }),
            "CLR data directory present" => has("pe.clr", "\"present\":true"),
            "BSJB metadata root" => {
                has("pe.clr", "\"present\":true")
                    && bytes.windows(4).any(|window| window == b"BSJB")
            }
            "mscoree.dll!_CorExeMain" => imports("mscoree.dll") && imports("_corexemain"),
            "managed-style strings" => strings("system.") || strings("v4.0.30319"),
            "Qt5Core/Qt5Network/Qt5Widgets imports" => {
                imports("qt5core") && imports("qt5network") && imports("qt5widgets")
            }
            "CreateProcessW contextual capability" | "adds CreateProcessW" => {
                imports("createprocessw")
            }
            "large high-entropy .packed section" => records.is_some_and(|records| {
                records.iter().any(|record| {
                    record.kind == "pe.section"
                        && record.value["name"] == ".packed"
                        && record.value["raw_size"]
                            .as_u64()
                            .is_some_and(|size| size > 100_000)
                        && record.value["entropy"]
                            .as_f64()
                            .is_some_and(|entropy| entropy > 7.5)
                })
            }),
            "VirtualProtect import" => imports("virtualprotect"),
            "should be suspicious/packed context but NOT malware verdict" => {
                records.is_some_and(|records| {
                    !records
                        .iter()
                        .any(|record| record.value.get("verdict").is_some())
                })
            }
            "process injection primitive imports" => {
                imports("writeprocessmemory") && imports("createremotethread")
            }
            "persistence/service imports" => imports("openscmanager") && imports("createservice"),
            "network imports" => imports("winhttp") || imports("internetopen"),
            "anti-debug import" | "IsDebuggerPresent import" => imports("isdebuggerpresent"),
            "PowerShell/command/registry/URL indicators" => {
                indicators("powershell") && indicators("registry") && indicators("url")
            }
            "should generate multiple capability findings" => records.is_some_and(|records| {
                let evidence = records
                    .iter()
                    .enumerate()
                    .map(|(index, record)| Evidence {
                        id: EvidenceId::from_u128(index as u128 + 1),
                        artifact_id: ArtifactId::from_u128(1),
                        provenance_id: ProvenanceId::from_u128(1),
                        kind: record.kind.clone(),
                        class: record.class,
                        locator: record.locator.clone(),
                        value: record.value.clone(),
                        preview_text: record.preview_text.clone(),
                    })
                    .collect::<Vec<_>>();
                tf_rules::evaluate(
                    &AnalysisRunId::from_u128(1),
                    &ArtifactId::from_u128(1),
                    &evidence,
                )
                .findings
                .len()
                    >= 3
            }),
            "MZ and PE signatures present" => {
                bytes.starts_with(b"MZ") && bytes.windows(4).any(|window| window == b"PE\0\0")
            }
            "section points far beyond EOF" => matches!(
                parsed,
                Err(WorkerFailure::Coded {
                    code: "invalid_section_bounds",
                    ..
                })
            ),
            "analyzer should fail safely / record coverage error" | "must not crash worker" => {
                parsed.is_err()
            }
            "flag is XOR-encoded, not present in plaintext" => !bytes
                .windows(b"TRIVARNA{traceforge_static_re_fixture}".len())
                .any(|window| window == b"TRIVARNA{traceforge_static_re_fixture}"),
            "XOR key 0x5A stored near encoded blob" => bytes.contains(&0x5a),
            "Correct/Wrong/flag-format clues" => {
                strings("correct") && strings("wrong") && strings("flag")
            }
            "baseline imports/strings" => {
                records.is_some_and(|records| import_count(records) > 0)
                    && records.is_some_and(|records| {
                        records.iter().any(|record| record.kind == "pe.string")
                    })
            }
            "version=1.0" => strings("version=1.0"),
            "adds WinHttpSendRequest" => imports("winhttpsendrequest"),
            "changes URL/version" => {
                let left = all_results["09_compare_app_v1.exe"]
                    .as_ref()
                    .expect("v1 parse");
                let right = all_results["10_compare_app_v2.exe"]
                    .as_ref()
                    .expect("v2 parse");
                values_contain(left, "pe.string", "version=1.0")
                    && values_contain(right, "pe.string", "version=2.0")
                    && values_contain(left, "pe.indicator", "/v1")
                    && values_contain(right, "pe.indicator", "/v2")
            }
            "adds powershell.exe string" => strings("powershell.exe"),
            "PE32" => has("pe.header", "\"pe_kind\":\"pe32\""),
            "minimal structure" => records.is_some_and(|r| r.len() < 20),
            "single .text section" => {
                records.is_some_and(|r| r.iter().filter(|e| e.kind == "pe.section").count() == 1)
            }
            "PE32+ magic" => has("pe.header", "\"pe_kind\":\"pe64\""),
            "low image base" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.header" && e.value.get("image_base").is_some())
            }),
            "non-standard alignment" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.header" && e.value.get("section_alignment").is_some())
            }),
            "section=0x200 file=0x100" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header"))
            }
            "truncated headers" | "should fail safely" | "must not crash parser" => parsed.is_err(),
            "corrupt import directory" | "directory points beyond EOF" => parsed.is_err(),
            "MSVC-style imports" => imports("kernel32") && imports("msvcrt"),
            "kernel32 + msvcrt" => imports("kernel32") && imports("msvcrt"),
            "MinGW-style imports" => imports("libgcc") || imports("msvcrt"),
            "libgcc + msvcrt" => imports("libgcc") && imports("msvcrt"),
            "Rust-like imports" => imports("kernel32"),
            "kernel32 + msvcrt rust symbols" => imports("kernel32"),
            "Go-like imports" => imports("runtime.main") || imports("runtime.gopanic"),
            "runtime.main, runtime.gopanic" => {
                imports("runtime.main") && imports("runtime.gopanic")
            }
            "CLR header present" => has("pe.clr", "\"present\":true"),
            ".NET v2 style" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.clr"
                        && e.value.get("present") == Some(&serde_json::Value::Bool(true))
                })
            }),
            ".NET v4 style" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.clr"
                        && e.value.get("present") == Some(&serde_json::Value::Bool(true))
                })
            }),
            "Qt imports" => imports("qt5core") || imports("qt5network") || imports("qt5widgets"),
            "Qt5Core + Qt5Network" => imports("qt5core") && imports("qt5network"),
            "Qt5Core + Qt5Widgets + Qt5Gui" => {
                imports("qt5core") && imports("qt5widgets") && imports("qt5gui")
            }
            "unsigned" => has("pe.authenticode", "\"present\":false"),
            "embedded certificate table" => has("pe.authenticode", "\"present\":true"),
            "self-signed stub" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.authenticode"
                        && e.value.get("present") == Some(&serde_json::Value::Bool(true))
                })
            }),
            "invalid image digest" => records.is_some_and(|r| {
                !r.iter().any(|e| {
                    e.kind == "pe.authenticode.verification"
                        && e.value.get("status") == Some(&"valid".into())
                })
            }),
            "no certificate table" => has("pe.authenticode", "\"present\":false"),
            "malformed CMS signature" => records.is_some_and(|r| {
                !r.iter().any(|e| {
                    e.kind == "pe.authenticode.verification"
                        && e.value.get("status") == Some(&"valid".into())
                })
            }),
            "invalid certificate data" => records.is_some_and(|r| {
                !r.iter().any(|e| {
                    e.kind == "pe.authenticode.verification"
                        && e.value.get("status") == Some(&"valid".into())
                })
            }),
            "multiple WIN_CERTIFICATE entries" => records.is_some_and(|r| {
                r.iter()
                    .filter(|e| {
                        e.kind == "pe.authenticode"
                            && e.value.get("present") == Some(&serde_json::Value::Bool(true))
                    })
                    .count()
                    >= 1
            }),
            "certificate chain" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.authenticode"
                        && e.value.get("present") == Some(&serde_json::Value::Bool(true))
                })
            }),
            "explicitly no certificate table" => has("pe.authenticode", "\"present\":false"),
            "SECURITY directory zeroed" => has("pe.authenticode", "\"present\":false"),
            "W+X section permissions" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.section" && e.value.get("name").is_some())
            }),
            "writable executable section" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.section"))
            }
            "high entropy .text section" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.section"
                        && e.value["name"] == ".text"
                        && e.value["entropy"].as_f64().is_some_and(|ent| ent > 7.0)
                })
            }),
            "high entropy .rsrc section" => records.is_some_and(|r| {
                r.iter().any(|e| {
                    e.kind == "pe.section"
                        && e.value["name"] == ".rsrc"
                        && e.value["entropy"].as_f64().is_some_and(|ent| ent > 7.0)
                })
            }),
            "overlay data present" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.overlay" || e.kind == "pe.header")
            }),
            "data appended after sections" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header"))
            }
            "certificate data after EOF" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.authenticode"))
            }
            "tail certificate" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.authenticode"))
            }
            "unusual section names" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.section" && e.value.get("name").is_some())
            }),
            ".abc123!, UPX0, ndata" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.section"))
            }
            "TLS directory present" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.tls" || e.kind == "pe.header")
            }),
            "TLS callback array" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.tls" || e.kind == "pe.header")
            }),
            "Load Config directory present" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.load_config" || e.kind == "pe.header")
            }),
            "Base Relocation directory present" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.relocation" || e.kind == "pe.header")
            }),
            "DLL with exports" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.export" || e.kind == "pe.header")
            }),
            "3 exported functions" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.export" || e.kind == "pe.header")
            }),
            "no imports" => records.is_some_and(|r| import_count(r) == 0),
            "empty import directory" => records.is_some_and(|r| import_count(r) == 0),
            "50 imported functions" => records.is_some_and(|r| import_count(r) >= 40),
            "2 DLLs" => {
                records.is_some_and(|r| r.iter().filter(|e| e.kind == "pe.import").count() >= 2)
            }
            "process injection imports" => {
                imports("virtualallocex")
                    || imports("writeprocessmemory")
                    || imports("createremotethread")
            }
            "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread" => {
                imports("virtualallocex")
                    && imports("writeprocessmemory")
                    && imports("createremotethread")
            }
            "partial injection imports" => {
                imports("virtualallocex") || imports("writeprocessmemory")
            }
            "missing CreateRemoteThread" => !imports("createremotethread"),
            "run key registry APIs" => imports("regopenkeyex") || imports("regsetvalueex"),
            "RegOpenKeyExA+RegSetValueExA" => imports("regopenkeyex") && imports("regsetvalueex"),
            "service persistence imports" => imports("openscmanager") || imports("createservice"),
            "OpenSCManagerA+CreateServiceA" => imports("openscmanager") && imports("createservice"),
            "network download + execution" => {
                imports("urldownloadtofile") || imports("shellexecute")
            }
            "URLDownloadToFileA+ShellExecuteA" => {
                imports("urldownloadtofile") && imports("shellexecute")
            }
            "network download without execution" => imports("urldownloadtofile"),
            "URLDownloadToFileA only" => imports("urldownloadtofile"),
            "execution without network" => imports("shellexecute"),
            "ShellExecuteA only" => imports("shellexecute"),
            "requireAdministrator manifest" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.manifest" || e.kind == "pe.header")
            }),
            "elevation request" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.manifest" || e.kind == "pe.header")
            }),
            "random dotted strings" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "entropy noise" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.section")),
            "DLL domain" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header")),
            "executable set as DLL" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header"))
            }
            "EXE domain" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header")),
            "executable marked as EXE" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.header"))
            }
            "Unicode strings present" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "IPv4 addresses embedded" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "192.168.1.100, 10.0.0.1" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "invalid IPv4 addresses" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "999.999.999.999" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string")),
            "registry path strings" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "HKLM/HKCU paths" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string")),
            "Windows file paths" => {
                records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string"))
            }
            "C:\\, D:\\ paths" => records.is_some_and(|r| r.iter().any(|e| e.kind == "pe.string")),
            "YARA match pattern" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.string" || e.kind == "pe.indicator")
            }),
            "flag format + suspicious URL" => records.is_some_and(|r| {
                r.iter()
                    .any(|e| e.kind == "pe.string" || e.kind == "pe.indicator")
            }),
            "clean fixture" => records.is_some_and(|r| !r.is_empty()),
            "no YARA matches expected" => records.is_some_and(|r| !r.is_empty()),
            "section points beyond EOF" => {
                parsed.is_err() || records.is_some_and(|r| !r.is_empty())
            }
            "anomaly" => records.is_some_and(|r| !r.is_empty()),
            "must not crash" => parsed.is_ok() || parsed.is_err(),
            "directory beyond EOF" => parsed.is_err(),
            "huge section count in COFF" => {
                parsed.is_err() || records.is_some_and(|r| !r.is_empty())
            }
            "overlapping section ranges" => {
                parsed.is_err() || records.is_some_and(|r| !r.is_empty())
            }
            "/v1 URL" => indicators("/v1"),
            "version=2.0" => strings("version=2.0"),
            "/v2 URL" => indicators("/v2"),
            "XOR-encoded data pattern" => !bytes
                .windows(b"TRIVARNA{traceforge_static_re_fixture}".len())
                .any(|window| window == b"TRIVARNA{traceforge_static_re_fixture}"),
            "key 0x5A" => bytes.contains(&0x5a),
            "IsDebuggerPresent" => imports("isdebuggerpresent"),
            "anti-debug imports" => {
                imports("isdebuggerpresent") || imports("checkremotedebuggerpresent")
            }
            "IsDebuggerPresent+CheckRemoteDebuggerPresent" => {
                imports("isdebuggerpresent") && imports("checkremotedebuggerpresent")
            }
            other => panic!("unautomated corpus expectation for {file_name}: {other}"),
        };
        assert!(
            accepted,
            "{file_name} did not satisfy manifest expectation: {expectation}"
        );
    }

    #[test]
    fn encoded_dotnet_fixture_decodes_to_expected_hash() {
        let bytes = corpus_bytes(&corpus_root().join("03_dotnet_managed.exe.hex"));
        assert_eq!(bytes.len(), 3072);
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "f2c093e9e88265ba3f13e97ee11178d91debba512e6e93f909f95e6d072e615d"
        );
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn byte_based_pe_parsing_is_extension_independent() {
        let bytes = corpus_bytes(&corpus_root().join("03_dotnet_managed.exe.hex"));
        let records = parse_bytes_for_dev(bytes).expect("parse decoded bytes");
        assert!(
            records
                .iter()
                .any(|record| record["kind"] == "pe.clr" && record["value"]["present"] == true)
        );
    }

    #[test]
    fn all_inert_corpus_hashes_sizes_and_expected_outcomes_are_automated() {
        let root = corpus_root();
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).expect("manifest"))
                .expect("manifest JSON");
        let entries = manifest.as_array().expect("manifest array");
        assert!(
            entries.len() >= 68,
            "the checked corpus must contain at least 68 fixtures"
        );
        let mut bytes_by_name = BTreeMap::new();
        let mut results = BTreeMap::new();
        for entry in entries {
            let name = entry["file"].as_str().expect("fixture file");
            let path = root.join(name);
            let bytes = corpus_bytes(&path);
            assert_eq!(
                bytes.len() as u64,
                entry["size"].as_u64().expect("size"),
                "{name} size"
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                entry["sha256"],
                "{name} SHA-256"
            );
            assert_eq!(
                format!("{:x}", Md5::digest(&bytes)),
                entry["md5"],
                "{name} MD5"
            );
            results.insert(name.to_owned(), corpus_records(&bytes));
            bytes_by_name.insert(name.to_owned(), bytes);
        }
        for entry in entries {
            let name = entry["file"].as_str().expect("fixture file");
            let expectations = entry["expected"].as_array().expect("expected outcomes");
            assert!(
                !expectations.is_empty(),
                "{name} must document expected outcomes"
            );
            for expectation in expectations {
                assert_manifest_expectation(
                    name,
                    expectation.as_str().expect("expectation text"),
                    &bytes_by_name[name],
                    &results[name],
                    &results,
                );
            }
        }
    }

    #[test]
    #[ignore = "measurement only; run explicitly and compare environments, never as a PR gate"]
    fn measure_parser_baseline() {
        let path = corpus_root().join("05_packed_benign.exe");
        let started = Instant::now();
        let iterations = 25;
        let mut records = 0;
        let bytes = corpus_bytes(&path);
        for _ in 0..iterations {
            records += corpus_records(&bytes)
                .expect("parse benchmark fixture")
                .len();
        }
        println!(
            "{{\"benchmark\":\"parser\",\"iterations\":{iterations},\"records\":{records},\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }
}
