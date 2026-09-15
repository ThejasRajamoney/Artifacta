//! Typed, versioned messages for disposable analyzer worker processes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tf_model::{AnalysisRunId, ArtifactId, Evidence, Provenance, YaraPackId, YaraRuleMetadata};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStage {
    Ingesting,
    VerifyingIdentity,
    ParsingPe,
    ExtractingSections,
    ExtractingStrings,
    CheckingAuthenticode,
    RunningRules,
    RunningYara,
    BuildingGraph,
    BuildingChronology,
    FinalizingQuickCheck,
    Complete,
}

impl AnalysisStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ingesting => "ingesting",
            Self::VerifyingIdentity => "verifying_identity",
            Self::ParsingPe => "parsing_pe",
            Self::ExtractingSections => "extracting_sections",
            Self::ExtractingStrings => "extracting_strings",
            Self::CheckingAuthenticode => "checking_authenticode",
            Self::RunningRules => "running_rules",
            Self::RunningYara => "running_yara",
            Self::BuildingGraph => "building_graph",
            Self::BuildingChronology => "building_chronology",
            Self::FinalizingQuickCheck => "finalizing_quick_check",
            Self::Complete => "complete",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ingesting => "Ingesting artifact",
            Self::VerifyingIdentity => "Verifying identity",
            Self::ParsingPe => "Parsing PE structure",
            Self::ExtractingSections => "Extracting sections",
            Self::ExtractingStrings => "Extracting strings",
            Self::CheckingAuthenticode => "Checking Authenticode",
            Self::RunningRules => "Running detection rules",
            Self::RunningYara => "Running YARA scans",
            Self::BuildingGraph => "Building relationship graph",
            Self::BuildingChronology => "Building chronology",
            Self::FinalizingQuickCheck => "Finalizing quick check",
            Self::Complete => "Analysis complete",
        }
    }
}

/// Ordered list of all stages for iteration and validation.
pub const ALL_STAGES: &[AnalysisStage] = &[
    AnalysisStage::Ingesting,
    AnalysisStage::VerifyingIdentity,
    AnalysisStage::ParsingPe,
    AnalysisStage::ExtractingSections,
    AnalysisStage::ExtractingStrings,
    AnalysisStage::CheckingAuthenticode,
    AnalysisStage::RunningRules,
    AnalysisStage::RunningYara,
    AnalysisStage::BuildingGraph,
    AnalysisStage::BuildingChronology,
    AnalysisStage::FinalizingQuickCheck,
    AnalysisStage::Complete,
];
pub const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_YARA_PACK_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    NativeStatic,
    PeStatic,
    Authenticode,
    YaraScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum YaraOperation {
    Validate,
    Scan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct YaraPackInput {
    pub id: YaraPackId,
    pub sha256: String,
    /// Host-created content-addressed library path; never returned through public host APIs.
    pub source_path: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct YaraWorkerRequest {
    pub protocol: u16,
    pub job_id: String,
    pub operation: YaraOperation,
    pub analysis_run_id: AnalysisRunId,
    pub artifact_id: ArtifactId,
    pub artifact_path: Option<String>,
    pub input_sha256: Option<String>,
    pub packs: Vec<YaraPackInput>,
    pub limits: WorkerLimits,
    pub max_rule_matches: u32,
    pub max_string_instances_per_match: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum YaraWorkerRecord {
    Hello {
        protocol: u16,
        analyzer: AnalyzerIdentity,
    },
    Validated {
        pack_sha256: String,
        rules: Vec<YaraRuleMetadata>,
    },
    Provenance {
        provenance: Provenance,
    },
    Evidence {
        evidence: Evidence,
    },
    Error {
        code: String,
        message: String,
    },
    Complete {
        stats: WorkerStats,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerLimits {
    pub wall_time_ms: u64,
    pub memory_bytes: u64,
    pub max_records: u32,
    pub max_message_bytes: u32,
    pub max_total_result_bytes: u64,
    pub max_strings: u32,
    pub max_indicators: u32,
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self {
            wall_time_ms: 15_000,
            memory_bytes: 512 * 1024 * 1024,
            max_records: 250_000,
            max_message_bytes: MAX_IPC_MESSAGE_BYTES as u32,
            max_total_result_bytes: 64 * 1024 * 1024,
            max_strings: 100_000,
            max_indicators: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerRequest {
    pub protocol: u16,
    pub job_id: String,
    pub analysis_run_id: AnalysisRunId,
    pub operation: Operation,
    pub artifact_id: ArtifactId,
    /// Host-created content store path. This is never derived from the original filename.
    pub artifact_path: String,
    pub input_sha256: String,
    pub limits: WorkerLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzerIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerStats {
    pub records_emitted: u32,
    pub bytes_emitted: u64,
    pub elapsed_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerRecord {
    Hello {
        protocol: u16,
        analyzer: AnalyzerIdentity,
    },
    Progress {
        stage: String,
        completed: u32,
        total: Option<u32>,
    },
    Provenance {
        provenance: Provenance,
    },
    Evidence {
        evidence: Evidence,
    },
    Warning {
        code: String,
        message: String,
    },
    Error {
        code: String,
        message: String,
        retryable: bool,
    },
    Complete {
        stats: WorkerStats,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IPC message is empty")]
    EmptyMessage,
    #[error("IPC message exceeds {limit} bytes")]
    MessageTooLarge { limit: usize },
    #[error("unsupported protocol version {received}; expected {expected}")]
    UnsupportedVersion { received: u16, expected: u16 },
    #[error("invalid JSON message: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

pub fn encode_ndjson<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            limit: MAX_IPC_MESSAGE_BYTES,
        });
    }
    Ok(bytes)
}

pub fn decode_ndjson<T: DeserializeOwned>(line: &[u8]) -> Result<T, ProtocolError> {
    if line.is_empty() || line == b"\n" || line == b"\r\n" {
        return Err(ProtocolError::EmptyMessage);
    }
    if line.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            limit: MAX_IPC_MESSAGE_BYTES,
        });
    }

    let payload = line
        .strip_suffix(b"\n")
        .unwrap_or(line)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line));
    Ok(serde_json::from_slice(payload)?)
}

pub fn validate_protocol_version(received: u16) -> Result<(), ProtocolError> {
    if received == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion {
            received,
            expected: PROTOCOL_VERSION,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_STAGES, AnalysisStage, MAX_IPC_MESSAGE_BYTES, Operation, PROTOCOL_VERSION,
        ProtocolError, WorkerLimits, WorkerRequest, decode_ndjson, encode_ndjson,
        validate_protocol_version,
    };
    use tf_model::{AnalysisRunId, ArtifactId};

    fn request() -> WorkerRequest {
        WorkerRequest {
            protocol: PROTOCOL_VERSION,
            job_id: "01KTESTJOB".to_owned(),
            analysis_run_id: AnalysisRunId::new(),
            operation: Operation::PeStatic,
            artifact_id: ArtifactId::new(),
            artifact_path: "a8/a81f".to_owned(),
            input_sha256: "a81f".to_owned(),
            limits: WorkerLimits::default(),
        }
    }

    #[test]
    fn request_round_trips_as_one_bounded_line() {
        let original = request();
        let encoded = encode_ndjson(&original).expect("request should encode");
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(encoded.len() < MAX_IPC_MESSAGE_BYTES);

        let decoded: WorkerRequest = decode_ndjson(&encoded).expect("request should decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn oversized_messages_are_rejected_before_json_parsing() {
        let oversized = vec![b'x'; MAX_IPC_MESSAGE_BYTES + 1];
        assert!(matches!(
            decode_ndjson::<WorkerRequest>(&oversized),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn protocol_version_is_explicitly_checked() {
        assert!(validate_protocol_version(PROTOCOL_VERSION).is_ok());
        assert!(matches!(
            validate_protocol_version(PROTOCOL_VERSION + 1),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn analysis_stages_are_ordered_correctly() {
        assert_eq!(ALL_STAGES.len(), 12);
        assert_eq!(ALL_STAGES.first(), Some(&AnalysisStage::Ingesting));
        assert_eq!(ALL_STAGES.last(), Some(&AnalysisStage::Complete));
        let expected = [
            AnalysisStage::Ingesting,
            AnalysisStage::VerifyingIdentity,
            AnalysisStage::ParsingPe,
            AnalysisStage::ExtractingSections,
            AnalysisStage::ExtractingStrings,
            AnalysisStage::CheckingAuthenticode,
            AnalysisStage::RunningRules,
            AnalysisStage::RunningYara,
            AnalysisStage::BuildingGraph,
            AnalysisStage::BuildingChronology,
            AnalysisStage::FinalizingQuickCheck,
            AnalysisStage::Complete,
        ];
        for (index, stage) in ALL_STAGES.iter().enumerate() {
            assert_eq!(stage, &expected[index]);
        }
    }

    #[test]
    fn analysis_stage_serializes_as_snake_case() {
        let json = serde_json::to_string(&AnalysisStage::ParsingPe).unwrap();
        assert_eq!(json, "\"parsing_pe\"");
        let json = serde_json::to_string(&AnalysisStage::RunningRules).unwrap();
        assert_eq!(json, "\"running_rules\"");
        let json = serde_json::to_string(&AnalysisStage::Complete).unwrap();
        assert_eq!(json, "\"complete\"");
    }

    #[test]
    fn analysis_stage_display_names_are_human_readable() {
        for stage in ALL_STAGES {
            let name = stage.display_name();
            assert!(!name.is_empty());
            assert!(!name.starts_with('_'));
            assert!(!name.ends_with('_'));
        }
    }

    #[test]
    fn analysis_stage_as_str_matches_serialization() {
        for stage in ALL_STAGES {
            let str_value = stage.as_str();
            let json = serde_json::to_string(stage).unwrap();
            let expected = format!("\"{}\"", str_value);
            assert_eq!(json, expected);
        }
    }
}
