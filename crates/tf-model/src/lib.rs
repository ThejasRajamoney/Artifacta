//! Canonical domain objects shared by the host, workers, reports, and public schemas.

use std::collections::BTreeMap;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use ulid::Ulid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Ulid::new().to_string())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Constructs an ID from deterministic projection material.
            #[must_use]
            pub fn from_u128(value: u128) -> Self {
                Self(Ulid::from(value).to_string())
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ulid::from_string(value).map_err(|_| InvalidId {
                    kind: stringify!($name),
                    value: value.to_owned(),
                })?;
                Ok(Self(value.to_owned()))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::from_str(&value).map_err(de::Error::custom)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Ulid> for $name {
            fn from(value: Ulid) -> Self {
                Self(value.to_string())
            }
        }
    };
}

id_type!(CaseId);
id_type!(ArtifactId);
id_type!(ArtifactLocationId);
id_type!(AnalysisRunId);
id_type!(ProvenanceId);
id_type!(EvidenceId);
id_type!(FindingId);
id_type!(EntityId);
id_type!(EdgeId);
id_type!(EventId);
id_type!(RuleRecordId);
id_type!(NoteId);
id_type!(ReportId);
id_type!(YaraPackId);
id_type!(BookmarkId);
id_type!(ReportManifestId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidId {
    kind: &'static str,
    value: String,
}

impl std::fmt::Display for InvalidId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid {} value: {}", self.kind, self.value)
    }
}

impl std::error::Error for InvalidId {}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Confidence(f32);

impl Confidence {
    pub const MIN: f32 = 0.0;
    pub const MAX: f32 = 1.0;

    pub fn new(value: f32) -> Result<Self, InvalidConfidence> {
        if value.is_finite() && (Self::MIN..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidConfidence(value))
        }
    }

    #[must_use]
    pub fn value(self) -> f32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InvalidConfidence(f32);

impl std::fmt::Display for InvalidConfidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "confidence must be a finite value between 0.0 and 1.0, got {}",
            self.0
        )
    }
}

impl std::error::Error for InvalidConfidence {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Active,
    Complete,
    Archived,
    Error,
}

impl CaseStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Archived => "archived",
            Self::Error => "error",
        }
    }
}

impl FromStr for CaseStatus {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "complete" => Ok(Self::Complete),
            "archived" => Ok(Self::Archived),
            "error" => Ok(Self::Error),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Unknown,
    Pe32,
    Pe64,
    DotNetPe32,
    DotNetPe64,
    Archive,
    Pcap,
    PcapNg,
    WindowsEventLog,
    StructuredLog,
    Other,
}

impl ArtifactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Pe32 => "pe32",
            Self::Pe64 => "pe64",
            Self::DotNetPe32 => "dot_net_pe32",
            Self::DotNetPe64 => "dot_net_pe64",
            Self::Archive => "archive",
            Self::Pcap => "pcap",
            Self::PcapNg => "pcap_ng",
            Self::WindowsEventLog => "windows_event_log",
            Self::StructuredLog => "structured_log",
            Self::Other => "other",
        }
    }
}

impl FromStr for ArtifactKind {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "pe32" => Ok(Self::Pe32),
            "pe64" => Ok(Self::Pe64),
            "dot_net_pe32" => Ok(Self::DotNetPe32),
            "dot_net_pe64" => Ok(Self::DotNetPe64),
            "archive" => Ok(Self::Archive),
            "pcap" => Ok(Self::Pcap),
            "pcap_ng" => Ok(Self::PcapNg),
            "windows_event_log" => Ok(Self::WindowsEventLog),
            "structured_log" => Ok(Self::StructuredLog),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEnumValue(String);

impl std::fmt::Display for InvalidEnumValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "unknown stored enum value: {}", self.0)
    }
}

impl std::error::Error for InvalidEnumValue {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Queued,
    Running,
    Complete,
    Partial,
    Failed,
    Cancelled,
    TimedOut,
    ResourceLimit,
}

impl AnalysisStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::ResourceLimit => "resource_limit",
        }
    }
}

impl FromStr for AnalysisStatus {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "complete" => Ok(Self::Complete),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "resource_limit" => Ok(Self::ResourceLimit),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationClass {
    Observed,
    Inferred,
    Unknown,
}

impl ObservationClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for ObservationClass {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "observed" => Ok(Self::Observed),
            "inferred" => Ok(Self::Inferred),
            "unknown" => Ok(Self::Unknown),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Contextual,
    Low,
    Medium,
    High,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contextual => "contextual",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl FromStr for Severity {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "contextual" => Ok(Self::Contextual),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Tentative,
    Moderate,
    Strong,
}

impl ConfidenceBand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
        }
    }
}

impl FromStr for ConfidenceBand {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tentative" => Ok(Self::Tentative),
            "moderate" => Ok(Self::Moderate),
            "strong" => Ok(Self::Strong),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionBand {
    NoStrongIndicators,
    Review,
    Suspicious,
    HighSuspicion,
}

impl SuspicionBand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoStrongIndicators => "no_strong_indicators",
            Self::Review => "review",
            Self::Suspicious => "suspicious",
            Self::HighSuspicion => "high_suspicion",
        }
    }
}

/// Independent evidence axes used by the versioned Quick Check policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuickCheckEvidenceFamily {
    Structure,
    Capability,
    Indicator,
    SignatureIntegrity,
    Yara,
    MetadataAnomaly,
}

impl QuickCheckEvidenceFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::Capability => "capability",
            Self::Indicator => "indicator",
            Self::SignatureIntegrity => "signature_integrity",
            Self::Yara => "yara",
            Self::MetadataAnomaly => "metadata_anomaly",
        }
    }
}

/// Counts of active findings before Quick Check correlation and family de-duplication.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuickCheckFindingCounts {
    pub contextual: u32,
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub total: u32,
}

/// One family in the aggregate, including transparent scoring suppression counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuickCheckFamilySummary {
    pub family: QuickCheckEvidenceFamily,
    pub finding_count: u32,
    /// Findings eligible to supply this family's single strongest scoring signal.
    pub contributing_finding_count: u32,
    pub strongest_severity: Option<Severity>,
}

/// A compact, plain-language finding selected for the Quick Check summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuickCheckTopFinding {
    pub finding_id: FindingId,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub evidence_family: QuickCheckEvidenceFamily,
}

/// Deterministic, non-verdict summary of active static-analysis findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuickCheck {
    pub policy_version: String,
    pub policy_sha256: String,
    pub band: SuspicionBand,
    pub finding_counts: QuickCheckFindingCounts,
    pub top_findings: Vec<QuickCheckTopFinding>,
    /// Always contains all six families in canonical enum order.
    pub evidence_families: Vec<QuickCheckFamilySummary>,
    pub statement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    New,
    Reviewed,
    Accepted,
    Dismissed,
}

impl FindingState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Reviewed => "reviewed",
            Self::Accepted => "accepted",
            Self::Dismissed => "dismissed",
        }
    }
}

impl FromStr for FindingState {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "new" => Ok(Self::New),
            "reviewed" => Ok(Self::Reviewed),
            "accepted" => Ok(Self::Accepted),
            "dismissed" => Ok(Self::Dismissed),
            "open" => Ok(Self::New),
            "acknowledged" => Ok(Self::Reviewed),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Supports,
    Context,
    Contradicts,
}

impl EvidenceRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::Context => "context",
            Self::Contradicts => "contradicts",
        }
    }
}

impl FromStr for EvidenceRole {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "supports" => Ok(Self::Supports),
            "context" => Ok(Self::Context),
            "contradicts" => Ok(Self::Contradicts),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Artifact,
    Section,
    ImportedApi,
    Export,
    Url,
    Domain,
    IpAddress,
    FilePath,
    RegistryPath,
    RegistryKey,
    CommandString,
    Certificate,
    Signer,
    YaraRule,
    Finding,
    NetworkFlow,
    Host,
    Process,
}

impl EntityType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Section => "section",
            Self::ImportedApi => "imported_api",
            Self::Export => "export",
            Self::Url => "url",
            Self::Domain => "domain",
            Self::IpAddress => "ip_address",
            Self::FilePath => "file_path",
            Self::RegistryPath => "registry_path",
            Self::RegistryKey => "registry_key",
            Self::CommandString => "command_string",
            Self::Certificate => "certificate",
            Self::Signer => "signer",
            Self::YaraRule => "yara_rule",
            Self::Finding => "finding",
            Self::NetworkFlow => "network_flow",
            Self::Host => "host",
            Self::Process => "process",
        }
    }
}

impl FromStr for EntityType {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "artifact" => Ok(Self::Artifact),
            "section" => Ok(Self::Section),
            "imported_api" => Ok(Self::ImportedApi),
            "export" => Ok(Self::Export),
            "url" => Ok(Self::Url),
            "domain" => Ok(Self::Domain),
            "ip_address" => Ok(Self::IpAddress),
            "file_path" => Ok(Self::FilePath),
            "registry_path" => Ok(Self::RegistryPath),
            "registry_key" => Ok(Self::RegistryKey),
            "command_string" => Ok(Self::CommandString),
            "certificate" => Ok(Self::Certificate),
            "signer" => Ok(Self::Signer),
            "yara_rule" => Ok(Self::YaraRule),
            "finding" => Ok(Self::Finding),
            "network_flow" => Ok(Self::NetworkFlow),
            "host" => Ok(Self::Host),
            "process" => Ok(Self::Process),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    Contains,
    Imports,
    Exports,
    ContainsIndicator,
    ReferencesPath,
    SignedBy,
    UsesCertificate,
    MatchedRule,
    SupportsFinding,
    ContradictsFinding,
    DerivedFrom,
    ResolvesTo,
    CommunicatesWith,
}

impl Relationship {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::ContainsIndicator => "contains_indicator",
            Self::ReferencesPath => "references_path",
            Self::SignedBy => "signed_by",
            Self::UsesCertificate => "uses_certificate",
            Self::MatchedRule => "matched_rule",
            Self::SupportsFinding => "supports_finding",
            Self::ContradictsFinding => "contradicts_finding",
            Self::DerivedFrom => "derived_from",
            Self::ResolvesTo => "resolves_to",
            Self::CommunicatesWith => "communicates_with",
        }
    }
}

impl FromStr for Relationship {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "contains" => Ok(Self::Contains),
            "imports" => Ok(Self::Imports),
            "exports" => Ok(Self::Exports),
            "contains_indicator" => Ok(Self::ContainsIndicator),
            "references_path" => Ok(Self::ReferencesPath),
            "signed_by" => Ok(Self::SignedBy),
            "uses_certificate" => Ok(Self::UsesCertificate),
            "matched_rule" => Ok(Self::MatchedRule),
            "supports_finding" => Ok(Self::SupportsFinding),
            "contradicts_finding" => Ok(Self::ContradictsFinding),
            "derived_from" => Ok(Self::DerivedFrom),
            "resolves_to" => Ok(Self::ResolvesTo),
            "communicates_with" => Ok(Self::CommunicatesWith),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TimestampReliability {
    AttackerControlled,
    FilesystemMetadata,
    CryptographicallyBound,
    ApplicationRecorded,
    ApplicationGenerated,
    ImportedTelemetry,
}

impl TimestampReliability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttackerControlled => "attacker_controlled",
            Self::FilesystemMetadata => "filesystem_metadata",
            Self::CryptographicallyBound => "cryptographically_bound",
            Self::ApplicationRecorded => "application_recorded",
            Self::ApplicationGenerated => "application_generated",
            Self::ImportedTelemetry => "imported_telemetry",
        }
    }
}

impl FromStr for TimestampReliability {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "attacker_controlled" => Ok(Self::AttackerControlled),
            "filesystem_metadata" => Ok(Self::FilesystemMetadata),
            "cryptographically_bound" => Ok(Self::CryptographicallyBound),
            "application_recorded" => Ok(Self::ApplicationRecorded),
            "application_generated" => Ok(Self::ApplicationGenerated),
            "imported_telemetry" => Ok(Self::ImportedTelemetry),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Case {
    pub id: CaseId,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub app_version: String,
    pub schema_version: u32,
    pub status: CaseStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    pub id: ArtifactId,
    pub case_id: CaseId,
    pub parent_artifact_id: Option<ArtifactId>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size_bytes: u64,
    pub kind: ArtifactKind,
    pub mime: Option<String>,
    pub original_name: String,
    /// Content-addressed path relative to the Artifacta store root.
    #[serde(skip_serializing)]
    pub store_path: String,
    pub created_at: String,
}

/// Artifact metadata safe to return from investigator APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactSummary {
    pub id: ArtifactId,
    pub case_id: CaseId,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size_bytes: u64,
    pub kind: ArtifactKind,
    pub mime: Option<String>,
    pub original_name: String,
    pub created_at: String,
}

impl From<&Artifact> for ArtifactSummary {
    fn from(value: &Artifact) -> Self {
        Self {
            id: value.id.clone(),
            case_id: value.case_id.clone(),
            sha256: value.sha256.clone(),
            sha1: value.sha1.clone(),
            md5: value.md5.clone(),
            size_bytes: value.size_bytes,
            kind: value.kind,
            mime: value.mime.clone(),
            original_name: value.original_name.clone(),
            created_at: value.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactLocation {
    pub id: ArtifactLocationId,
    pub artifact_id: ArtifactId,
    pub display_name: String,
    #[serde(skip_serializing)]
    pub source_path: Option<String>,
    pub modified_at_utc: Option<String>,
    pub created_at_utc: Option<String>,
    pub ingested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisRun {
    pub id: AnalysisRunId,
    pub artifact_id: ArtifactId,
    pub analyzer: String,
    pub analyzer_version: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: AnalysisStatus,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Provenance {
    pub id: ProvenanceId,
    pub analysis_run_id: AnalysisRunId,
    pub analyzer: String,
    pub analyzer_version: String,
    pub rule_id: Option<String>,
    pub rule_version: Option<String>,
    pub rule_pack_sha256: Option<String>,
    pub input_sha256: String,
    pub parameters: BTreeMap<String, Value>,
}

/// Public rule-pack metadata. Rule text and its content-store path are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct YaraPack {
    pub id: YaraPackId,
    pub sha256: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub license: String,
    pub imported_at: String,
    pub enabled: bool,
    pub rule_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct YaraRuleMetadata {
    pub namespace: String,
    pub identifier: String,
    pub tags: Vec<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub id: EvidenceId,
    pub artifact_id: ArtifactId,
    pub provenance_id: ProvenanceId,
    pub kind: String,
    pub class: ObservationClass,
    pub locator: BTreeMap<String, Value>,
    pub value: Value,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub id: FindingId,
    pub analysis_run_id: AnalysisRunId,
    pub artifact_id: ArtifactId,
    pub rule_id: String,
    pub rule_version: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub confidence_band: ConfidenceBand,
    pub explanation_template_id: String,
    pub state: FindingState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingEvidence {
    pub finding_id: FindingId,
    pub evidence_id: EvidenceId,
    pub role: EvidenceRole,
}

/// Human-readable, non-verdict context for one finding and its exact evidence links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingExplanation {
    pub finding_id: FindingId,
    pub template_id: String,
    pub observation: String,
    pub why_it_matters: String,
    pub limitations: String,
    pub supporting_evidence: Vec<FindingEvidence>,
}

/// Canonical MITRE ATT&CK context attached to a static finding explanation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct AttackMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

/// Associates canonical ATT&CK context with one persisted finding explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingExplanationAttackMapping {
    pub finding_id: FindingId,
    pub mapping: AttackMapping,
}

/// Atomic output of a deterministic rule evaluation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FindingSet {
    pub rules: Vec<RuleRecord>,
    pub findings: Vec<Finding>,
    pub evidence_links: Vec<FindingEvidence>,
    pub explanations: Vec<FindingExplanation>,
    pub attack_mappings: Vec<FindingExplanationAttackMapping>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Entity {
    pub id: EntityId,
    pub case_id: CaseId,
    pub entity_type: EntityType,
    pub canonical_value: String,
    pub display_value: String,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Edge {
    pub id: EdgeId,
    pub source_entity_id: EntityId,
    pub target_entity_id: EntityId,
    pub relationship: Relationship,
    pub evidence_id: EvidenceId,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EntityEvidence {
    pub entity_id: EntityId,
    pub evidence_id: EvidenceId,
    pub role: EvidenceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceEvent {
    pub id: EventId,
    pub case_id: CaseId,
    pub timestamp_utc: String,
    pub timestamp_type: String,
    pub reliability: TimestampReliability,
    pub event_type: String,
    pub artifact_id: Option<ArtifactId>,
    pub evidence_id: Option<EvidenceId>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CaseGraph {
    pub case_id: CaseId,
    pub projection_version: u32,
    pub source_analysis_run_id: Option<AnalysisRunId>,
    pub entities: Vec<Entity>,
    pub edges: Vec<Edge>,
    pub entity_evidence: Vec<EntityEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaseChronology {
    pub case_id: CaseId,
    pub projection_version: u32,
    pub source_analysis_run_id: Option<AnalysisRunId>,
    pub events: Vec<EvidenceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NavigationTarget {
    Evidence { evidence_id: EvidenceId },
    Finding { finding_id: FindingId },
    Entity { entity_id: EntityId },
    Edge { edge_id: EdgeId },
    Event { event_id: EventId },
}

impl NavigationTarget {
    #[must_use]
    pub const fn target_type(&self) -> &'static str {
        match self {
            Self::Evidence { .. } => "evidence",
            Self::Finding { .. } => "finding",
            Self::Entity { .. } => "entity",
            Self::Edge { .. } => "edge",
            Self::Event { .. } => "event",
        }
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        match self {
            Self::Evidence { evidence_id } => evidence_id.as_str(),
            Self::Finding { finding_id } => finding_id.as_str(),
            Self::Entity { entity_id } => entity_id.as_str(),
            Self::Edge { edge_id } => edge_id.as_str(),
            Self::Event { event_id } => event_id.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Bookmark {
    pub id: BookmarkId,
    pub case_id: CaseId,
    pub target: NavigationTarget,
    pub label: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleRecord {
    pub id: RuleRecordId,
    pub engine: String,
    pub rule_id: String,
    pub version: String,
    pub source: String,
    pub license: String,
    pub sha256: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalystNote {
    pub id: NoteId,
    pub case_id: CaseId,
    pub entity_id: Option<EntityId>,
    pub finding_id: Option<FindingId>,
    pub body: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    Review,
    Accept,
    Dismiss,
    Reopen,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SearchField {
    Sha256,
    Sha1,
    Md5,
    CaseTitle,
    Import,
    Indicator,
    Certificate,
    Signer,
    RuleId,
    FindingTitle,
    FindingCategory,
    EvidenceValue,
}

impl SearchField {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Md5 => "md5",
            Self::CaseTitle => "case_title",
            Self::Import => "import",
            Self::Indicator => "indicator",
            Self::Certificate => "certificate",
            Self::Signer => "signer",
            Self::RuleId => "rule_id",
            Self::FindingTitle => "finding_title",
            Self::FindingCategory => "finding_category",
            Self::EvidenceValue => "evidence_value",
        }
    }
}

impl FromStr for SearchField {
    type Err = InvalidEnumValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sha256" => Ok(Self::Sha256),
            "sha1" => Ok(Self::Sha1),
            "md5" => Ok(Self::Md5),
            "case_title" => Ok(Self::CaseTitle),
            "import" => Ok(Self::Import),
            "indicator" => Ok(Self::Indicator),
            "certificate" => Ok(Self::Certificate),
            "signer" => Ok(Self::Signer),
            "rule_id" => Ok(Self::RuleId),
            "finding_title" => Ok(Self::FindingTitle),
            "finding_category" => Ok(Self::FindingCategory),
            "evidence_value" => Ok(Self::EvidenceValue),
            _ => Err(InvalidEnumValue(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaseSearchRequest {
    pub query: String,
    pub fields: Vec<SearchField>,
    pub include_archived: bool,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CaseSearchHit {
    pub case_id: CaseId,
    pub case_title: String,
    pub case_status: CaseStatus,
    pub artifact_id: Option<ArtifactId>,
    pub analysis_run_id: Option<AnalysisRunId>,
    pub evidence_id: Option<EvidenceId>,
    pub finding_id: Option<FindingId>,
    pub field: SearchField,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Removed,
    RetainedShared,
    AlreadyMissing,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeleteCaseResult {
    pub case_id: CaseId,
    pub objects: Vec<ObjectCleanupResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectCleanupResult {
    pub sha256: String,
    pub cleanup: CleanupStatus,
    pub cleanup_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonDelta {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonValue {
    pub key: String,
    pub value: Value,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonEntry {
    pub delta: ComparisonDelta,
    pub key: String,
    pub left: Option<ComparisonValue>,
    pub right: Option<ComparisonValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonGroup {
    pub added: Vec<ComparisonEntry>,
    pub removed: Vec<ComparisonEntry>,
    pub changed: Vec<ComparisonEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactComparison {
    pub left: ArtifactSummary,
    pub right: ArtifactSummary,
    pub hashes: ComparisonGroup,
    pub headers: ComparisonGroup,
    pub sections: ComparisonGroup,
    pub imports: ComparisonGroup,
    pub strings: ComparisonGroup,
    pub signatures: ComparisonGroup,
    pub findings: ComparisonGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportRecord {
    pub id: ReportId,
    pub case_id: CaseId,
    pub format: String,
    pub generated_at: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportManifestRecord {
    pub id: ReportManifestId,
    pub report_id: ReportId,
    pub case_id: CaseId,
    pub generated_at: String,
    pub path: String,
    pub schema_version: u32,
    pub snapshot_sha256: String,
    /// SHA-256 of the exact external manifest bytes.
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerificationStatus {
    Verified,
    Mismatch,
    Unavailable,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::{ArtifactId, Confidence};

    #[test]
    fn confidence_accepts_only_closed_unit_interval() {
        assert_eq!(Confidence::new(0.0).expect("zero is valid").value(), 0.0);
        assert_eq!(Confidence::new(1.0).expect("one is valid").value(), 1.0);
        assert!(Confidence::new(-0.01).is_err());
        assert!(Confidence::new(1.01).is_err());
        assert!(Confidence::new(f32::NAN).is_err());
    }

    #[test]
    fn confidence_rejects_invalid_deserialized_values() {
        assert!(serde_json::from_str::<Confidence>("1.5").is_err());
        assert!(serde_json::from_str::<Confidence>("0.72").is_ok());
    }

    #[test]
    fn ids_reject_untrusted_non_ulid_values() {
        assert!(serde_json::from_str::<ArtifactId>(r#""not-an-id""#).is_err());
        let id = ArtifactId::new();
        let encoded = serde_json::to_string(&id).expect("serialize ID");
        assert_eq!(
            serde_json::from_str::<ArtifactId>(&encoded).expect("deserialize ID"),
            id
        );
    }
}
