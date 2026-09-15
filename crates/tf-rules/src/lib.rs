#![forbid(unsafe_code)]

//! Deterministic, local capability context over persisted Analysis v1/v2 evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tf_model::{
    AnalysisRunId, ArtifactId, AttackMapping, Confidence, ConfidenceBand, Evidence, EvidenceRole,
    Finding, FindingEvidence, FindingExplanation, FindingExplanationAttackMapping, FindingId,
    FindingSet, FindingState, QuickCheck, QuickCheckEvidenceFamily, QuickCheckFamilySummary,
    QuickCheckFindingCounts, QuickCheckTopFinding, RuleRecord, RuleRecordId, Severity,
    SuspicionBand,
};
use ulid::Ulid;

pub const ENGINE_NAME: &str = "traceforge.local.v2";
pub const ENGINE_VERSION: &str = "2.2.0";

pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;
/// Zero preserves the policy that every non-empty section measured by the analyzer is eligible.
pub const HIGH_ENTROPY_MIN_SECTION_SIZE_BYTES: u64 = 0;
pub const EXECUTABLE_SECTION_MASK: u64 = 0x2000_0000;
pub const WRITABLE_SECTION_MASK: u64 = 0x8000_0000;
pub const PACKED_RESOURCE_MIN_SIZE_BYTES: u64 = 1_048_576;
pub const PACKED_OVERLAY_MIN_SIZE_BYTES: u64 = 1;
pub const CONFIDENCE_MODERATE_MIN: f64 = 0.70;
pub const CONFIDENCE_STRONG_MIN: f64 = 0.85;

pub const QUICK_CHECK_POLICY_VERSION: &str = "1.0.0";
pub const QUICK_CHECK_TOP_FINDINGS_LIMIT: usize = 5;
pub const QUICK_CHECK_STATEMENT: &str = "Quick Check summarizes static evidence for investigator review; it is not a malware or safety verdict.";

/// Canonical policy material. Any scoring or correlation change must update this text and version.
///
/// Counts remain literal active-finding counts. Scoring first suppresses YARA findings whose
/// `category`, `traceforge_category`, `correlates_with`, `traceforge_rule_id`, or tag exactly
/// matches a built-in category/rule ID after normalization. It then takes only the strongest
/// severity per independent family, so correlated findings never accumulate weight.
pub const QUICK_CHECK_POLICY_SOURCE: &str = "\
policy=traceforge.quick_check\n\
version=1.0.0\n\
active_states=open,acknowledged\n\
families=structure,capability,indicator,signature_integrity,yara,metadata_anomaly\n\
severity_weights=contextual:0,low:1,medium:2,high:4\n\
family_aggregation=maximum_severity_only\n\
yara_correlation_fields=category,traceforge_category,correlates_with,traceforge_rule_id,tags\n\
yara_correlation=display_and_count_but_do_not_score\n\
bands=no_strong_indicators:0,review:1-2,suspicious:3+_unless_high_criteria,high_suspicion:6+_and_2+_families\n\
top_findings=5,severity_desc,confidence_desc,title,rule_id,finding_id\n\
statement=non_verdict";

const QUICK_CHECK_FAMILIES: [QuickCheckEvidenceFamily; 6] = [
    QuickCheckEvidenceFamily::Structure,
    QuickCheckEvidenceFamily::Capability,
    QuickCheckEvidenceFamily::Indicator,
    QuickCheckEvidenceFamily::SignatureIntegrity,
    QuickCheckEvidenceFamily::Yara,
    QuickCheckEvidenceFamily::MetadataAnomaly,
];

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: Severity,
    confidence: f32,
    template: &'static str,
    observation: &'static str,
    why: &'static str,
    limitations: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "TF-PE-001",
        title: "High-entropy executable or writable section",
        category: "section_characteristics",
        severity: Severity::Low,
        confidence: 0.68,
        template: "section.high_entropy_permissions.v1",
        observation: "A section with high measured entropy is marked executable or writable.",
        why: "Compressed, encrypted, or generated code and data can have this combination and may warrant focused review.",
        limitations: "Packers, installers, protected commercial software, and compressed resources can produce the same observation; entropy and permissions do not establish intent.",
    },
    Rule {
        id: "TF-PE-002",
        title: "Section name associated with packing or obfuscation",
        category: "section_naming",
        severity: Severity::Low,
        confidence: 0.72,
        template: "section.suspicious_name.v1",
        observation: "A section name matches a name commonly used by packers or protectors.",
        why: "Nonstandard section naming can help identify areas that need manual inspection.",
        limitations: "Section names are author-controlled, are not unique to harmful software, and may identify legitimate compression or protection tooling.",
    },
    Rule {
        id: "TF-PE-003",
        title: "Unusual entry-point section mapping",
        category: "entry_point",
        severity: Severity::Medium,
        confidence: 0.76,
        template: "entry_point.section_mismatch.v1",
        observation: "The nonzero entry-point RVA does not map to a declared executable section.",
        why: "Entry points normally resolve into executable image content, so a mismatch can indicate an unusual layout or incomplete parsing.",
        limitations: "Drivers, protectors, malformed files, overlapping sections, and parser coverage can affect this mapping; the observation is not a verdict.",
    },
    Rule {
        id: "TF-IMP-001",
        title: "Process-injection primitive import context",
        category: "process_injection",
        severity: Severity::Low,
        confidence: 0.68,
        template: "imports.process_injection_primitive.v2",
        observation: "A normal or delayed import names one or more APIs that can serve as a process-injection primitive.",
        why: "The primitive provides static capability context for focused process-manipulation review.",
        limitations: "A single import can support debuggers, security products, accessibility tools, and other legitimate software. It does not show invocation, target process, observed injection or execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-IMP-002",
        title: "Credential-access import context",
        category: "credential_access",
        severity: Severity::Low,
        confidence: 0.68,
        template: "imports.credential_access.v2",
        observation: "Imports include APIs that can access credentials, security authority data, or protected process memory.",
        why: "The capabilities are relevant to credential and authentication-material review.",
        limitations: "Authentication clients, administration tools, and security software may legitimately use these APIs; imports do not show arguments or execution.",
    },
    Rule {
        id: "TF-IMP-003",
        title: "Persistence-related import context",
        category: "persistence",
        severity: Severity::Low,
        confidence: 0.67,
        template: "imports.persistence.v2",
        observation: "Imports include APIs commonly used to create services, scheduled tasks, or startup configuration.",
        why: "These capabilities are relevant when reviewing how software may arrange repeated execution.",
        limitations: "Installers, updaters, and system-management software commonly use these APIs legitimately; imports alone do not establish configuration changes.",
    },
    Rule {
        id: "TF-IMP-004",
        title: "Download or network-retrieval import context",
        category: "network_execution",
        severity: Severity::Low,
        confidence: 0.68,
        template: "imports.network_retrieval.v2",
        observation: "A normal or delayed import names an API capable of retrieving network content.",
        why: "The primitive provides static context for reviewing network retrieval behavior.",
        limitations: "Browsers, installers, updaters, and enterprise agents commonly import these APIs; an import does not show a connection, transfer, execution, or attribution.",
    },
    Rule {
        id: "TF-PE-004",
        title: "TLS callback present",
        category: "execution_context",
        severity: Severity::Low,
        confidence: 0.88,
        template: "pe.tls_callback.v1",
        observation: "The PE metadata declares one or more TLS callbacks that may execute before the normal entry point.",
        why: "Pre-entry-point execution changes the order in which code should be examined.",
        limitations: "TLS callbacks are a normal PE feature used by legitimate runtimes and libraries; presence does not establish suspicious behavior.",
    },
    Rule {
        id: "TF-SIG-001",
        title: "Authenticode signature not present",
        category: "authenticode",
        severity: Severity::Contextual,
        confidence: 0.93,
        template: "authenticode.missing.v1",
        observation: "No embedded Authenticode signature was reported for the artifact.",
        why: "Signature absence removes one source of publisher and integrity context.",
        limitations: "Many legitimate files are unsigned, signatures may be supplied through catalogs, and absence says nothing by itself about intent or safety.",
    },
    Rule {
        id: "TF-SIG-002",
        title: "Authenticode data present but malformed",
        category: "authenticode",
        severity: Severity::Low,
        confidence: 0.88,
        template: "authenticode.malformed.v1",
        observation: "Authenticode-related data is present but the parser reported malformed or invalid structure.",
        why: "Malformed signature data can prevent reliable publisher or integrity assessment and may indicate file damage or unusual construction.",
        limitations: "Corruption, unsupported algorithms, parser limitations, or nonstandard signing tools can cause this result; validation failure is not attribution.",
    },
    Rule {
        id: "TF-IND-001",
        title: "Command-like indicator requires review",
        category: "command_indicator",
        severity: Severity::Low,
        confidence: 0.74,
        template: "indicator.command.v1",
        observation: "Extracted text contains command-shell or script-execution syntax.",
        why: "Commands can reveal operational behavior that is not apparent from imports alone.",
        limitations: "Strings may be documentation, examples, dead data, or user-facing features and may never execute.",
    },
    Rule {
        id: "TF-IND-002",
        title: "URL indicator requires review",
        category: "url_indicator",
        severity: Severity::Low,
        confidence: 0.70,
        template: "indicator.url.v1",
        observation: "An HTTP, HTTPS, or FTP URL was extracted from the artifact.",
        why: "URLs provide concrete context for reviewing network-facing behavior and dependencies.",
        limitations: "URLs may be benign vendor links, documentation, test data, or unreachable content and may never be contacted.",
    },
    Rule {
        id: "TF-IND-003",
        title: "Startup or service registry indicator",
        category: "registry_indicator",
        severity: Severity::Low,
        confidence: 0.77,
        template: "indicator.registry_persistence.v1",
        observation: "An extracted registry path references a startup or service configuration location.",
        why: "These locations are relevant when reviewing software installation and repeated-execution behavior.",
        limitations: "Installers, management agents, and configuration tools routinely reference these keys; a string does not prove a registry operation.",
    },
    Rule {
        id: "TF-IND-004",
        title: "User-writable execution path indicator",
        category: "path_indicator",
        severity: Severity::Low,
        confidence: 0.69,
        template: "indicator.user_writable_path.v1",
        observation: "An extracted path combines a user-writable or temporary location with executable or script content.",
        why: "Such paths can focus review on staging, installation, or execution behavior.",
        limitations: "Per-user applications, installers, caches, and update systems legitimately execute from these locations; extracted paths may be inactive text.",
    },
    Rule {
        id: "TF-DOTNET-001",
        title: ".NET metadata context present",
        category: "runtime_context",
        severity: Severity::Contextual,
        confidence: 0.96,
        template: "dotnet.context.v1",
        observation: "The artifact contains .NET runtime or managed metadata context.",
        why: "Managed-code tooling and metadata inspection may provide more complete behavioral context than native PE inspection alone.",
        limitations: ".NET is a common application platform and this observation carries no implication about intent or safety.",
    },
    Rule {
        id: "TF-PARSE-001",
        title: "Parser coverage limit reported",
        category: "analysis_coverage",
        severity: Severity::Contextual,
        confidence: 0.94,
        template: "parser.limit.v1",
        observation: "The analyzer reported that a parser or extraction limit reduced coverage.",
        why: "Unexamined records or content can make other observations incomplete.",
        limitations: "A limit is an analysis-quality note, not a property proving harmful or benign behavior; rerun with suitable controls if appropriate.",
    },
    Rule {
        id: "TF-PARSE-002",
        title: "Parser anomaly reported",
        category: "analysis_quality",
        severity: Severity::Low,
        confidence: 0.82,
        template: "parser.anomaly.v1",
        observation: "The analyzer reported an unusual, inconsistent, or malformed structure while retaining a completed result.",
        why: "Structural anomalies can affect interpretation and identify areas needing alternate parser or manual review.",
        limitations: "File damage, uncommon toolchains, format extensions, and parser limitations can produce anomalies; they do not establish intent.",
    },
    Rule {
        id: "TF-CAP-001",
        title: "Corroborated process-injection capability",
        category: "process_injection",
        severity: Severity::High,
        confidence: 0.88,
        template: "capability.process_injection_combination.v2",
        observation: "Normal or delayed imports combine remote-process memory manipulation with a remote execution primitive.",
        why: "The linked primitives form a more specific static process-injection capability than either import alone.",
        limitations: "Debuggers, security products, profilers, and administration tools can expose the same combination. Imports do not show invocation, target process, observed injection or execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-002",
        title: "Corroborated process-memory credential-dump capability",
        category: "credential_access",
        severity: Severity::Medium,
        confidence: 0.82,
        template: "capability.credential_dump_combination.v2",
        observation: "Normal or delayed imports combine process access with MiniDumpWriteDump.",
        why: "The combination can support collection of process memory for credential-material review.",
        limitations: "Crash reporters, debuggers, diagnostics, and security products commonly use this combination. Static imports do not identify LSASS, show a dump or execution, establish credential access, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-003",
        title: "Corroborated Windows service persistence capability",
        category: "persistence",
        severity: Severity::Medium,
        confidence: 0.84,
        template: "capability.service_persistence_combination.v3",
        observation: "Normal or delayed imports combine service-control-manager access with service creation.",
        why: "The linked API pair provides specific static context for service installation review.",
        limitations: "Installers, service managers, and enterprise agents routinely use both APIs. Static imports do not show a service change, repeated execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-004",
        title: "Corroborated registry run-key persistence capability",
        category: "persistence",
        severity: Severity::Medium,
        confidence: 0.83,
        template: "capability.registry_run_key_combination.v2",
        observation: "A registry-write import is corroborated by an extracted Run or RunOnce registry path.",
        why: "The combination provides specific static context for startup configuration review.",
        limitations: "Installers, configuration tools, and legitimate per-user applications use these keys. The evidence does not show a registry write, startup execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-005",
        title: "Corroborated network retrieval and execution capability",
        category: "capability",
        severity: Severity::High,
        confidence: 0.86,
        template: "capability.network_retrieval_execution_combination.v3",
        observation: "Native or Qt imports combine network retrieval with a process or command execution primitive, optionally corroborated by a URL indicator.",
        why: "The combination provides static context for reviewing retrieval followed by possible execution.",
        limitations: "Browsers, installers, updaters, and management agents can contain this combination. The evidence does not link the URL to an API call or show a transfer, execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-006",
        title: "Corroborated anti-debugging capability",
        category: "anti_debugging",
        severity: Severity::Medium,
        confidence: 0.82,
        template: "capability.anti_debug_combination.v2",
        observation: "Normal or delayed imports include both direct debugger checks and lower-level process or thread inspection primitives.",
        why: "Multiple anti-debugging primitives provide stronger static evasion context than one import alone.",
        limitations: "Diagnostics, copy protection, crash handling, and security software can use the same APIs. Imports do not show debugger detection, evasion, execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-007",
        title: "Anti-debugging primitive import context",
        category: "anti_debugging",
        severity: Severity::Low,
        confidence: 0.66,
        template: "capability.anti_debug_primitive.v2",
        observation: "A normal or delayed import names an API that can inspect or alter debugging state.",
        why: "The primitive provides low-confidence static context for anti-debugging review.",
        limitations: "Diagnostics, crash handling, copy protection, and security software can use this API. A single import does not show debugger detection, evasion, execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-008",
        title: "Corroborated Windows command-shell capability",
        category: "command_execution",
        severity: Severity::Medium,
        confidence: 0.84,
        template: "capability.command_shell_combination.v2",
        observation: "A process or shell execution import is corroborated by an extracted Windows shell command indicator.",
        why: "The linked artifacts provide more specific static command-execution context than a string or import alone.",
        limitations: "Administrative tools, installers, launchers, and support utilities often expose this combination. It does not show command invocation, successful execution, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-009",
        title: "Dynamic API resolution capability",
        category: "dynamic_api_resolution",
        severity: Severity::Low,
        confidence: 0.80,
        template: "capability.dynamic_api_resolution.v2",
        observation: "Normal or delayed imports combine library loading with exported-symbol resolution APIs.",
        why: "The combination can resolve APIs at runtime and reduce what is visible in the static import table.",
        limitations: "Plugins, compatibility layers, and many ordinary applications use dynamic resolution. Imports do not show which library or symbol is resolved, execution, concealment intent, or attribution; the ATT&CK mapping is static capability context only.",
    },
    Rule {
        id: "TF-CAP-010",
        title: "Corroborated packed or obfuscated file context",
        category: "packed_obfuscated",
        severity: Severity::Medium,
        confidence: 0.84,
        template: "capability.packed_obfuscated_combination.v2",
        observation: "A high-entropy executable or writable section is corroborated by a packer-style section name, overlay, or large resource payload.",
        why: "Corroborating structure provides stronger packed or encoded-content context than entropy alone.",
        limitations: "Installers, protected commercial software, compressed resources, and signed update packages can have the same structure. This does not establish unpacking at runtime, harmful intent, or attribution; the ATT&CK mapping is static context only.",
    },
    Rule {
        id: "TF-SIG-003",
        title: "Authenticode verification did not validate signed content",
        category: "authenticode",
        severity: Severity::Low,
        confidence: 0.90,
        template: "authenticode.verification_invalid.v2",
        observation: "Authenticode verification reported an invalid image digest, CMS signature, or local signature chain result.",
        why: "The reported verification result limits use of the signature as publisher or integrity context.",
        limitations: "Corruption, unsupported signing forms, local trust-store state, and verification coverage can affect results. Invalid or untrusted signature context is not a malware verdict and does not establish attribution.",
    },
    Rule {
        id: "TF-PE-005",
        title: "PE mitigation posture context",
        category: "load_config",
        severity: Severity::Contextual,
        confidence: 0.94,
        template: "pe.load_config_mitigations.v2",
        observation: "PE load-config and header evidence records one or more absent exploit mitigations.",
        why: "Mitigation posture can guide defensive review of how the image was built and protected.",
        limitations: "Toolchain, target platform, image type, and compatibility requirements affect mitigations. Their absence does not establish exploitation, evasion, intent, or safety.",
    },
    Rule {
        id: "TF-PE-006",
        title: "Elevated manifest execution context",
        category: "manifest",
        severity: Severity::Contextual,
        confidence: 0.90,
        template: "pe.manifest_elevation.v2",
        observation: "The embedded manifest text requests administrator or highest-available execution level.",
        why: "Requested execution level is useful context when reviewing capabilities that may affect protected system state.",
        limitations: "Installers, administration tools, and system utilities legitimately request elevation. A manifest request does not show elevation was granted, execution, or attribution.",
    },
    Rule {
        id: "TF-PE-007",
        title: "Debug metadata path context",
        category: "debug_metadata",
        severity: Severity::Contextual,
        confidence: 0.96,
        template: "pe.debug_path_context.v2",
        observation: "PE debug metadata contains a bounded CodeView program-database path.",
        why: "Build paths can provide compiler and project context for manual review.",
        limitations: "Debug paths are build artifacts, can be stale or author-controlled, and do not establish source identity, execution, intent, or attribution.",
    },
];

/// Returns the complete set of numeric thresholds and caps used by the rule engine.
///
/// Every value that affects finding generation is included so provenance records capture
/// everything needed for deterministic reproduction.
#[must_use]
pub fn rule_engine_parameters() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("engine_name".to_owned(), Value::from(ENGINE_NAME)),
        ("engine_version".to_owned(), Value::from(ENGINE_VERSION)),
        (
            "entropy_threshold_bits_per_byte".to_owned(),
            Value::from(HIGH_ENTROPY_THRESHOLD),
        ),
        (
            "entropy_min_section_size_bytes".to_owned(),
            Value::from(HIGH_ENTROPY_MIN_SECTION_SIZE_BYTES),
        ),
        (
            "executable_section_mask".to_owned(),
            Value::from(EXECUTABLE_SECTION_MASK),
        ),
        (
            "writable_section_mask".to_owned(),
            Value::from(WRITABLE_SECTION_MASK),
        ),
        (
            "packed_resource_min_size_bytes".to_owned(),
            Value::from(PACKED_RESOURCE_MIN_SIZE_BYTES),
        ),
        (
            "packed_overlay_min_size_bytes".to_owned(),
            Value::from(PACKED_OVERLAY_MIN_SIZE_BYTES),
        ),
        (
            "confidence_band_moderate_min".to_owned(),
            Value::from(CONFIDENCE_MODERATE_MIN),
        ),
        (
            "confidence_band_strong_min".to_owned(),
            Value::from(CONFIDENCE_STRONG_MIN),
        ),
        (
            "quick_check_policy_version".to_owned(),
            Value::from(QUICK_CHECK_POLICY_VERSION),
        ),
        (
            "quick_check_top_findings_limit".to_owned(),
            Value::from(QUICK_CHECK_TOP_FINDINGS_LIMIT as u64),
        ),
    ])
}

/// Returns the numeric semantic inputs included in the canonical source and hash for one rule.
///
/// This map is intentionally public for provenance and audit tooling. Predicate changes involving
/// a number must use and update this map so a semantic change cannot retain the previous hash.
#[must_use]
pub fn rule_parameters(rule_id: &str) -> BTreeMap<String, Value> {
    let required_groups = match rule_id {
        "TF-CAP-005" => 3,
        "TF-CAP-001" | "TF-CAP-002" | "TF-CAP-003" | "TF-CAP-004" | "TF-CAP-006" | "TF-CAP-008"
        | "TF-CAP-009" | "TF-CAP-010" => 2,
        _ => 1,
    };
    let mut parameters = BTreeMap::from([
        (
            "confidence_band_moderate_min".to_owned(),
            Value::from(CONFIDENCE_MODERATE_MIN),
        ),
        (
            "confidence_band_strong_min".to_owned(),
            Value::from(CONFIDENCE_STRONG_MIN),
        ),
        (
            "required_evidence_groups".to_owned(),
            Value::from(required_groups),
        ),
    ]);
    match rule_id {
        "TF-PE-001" | "TF-CAP-010" => {
            parameters.insert(
                "entropy_threshold_bits_per_byte".to_owned(),
                Value::from(HIGH_ENTROPY_THRESHOLD),
            );
            parameters.insert(
                "entropy_min_section_size_bytes".to_owned(),
                Value::from(HIGH_ENTROPY_MIN_SECTION_SIZE_BYTES),
            );
            parameters.insert(
                "eligible_section_permissions_mask".to_owned(),
                Value::from(EXECUTABLE_SECTION_MASK | WRITABLE_SECTION_MASK),
            );
        }
        _ => {}
    }
    match rule_id {
        "TF-PE-003" => {
            parameters.insert("entry_point_min_rva".to_owned(), Value::from(1));
            parameters.insert(
                "executable_section_mask".to_owned(),
                Value::from(EXECUTABLE_SECTION_MASK),
            );
        }
        "TF-PE-004" => {
            parameters.insert("minimum_tls_callback_count".to_owned(), Value::from(1));
        }
        "TF-PE-005" => {
            parameters.insert("minimum_absent_mitigations".to_owned(), Value::from(1));
        }
        "TF-PE-007" => {
            parameters.insert("minimum_pdb_path_bytes".to_owned(), Value::from(1));
        }
        "TF-CAP-010" => {
            parameters.insert(
                "packed_resource_min_size_bytes".to_owned(),
                Value::from(PACKED_RESOURCE_MIN_SIZE_BYTES),
            );
            parameters.insert(
                "packed_overlay_min_size_bytes".to_owned(),
                Value::from(PACKED_OVERLAY_MIN_SIZE_BYTES),
            );
        }
        _ => {}
    }
    parameters
}

/// Aggregates active findings into the deterministic Quick Check policy projection.
///
/// `evidence_links` and `evidence` are used only to recognize explicit built-in/YARA
/// correlation. Missing links never cause an otherwise valid finding to be dropped.
#[must_use]
pub fn quick_check(
    findings: &[Finding],
    evidence_links: &[FindingEvidence],
    evidence: &[Evidence],
) -> QuickCheck {
    let mut active = findings
        .iter()
        .filter(|finding| finding.state != FindingState::Dismissed)
        .collect::<Vec<_>>();
    let mut counts = QuickCheckFindingCounts::default();
    for finding in &active {
        counts.total = counts.total.saturating_add(1);
        let count = match finding.severity {
            Severity::Contextual => &mut counts.contextual,
            Severity::Low => &mut counts.low,
            Severity::Medium => &mut counts.medium,
            Severity::High => &mut counts.high,
        };
        *count = count.saturating_add(1);
    }

    let evidence_by_id = evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut links_by_finding = BTreeMap::<&str, Vec<&str>>::new();
    for link in evidence_links {
        links_by_finding
            .entry(link.finding_id.as_str())
            .or_default()
            .push(link.evidence_id.as_str());
    }
    let built_in_keys = active
        .iter()
        .filter(|finding| finding_family(finding) != QuickCheckEvidenceFamily::Yara)
        .flat_map(|finding| {
            [
                normalize_correlation_key(&finding.rule_id),
                normalize_correlation_key(&finding.category),
            ]
        })
        .filter(|key| !key.is_empty())
        .collect::<BTreeSet<_>>();

    let mut by_family = BTreeMap::<QuickCheckEvidenceFamily, Vec<(&Finding, bool)>>::new();
    for finding in &active {
        let family = finding_family(finding);
        let correlated = family == QuickCheckEvidenceFamily::Yara
            && yara_correlation_keys(finding, &links_by_finding, &evidence_by_id)
                .iter()
                .any(|key| built_in_keys.contains(key));
        by_family
            .entry(family)
            .or_default()
            .push((finding, correlated));
    }

    let mut score = 0_u32;
    let mut scoring_families = 0_u32;
    let evidence_families = QUICK_CHECK_FAMILIES
        .iter()
        .map(|family| {
            let family_findings = by_family.get(family).map(Vec::as_slice).unwrap_or(&[]);
            let contributors = family_findings
                .iter()
                .filter(|(_, correlated)| !correlated)
                .map(|(finding, _)| *finding)
                .collect::<Vec<_>>();
            let strongest_severity = contributors
                .iter()
                .max_by_key(|finding| severity_rank(finding.severity))
                .map(|finding| finding.severity);
            let family_score = strongest_severity.map_or(0, severity_weight);
            score = score.saturating_add(family_score);
            if family_score != 0 {
                scoring_families = scoring_families.saturating_add(1);
            }
            QuickCheckFamilySummary {
                family: *family,
                finding_count: saturating_u32(family_findings.len()),
                contributing_finding_count: saturating_u32(contributors.len()),
                strongest_severity,
            }
        })
        .collect();

    let band = match score {
        0 => SuspicionBand::NoStrongIndicators,
        1..=2 => SuspicionBand::Review,
        6.. if scoring_families >= 2 => SuspicionBand::HighSuspicion,
        _ => SuspicionBand::Suspicious,
    };
    active.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| right.confidence.value().total_cmp(&left.confidence.value()))
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.id.cmp(&right.id))
    });
    let top_findings = active
        .into_iter()
        .take(QUICK_CHECK_TOP_FINDINGS_LIMIT)
        .map(|finding| QuickCheckTopFinding {
            finding_id: finding.id.clone(),
            title: finding.title.clone(),
            category: finding.category.clone(),
            severity: finding.severity,
            evidence_family: finding_family(finding),
        })
        .collect();

    QuickCheck {
        policy_version: QUICK_CHECK_POLICY_VERSION.to_owned(),
        policy_sha256: format!("{:x}", Sha256::digest(QUICK_CHECK_POLICY_SOURCE.as_bytes())),
        band,
        finding_counts: counts,
        top_findings,
        evidence_families,
        statement: QUICK_CHECK_STATEMENT.to_owned(),
    }
}

fn finding_family(finding: &Finding) -> QuickCheckEvidenceFamily {
    if finding.rule_id.starts_with("yara:") || finding.category == "yara_match" {
        QuickCheckEvidenceFamily::Yara
    } else if finding.rule_id.starts_with("TF-CAP-") || finding.rule_id.starts_with("TF-IMP-") {
        QuickCheckEvidenceFamily::Capability
    } else if finding.rule_id.starts_with("TF-IND-") || finding.category.contains("indicator") {
        QuickCheckEvidenceFamily::Indicator
    } else if finding.rule_id.starts_with("TF-SIG-") || finding.category == "authenticode" {
        QuickCheckEvidenceFamily::SignatureIntegrity
    } else if finding.rule_id.starts_with("TF-DOTNET-")
        || finding.rule_id.starts_with("TF-PARSE-")
        || matches!(
            finding.rule_id.as_str(),
            "TF-PE-005" | "TF-PE-006" | "TF-PE-007"
        )
        || matches!(
            finding.category.as_str(),
            "analysis_coverage"
                | "analysis_quality"
                | "load_config"
                | "manifest"
                | "debug_metadata"
                | "runtime_context"
        )
    {
        QuickCheckEvidenceFamily::MetadataAnomaly
    } else {
        QuickCheckEvidenceFamily::Structure
    }
}

fn yara_correlation_keys(
    finding: &Finding,
    links_by_finding: &BTreeMap<&str, Vec<&str>>,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for evidence_id in links_by_finding
        .get(finding.id.as_str())
        .into_iter()
        .flatten()
    {
        let Some(item) = evidence_by_id.get(evidence_id) else {
            continue;
        };
        if item.kind != "yara.match" {
            continue;
        }
        if let Some(metadata) = item.value.get("metadata") {
            for field in [
                "category",
                "traceforge_category",
                "correlates_with",
                "traceforge_rule_id",
            ] {
                if let Some(value) = metadata.get(field) {
                    collect_correlation_values(value, &mut keys);
                }
            }
        }
        if let Some(tags) = item.value.get("tags") {
            collect_correlation_values(tags, &mut keys);
        }
    }
    keys
}

fn collect_correlation_values(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            let value = normalize_correlation_key(value);
            if !value.is_empty() {
                output.insert(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_correlation_values(value, output);
            }
        }
        _ => {}
    }
}

fn normalize_correlation_key(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| match character {
            ' ' | '-' => '_',
            _ => character,
        })
        .collect()
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Contextual => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
    }
}

const fn severity_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Contextual => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 4,
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Returns the complete built-in catalog in stable rule-ID order.
#[must_use]
pub fn rule_catalog() -> Vec<RuleRecord> {
    let mut catalog = RULES.iter().map(rule_record).collect::<Vec<_>>();
    catalog.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    catalog
}

/// Evaluates one completed run. Input order does not affect output or identifiers.
#[must_use]
pub fn evaluate(
    analysis_run_id: &AnalysisRunId,
    artifact_id: &ArtifactId,
    evidence: &[Evidence],
) -> FindingSet {
    let mut ordered = evidence.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));
    let mut output = FindingSet {
        rules: rule_catalog(),
        ..FindingSet::default()
    };

    let mut rules = RULES.iter().collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule.id);
    for rule in rules {
        let mut links = matching_evidence(rule.id, &ordered);
        links.sort_by(|left, right| left.0.id.cmp(&right.0.id));
        if links.is_empty() {
            continue;
        }
        let finding_id = finding_id(analysis_run_id, artifact_id, rule, &links);
        let evidence_links = links
            .into_iter()
            .map(|(evidence, role)| FindingEvidence {
                finding_id: finding_id.clone(),
                evidence_id: evidence.id.clone(),
                role,
            })
            .collect::<Vec<_>>();
        let finding = Finding {
            id: finding_id.clone(),
            analysis_run_id: analysis_run_id.clone(),
            artifact_id: artifact_id.clone(),
            rule_id: rule.id.to_owned(),
            rule_version: ENGINE_VERSION.to_owned(),
            title: rule.title.to_owned(),
            category: rule.category.to_owned(),
            severity: rule.severity,
            confidence: Confidence::new(rule.confidence).expect("static confidence is valid"),
            confidence_band: confidence_band(rule.confidence),
            explanation_template_id: rule.template.to_owned(),
            state: FindingState::New,
        };
        output.explanations.push(FindingExplanation {
            finding_id: finding_id.clone(),
            template_id: rule.template.to_owned(),
            observation: rule.observation.to_owned(),
            why_it_matters: rule.why.to_owned(),
            limitations: rule.limitations.to_owned(),
            supporting_evidence: evidence_links.clone(),
        });
        output
            .attack_mappings
            .extend(attack_mappings(rule.id).into_iter().map(|mapping| {
                FindingExplanationAttackMapping {
                    finding_id: finding_id.clone(),
                    mapping,
                }
            }));
        output.findings.push(finding);
        output.evidence_links.extend(evidence_links);
    }
    output
}

fn matching_evidence<'a>(
    rule_id: &str,
    evidence: &[&'a Evidence],
) -> Vec<(&'a Evidence, EvidenceRole)> {
    match rule_id {
        "TF-PE-003" => return entry_point_links(evidence),
        "TF-CAP-001" => {
            return import_combination(evidence, REMOTE_MEMORY_APIS, REMOTE_EXECUTION_APIS);
        }
        "TF-CAP-002" => {
            return import_combination(evidence, PROCESS_ACCESS_APIS, &["minidumpwritedump"]);
        }
        "TF-CAP-003" => {
            return import_combination(evidence, SERVICE_MANAGER_APIS, SERVICE_CREATE_APIS);
        }
        "TF-CAP-004" => {
            return import_indicator_combination(evidence, REGISTRY_WRITE_APIS, run_key_text);
        }
        "TF-CAP-005" => return network_execution_links(evidence),
        "TF-CAP-006" => {
            return import_combination(evidence, DIRECT_DEBUG_CHECK_APIS, LOW_LEVEL_DEBUG_APIS);
        }
        "TF-CAP-008" => return command_execution_links(evidence),
        "TF-CAP-009" => {
            return import_combination(evidence, LIBRARY_LOAD_APIS, SYMBOL_RESOLUTION_APIS);
        }
        "TF-CAP-010" => return packed_context_links(evidence),
        _ => {}
    }
    evidence
        .iter()
        .filter_map(|item| {
            let role = match rule_id {
                "TF-PE-001" if high_entropy_section(item) => EvidenceRole::Supports,
                "TF-PE-002" if suspicious_section_name(item) => EvidenceRole::Supports,
                "TF-IMP-001" if risky_import(item, PROCESS_APIS) => EvidenceRole::Supports,
                "TF-IMP-002" if risky_import(item, CREDENTIAL_APIS) => EvidenceRole::Supports,
                "TF-IMP-003" if risky_import(item, PERSISTENCE_APIS) => EvidenceRole::Supports,
                "TF-IMP-004" if risky_import(item, NETWORK_EXEC_APIS) => EvidenceRole::Supports,
                "TF-CAP-007" if risky_import(item, ANTI_DEBUG_APIS) => EvidenceRole::Context,
                "TF-PE-004" if tls_callback(item) => EvidenceRole::Supports,
                "TF-SIG-001" if authenticode_missing(item) => EvidenceRole::Context,
                "TF-SIG-002" if authenticode_malformed(item) => EvidenceRole::Supports,
                "TF-SIG-003" if authenticode_invalid(item) => EvidenceRole::Supports,
                "TF-IND-001" if indicator(item, "command", command_text) => EvidenceRole::Supports,
                "TF-IND-002" if indicator(item, "url", url_text) => EvidenceRole::Supports,
                "TF-IND-003" if indicator(item, "registry", registry_text) => {
                    EvidenceRole::Supports
                }
                "TF-IND-004" if indicator(item, "path", path_text) => EvidenceRole::Supports,
                "TF-DOTNET-001" if dotnet_context(item) => EvidenceRole::Context,
                "TF-PE-005" if mitigation_gap(item) => EvidenceRole::Context,
                "TF-PE-006" if elevated_manifest(item) => EvidenceRole::Context,
                "TF-PE-007" if debug_path(item) => EvidenceRole::Context,
                "TF-PARSE-001" if parser_limit(item) => EvidenceRole::Context,
                "TF-PARSE-002" if parser_anomaly(item) => EvidenceRole::Supports,
                _ => return None,
            };
            Some((*item, role))
        })
        .collect()
}

fn high_entropy_section(evidence: &Evidence) -> bool {
    if evidence.kind != "pe.section" {
        return false;
    }
    let entropy = evidence.value.get("entropy").and_then(Value::as_f64);
    let characteristics = evidence
        .value
        .get("characteristics")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let raw_size = evidence
        .value
        .get("raw_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    entropy.is_some_and(|value| value >= HIGH_ENTROPY_THRESHOLD)
        && meets_minimum(raw_size, HIGH_ENTROPY_MIN_SECTION_SIZE_BYTES)
        && characteristics & (EXECUTABLE_SECTION_MASK | WRITABLE_SECTION_MASK) != 0
}

const fn meets_minimum(value: u64, minimum: u64) -> bool {
    value >= minimum
}

fn suspicious_section_name(evidence: &Evidence) -> bool {
    const NAMES: &[&str] = &[
        ".aspack", ".packed", ".petite", ".themida", "aspack", "mpress1", "mpress2", "upx0",
        "upx1", "upx2",
    ];
    evidence.kind == "pe.section"
        && evidence
            .value
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| NAMES.contains(&name.to_ascii_lowercase().as_str()))
}

fn entry_point_links<'a>(evidence: &[&'a Evidence]) -> Vec<(&'a Evidence, EvidenceRole)> {
    if let Some(explicit) = evidence.iter().find(|item| {
        item.kind == "pe.entry_point"
            && (bool_field(&item.value, "section_mismatch")
                || item.value.get("section_executable") == Some(&Value::Bool(false)))
    }) {
        return vec![(*explicit, EvidenceRole::Supports)];
    }
    let Some(header) = evidence.iter().find(|item| item.kind == "pe.header") else {
        return Vec::new();
    };
    let Some(entry_point) = header
        .value
        .get("entry_point_rva")
        .and_then(Value::as_u64)
        .filter(|rva| *rva != 0)
    else {
        return Vec::new();
    };
    let containing = evidence.iter().find(|item| {
        if item.kind != "pe.section" {
            return false;
        }
        let start = item.value.get("virtual_address").and_then(Value::as_u64);
        let size = ["virtual_size", "raw_size"]
            .iter()
            .filter_map(|key| item.value.get(*key).and_then(Value::as_u64))
            .max();
        start.zip(size).is_some_and(|(start, size)| {
            entry_point >= start && entry_point < start.saturating_add(size)
        })
    });
    match containing {
        Some(section)
            if section
                .value
                .get("characteristics")
                .and_then(Value::as_u64)
                .is_some_and(|flags| flags & EXECUTABLE_SECTION_MASK == 0) =>
        {
            vec![
                (*header, EvidenceRole::Context),
                (*section, EvidenceRole::Supports),
            ]
        }
        None => vec![(*header, EvidenceRole::Supports)],
        _ => Vec::new(),
    }
}

const PROCESS_APIS: &[&str] = &[
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
    "virtualallocex",
    "writeprocessmemory",
    "rtlcreateuserthread",
];
const REMOTE_MEMORY_APIS: &[&str] = &[
    "virtualallocex",
    "virtualprotectex",
    "writeprocessmemory",
    "ntallocatevirtualmemory",
    "ntwritevirtualmemory",
    "mapviewoffile2",
];
const REMOTE_EXECUTION_APIS: &[&str] = &[
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
    "rtlcreateuserthread",
];
const PROCESS_ACCESS_APIS: &[&str] = &["openprocess", "ntopenprocess"];
const CREDENTIAL_APIS: &[&str] = &[
    "cryptunprotectdata",
    "credread",
    "credenumerate",
    "lsaenumeratelogonSessions",
    "lsaretrieveprivatedata",
    "minidumpwritedump",
    "samiconnect",
    "samropendomain",
    "vaultenumerateitems",
    "vaultenumeratevaults",
    "vaultgetitem",
];
const PERSISTENCE_APIS: &[&str] = &[
    "createservice",
    "changeserviceconfig",
    "schtasks",
    "regcreatekey",
    "regsetvalue",
    "setwindowsHookex",
];
const SERVICE_MANAGER_APIS: &[&str] = &["openscmanager"];
const SERVICE_CREATE_APIS: &[&str] = &["createservice"];
const REGISTRY_WRITE_APIS: &[&str] = &[
    "regcreatekey",
    "regcreatekeyex",
    "regsetvalue",
    "regsetvalueex",
];
const NETWORK_EXEC_APIS: &[&str] = &[
    "urldownloadtofile",
    "internetopenurl",
    "internetreadfile",
    "httpopenrequest",
    "winhttpopen",
    "winhttpreceiveresponse",
    "winhttpreaddata",
    "winhttpsendrequest",
    "qt:qnetworkaccessmanager::get",
];
const EXECUTION_APIS: &[&str] = &[
    "createprocess",
    "shellexecute",
    "winexec",
    "system",
    "_wsystem",
    "qt:qprocess::startdetached",
];
const DIRECT_DEBUG_CHECK_APIS: &[&str] = &["isdebuggerpresent", "checkremotedebuggerpresent"];
const LOW_LEVEL_DEBUG_APIS: &[&str] = &[
    "ntqueryinformationprocess",
    "ntsetinformationthread",
    "outputdebugstring",
];
const ANTI_DEBUG_APIS: &[&str] = &[
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "ntsetinformationthread",
    "outputdebugstring",
];
const LIBRARY_LOAD_APIS: &[&str] = &["loadlibrary", "loadlibraryex", "ldrloaddll"];
const SYMBOL_RESOLUTION_APIS: &[&str] = &["getprocaddress", "ldrgetprocedureaddress"];

fn risky_import(evidence: &Evidence, names: &[&str]) -> bool {
    if !matches!(
        evidence.kind.as_str(),
        "pe.import" | "pe.delay_import" | "pe.imports" | "pe.imported_function"
    ) {
        return false;
    }
    json_has_api(&evidence.value, names)
}

fn json_has_api(value: &Value, names: &[&str]) -> bool {
    match value {
        Value::String(value) => api_matches(value, names),
        Value::Array(items) => items.iter().any(|item| json_has_api(item, names)),
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "function" | "name" | "symbol" | "imports" | "functions"
            ) && json_has_api(value, names)
        }),
        _ => false,
    }
}

fn api_matches(actual: &str, names: &[&str]) -> bool {
    let actual = actual.to_ascii_lowercase();
    names.iter().any(|name| {
        if let Some(qt) = name.strip_prefix("qt:") {
            let Some((class, method)) = qt.split_once("::") else {
                return false;
            };
            return actual.contains(&format!("?{method}@{class}@"))
                || actual.contains(&format!("{class}::{method}"));
        }
        actual == *name
            || actual
                .strip_suffix('a')
                .or_else(|| actual.strip_suffix('w'))
                .is_some_and(|base| base == *name)
    })
}

fn import_combination<'a>(
    evidence: &[&'a Evidence],
    first: &[&str],
    second: &[&str],
) -> Vec<(&'a Evidence, EvidenceRole)> {
    let first_links = matching_imports(evidence, first);
    let second_links = matching_imports(evidence, second);
    if first_links.is_empty() || second_links.is_empty() {
        return Vec::new();
    }
    exact_links(
        first_links.into_iter().chain(second_links),
        EvidenceRole::Supports,
    )
}

fn matching_imports<'a>(evidence: &[&'a Evidence], names: &[&str]) -> Vec<&'a Evidence> {
    evidence
        .iter()
        .copied()
        .filter(|item| risky_import(item, names))
        .collect()
}

fn import_indicator_combination<'a>(
    evidence: &[&'a Evidence],
    names: &[&str],
    text_predicate: fn(&str) -> bool,
) -> Vec<(&'a Evidence, EvidenceRole)> {
    let imports = matching_imports(evidence, names);
    let indicators = evidence
        .iter()
        .copied()
        .filter(|item| indicator(item, "registry", text_predicate))
        .collect::<Vec<_>>();
    if imports.is_empty() || indicators.is_empty() {
        return Vec::new();
    }
    exact_links(
        imports.into_iter().chain(indicators),
        EvidenceRole::Supports,
    )
}

fn network_execution_links<'a>(evidence: &[&'a Evidence]) -> Vec<(&'a Evidence, EvidenceRole)> {
    let network = matching_imports(evidence, NETWORK_EXEC_APIS);
    let urls = evidence
        .iter()
        .copied()
        .filter(|item| indicator(item, "url", url_text))
        .collect::<Vec<_>>();
    let execution = evidence
        .iter()
        .copied()
        .filter(|item| {
            risky_import(item, EXECUTION_APIS) || indicator(item, "command", command_text)
        })
        .collect::<Vec<_>>();
    if network.is_empty() || execution.is_empty() {
        return Vec::new();
    }
    exact_links(
        network.into_iter().chain(urls).chain(execution),
        EvidenceRole::Supports,
    )
}

fn command_execution_links<'a>(evidence: &[&'a Evidence]) -> Vec<(&'a Evidence, EvidenceRole)> {
    let execution = matching_imports(evidence, EXECUTION_APIS);
    let commands = evidence
        .iter()
        .copied()
        .filter(|item| indicator(item, "command", windows_shell_text))
        .collect::<Vec<_>>();
    if execution.is_empty() || commands.is_empty() {
        return Vec::new();
    }
    exact_links(
        execution.into_iter().chain(commands),
        EvidenceRole::Supports,
    )
}

fn packed_context_links<'a>(evidence: &[&'a Evidence]) -> Vec<(&'a Evidence, EvidenceRole)> {
    let primary = evidence
        .iter()
        .copied()
        .filter(|item| high_entropy_section(item))
        .collect::<Vec<_>>();
    let corroboration = evidence
        .iter()
        .copied()
        .filter(|item| {
            suspicious_section_name(item)
                || item.kind == "pe.overlay"
                    && bool_field(&item.value, "present")
                    && item.value.get("size").and_then(Value::as_u64).unwrap_or(0)
                        >= PACKED_OVERLAY_MIN_SIZE_BYTES
                || item.kind == "pe.resource"
                    && item.value.get("size").and_then(Value::as_u64).unwrap_or(0)
                        >= PACKED_RESOURCE_MIN_SIZE_BYTES
        })
        .collect::<Vec<_>>();
    if primary.is_empty() || corroboration.is_empty() {
        return Vec::new();
    }
    let mut links = exact_links(primary.into_iter(), EvidenceRole::Supports);
    for item in corroboration {
        if let Some(link) = links.iter_mut().find(|link| link.0.id == item.id) {
            link.1 = EvidenceRole::Supports;
        } else {
            links.push((item, EvidenceRole::Context));
        }
    }
    links.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    links
}

fn exact_links<'a>(
    items: impl Iterator<Item = &'a Evidence>,
    role: EvidenceRole,
) -> Vec<(&'a Evidence, EvidenceRole)> {
    let mut links = items.map(|item| (item, role)).collect::<Vec<_>>();
    links.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    links.dedup_by(|left, right| left.0.id == right.0.id);
    links
}

fn tls_callback(evidence: &Evidence) -> bool {
    matches!(
        evidence.kind.as_str(),
        "pe.tls_callback" | "pe.tls_callbacks"
    ) && (evidence.kind == "pe.tls_callback" && evidence.value.is_object()
        || evidence.value.as_u64().is_some_and(|count| count > 0)
        || evidence
            .value
            .as_array()
            .is_some_and(|items| !items.is_empty())
        || evidence.value.as_object().is_some_and(|object| {
            object
                .get("count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0)
                || object
                    .get("callbacks")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())
                || object.get("present") == Some(&Value::Bool(true))
        }))
}

fn authenticode_missing(evidence: &Evidence) -> bool {
    evidence.kind == "pe.authenticode"
        && (evidence.value.get("present") == Some(&Value::Bool(false))
            || string_field(&evidence.value, "structural_status") == Some("absent"))
}

fn authenticode_malformed(evidence: &Evidence) -> bool {
    const STATUSES: &[&str] = &[
        "table_out_of_bounds",
        "truncated_win_certificate_header",
        "invalid_win_certificate_length",
        "malformed_content_info",
        "malformed_signed_data",
        "not_signed_data",
    ];
    if evidence.kind != "pe.authenticode"
        || evidence.value.get("present") != Some(&Value::Bool(true))
    {
        return false;
    }
    string_field(&evidence.value, "structural_status")
        .is_some_and(|status| STATUSES.contains(&status))
        || evidence
            .value
            .get("pkcs7")
            .and_then(|value| string_field(value, "status"))
            .is_some_and(|status| STATUSES.contains(&status))
}

fn indicator(evidence: &Evidence, expected: &str, predicate: fn(&str) -> bool) -> bool {
    let kind_matches = evidence.kind == format!("indicator.{expected}")
        || evidence.kind == format!("pe.indicator.{expected}")
        || matches!(evidence.kind.as_str(), "indicator" | "pe.indicator")
            && evidence
                .value
                .get("kind")
                .or_else(|| evidence.value.get("category"))
                .and_then(Value::as_str)
                .is_some_and(|kind| indicator_category_matches(kind, expected));
    kind_matches && indicator_text(&evidence.value).is_some_and(predicate)
}

fn indicator_category_matches(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || matches!(
            (actual, expected),
            ("registry_key", "registry") | ("windows_path", "path")
        )
}

fn indicator_text(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        ["value", "text", "indicator"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
    })
}

fn command_text(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "-encodedcommand",
    ]
    .iter()
    .any(|term| value.contains(term))
}

fn windows_shell_text(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("cmd.exe") || value.contains("%comspec%")
}

fn url_text(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    ["http://", "https://", "ftp://"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn registry_text(value: &str) -> bool {
    let value = value.replace('/', "\\").to_ascii_lowercase();
    value.contains("\\currentversion\\run")
        || value.contains("\\currentversion\\runonce")
        || value.contains("\\system\\currentcontrolset\\services\\")
}

fn run_key_text(value: &str) -> bool {
    let value = value.replace('/', "\\").to_ascii_lowercase();
    value.contains("\\currentversion\\run\\")
        || value.ends_with("\\currentversion\\run")
        || value.contains("\\currentversion\\runonce\\")
        || value.ends_with("\\currentversion\\runonce")
}

fn path_text(value: &str) -> bool {
    let value = value.replace('/', "\\").to_ascii_lowercase();
    let writable = ["\\appdata\\", "\\temp\\", "\\tmp\\", "\\startup\\"]
        .iter()
        .any(|part| value.contains(part));
    let executable = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js"]
        .iter()
        .any(|extension| value.contains(extension));
    writable && executable
}

fn dotnet_context(evidence: &Evidence) -> bool {
    matches!(
        evidence.kind.as_str(),
        "pe.clr" | "pe.dotnet" | "pe.dotnet_metadata" | "dotnet.metadata"
    ) && evidence.value.get("present") != Some(&Value::Bool(false))
        && evidence.value != Value::Bool(false)
        && !evidence.value.is_null()
}

fn authenticode_invalid(evidence: &Evidence) -> bool {
    if evidence.kind != "pe.authenticode.verification" {
        return false;
    }
    evidence.value.pointer("/image_digest/matches") == Some(&Value::Bool(false))
        || value_has_status(&evidence.value, &["invalid", "untrusted", "revoked"])
}

fn value_has_status(value: &Value, statuses: &[&str]) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| value_has_status(item, statuses)),
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            key == "status"
                && value
                    .as_str()
                    .is_some_and(|status| statuses.contains(&status))
                || value_has_status(value, statuses)
        }),
        _ => false,
    }
}

fn mitigation_gap(evidence: &Evidence) -> bool {
    evidence.kind == "pe.load_config"
        && evidence
            .value
            .get("mitigations")
            .and_then(Value::as_object)
            .is_some_and(|mitigations| {
                ["aslr", "dep", "cfg_declared", "cfg_instrumented"]
                    .iter()
                    .any(|name| mitigations.get(*name) == Some(&Value::Bool(false)))
            })
}

fn elevated_manifest(evidence: &Evidence) -> bool {
    if evidence.kind != "pe.manifest" {
        return false;
    }
    evidence
        .value
        .get("text")
        .and_then(Value::as_str)
        .is_some_and(|text| {
            let text = text.to_ascii_lowercase();
            text.contains("requireadministrator") || text.contains("highestavailable")
        })
}

fn debug_path(evidence: &Evidence) -> bool {
    evidence.kind == "pe.debug"
        && evidence
            .value
            .pointer("/codeview/pdb_path")
            .and_then(Value::as_str)
            .is_some_and(|path| !path.is_empty())
}

fn parser_limit(evidence: &Evidence) -> bool {
    matches!(
        evidence.kind.as_str(),
        "parser.limit" | "analysis.limit" | "parser.truncation"
    ) || matches!(evidence.kind.as_str(), "parser.status" | "analysis.status")
        && (bool_field(&evidence.value, "truncated")
            || bool_field(&evidence.value, "limit_reached"))
        || evidence.kind == "pe.string" && bool_field(&evidence.value, "truncated")
        || evidence.kind == "pe.authenticode"
            && string_field(&evidence.value, "structural_status")
                .is_some_and(|status| status.ends_with("_limit"))
}

fn parser_anomaly(evidence: &Evidence) -> bool {
    matches!(
        evidence.kind.as_str(),
        "parser.anomaly" | "analysis.anomaly" | "pe.anomaly"
    ) || authenticode_malformed(evidence)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key) == Some(&Value::Bool(true))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn confidence_band(confidence: f32) -> ConfidenceBand {
    if f64::from(confidence) >= CONFIDENCE_STRONG_MIN {
        ConfidenceBand::Strong
    } else if f64::from(confidence) >= CONFIDENCE_MODERATE_MIN {
        ConfidenceBand::Moderate
    } else {
        ConfidenceBand::Tentative
    }
}

fn rule_record(rule: &Rule) -> RuleRecord {
    let mappings = attack_mappings(rule.id)
        .into_iter()
        .map(|mapping| {
            format!(
                "{}|{}|{}",
                mapping.technique_id, mapping.technique_name, mapping.tactic
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let parameters = serde_json::to_string(&rule_parameters(rule.id))
        .expect("rule parameters contain only serializable values");
    let source = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{:.2}\n{}\n{}",
        rule.id,
        rule.title,
        rule.category,
        rule.template,
        rule.observation,
        rule.why,
        rule.limitations,
        rule.severity.as_str(),
        rule.confidence,
        mappings,
        parameters,
    );
    let sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
    RuleRecord {
        id: deterministic_id::<RuleRecordId>(&[
            ENGINE_NAME.as_bytes(),
            rule.id.as_bytes(),
            ENGINE_VERSION.as_bytes(),
        ]),
        engine: ENGINE_NAME.to_owned(),
        rule_id: rule.id.to_owned(),
        version: ENGINE_VERSION.to_owned(),
        source,
        license: "Apache-2.0".to_owned(),
        sha256,
        enabled: true,
    }
}

fn attack_mappings(rule_id: &str) -> Vec<AttackMapping> {
    let definitions: &[(&str, &str, &str)] = match rule_id {
        "TF-IMP-001" | "TF-CAP-001" => &[("T1055", "Process Injection", "Defense Evasion")],
        "TF-CAP-002" => &[("T1003", "OS Credential Dumping", "Credential Access")],
        "TF-CAP-003" => &[(
            "T1543.003",
            "Create or Modify System Process: Windows Service",
            "Persistence",
        )],
        "TF-CAP-004" => &[(
            "T1547.001",
            "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "Persistence",
        )],
        "TF-CAP-005" => &[("T1105", "Ingress Tool Transfer", "Command and Control")],
        "TF-CAP-006" | "TF-CAP-007" => &[("T1622", "Debugger Evasion", "Defense Evasion")],
        "TF-CAP-008" => &[(
            "T1059.003",
            "Command and Scripting Interpreter: Windows Command Shell",
            "Execution",
        )],
        "TF-CAP-009" => &[(
            "T1027.007",
            "Obfuscated Files or Information: Dynamic API Resolution",
            "Defense Evasion",
        )],
        "TF-CAP-010" => &[(
            "T1027",
            "Obfuscated Files or Information",
            "Defense Evasion",
        )],
        _ => &[],
    };
    definitions
        .iter()
        .map(|(technique_id, technique_name, tactic)| AttackMapping {
            technique_id: (*technique_id).to_owned(),
            technique_name: (*technique_name).to_owned(),
            tactic: (*tactic).to_owned(),
        })
        .collect()
}

fn finding_id(
    analysis_run_id: &AnalysisRunId,
    artifact_id: &ArtifactId,
    rule: &Rule,
    links: &[(&Evidence, EvidenceRole)],
) -> FindingId {
    let mut parts = vec![
        analysis_run_id.as_str().as_bytes(),
        artifact_id.as_str().as_bytes(),
        rule.id.as_bytes(),
        ENGINE_VERSION.as_bytes(),
    ];
    parts.extend(
        links
            .iter()
            .map(|(evidence, _)| evidence.id.as_str().as_bytes()),
    );
    deterministic_id(&parts)
}

fn deterministic_id<T>(parts: &[&[u8]]) -> T
where
    T: From<Ulid>,
{
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("SHA-256 prefix has fixed length");
    T::from(Ulid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;
    use tf_model::{EvidenceId, ObservationClass, ProvenanceId};

    use super::*;

    fn evidence(artifact_id: &ArtifactId, kind: &str, value: Value) -> Evidence {
        Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact_id.clone(),
            provenance_id: ProvenanceId::new(),
            kind: kind.to_owned(),
            class: ObservationClass::Observed,
            locator: BTreeMap::new(),
            value,
            preview_text: None,
        }
    }

    fn finding(
        run_id: &AnalysisRunId,
        artifact_id: &ArtifactId,
        rule_id: &str,
        category: &str,
        severity: Severity,
    ) -> Finding {
        Finding {
            id: FindingId::new(),
            analysis_run_id: run_id.clone(),
            artifact_id: artifact_id.clone(),
            rule_id: rule_id.to_owned(),
            rule_version: "test".to_owned(),
            title: format!("Plain finding for {rule_id}"),
            category: category.to_owned(),
            severity,
            confidence: Confidence::new(0.8).expect("test confidence"),
            confidence_band: ConfidenceBand::Moderate,
            explanation_template_id: "test".to_owned(),
            state: FindingState::New,
        }
    }

    #[test]
    fn quick_check_benign_and_empty_have_no_strong_indicators() {
        let empty = quick_check(&[], &[], &[]);
        assert_eq!(empty.band, SuspicionBand::NoStrongIndicators);
        assert_eq!(empty.finding_counts.total, 0);
        assert!(empty.top_findings.is_empty());
        assert_eq!(empty.evidence_families.len(), 6);
        assert!(empty.statement.contains("not a malware or safety verdict"));

        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let contextual = finding(
            &run_id,
            &artifact_id,
            "TF-SIG-001",
            "authenticode",
            Severity::Contextual,
        );
        let benign = quick_check(&[contextual], &[], &[]);
        assert_eq!(benign.band, SuspicionBand::NoStrongIndicators);
        assert_eq!(benign.finding_counts.contextual, 1);
        assert_eq!(benign.top_findings.len(), 1);
    }

    #[test]
    fn quick_check_combines_independent_signals_as_suspicious() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let findings = [
            finding(
                &run_id,
                &artifact_id,
                "TF-PE-003",
                "entry_point",
                Severity::Medium,
            ),
            finding(
                &run_id,
                &artifact_id,
                "TF-IND-001",
                "command_indicator",
                Severity::Low,
            ),
        ];
        let summary = quick_check(&findings, &[], &[]);
        assert_eq!(summary.band, SuspicionBand::Suspicious);
        assert_eq!(summary.finding_counts.medium, 1);
        assert_eq!(summary.finding_counts.low, 1);
    }

    #[test]
    fn quick_check_requires_independent_families_for_high_suspicion() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let findings = [
            finding(
                &run_id,
                &artifact_id,
                "TF-CAP-001",
                "process_injection",
                Severity::High,
            ),
            finding(
                &run_id,
                &artifact_id,
                "TF-PE-003",
                "entry_point",
                Severity::Medium,
            ),
        ];
        assert_eq!(
            quick_check(&findings, &[], &[]).band,
            SuspicionBand::HighSuspicion
        );
    }

    #[test]
    fn quick_check_does_not_double_count_explicit_yara_correlation() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let built_in = finding(
            &run_id,
            &artifact_id,
            "TF-CAP-001",
            "process_injection",
            Severity::High,
        );
        let yara = finding(
            &run_id,
            &artifact_id,
            "yara:pack:default:InjectionContext",
            "yara_match",
            Severity::High,
        );
        let match_evidence = evidence(
            &artifact_id,
            "yara.match",
            json!({
                "metadata": {"traceforge_category": "process-injection"},
                "tags": ["static_context"]
            }),
        );
        let link = FindingEvidence {
            finding_id: yara.id.clone(),
            evidence_id: match_evidence.id.clone(),
            role: EvidenceRole::Context,
        };
        let summary = quick_check(&[built_in, yara], &[link], &[match_evidence]);
        assert_eq!(summary.band, SuspicionBand::Suspicious);
        assert_eq!(summary.finding_counts.high, 2);
        let yara_family = summary
            .evidence_families
            .iter()
            .find(|family| family.family == QuickCheckEvidenceFamily::Yara)
            .expect("YARA family");
        assert_eq!(yara_family.finding_count, 1);
        assert_eq!(yara_family.contributing_finding_count, 0);
        assert_eq!(yara_family.strongest_severity, None);
    }

    #[test]
    fn quick_check_is_order_independent() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let first = finding(
            &run_id,
            &artifact_id,
            "TF-CAP-001",
            "process_injection",
            Severity::High,
        );
        let second = finding(
            &run_id,
            &artifact_id,
            "TF-PE-003",
            "entry_point",
            Severity::Medium,
        );
        let forward = quick_check(&[first.clone(), second.clone()], &[], &[]);
        let reverse = quick_check(&[second, first], &[], &[]);
        assert_eq!(forward, reverse);
    }

    #[test]
    fn evaluation_is_order_independent_and_links_only_matching_evidence() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let section = evidence(
            &artifact_id,
            "pe.section",
            json!({"name":"UPX0","entropy":7.8,"characteristics":0x60000020_u64}),
        );
        let benign = evidence(
            &artifact_id,
            "pe.section",
            json!({"name":".text","entropy":6.1,"characteristics":0x60000020_u64}),
        );
        let first = evaluate(&run_id, &artifact_id, &[section.clone(), benign.clone()]);
        let second = evaluate(&run_id, &artifact_id, &[benign, section.clone()]);

        assert_eq!(first, second);
        assert_eq!(first.findings.len(), 3);
        assert!(
            first
                .evidence_links
                .iter()
                .all(|link| link.evidence_id == section.id)
        );
        assert!(first.explanations.iter().all(|explanation| {
            explanation.supporting_evidence
                == first
                    .evidence_links
                    .iter()
                    .filter(|link| link.finding_id == explanation.finding_id)
                    .cloned()
                    .collect::<Vec<_>>()
        }));
    }

    #[test]
    fn entry_point_has_exact_context_and_support_roles() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let header = evidence(&artifact_id, "pe.header", json!({"entry_point_rva":4096}));
        let section = evidence(
            &artifact_id,
            "pe.section",
            json!({"virtual_address":4096,"virtual_size":512,"raw_size":512,"characteristics":0x40000040_u64}),
        );
        let output = evaluate(&run_id, &artifact_id, &[section.clone(), header.clone()]);
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id == "TF-PE-003")
            .expect("entry-point finding");
        let links = output
            .evidence_links
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 2);
        assert!(
            links
                .iter()
                .any(|link| link.evidence_id == header.id && link.role == EvidenceRole::Context)
        );
        assert!(
            links
                .iter()
                .any(|link| link.evidence_id == section.id && link.role == EvidenceRole::Supports)
        );
    }

    #[test]
    fn catalog_is_stable_complete_and_non_verdict() {
        let catalog = rule_catalog();
        assert_eq!(catalog.len(), RULES.len());
        assert_eq!(
            catalog
                .iter()
                .map(|rule| rule.rule_id.as_str())
                .collect::<Vec<_>>(),
            [
                "TF-CAP-001",
                "TF-CAP-002",
                "TF-CAP-003",
                "TF-CAP-004",
                "TF-CAP-005",
                "TF-CAP-006",
                "TF-CAP-007",
                "TF-CAP-008",
                "TF-CAP-009",
                "TF-CAP-010",
                "TF-DOTNET-001",
                "TF-IMP-001",
                "TF-IMP-002",
                "TF-IMP-003",
                "TF-IMP-004",
                "TF-IND-001",
                "TF-IND-002",
                "TF-IND-003",
                "TF-IND-004",
                "TF-PARSE-001",
                "TF-PARSE-002",
                "TF-PE-001",
                "TF-PE-002",
                "TF-PE-003",
                "TF-PE-004",
                "TF-PE-005",
                "TF-PE-006",
                "TF-PE-007",
                "TF-SIG-001",
                "TF-SIG-002",
                "TF-SIG-003",
            ]
        );
        assert!(
            catalog
                .windows(2)
                .all(|pair| pair[0].rule_id < pair[1].rule_id)
        );
        assert!(catalog.iter().all(|rule| rule.sha256.len() == 64));
        let language = RULES
            .iter()
            .map(|rule| {
                format!("{} {} {}", rule.title, rule.observation, rule.limitations)
                    .to_ascii_lowercase()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<String>();
        assert!(!language.contains("malicious"));
        assert!(!language.contains(" is safe"));
    }

    #[test]
    fn rule_engine_parameters_are_nonempty_and_deterministic() {
        let params = rule_engine_parameters();
        assert!(
            !params.is_empty(),
            "rule_engine_parameters must not be empty"
        );
        assert_eq!(
            params,
            rule_engine_parameters(),
            "must be deterministic across calls"
        );

        let keys: Vec<_> = params.keys().cloned().collect();
        assert!(keys.contains(&"entropy_threshold_bits_per_byte".to_owned()));
        assert!(keys.contains(&"confidence_band_moderate_min".to_owned()));
        assert!(keys.contains(&"packed_resource_min_size_bytes".to_owned()));
        assert!(keys.contains(&"engine_version".to_owned()));
    }

    #[test]
    fn rule_engine_parameters_change_hash_when_value_differs() {
        let original = rule_engine_parameters();
        let original_json = serde_json::to_string(&original).unwrap();
        let original_hash = format!("{:x}", Sha256::digest(original_json.as_bytes()));

        let mut modified = original.clone();
        let entry = modified
            .get_mut("entropy_threshold_bits_per_byte")
            .expect("key exists");
        *entry = Value::from(9.9);

        let modified_json = serde_json::to_string(&modified).unwrap();
        let modified_hash = format!("{:x}", Sha256::digest(modified_json.as_bytes()));

        assert_ne!(
            original_hash, modified_hash,
            "changing a parameter must change the hash"
        );
    }

    #[test]
    fn numeric_rule_parameters_are_exported_and_hashed_in_canonical_source() {
        let parameters = rule_parameters("TF-CAP-010");
        assert_eq!(
            parameters["entropy_threshold_bits_per_byte"],
            HIGH_ENTROPY_THRESHOLD
        );
        assert_eq!(
            parameters["entropy_min_section_size_bytes"],
            HIGH_ENTROPY_MIN_SECTION_SIZE_BYTES
        );
        assert_eq!(
            parameters["packed_resource_min_size_bytes"],
            PACKED_RESOURCE_MIN_SIZE_BYTES
        );
        let canonical = serde_json::to_string(&parameters).expect("parameters");
        let record = rule_catalog()
            .into_iter()
            .find(|record| record.rule_id == "TF-CAP-010")
            .expect("packed-context rule");
        assert!(record.source.ends_with(&canonical));
        assert_eq!(
            record.sha256,
            format!("{:x}", Sha256::digest(record.source.as_bytes()))
        );
    }

    #[test]
    fn corroborated_injection_outranks_singleton_and_accepts_delayed_imports() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let memory = evidence(
            &artifact_id,
            "pe.import",
            json!({"dll":"kernel32.dll","function":"WriteProcessMemory"}),
        );
        let singleton = evaluate(&run_id, &artifact_id, std::slice::from_ref(&memory));
        assert!(singleton.findings.iter().any(|finding| {
            finding.rule_id == "TF-IMP-001" && finding.severity == Severity::Low
        }));
        assert!(
            !singleton
                .findings
                .iter()
                .any(|finding| finding.rule_id == "TF-CAP-001")
        );

        let execution = evidence(
            &artifact_id,
            "pe.delay_import",
            json!({"dll":"kernel32.dll","function":"CreateRemoteThread"}),
        );
        let combined = evaluate(&run_id, &artifact_id, &[execution.clone(), memory.clone()]);
        let finding = combined
            .findings
            .iter()
            .find(|finding| finding.rule_id == "TF-CAP-001")
            .expect("combination finding");
        assert_eq!(finding.severity, Severity::High);
        let links = combined
            .evidence_links
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 2);
        assert!(links.iter().all(|link| link.role == EvidenceRole::Supports));
        assert!(links.iter().any(|link| link.evidence_id == memory.id));
        assert!(links.iter().any(|link| link.evidence_id == execution.id));
        assert!(combined.attack_mappings.iter().any(|record| {
            record.finding_id == finding.id && record.mapping.technique_id == "T1055"
        }));
    }

    #[test]
    fn service_creation_links_only_the_required_api_pair() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let manager = evidence(
            &artifact_id,
            "pe.delay_import",
            json!({"function":"OpenSCManagerW"}),
        );
        let service = evidence(
            &artifact_id,
            "pe.import",
            json!({"function":"CreateServiceW"}),
        );
        let unrelated = evidence(&artifact_id, "pe.manifest", json!({"text":"<assembly/>"}));
        let output = evaluate(
            &run_id,
            &artifact_id,
            &[unrelated.clone(), manager.clone(), service.clone()],
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id == "TF-CAP-003")
            .expect("service finding");
        let links = output
            .evidence_links
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 2);
        assert!(links.iter().all(|link| link.role == EvidenceRole::Supports));
        assert!(links.iter().any(|link| link.evidence_id == manager.id));
        assert!(links.iter().any(|link| link.evidence_id == service.id));
        assert!(!links.iter().any(|link| link.evidence_id == unrelated.id));
    }

    #[test]
    fn qt_network_and_process_symbols_correlate_with_a_url() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let network = evidence(
            &artifact_id,
            "pe.import",
            json!({"dll":"Qt5Network.dll","function":"?get@QNetworkAccessManager@@QEAAPEAVQNetworkReply@@AEBVQNetworkRequest@@@Z"}),
        );
        let execution = evidence(
            &artifact_id,
            "pe.import",
            json!({"dll":"Qt5Core.dll","function":"?startDetached@QProcess@@SA_NAEBVQString@@@Z"}),
        );
        let url = evidence(
            &artifact_id,
            "pe.indicator",
            json!({"category":"url","value":"https://updates.example.test/version.json"}),
        );
        let output = evaluate(
            &run_id,
            &artifact_id,
            &[network.clone(), execution.clone(), url.clone()],
        );
        let finding = output
            .findings
            .iter()
            .find(|finding| finding.rule_id == "TF-CAP-005")
            .expect("Qt network/execution finding");
        let linked = output
            .evidence_links
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .map(|link| &link.evidence_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            linked,
            BTreeSet::from([&network.id, &execution.id, &url.id])
        );
    }

    #[test]
    fn v2_structure_and_signature_context_is_consumed_without_verdicts() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![
            evidence(
                &artifact_id,
                "pe.load_config",
                json!({"present":true,"mitigations":{"aslr":true,"dep":true,"cfg_declared":false,"cfg_instrumented":false}}),
            ),
            evidence(
                &artifact_id,
                "pe.manifest",
                json!({"text":"<requestedExecutionLevel level=\"requireAdministrator\"/>"}),
            ),
            evidence(
                &artifact_id,
                "pe.debug",
                json!({"codeview":{"format":"rsds","pdb_path":"C:\\build\\demo.pdb"}}),
            ),
            evidence(
                &artifact_id,
                "pe.authenticode.verification",
                json!({"image_digest":{"status":"observed","matches":false},"safe_file_assessment":{"status":"unknown"}}),
            ),
        ];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let ids = output
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        for expected in ["TF-PE-005", "TF-PE-006", "TF-PE-007", "TF-SIG-003"] {
            assert!(ids.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn attack_mappings_are_constrained_and_caveated_static_context() {
        for rule in RULES {
            for mapping in attack_mappings(rule.id) {
                assert!(mapping.technique_id.starts_with('T'));
                assert!(!mapping.technique_name.is_empty());
                assert!(!mapping.tactic.is_empty());
                let limitations = rule.limitations.to_ascii_lowercase();
                assert!(
                    limitations.contains("static"),
                    "{} lacks static caveat",
                    rule.id
                );
                assert!(
                    limitations.contains("execution") || limitations.contains("runtime"),
                    "{} lacks execution caveat",
                    rule.id
                );
                assert!(
                    limitations.contains("attribution"),
                    "{} lacks attribution caveat",
                    rule.id
                );
            }
        }
        assert!(attack_mappings("TF-IMP-002").is_empty());
        assert!(attack_mappings("TF-SIG-003").is_empty());
    }

    #[test]
    fn consumes_analysis_v1_worker_shapes() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![
            evidence(
                &artifact_id,
                "pe.tls_callback",
                json!({"va":5368713216_u64,"rva":4096}),
            ),
            evidence(
                &artifact_id,
                "pe.clr",
                json!({"present":true,"metadata_present":true}),
            ),
            evidence(
                &artifact_id,
                "pe.authenticode",
                json!({"present":false,"structural_status":"absent"}),
            ),
            evidence(
                &artifact_id,
                "pe.authenticode",
                json!({"present":true,"structural_status":"malformed_content_info"}),
            ),
            evidence(
                &artifact_id,
                "pe.indicator",
                json!({"category":"command","value":"powershell -EncodedCommand AAA"}),
            ),
            evidence(
                &artifact_id,
                "pe.indicator",
                json!({"category":"registry_key","value":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Tool"}),
            ),
            evidence(
                &artifact_id,
                "pe.string",
                json!({"text":"long string","truncated":true}),
            ),
        ];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let rule_ids = output
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();

        for expected in [
            "TF-DOTNET-001",
            "TF-IND-001",
            "TF-IND-003",
            "TF-PARSE-001",
            "TF-PARSE-002",
            "TF-PE-004",
            "TF-SIG-001",
            "TF-SIG-002",
        ] {
            assert!(rule_ids.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn regression_network_and_shellexecute_correlate() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![
            evidence(
                &artifact_id,
                "pe.import",
                json!({"dll":"winhttp.dll","function":"WinHttpOpen"}),
            ),
            evidence(
                &artifact_id,
                "pe.import",
                json!({"dll":"shell32.dll","function":"ShellExecuteA"}),
            ),
        ];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let categories: Vec<_> = output
            .findings
            .iter()
            .map(|f| f.category.as_str())
            .collect();
        assert!(
            categories.contains(&"capability"),
            "network+exec should produce capability finding, got: {categories:?}"
        );
    }

    #[test]
    fn regression_download_only_negative() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![evidence(
            &artifact_id,
            "pe.import",
            json!({"dll":"urlmon.dll","function":"URLDownloadToFileA"}),
        )];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let has_network_exec = output.findings.iter().any(|f| {
            f.title.to_lowercase().contains("network") && f.title.to_lowercase().contains("exec")
        });
        assert!(
            !has_network_exec,
            "download-only should not produce network+exec finding"
        );
    }

    #[test]
    fn regression_shellexecute_only_negative() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![evidence(
            &artifact_id,
            "pe.import",
            json!({"dll":"shell32.dll","function":"ShellExecuteA"}),
        )];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let has_network = output
            .findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("network"));
        assert!(
            !has_network,
            "ShellExecute-only should not produce network finding"
        );
    }

    #[test]
    fn regression_high_entropy_resource_only_negative() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![evidence(
            &artifact_id,
            "pe.section",
            json!({".rsrc":{"entropy":8.5,"raw_size":2048}}),
        )];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let has_capability = output.findings.iter().any(|f| f.category == "capability");
        assert!(
            !has_capability,
            "high-entropy resource only should not produce capability finding"
        );
    }

    #[test]
    fn regression_admin_manifest_only_negative() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![evidence(
            &artifact_id,
            "pe.manifest",
            json!({"text":"<requestedExecutionLevel level=\"requireAdministrator\"/>"}),
        )];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let has_capability = output.findings.iter().any(|f| f.category == "capability");
        assert!(
            !has_capability,
            "admin manifest only should not produce capability finding"
        );
    }

    #[test]
    fn regression_entry_point_high_entropy_finding() {
        let artifact_id = ArtifactId::new();
        let run_id = AnalysisRunId::new();
        let evidence = vec![
            evidence(&artifact_id, "pe.header", json!({"entry_point_rva":4096})),
            evidence(
                &artifact_id,
                "pe.section",
                json!({".text":{"entropy":8.0,"virtual_size":4096,"characteristics":"0xE0000060"}}),
            ),
        ];
        let output = evaluate(&run_id, &artifact_id, &evidence);
        let has_structural = output
            .findings
            .iter()
            .any(|f| f.category == "structural" || f.category == "entry_point");
        assert!(
            has_structural,
            "entry point in high-entropy section should produce structural/entry_point finding"
        );
    }
}
