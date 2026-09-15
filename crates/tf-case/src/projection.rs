use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tf_model::{
    AnalysisRun, AnalysisStatus, Artifact, ArtifactLocation, CaseChronology, CaseGraph, CaseId,
    Confidence, Edge, EdgeId, Entity, EntityEvidence, EntityId, EntityType, EventId, Evidence,
    EvidenceEvent, EvidenceRole, Finding, FindingEvidence, Relationship, TimestampReliability,
};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub(crate) const INVESTIGATION_PROJECTION_VERSION: u32 = 2;

pub(crate) struct ProjectionInput<'a> {
    pub case_id: &'a CaseId,
    pub artifact: &'a Artifact,
    pub locations: &'a [ArtifactLocation],
    pub analysis_run: Option<&'a AnalysisRun>,
    pub run_history: &'a [AnalysisRun],
    pub evidence: &'a [Evidence],
    pub findings: &'a [Finding],
    pub finding_evidence: &'a [FindingEvidence],
    pub finding_history: &'a [Finding],
}

pub(crate) fn build(input: ProjectionInput<'_>) -> (CaseGraph, CaseChronology) {
    let ProjectionInput {
        case_id,
        artifact,
        locations,
        analysis_run,
        run_history,
        evidence,
        findings,
        finding_evidence,
        finding_history,
    } = input;
    let mut builder = GraphBuilder::new(case_id);
    let artifact_id = builder.add_entity(
        EntityType::Artifact,
        artifact.sha256.to_ascii_lowercase(),
        artifact.original_name.clone(),
        BTreeMap::from([
            ("artifact_id".to_owned(), json!(artifact.id)),
            ("kind".to_owned(), json!(artifact.kind)),
            ("md5".to_owned(), json!(artifact.md5)),
            ("sha1".to_owned(), json!(artifact.sha1)),
            ("sha256".to_owned(), json!(artifact.sha256)),
            ("size_bytes".to_owned(), json!(artifact.size_bytes)),
        ]),
        None,
    );

    let mut ordered_evidence = evidence.iter().collect::<Vec<_>>();
    ordered_evidence.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    for item in ordered_evidence {
        match item.kind.as_str() {
            "pe.section" => project_section(&mut builder, &artifact_id, artifact, item),
            "pe.import" | "pe.delay_import" => {
                project_import(&mut builder, &artifact_id, item);
            }
            "pe.export" => project_export(&mut builder, &artifact_id, artifact, item),
            "pe.indicator" => project_indicator(&mut builder, &artifact_id, item),
            "pe.authenticode" => project_authenticode(&mut builder, &artifact_id, item),
            "yara.match" => project_yara_match(&mut builder, &artifact_id, item),
            _ => {}
        }
    }
    project_findings(
        &mut builder,
        &artifact_id,
        evidence,
        findings,
        finding_evidence,
    );

    let events = chronology_events(
        case_id,
        artifact,
        locations,
        analysis_run,
        run_history,
        evidence,
        finding_history,
    );
    let source_analysis_run_id = analysis_run.map(|run| run.id.clone());
    (
        CaseGraph {
            case_id: case_id.clone(),
            projection_version: INVESTIGATION_PROJECTION_VERSION,
            source_analysis_run_id: source_analysis_run_id.clone(),
            entities: builder.entities.into_values().collect(),
            edges: builder.edges.into_values().collect(),
            entity_evidence: builder
                .entity_evidence
                .into_iter()
                .map(|(entity_id, evidence_id, role)| EntityEvidence {
                    entity_id,
                    evidence_id,
                    role,
                })
                .collect(),
        },
        CaseChronology {
            case_id: case_id.clone(),
            projection_version: INVESTIGATION_PROJECTION_VERSION,
            source_analysis_run_id,
            events,
        },
    )
}

struct GraphBuilder<'a> {
    case_id: &'a CaseId,
    entities: BTreeMap<(EntityType, String), Entity>,
    edges: BTreeMap<(EntityId, EntityId, Relationship), Edge>,
    entity_evidence: BTreeSet<(EntityId, tf_model::EvidenceId, EvidenceRole)>,
}

impl<'a> GraphBuilder<'a> {
    fn new(case_id: &'a CaseId) -> Self {
        Self {
            case_id,
            entities: BTreeMap::new(),
            edges: BTreeMap::new(),
            entity_evidence: BTreeSet::new(),
        }
    }

    fn add_entity(
        &mut self,
        entity_type: EntityType,
        canonical_value: String,
        display_value: String,
        metadata: BTreeMap<String, Value>,
        evidence: Option<&Evidence>,
    ) -> EntityId {
        let key = (entity_type, canonical_value.clone());
        let id = stable_entity_id(self.case_id, entity_type, &canonical_value);
        self.entities.entry(key).or_insert_with(|| Entity {
            id: id.clone(),
            case_id: self.case_id.clone(),
            entity_type,
            canonical_value,
            display_value,
            metadata,
        });
        if let Some(evidence) = evidence {
            self.entity_evidence
                .insert((id.clone(), evidence.id.clone(), EvidenceRole::Supports));
        }
        id
    }

    fn add_edge(
        &mut self,
        source: &EntityId,
        target: &EntityId,
        relationship: Relationship,
        evidence: &Evidence,
    ) {
        let key = (source.clone(), target.clone(), relationship);
        self.edges.entry(key).or_insert_with(|| Edge {
            id: stable_edge_id(self.case_id, source, target, relationship),
            source_entity_id: source.clone(),
            target_entity_id: target.clone(),
            relationship,
            evidence_id: evidence.id.clone(),
            // Confidence describes the exact evidence linkage, not the safety of the value.
            confidence: Confidence::new(1.0).expect("unit confidence is valid"),
        });
    }

    fn add_entity_evidence(
        &mut self,
        entity_id: &EntityId,
        evidence_id: &tf_model::EvidenceId,
        role: EvidenceRole,
    ) {
        self.entity_evidence
            .insert((entity_id.clone(), evidence_id.clone(), role));
    }
}

fn project_section(
    builder: &mut GraphBuilder<'_>,
    root: &EntityId,
    artifact: &Artifact,
    evidence: &Evidence,
) {
    let Some(index) = evidence.value.get("index").and_then(Value::as_u64) else {
        return;
    };
    let Some(name) = nonempty_string(&evidence.value, "name") else {
        return;
    };
    let canonical = format!("{}:section:{index}", artifact.id.as_str());
    let id = builder.add_entity(
        EntityType::Section,
        canonical,
        name.to_owned(),
        object_metadata(&evidence.value),
        Some(evidence),
    );
    builder.add_edge(root, &id, Relationship::Contains, evidence);
}

fn project_import(builder: &mut GraphBuilder<'_>, root: &EntityId, evidence: &Evidence) {
    let Some(dll) = nonempty_string(&evidence.value, "dll") else {
        return;
    };
    let symbol = nonempty_string(&evidence.value, "function")
        .map(str::to_owned)
        .or_else(|| {
            evidence
                .value
                .get("ordinal")
                .and_then(Value::as_u64)
                .map(|ordinal| format!("#{ordinal}"))
        });
    let Some(symbol) = symbol else {
        return;
    };
    let display = format!("{dll}!{symbol}");
    let id = builder.add_entity(
        EntityType::ImportedApi,
        display.to_ascii_lowercase(),
        display,
        object_metadata(&evidence.value),
        Some(evidence),
    );
    builder.add_edge(root, &id, Relationship::Imports, evidence);
}

fn project_export(
    builder: &mut GraphBuilder<'_>,
    root: &EntityId,
    artifact: &Artifact,
    evidence: &Evidence,
) {
    let Some(ordinal) = evidence.value.get("ordinal").and_then(Value::as_u64) else {
        return;
    };
    let display = nonempty_string(&evidence.value, "name")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("#{ordinal}"));
    let canonical = format!(
        "{}:export:{}:{ordinal}",
        artifact.id.as_str(),
        display.to_ascii_lowercase()
    );
    let id = builder.add_entity(
        EntityType::Export,
        canonical,
        display,
        object_metadata(&evidence.value),
        Some(evidence),
    );
    builder.add_edge(root, &id, Relationship::Exports, evidence);
}

fn project_indicator(builder: &mut GraphBuilder<'_>, root: &EntityId, evidence: &Evidence) {
    let Some(category) = nonempty_string(&evidence.value, "category") else {
        return;
    };
    let Some(display) = nonempty_string(&evidence.value, "value") else {
        return;
    };
    let Some(canonical) = nonempty_string(&evidence.value, "canonical_value") else {
        return;
    };
    let entity_type = match category {
        "url" => EntityType::Url,
        "domain" => EntityType::Domain,
        "ipv4" => EntityType::IpAddress,
        "windows_path" => EntityType::FilePath,
        "registry_path" => EntityType::RegistryPath,
        "registry_key" => EntityType::RegistryKey,
        "command" => EntityType::CommandString,
        _ => return,
    };
    let id = builder.add_entity(
        entity_type,
        canonical.to_owned(),
        display.to_owned(),
        object_metadata(&evidence.value),
        Some(evidence),
    );
    builder.add_edge(root, &id, Relationship::ContainsIndicator, evidence);
}

fn project_authenticode(builder: &mut GraphBuilder<'_>, root: &EntityId, evidence: &Evidence) {
    let Some(pkcs7) = evidence.value.get("pkcs7") else {
        return;
    };
    let mut certificate_ids = Vec::new();
    if let Some(certificates) = pkcs7.get("certificates").and_then(Value::as_array) {
        for certificate in certificates {
            let Some(subject) = nonempty_string(certificate, "subject") else {
                certificate_ids.push(None);
                continue;
            };
            let Some(issuer) = nonempty_string(certificate, "issuer") else {
                certificate_ids.push(None);
                continue;
            };
            let Some(serial) = nonempty_string(certificate, "serial") else {
                certificate_ids.push(None);
                continue;
            };
            let id = builder.add_entity(
                EntityType::Certificate,
                format!(
                    "{}|{}",
                    issuer.to_ascii_lowercase(),
                    serial.to_ascii_lowercase()
                ),
                subject.to_owned(),
                object_metadata(certificate),
                Some(evidence),
            );
            certificate_ids.push(Some(id));
        }
    }
    if let Some(signers) = pkcs7.get("signers").and_then(Value::as_array) {
        for signer in signers {
            let Some(subject) = nonempty_string(signer, "subject") else {
                continue;
            };
            let issuer = nonempty_string(signer, "issuer").unwrap_or("");
            let serial = nonempty_string(signer, "serial").unwrap_or("");
            if issuer.is_empty() && serial.is_empty() {
                continue;
            }
            let id = builder.add_entity(
                EntityType::Signer,
                format!(
                    "{}|{}",
                    issuer.to_ascii_lowercase(),
                    serial.to_ascii_lowercase()
                ),
                subject.to_owned(),
                object_metadata(signer),
                Some(evidence),
            );
            builder.add_edge(root, &id, Relationship::SignedBy, evidence);
            if let Some(certificate_id) = signer
                .get("certificate_index")
                .and_then(Value::as_u64)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| certificate_ids.get(index))
                .and_then(Option::as_ref)
            {
                builder.add_edge(&id, certificate_id, Relationship::UsesCertificate, evidence);
            }
        }
    }
}

fn project_findings(
    builder: &mut GraphBuilder<'_>,
    root: &EntityId,
    evidence: &[Evidence],
    findings: &[Finding],
    finding_evidence: &[FindingEvidence],
) {
    let mut sources = BTreeMap::<tf_model::EvidenceId, Vec<EntityId>>::new();
    for (entity_id, evidence_id, _) in &builder.entity_evidence {
        sources
            .entry(evidence_id.clone())
            .or_default()
            .push(entity_id.clone());
    }
    let evidence_by_id = evidence
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    let mut ordered_findings = findings.iter().collect::<Vec<_>>();
    ordered_findings
        .sort_by(|left, right| (&left.rule_id, &left.id).cmp(&(&right.rule_id, &right.id)));
    for finding in ordered_findings {
        let finding_id = builder.add_entity(
            EntityType::Finding,
            finding.rule_id.to_ascii_lowercase(),
            finding.title.clone(),
            BTreeMap::from([
                ("category".to_owned(), json!(finding.category)),
                ("confidence".to_owned(), json!(finding.confidence.value())),
                ("confidence_band".to_owned(), json!(finding.confidence_band)),
                ("finding_id".to_owned(), json!(finding.id)),
                ("rule_id".to_owned(), json!(finding.rule_id)),
                ("rule_version".to_owned(), json!(finding.rule_version)),
                ("severity".to_owned(), json!(finding.severity)),
                ("state".to_owned(), json!(finding.state)),
            ]),
            None,
        );
        let mut links = finding_evidence
            .iter()
            .filter(|link| link.finding_id == finding.id)
            .collect::<Vec<_>>();
        links.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        for link in links {
            builder.add_entity_evidence(&finding_id, &link.evidence_id, link.role);
            let relationship = match link.role {
                EvidenceRole::Supports => Some(Relationship::SupportsFinding),
                EvidenceRole::Contradicts => Some(Relationship::ContradictsFinding),
                EvidenceRole::Context => None,
            };
            let Some(relationship) = relationship else {
                continue;
            };
            let source_ids = sources
                .get(&link.evidence_id)
                .cloned()
                .unwrap_or_else(|| vec![root.clone()]);
            let Some(evidence) = evidence_by_id.get(&link.evidence_id) else {
                continue;
            };
            for source_id in source_ids {
                builder.add_edge(&source_id, &finding_id, relationship, evidence);
            }
        }
    }
}

fn project_yara_match(builder: &mut GraphBuilder<'_>, root: &EntityId, evidence: &Evidence) {
    let Some(pack) = nonempty_string(&evidence.value, "pack_sha256") else {
        return;
    };
    let Some(namespace) = nonempty_string(&evidence.value, "namespace") else {
        return;
    };
    let Some(identifier) = nonempty_string(&evidence.value, "rule_identifier") else {
        return;
    };
    if pack.len() != 64 || !pack.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return;
    }
    let display = format!("{namespace}:{identifier}");
    let id = builder.add_entity(
        EntityType::YaraRule,
        format!(
            "{}:{}:{}",
            pack.to_ascii_lowercase(),
            namespace.to_ascii_lowercase(),
            identifier
        ),
        display,
        object_metadata(&evidence.value),
        Some(evidence),
    );
    builder.add_edge(root, &id, Relationship::MatchedRule, evidence);
}

fn chronology_events(
    case_id: &CaseId,
    artifact: &Artifact,
    locations: &[ArtifactLocation],
    analysis_run: Option<&AnalysisRun>,
    run_history: &[AnalysisRun],
    evidence: &[Evidence],
    finding_history: &[Finding],
) -> Vec<EvidenceEvent> {
    let mut events = BTreeMap::<EventId, EvidenceEvent>::new();
    insert_timestamp_event(
        &mut events,
        case_id,
        artifact,
        &artifact.created_at,
        "artifact_ingested",
        TimestampReliability::ApplicationRecorded,
        "artifact_ingested",
        None,
        "Artifact ingested",
        artifact.id.as_str(),
    );
    for location in locations {
        if let Some(timestamp) = &location.created_at_utc {
            insert_timestamp_event(
                &mut events,
                case_id,
                artifact,
                timestamp,
                "filesystem_created",
                TimestampReliability::FilesystemMetadata,
                "file_created",
                None,
                "Filesystem creation timestamp",
                location.id.as_str(),
            );
        }
        if let Some(timestamp) = &location.modified_at_utc {
            insert_timestamp_event(
                &mut events,
                case_id,
                artifact,
                timestamp,
                "filesystem_modified",
                TimestampReliability::FilesystemMetadata,
                "file_modified",
                None,
                "Filesystem modification timestamp",
                location.id.as_str(),
            );
        }
    }
    let mut runs = run_history.iter().collect::<Vec<_>>();
    if let Some(run) = analysis_run
        && !runs.iter().any(|candidate| candidate.id == run.id)
    {
        runs.push(run);
    }
    runs.retain(|run| parse_rfc3339(&run.started_at).is_some());
    runs.sort_by(|left, right| {
        parse_rfc3339(&left.started_at)
            .cmp(&parse_rfc3339(&right.started_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    for (index, run) in runs.iter().enumerate() {
        let reanalysis = index != 0;
        insert_timestamp_event(
            &mut events,
            case_id,
            artifact,
            &run.started_at,
            "application_generated",
            TimestampReliability::ApplicationGenerated,
            if reanalysis {
                "reanalysis_started"
            } else {
                "analysis_started"
            },
            None,
            if reanalysis {
                "Static reanalysis started"
            } else {
                "Static analysis started"
            },
            run.id.as_str(),
        );
        let Some(finished_at) = run.finished_at.as_deref() else {
            continue;
        };
        let (event_type, summary) = if run.status == AnalysisStatus::Complete {
            if reanalysis {
                ("reanalysis_completed", "Static reanalysis completed")
            } else {
                ("analysis_completed", "Static analysis completed")
            }
        } else if matches!(
            run.status,
            AnalysisStatus::Failed
                | AnalysisStatus::Cancelled
                | AnalysisStatus::TimedOut
                | AnalysisStatus::ResourceLimit
                | AnalysisStatus::Partial
        ) {
            if reanalysis {
                ("reanalysis_failed", "Static reanalysis did not complete")
            } else {
                ("analysis_failed", "Static analysis did not complete")
            }
        } else {
            continue;
        };
        insert_timestamp_event(
            &mut events,
            case_id,
            artifact,
            finished_at,
            "application_generated",
            TimestampReliability::ApplicationGenerated,
            event_type,
            None,
            summary,
            run.id.as_str(),
        );
    }
    let runs_by_id = runs
        .iter()
        .map(|run| (&run.id, *run))
        .collect::<BTreeMap<_, _>>();
    let mut ordered_findings = finding_history.iter().collect::<Vec<_>>();
    ordered_findings.sort_by(|left, right| {
        (&left.analysis_run_id, &left.rule_id, &left.id).cmp(&(
            &right.analysis_run_id,
            &right.rule_id,
            &right.id,
        ))
    });
    for finding in ordered_findings {
        let Some(run) = runs_by_id.get(&finding.analysis_run_id) else {
            continue;
        };
        let Some(finished_at) = run.finished_at.as_deref() else {
            continue;
        };
        insert_timestamp_event(
            &mut events,
            case_id,
            artifact,
            finished_at,
            "rule_generated",
            TimestampReliability::ApplicationGenerated,
            "rule_finding_generated",
            None,
            &format!(
                "Rule {} generated finding: {}",
                finding.rule_id, finding.title
            ),
            finding.id.as_str(),
        );
    }
    for item in evidence.iter().filter(|item| item.kind == "pe.header") {
        let Some(timestamp) = item.value.get("coff_timestamp").and_then(Value::as_u64) else {
            continue;
        };
        if timestamp == 0 || timestamp > i64::MAX as u64 {
            continue;
        }
        let Ok(value) = OffsetDateTime::from_unix_timestamp(timestamp as i64) else {
            continue;
        };
        let Ok(timestamp_utc) = value.format(&Rfc3339) else {
            continue;
        };
        insert_timestamp_event(
            &mut events,
            case_id,
            artifact,
            &timestamp_utc,
            "pe_coff_header",
            TimestampReliability::AttackerControlled,
            "pe_coff_timestamp",
            Some(item),
            "PE COFF timestamp",
            "coff_timestamp",
        );
    }
    let mut events = events.into_values().collect::<Vec<_>>();
    events.sort_by(|left, right| {
        parse_rfc3339(&left.timestamp_utc)
            .cmp(&parse_rfc3339(&right.timestamp_utc))
            .then_with(|| left.event_type.cmp(&right.event_type))
            .then_with(|| left.id.cmp(&right.id))
    });
    events
}

#[allow(clippy::too_many_arguments)]
fn insert_timestamp_event(
    events: &mut BTreeMap<EventId, EvidenceEvent>,
    case_id: &CaseId,
    artifact: &Artifact,
    timestamp: &str,
    timestamp_type: &str,
    reliability: TimestampReliability,
    event_type: &str,
    evidence: Option<&Evidence>,
    summary: &str,
    discriminator: &str,
) {
    let Some(timestamp) = normalize_rfc3339(timestamp) else {
        return;
    };
    let id = stable_event_id(case_id, event_type, &timestamp, discriminator);
    events.insert(
        id.clone(),
        EvidenceEvent {
            id,
            case_id: case_id.clone(),
            timestamp_utc: timestamp,
            timestamp_type: timestamp_type.to_owned(),
            reliability,
            event_type: event_type.to_owned(),
            artifact_id: Some(artifact.id.clone()),
            evidence_id: evidence.map(|item| item.id.clone()),
            summary: summary.to_owned(),
        },
    );
}

fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn normalize_rfc3339(value: &str) -> Option<String> {
    parse_rfc3339(value)?
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .ok()
}

fn nonempty_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn object_metadata(value: &Value) -> BTreeMap<String, Value> {
    value
        .as_object()
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn stable_entity_id(case_id: &CaseId, entity_type: EntityType, canonical: &str) -> EntityId {
    EntityId::from_u128(stable_u128(&[
        "entity",
        case_id.as_str(),
        entity_type.as_str(),
        canonical,
    ]))
}

fn stable_edge_id(
    case_id: &CaseId,
    source: &EntityId,
    target: &EntityId,
    relationship: Relationship,
) -> EdgeId {
    EdgeId::from_u128(stable_u128(&[
        "edge",
        case_id.as_str(),
        source.as_str(),
        target.as_str(),
        relationship.as_str(),
    ]))
}

fn stable_event_id(
    case_id: &CaseId,
    event_type: &str,
    timestamp: &str,
    discriminator: &str,
) -> EventId {
    EventId::from_u128(stable_u128(&[
        "event",
        case_id.as_str(),
        event_type,
        timestamp,
        discriminator,
    ]))
}

fn stable_u128(parts: &[&str]) -> u128 {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let bytes = digest.finalize();
    u128::from_be_bytes(
        bytes[..16]
            .try_into()
            .expect("SHA-256 has at least 16 bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tf_model::{
        AnalysisRunId, ArtifactId, ArtifactKind, ArtifactLocationId, EvidenceId, ProvenanceId,
    };

    fn artifact(case_id: &CaseId) -> Artifact {
        Artifact {
            id: ArtifactId::new(),
            case_id: case_id.clone(),
            parent_artifact_id: None,
            sha256: "a".repeat(64),
            sha1: "b".repeat(40),
            md5: "c".repeat(32),
            size_bytes: 10,
            kind: ArtifactKind::Pe64,
            mime: None,
            original_name: "sample.exe".to_owned(),
            store_path: "private".to_owned(),
            created_at: "2026-08-25T12:00:00Z".to_owned(),
        }
    }

    fn evidence(artifact: &Artifact, kind: &str, value: Value) -> Evidence {
        Evidence {
            id: EvidenceId::new(),
            artifact_id: artifact.id.clone(),
            provenance_id: ProvenanceId::new(),
            kind: kind.to_owned(),
            class: tf_model::ObservationClass::Observed,
            locator: BTreeMap::new(),
            value,
            preview_text: None,
        }
    }

    fn build_test_projection(
        case_id: &CaseId,
        artifact: &Artifact,
        evidence: &[Evidence],
        findings: &[Finding],
        finding_evidence: &[FindingEvidence],
    ) -> (CaseGraph, CaseChronology) {
        build(ProjectionInput {
            case_id,
            artifact,
            locations: &[],
            analysis_run: None,
            run_history: &[],
            evidence,
            findings,
            finding_evidence,
            finding_history: findings,
        })
    }

    #[test]
    fn graph_is_deterministic_and_skips_malformed_or_unknown_evidence() {
        let case_id = CaseId::new();
        let artifact = artifact(&case_id);
        let valid = evidence(
            &artifact,
            "pe.import",
            json!({"dll":"KERNEL32.dll", "function":"CreateFileW", "ordinal":null}),
        );
        let malformed = evidence(&artifact, "pe.section", json!({"index":"zero"}));
        let unknown = evidence(
            &artifact,
            "future.runtime",
            json!({"process":"not observed"}),
        );
        let input = vec![valid.clone(), malformed, unknown];
        let (first, _) = build_test_projection(&case_id, &artifact, &input, &[], &[]);
        let (second, _) = build_test_projection(&case_id, &artifact, &input, &[], &[]);

        assert_eq!(first, second);
        assert_eq!(first.entities.len(), 2);
        assert_eq!(first.edges.len(), 1);
        assert_eq!(first.edges[0].evidence_id, valid.id);
        assert_eq!(first.entity_evidence.len(), 1);
    }

    #[test]
    fn empty_evidence_keeps_only_authoritative_artifact_and_ingestion_time() {
        let case_id = CaseId::new();
        let artifact = artifact(&case_id);
        let (graph, chronology) = build_test_projection(&case_id, &artifact, &[], &[], &[]);
        assert_eq!(graph.entities.len(), 1);
        assert!(graph.edges.is_empty());
        assert!(graph.entity_evidence.is_empty());
        assert_eq!(chronology.events.len(), 1);
        assert_eq!(
            chronology.events[0].reliability,
            TimestampReliability::ApplicationRecorded
        );
    }

    #[test]
    fn chronology_orders_reliability_and_rejects_bad_or_zero_timestamps() {
        let case_id = CaseId::new();
        let artifact = artifact(&case_id);
        let good = evidence(
            &artifact,
            "pe.header",
            json!({"coff_timestamp": 1_700_000_000_u64}),
        );
        let zero = evidence(&artifact, "pe.header", json!({"coff_timestamp": 0}));
        let malformed = evidence(
            &artifact,
            "pe.header",
            json!({"coff_timestamp": "yesterday"}),
        );
        let (_, chronology) = build_test_projection(
            &case_id,
            &artifact,
            &[good.clone(), zero, malformed],
            &[],
            &[],
        );
        assert_eq!(chronology.events.len(), 2);
        let coff = chronology
            .events
            .iter()
            .find(|event| event.event_type == "pe_coff_timestamp")
            .expect("COFF event");
        assert_eq!(coff.evidence_id.as_ref(), Some(&good.id));
        assert_eq!(coff.reliability, TimestampReliability::AttackerControlled);
    }

    #[test]
    fn chronology_orders_true_instants_normalizes_offsets_and_rejects_impossible_dates() {
        let case_id = CaseId::new();
        let mut artifact = artifact(&case_id);
        artifact.created_at = "2026-08-25T00:00:00Z".to_owned();
        let valid_location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: artifact.original_name.clone(),
            source_path: None,
            modified_at_utc: Some("2026-08-24T23:30:00Z".to_owned()),
            created_at_utc: Some("2026-08-25T01:00:00+02:00".to_owned()),
            ingested_at: artifact.created_at.clone(),
        };
        let impossible_location = ArtifactLocation {
            id: ArtifactLocationId::new(),
            artifact_id: artifact.id.clone(),
            display_name: artifact.original_name.clone(),
            source_path: None,
            modified_at_utc: Some("2026-02-30T12:00:00Z".to_owned()),
            created_at_utc: None,
            ingested_at: artifact.created_at.clone(),
        };
        let (_, chronology) = build(ProjectionInput {
            case_id: &case_id,
            artifact: &artifact,
            locations: &[valid_location, impossible_location],
            analysis_run: None,
            run_history: &[],
            evidence: &[],
            findings: &[],
            finding_evidence: &[],
            finding_history: &[],
        });

        assert_eq!(
            chronology
                .events
                .iter()
                .map(|event| (event.event_type.as_str(), event.timestamp_utc.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("file_created", "2026-08-24T23:00:00Z"),
                ("file_modified", "2026-08-24T23:30:00Z"),
                ("artifact_ingested", "2026-08-25T00:00:00Z"),
            ]
        );
    }

    #[test]
    fn projects_registry_findings_and_matched_signer_certificates_without_inference() {
        let case_id = CaseId::new();
        let artifact = artifact(&case_id);
        let registry = evidence(
            &artifact,
            "pe.indicator",
            json!({
                "category": "registry_key",
                "value": "HKCU\\Software\\Demo",
                "canonical_value": "hkcu\\software\\demo"
            }),
        );
        let registry_path = evidence(
            &artifact,
            "pe.indicator",
            json!({
                "category": "registry_path",
                "value": "HKLM\\Software\\Demo\\Value",
                "canonical_value": "hklm\\software\\demo\\value"
            }),
        );
        let signature = evidence(
            &artifact,
            "pe.authenticode",
            json!({
                "pkcs7": {
                    "certificates": [{"subject":"CN=Demo", "issuer":"CN=Root", "serial":"01"}],
                    "signers": [{
                        "subject":"CN=Demo", "issuer":"CN=Root", "serial":"01",
                        "certificate_index": 0
                    }]
                }
            }),
        );
        let finding = Finding {
            id: tf_model::FindingId::new(),
            analysis_run_id: AnalysisRunId::new(),
            artifact_id: artifact.id.clone(),
            rule_id: "TF-TEST-001".to_owned(),
            rule_version: "1".to_owned(),
            title: "Persisted test finding".to_owned(),
            category: "test".to_owned(),
            severity: tf_model::Severity::Low,
            confidence: Confidence::new(0.5).expect("confidence"),
            confidence_band: tf_model::ConfidenceBand::Tentative,
            explanation_template_id: "test.v1".to_owned(),
            state: tf_model::FindingState::New,
        };
        let links = vec![
            FindingEvidence {
                finding_id: finding.id.clone(),
                evidence_id: registry.id.clone(),
                role: EvidenceRole::Supports,
            },
            FindingEvidence {
                finding_id: finding.id.clone(),
                evidence_id: signature.id.clone(),
                role: EvidenceRole::Contradicts,
            },
        ];
        let (graph, _) = build_test_projection(
            &case_id,
            &artifact,
            &[registry, registry_path, signature],
            std::slice::from_ref(&finding),
            &links,
        );

        for entity_type in [
            EntityType::RegistryKey,
            EntityType::RegistryPath,
            EntityType::Certificate,
            EntityType::Signer,
            EntityType::Finding,
        ] {
            assert!(
                graph
                    .entities
                    .iter()
                    .any(|entity| entity.entity_type == entity_type),
                "missing {entity_type:?}"
            );
        }
        for relationship in [
            Relationship::UsesCertificate,
            Relationship::SupportsFinding,
            Relationship::ContradictsFinding,
        ] {
            assert!(
                graph
                    .edges
                    .iter()
                    .any(|edge| edge.relationship == relationship),
                "missing {relationship:?}"
            );
        }
        assert!(graph.entity_evidence.iter().any(|link| {
            link.role == EvidenceRole::Contradicts
                && graph.entities.iter().any(|entity| {
                    entity.id == link.entity_id && entity.entity_type == EntityType::Finding
                })
        }));
    }

    #[test]
    #[ignore = "measurement only; run explicitly and compare environments, never as a PR gate"]
    fn measure_projection_baseline() {
        let case_id = CaseId::from_u128(1);
        let artifact = artifact(&case_id);
        let evidence = (0..500).map(|index| evidence(
            &artifact,
            "pe.import",
            json!({"dll":"KERNEL32.dll", "function":format!("Function{index}"), "ordinal":null}),
        )).collect::<Vec<_>>();
        let iterations = 100;
        let started = std::time::Instant::now();
        let mut entities = 0;
        for _ in 0..iterations {
            entities += build_test_projection(&case_id, &artifact, &evidence, &[], &[])
                .0
                .entities
                .len();
        }
        println!(
            "{{\"benchmark\":\"projection\",\"iterations\":{iterations},\"entities\":{entities},\"elapsed_ms\":{}}}",
            started.elapsed().as_millis()
        );
    }
}
