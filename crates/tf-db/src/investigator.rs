use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter};
use serde_json::Value as JsonValue;
use tf_model::{
    AnalysisRun, AnalysisRunId, AnalysisStatus, AnalystNote, Artifact, ArtifactId, Case, CaseId,
    CaseSearchHit, CaseSearchRequest, CaseStatus, EntityId, Evidence, Finding, FindingAction,
    FindingId, FindingState, NoteId, SearchField,
};

use super::{
    CaseDatabase, DatabaseCaseAnalysis, DatabaseError, load_findings,
    load_provenances_and_evidence, map_analysis_run, map_artifact, map_case, update_case,
};

pub const MAX_CASE_TITLE_BYTES: usize = 256;
pub const MAX_NOTE_BYTES: usize = 16 * 1024;
pub const MAX_SEARCH_QUERY_BYTES: usize = 256;
pub const MAX_SEARCH_RESULTS: u32 = 100;
const MAX_INDEX_VALUE_BYTES: usize = 2048;
pub(super) const MAX_SCALARS_PER_EVIDENCE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObject {
    pub sha256: String,
    pub store_path: String,
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedCaseObject {
    pub case_id: CaseId,
    pub objects: Vec<DeletedObject>,
}

impl CaseDatabase {
    pub fn start_analysis(
        &self,
        case_id: &CaseId,
        run: &AnalysisRun,
        updated_at: &str,
    ) -> Result<(), DatabaseError> {
        if run.status != AnalysisStatus::Running
            || run.finished_at.is_some()
            || run.error_code.is_some()
            || !valid_timestamp(updated_at)
        {
            return Err(DatabaseError::InvalidAnalysisStatus);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::guard_artifact_identity(&transaction, case_id, run, None)?;
        let case_status: String = transaction.query_row(
            "SELECT status FROM cases WHERE id = ?1",
            params![case_id.as_str()],
            |row| row.get(0),
        )?;
        if case_status == CaseStatus::Archived.as_str() {
            return Err(DatabaseError::InvalidStateTransition);
        }
        let active: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM analysis_runs r
                JOIN artifacts a ON a.id = r.artifact_id
                WHERE a.case_id = ?1 AND r.status IN ('queued', 'running')
             )",
            params![case_id.as_str()],
            |row| row.get(0),
        )?;
        if active {
            return Err(DatabaseError::ActiveAnalysis);
        }
        super::insert_analysis_run(&transaction, run)?;
        update_case(&transaction, case_id, updated_at, CaseStatus::Active)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn rename_case(
        &self,
        case_id: &CaseId,
        title: &str,
        updated_at: &str,
    ) -> Result<Case, DatabaseError> {
        let title = title.trim();
        validate_text(title, MAX_CASE_TITLE_BYTES, "case title")?;
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE cases SET title = ?1, updated_at = ?2 WHERE id = ?3",
            params![title, updated_at, case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        transaction.execute(
            "DELETE FROM search_terms WHERE case_id = ?1 AND field = 'case_title'",
            params![case_id.as_str()],
        )?;
        insert_search_term(
            &transaction,
            case_id,
            None,
            None,
            None,
            None,
            SearchField::CaseTitle,
            title,
        )?;
        let case = transaction.query_row(
            "SELECT id, title, created_at, updated_at, app_version, schema_version, status
             FROM cases WHERE id = ?1",
            params![case_id.as_str()],
            map_case,
        )?;
        transaction.commit()?;
        Ok(case)
    }

    pub fn archive_case(&self, case_id: &CaseId, updated_at: &str) -> Result<Case, DatabaseError> {
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        refuse_active_analysis(&transaction, case_id)?;
        let changed = transaction.execute(
            "UPDATE cases
             SET pre_archive_status = status, status = 'archived', updated_at = ?1
             WHERE id = ?2 AND status <> 'archived'",
            params![updated_at, case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(state_or_not_found(&transaction, case_id)?);
        }
        let case = load_case(&transaction, case_id)?;
        transaction.commit()?;
        Ok(case)
    }

    pub fn unarchive_case(
        &self,
        case_id: &CaseId,
        updated_at: &str,
    ) -> Result<Case, DatabaseError> {
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE cases
             SET status = COALESCE(pre_archive_status, 'complete'),
                 pre_archive_status = NULL, updated_at = ?1
             WHERE id = ?2 AND status = 'archived'",
            params![updated_at, case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(state_or_not_found(&transaction, case_id)?);
        }
        let case = load_case(&transaction, case_id)?;
        transaction.commit()?;
        Ok(case)
    }

    pub fn delete_case_transactional(
        &self,
        case_id: &CaseId,
    ) -> Result<DeletedCaseObject, DatabaseError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        refuse_active_analysis(&transaction, case_id)?;
        let objects = {
            let mut statement = transaction.prepare(
                "SELECT DISTINCT sha256, store_path FROM artifacts WHERE case_id = ?1
                 ORDER BY sha256, store_path",
            )?;
            statement
                .query_map(params![case_id.as_str()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if objects.is_empty() {
            return Err(DatabaseError::NotFound);
        }
        let changed =
            transaction.execute("DELETE FROM cases WHERE id = ?1", params![case_id.as_str()])?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        let mut deleted_objects = Vec::with_capacity(objects.len());
        for (sha256, store_path) in objects {
            let references: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM artifacts
                 WHERE lower(sha256) = lower(?1) OR store_path = ?2",
                params![sha256, store_path],
                |row| row.get(0),
            )?;
            deleted_objects.push(DeletedObject {
                sha256,
                store_path,
                shared: references != 0,
            });
        }
        transaction.commit()?;
        Ok(DeletedCaseObject {
            case_id: case_id.clone(),
            objects: deleted_objects,
        })
    }

    pub fn transition_finding(
        &self,
        case_id: &CaseId,
        finding_id: &FindingId,
        action: FindingAction,
        updated_at: &str,
    ) -> Result<Finding, DatabaseError> {
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT f.state FROM findings f
                 JOIN artifacts a ON a.id = f.artifact_id
                 WHERE f.id = ?1 AND a.case_id = ?2",
                params![finding_id.as_str(), case_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(DatabaseError::NotFound)?;
        let current: FindingState = current
            .parse()
            .map_err(|_| DatabaseError::InvalidStateTransition)?;
        let target = match (current, action) {
            (FindingState::New, FindingAction::Review) => FindingState::Reviewed,
            (FindingState::Reviewed, FindingAction::Accept) => FindingState::Accepted,
            (
                FindingState::New | FindingState::Reviewed | FindingState::Accepted,
                FindingAction::Dismiss,
            ) => FindingState::Dismissed,
            (
                FindingState::Reviewed | FindingState::Accepted | FindingState::Dismissed,
                FindingAction::Reopen,
            ) => FindingState::New,
            _ => return Err(DatabaseError::InvalidStateTransition),
        };
        transaction.execute(
            "UPDATE findings SET state = ?1 WHERE id = ?2",
            params![target.as_str(), finding_id.as_str()],
        )?;
        transaction.execute(
            "UPDATE entities
             SET metadata_json = json_set(metadata_json, '$.state', ?1)
             WHERE case_id = ?2 AND entity_type = 'finding'
               AND json_extract(metadata_json, '$.finding_id') = ?3
               AND id IN (SELECT entity_id FROM projection_entities WHERE case_id = ?2)",
            params![target.as_str(), case_id.as_str(), finding_id.as_str()],
        )?;
        transaction.execute(
            "UPDATE cases SET updated_at = ?1 WHERE id = ?2",
            params![updated_at, case_id.as_str()],
        )?;
        let finding = transaction.query_row(
            "SELECT id, analysis_run_id, artifact_id, rule_id, rule_version, title, category,
                    severity, confidence, confidence_band, explanation_template_id, state
             FROM findings WHERE id = ?1",
            params![finding_id.as_str()],
            super::map_finding,
        )?;
        transaction.commit()?;
        Ok(finding)
    }

    pub fn create_note(&self, note: &AnalystNote) -> Result<(), DatabaseError> {
        validate_note(note)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_note_links(&transaction, note)?;
        transaction.execute(
            "INSERT INTO notes(id, case_id, entity_id, finding_id, body, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                note.id.as_str(),
                note.case_id.as_str(),
                note.entity_id.as_ref().map(EntityId::as_str),
                note.finding_id.as_ref().map(FindingId::as_str),
                note.body,
                note.created_at,
                note.updated_at
            ],
        )?;
        transaction.execute(
            "UPDATE cases SET updated_at = ?1 WHERE id = ?2",
            params![note.updated_at, note.case_id.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn update_note(
        &self,
        case_id: &CaseId,
        note_id: &NoteId,
        body: &str,
        updated_at: &str,
    ) -> Result<AnalystNote, DatabaseError> {
        validate_note_body(body)?;
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE notes SET body = ?1, updated_at = ?2 WHERE id = ?3 AND case_id = ?4",
            params![body.trim(), updated_at, note_id.as_str(), case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        transaction.execute(
            "UPDATE cases SET updated_at = ?1 WHERE id = ?2",
            params![updated_at, case_id.as_str()],
        )?;
        let note = load_note(&transaction, note_id)?;
        transaction.commit()?;
        Ok(note)
    }

    pub fn delete_note(
        &self,
        case_id: &CaseId,
        note_id: &NoteId,
        updated_at: &str,
    ) -> Result<(), DatabaseError> {
        validate_timestamp(updated_at)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "DELETE FROM notes WHERE id = ?1 AND case_id = ?2",
            params![note_id.as_str(), case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        transaction.execute(
            "UPDATE cases SET updated_at = ?1 WHERE id = ?2",
            params![updated_at, case_id.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_notes(&self, case_id: &CaseId) -> Result<Vec<AnalystNote>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, case_id, entity_id, finding_id, body, created_at, updated_at
             FROM notes WHERE case_id = ?1 ORDER BY updated_at DESC, id DESC",
        )?;
        let rows = statement.query_map(params![case_id.as_str()], map_note)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search_cases(
        &self,
        request: &CaseSearchRequest,
    ) -> Result<Vec<CaseSearchHit>, DatabaseError> {
        let query = request.query.trim().to_ascii_lowercase();
        validate_text(&query, MAX_SEARCH_QUERY_BYTES, "search query")?;
        if request.limit == 0 || request.limit > MAX_SEARCH_RESULTS {
            return Err(DatabaseError::Validation("search limit"));
        }
        let fields = if request.fields.is_empty() {
            all_search_fields()
        } else {
            request.fields.iter().copied().collect::<BTreeSet<_>>()
        };
        let placeholders = (0..fields.len())
            .map(|index| format!("?{}", index + 4))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT s.case_id, c.title, c.status, s.artifact_id, s.analysis_run_id,
                    s.evidence_id, s.finding_id, s.field, s.value
             FROM search_terms s JOIN cases c ON c.id = s.case_id
             WHERE s.normalized_value >= ?1 AND s.normalized_value < ?2
               AND (?3 OR c.status <> 'archived') AND s.field IN ({placeholders})
             ORDER BY s.normalized_value, s.field, c.title COLLATE NOCASE, s.case_id, s.id
             LIMIT ?{}",
            fields.len() + 4
        );
        let mut values = vec![
            rusqlite::types::Value::Text(query.clone()),
            rusqlite::types::Value::Text(format!("{query}\u{10ffff}")),
            rusqlite::types::Value::Integer(i64::from(request.include_archived)),
        ];
        values.extend(
            fields
                .iter()
                .map(|field| rusqlite::types::Value::Text(field.as_str().to_owned())),
        );
        values.push(rusqlite::types::Value::Integer(i64::from(request.limit)));
        let connection = self.lock()?;
        let mut statement = connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| {
            let status = row.get::<_, String>(2)?;
            let field = row.get::<_, String>(7)?;
            Ok(CaseSearchHit {
                case_id: super::parse_text(0, &row.get::<_, String>(0)?)?,
                case_title: row.get(1)?,
                case_status: super::parse_text(2, &status)?,
                artifact_id: parse_optional(row, 3)?,
                analysis_run_id: parse_optional(row, 4)?,
                evidence_id: parse_optional(row, 5)?,
                finding_id: parse_optional(row, 6)?,
                field: super::parse_text(7, &field)?,
                value: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn artifact_for_case(&self, case_id: &CaseId) -> Result<Option<Artifact>, DatabaseError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT id, case_id, parent_artifact_id, sha256, sha1, md5, size_bytes, kind,
                        mime, original_name, store_path, created_at
                 FROM artifacts WHERE case_id = ?1 ORDER BY created_at, id LIMIT 1",
                params![case_id.as_str()],
                map_artifact,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn artifact_locations_for_case(
        &self,
        case_id: &CaseId,
    ) -> Result<Vec<tf_model::ArtifactLocation>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT l.id, l.artifact_id, l.display_name, l.source_path, l.modified_at_utc,
                    l.created_at_utc, l.ingested_at
             FROM artifact_locations l JOIN artifacts a ON a.id = l.artifact_id
             WHERE a.case_id = ?1 ORDER BY l.ingested_at, l.id",
        )?;
        statement
            .query_map(params![case_id.as_str()], |row| {
                Ok(tf_model::ArtifactLocation {
                    id: super::parse_text(0, &row.get::<_, String>(0)?)?,
                    artifact_id: super::parse_text(1, &row.get::<_, String>(1)?)?,
                    display_name: row.get(2)?,
                    source_path: row.get(3)?,
                    modified_at_utc: row.get(4)?,
                    created_at_utc: row.get(5)?,
                    ingested_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

pub(super) fn get_case_analysis_run(
    database: &CaseDatabase,
    case_id: &CaseId,
    run_id: &AnalysisRunId,
) -> Result<Option<DatabaseCaseAnalysis>, DatabaseError> {
    let mut connection = database.lock()?;
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
             FROM artifacts WHERE case_id = ?1 ORDER BY created_at, id LIMIT 1",
            params![case_id.as_str()],
            map_artifact,
        )
        .optional()?
        .ok_or(DatabaseError::IdentityMismatch)?;
    let run = transaction
        .query_row(
            "SELECT id, artifact_id, analyzer, analyzer_version, started_at, finished_at,
                    status, error_code
             FROM analysis_runs WHERE id = ?1 AND artifact_id = ?2",
            params![run_id.as_str(), artifact.id.as_str()],
            map_analysis_run,
        )
        .optional()?;
    let Some(run) = run else {
        transaction.commit()?;
        return Ok(None);
    };
    let (provenances, evidence) = load_provenances_and_evidence(&transaction, &run)?;
    let (rules, findings, finding_evidence, explanations, attack_mappings) =
        if run.status == AnalysisStatus::Complete {
            load_findings(&transaction, &run)?
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
    let run_history = load_run_history(&transaction, &artifact.id)?;
    transaction.commit()?;
    Ok(Some(DatabaseCaseAnalysis {
        case,
        artifact,
        analysis_run: Some(run),
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

pub(super) fn load_run_history(
    transaction: &Transaction<'_>,
    artifact_id: &ArtifactId,
) -> Result<Vec<AnalysisRun>, DatabaseError> {
    let mut statement = transaction.prepare(
        "SELECT id, artifact_id, analyzer, analyzer_version, started_at, finished_at, status,
                error_code FROM analysis_runs WHERE artifact_id = ?1
         ORDER BY julianday(started_at) DESC, id DESC",
    )?;
    let rows = statement.query_map(params![artifact_id.as_str()], map_analysis_run)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(super) fn index_case_artifact(
    transaction: &Transaction<'_>,
    case: &Case,
    artifact: &Artifact,
) -> Result<(), DatabaseError> {
    insert_search_term(
        transaction,
        &case.id,
        None,
        None,
        None,
        None,
        SearchField::CaseTitle,
        &case.title,
    )?;
    for (field, value) in [
        (SearchField::Sha256, artifact.sha256.as_str()),
        (SearchField::Sha1, artifact.sha1.as_str()),
        (SearchField::Md5, artifact.md5.as_str()),
    ] {
        insert_search_term(
            transaction,
            &case.id,
            Some(&artifact.id),
            None,
            None,
            None,
            field,
            value,
        )?;
    }
    Ok(())
}

pub(super) fn index_evidence(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
    run: &AnalysisRun,
    evidence: &Evidence,
) -> Result<(), DatabaseError> {
    let mut scalars = Vec::new();
    collect_scalars(&evidence.value, "$", &mut scalars);
    for (path, value) in scalars {
        let field = match evidence.kind.as_str() {
            "pe.import" | "pe.delay_import" => SearchField::Import,
            "pe.indicator" => SearchField::Indicator,
            "pe.authenticode" if path.contains("signers") => SearchField::Signer,
            "pe.authenticode" if path.contains("certificates") => SearchField::Certificate,
            _ => SearchField::EvidenceValue,
        };
        insert_search_term(
            transaction,
            case_id,
            Some(&evidence.artifact_id),
            Some(&run.id),
            Some(&evidence.id),
            None,
            field,
            &value,
        )?;
    }
    Ok(())
}

pub(super) fn index_finding(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
    finding: &Finding,
) -> Result<(), DatabaseError> {
    for (field, value) in [
        (SearchField::RuleId, finding.rule_id.as_str()),
        (SearchField::FindingTitle, finding.title.as_str()),
        (SearchField::FindingCategory, finding.category.as_str()),
    ] {
        insert_search_term(
            transaction,
            case_id,
            Some(&finding.artifact_id),
            Some(&finding.analysis_run_id),
            None,
            Some(&finding.id),
            field,
            value,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_search_term(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
    artifact_id: Option<&ArtifactId>,
    run_id: Option<&AnalysisRunId>,
    evidence_id: Option<&tf_model::EvidenceId>,
    finding_id: Option<&FindingId>,
    field: SearchField,
    value: &str,
) -> Result<(), DatabaseError> {
    let value = truncate_utf8(value.trim(), MAX_INDEX_VALUE_BYTES);
    if value.is_empty() {
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO search_terms(
            case_id, artifact_id, analysis_run_id, evidence_id, finding_id, field, value,
            normalized_value
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            case_id.as_str(),
            artifact_id.map(ArtifactId::as_str),
            run_id.map(AnalysisRunId::as_str),
            evidence_id.map(tf_model::EvidenceId::as_str),
            finding_id.map(FindingId::as_str),
            field.as_str(),
            value,
            value.to_ascii_lowercase()
        ],
    )?;
    Ok(())
}

fn collect_scalars(value: &JsonValue, path: &str, output: &mut Vec<(String, String)>) {
    if output.len() >= MAX_SCALARS_PER_EVIDENCE {
        return;
    }
    match value {
        JsonValue::Object(values) => {
            for (key, child) in values {
                collect_scalars(child, &format!("{path}.{key}"), output);
                if output.len() >= MAX_SCALARS_PER_EVIDENCE {
                    break;
                }
            }
        }
        JsonValue::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_scalars(child, &format!("{path}[{index}]"), output);
                if output.len() >= MAX_SCALARS_PER_EVIDENCE {
                    break;
                }
            }
        }
        JsonValue::String(value) => output.push((path.to_owned(), value.clone())),
        JsonValue::Number(value) => output.push((path.to_owned(), value.to_string())),
        JsonValue::Bool(value) => output.push((path.to_owned(), value.to_string())),
        JsonValue::Null => {}
    }
}

fn refuse_active_analysis(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
) -> Result<(), DatabaseError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
        params![case_id.as_str()],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(DatabaseError::NotFound);
    }
    let active: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM analysis_runs r JOIN artifacts a ON a.id = r.artifact_id
            WHERE a.case_id = ?1 AND r.status IN ('queued', 'running')
         )",
        params![case_id.as_str()],
        |row| row.get(0),
    )?;
    if active {
        Err(DatabaseError::ActiveAnalysis)
    } else {
        Ok(())
    }
}

fn state_or_not_found(
    transaction: &Transaction<'_>,
    case_id: &CaseId,
) -> Result<DatabaseError, DatabaseError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
        params![case_id.as_str()],
        |row| row.get(0),
    )?;
    Ok(if exists {
        DatabaseError::InvalidStateTransition
    } else {
        DatabaseError::NotFound
    })
}

fn load_case(transaction: &Transaction<'_>, case_id: &CaseId) -> Result<Case, DatabaseError> {
    transaction
        .query_row(
            "SELECT id, title, created_at, updated_at, app_version, schema_version, status
             FROM cases WHERE id = ?1",
            params![case_id.as_str()],
            map_case,
        )
        .map_err(Into::into)
}

fn validate_note(note: &AnalystNote) -> Result<(), DatabaseError> {
    validate_note_body(&note.body)?;
    validate_timestamp(&note.created_at)?;
    validate_timestamp(&note.updated_at)?;
    if note.created_at > note.updated_at {
        return Err(DatabaseError::Validation("note timestamps"));
    }
    Ok(())
}

fn validate_note_body(value: &str) -> Result<(), DatabaseError> {
    if value.trim().is_empty()
        || value.len() > MAX_NOTE_BYTES
        || value.chars().any(|character| {
            character == '\0' || (character.is_control() && character != '\n' && character != '\t')
        })
    {
        Err(DatabaseError::Validation("note body"))
    } else {
        Ok(())
    }
}

fn validate_note_links(
    transaction: &Transaction<'_>,
    note: &AnalystNote,
) -> Result<(), DatabaseError> {
    let case_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
        params![note.case_id.as_str()],
        |row| row.get(0),
    )?;
    let entity_valid = if let Some(entity_id) = &note.entity_id {
        transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM entities WHERE id = ?1 AND case_id = ?2)",
            params![entity_id.as_str(), note.case_id.as_str()],
            |row| row.get(0),
        )?
    } else {
        true
    };
    let finding_valid = if let Some(finding_id) = &note.finding_id {
        transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM findings f JOIN artifacts a ON a.id = f.artifact_id
                WHERE f.id = ?1 AND a.case_id = ?2
             )",
            params![finding_id.as_str(), note.case_id.as_str()],
            |row| row.get(0),
        )?
    } else {
        true
    };
    if case_exists && entity_valid && finding_valid {
        Ok(())
    } else {
        Err(DatabaseError::IdentityMismatch)
    }
}

fn load_note(
    transaction: &Transaction<'_>,
    note_id: &NoteId,
) -> Result<AnalystNote, DatabaseError> {
    transaction
        .query_row(
            "SELECT id, case_id, entity_id, finding_id, body, created_at, updated_at
             FROM notes WHERE id = ?1",
            params![note_id.as_str()],
            map_note,
        )
        .map_err(Into::into)
}

fn map_note(row: &rusqlite::Row<'_>) -> Result<AnalystNote, rusqlite::Error> {
    Ok(AnalystNote {
        id: super::parse_text(0, &row.get::<_, String>(0)?)?,
        case_id: super::parse_text(1, &row.get::<_, String>(1)?)?,
        entity_id: parse_optional(row, 2)?,
        finding_id: parse_optional(row, 3)?,
        body: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn parse_optional<T>(row: &rusqlite::Row<'_>, column: usize) -> Result<Option<T>, rusqlite::Error>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    row.get::<_, Option<String>>(column)?
        .as_deref()
        .map(|value| super::parse_text(column, value))
        .transpose()
}

fn validate_text(value: &str, max: usize, label: &'static str) -> Result<(), DatabaseError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| {
            character == '\0' || (character.is_control() && character != '\n' && character != '\t')
        })
    {
        Err(DatabaseError::Validation(label))
    } else {
        Ok(())
    }
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control)
}

fn validate_timestamp(value: &str) -> Result<(), DatabaseError> {
    if valid_timestamp(value) {
        Ok(())
    } else {
        Err(DatabaseError::Validation("timestamp"))
    }
}

fn truncate_utf8(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn all_search_fields() -> BTreeSet<SearchField> {
    [
        SearchField::Sha256,
        SearchField::Sha1,
        SearchField::Md5,
        SearchField::CaseTitle,
        SearchField::Import,
        SearchField::Indicator,
        SearchField::Certificate,
        SearchField::Signer,
        SearchField::RuleId,
        SearchField::FindingTitle,
        SearchField::FindingCategory,
        SearchField::EvidenceValue,
    ]
    .into_iter()
    .collect()
}
