use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use tf_model::{
    AnalysisRunId, ArtifactId, CaseChronology, CaseGraph, CaseId, Edge, Entity, EntityEvidence,
    EvidenceEvent, Finding,
};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{CaseDatabase, DatabaseError, map_finding, parse_json, parse_text};

impl CaseDatabase {
    pub fn projection_finding_history(
        &self,
        case_id: &CaseId,
    ) -> Result<Vec<Finding>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT f.id, f.analysis_run_id, f.artifact_id, f.rule_id, f.rule_version,
                    f.title, f.category, f.severity, f.confidence, f.confidence_band,
                    f.explanation_template_id, f.state
             FROM findings f
             WHERE f.analysis_run_id IS NOT NULL AND f.artifact_id = (
                SELECT a.id FROM artifacts a WHERE a.case_id = ?1
                ORDER BY a.created_at, a.id LIMIT 1
             )
             ORDER BY f.analysis_run_id, f.rule_id, f.id",
        )?;
        statement
            .query_map(params![case_id.as_str()], map_finding)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn projection_cases_needing_rebuild(
        &self,
        projection_version: u32,
    ) -> Result<Vec<CaseId>, DatabaseError> {
        if projection_version == 0 {
            return Err(DatabaseError::Validation("projection version"));
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT c.id
             FROM cases c
             LEFT JOIN case_projections cp ON cp.case_id = c.id
             WHERE cp.case_id IS NULL OR cp.projection_version <> ?1
                OR COALESCE(cp.source_analysis_run_id, '') <> COALESCE((
                    SELECT r.id FROM analysis_runs r
                    WHERE r.artifact_id = (
                        SELECT a.id FROM artifacts a WHERE a.case_id = c.id
                        ORDER BY a.created_at, a.id LIMIT 1
                    )
                    ORDER BY julianday(r.started_at) DESC, r.id DESC LIMIT 1
                ), '')
             ORDER BY c.id",
        )?;
        statement
            .query_map(params![i64::from(projection_version)], |row| {
                parse_text(0, &row.get::<_, String>(0)?)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn replace_case_projection(
        &self,
        graph: &CaseGraph,
        chronology: &CaseChronology,
    ) -> Result<(), DatabaseError> {
        validate_projection_models(graph, chronology)?;
        let entities_json = serde_json::to_string(
            &graph
                .entities
                .iter()
                .map(|entity| entity.id.as_str())
                .collect::<Vec<_>>(),
        )?;
        let edges_json = serde_json::to_string(
            &graph
                .edges
                .iter()
                .map(|edge| edge.id.as_str())
                .collect::<Vec<_>>(),
        )?;
        let events_json = serde_json::to_string(
            &chronology
                .events
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
        )?;
        let normalized_timestamps = chronology
            .events
            .iter()
            .map(|event| normalize_timestamp(&event.timestamp_utc))
            .collect::<Result<Vec<_>, _>>()?;
        let metadata = graph
            .entities
            .iter()
            .map(|entity| serde_json::to_string(&entity.metadata))
            .collect::<Result<Vec<_>, _>>()?;

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest_run = transaction
            .query_row(
                "SELECT r.id FROM analysis_runs r
                 WHERE r.artifact_id = (
                    SELECT a.id FROM artifacts a WHERE a.case_id = ?1
                    ORDER BY a.created_at, a.id LIMIT 1
                 )
                 ORDER BY julianday(r.started_at) DESC, r.id DESC LIMIT 1",
                params![graph.case_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let expected_run = graph
            .source_analysis_run_id
            .as_ref()
            .map(AnalysisRunId::as_str);
        if latest_run.as_deref() != expected_run {
            return Err(DatabaseError::IdentityMismatch);
        }
        let case_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
            params![graph.case_id.as_str()],
            |row| row.get(0),
        )?;
        if !case_exists {
            return Err(DatabaseError::NotFound);
        }
        validate_projection_links(&transaction, graph, chronology)?;

        let overwrites_legacy: bool = transaction.query_row(
            "SELECT
                EXISTS(
                    SELECT 1 FROM entities e JOIN json_each(?1) incoming ON incoming.value = e.id
                    WHERE NOT EXISTS(
                        SELECT 1 FROM projection_entities pe WHERE pe.entity_id = e.id
                    )
                ) OR EXISTS(
                    SELECT 1 FROM edges e JOIN json_each(?2) incoming ON incoming.value = e.id
                    WHERE NOT EXISTS(
                        SELECT 1 FROM projection_edges pe WHERE pe.edge_id = e.id
                    )
                ) OR EXISTS(
                    SELECT 1 FROM events e JOIN json_each(?3) incoming ON incoming.value = e.id
                    WHERE NOT EXISTS(
                        SELECT 1 FROM projection_events pe WHERE pe.event_id = e.id
                    )
                ) OR EXISTS(
                    SELECT 1 FROM edges e
                    WHERE NOT EXISTS(
                        SELECT 1 FROM projection_edges pe WHERE pe.edge_id = e.id
                    ) AND (
                        e.source_entity_id IN (
                            SELECT entity_id FROM projection_entities
                            WHERE case_id = ?4
                              AND entity_id NOT IN (SELECT value FROM json_each(?1))
                        ) OR e.target_entity_id IN (
                            SELECT entity_id FROM projection_entities
                            WHERE case_id = ?4
                              AND entity_id NOT IN (SELECT value FROM json_each(?1))
                        )
                    )
                )",
            params![
                entities_json,
                edges_json,
                events_json,
                graph.case_id.as_str()
            ],
            |row| row.get(0),
        )?;
        if overwrites_legacy {
            return Err(DatabaseError::IdentityMismatch);
        }
        transaction.execute(
            "DELETE FROM bookmarks
             WHERE case_id = ?1 AND (
                (target_type = 'entity'
                 AND target_id IN (
                    SELECT entity_id FROM projection_entities WHERE case_id = ?1
                 )
                 AND target_id NOT IN (SELECT value FROM json_each(?2)))
                OR (target_type = 'edge'
                    AND target_id IN (
                        SELECT edge_id FROM projection_edges WHERE case_id = ?1
                    )
                    AND target_id NOT IN (SELECT value FROM json_each(?3)))
                OR (target_type = 'event'
                    AND target_id IN (
                        SELECT event_id FROM projection_events WHERE case_id = ?1
                    )
                    AND target_id NOT IN (SELECT value FROM json_each(?4)))
             )",
            params![
                graph.case_id.as_str(),
                entities_json,
                edges_json,
                events_json
            ],
        )?;
        transaction.execute(
            "DELETE FROM entity_evidence WHERE entity_id IN
                (SELECT entity_id FROM projection_entities WHERE case_id = ?1)",
            params![graph.case_id.as_str()],
        )?;
        transaction.execute(
            "DELETE FROM edges WHERE id IN
                (SELECT edge_id FROM projection_edges WHERE case_id = ?1)",
            params![graph.case_id.as_str()],
        )?;
        transaction.execute(
            "DELETE FROM events WHERE id IN
                (SELECT event_id FROM projection_events WHERE case_id = ?1)",
            params![graph.case_id.as_str()],
        )?;
        transaction.execute(
            "DELETE FROM entities WHERE id IN
                (SELECT entity_id FROM projection_entities WHERE case_id = ?1)
               AND id NOT IN (SELECT value FROM json_each(?2))",
            params![graph.case_id.as_str(), entities_json],
        )?;
        for (entity, metadata_json) in graph.entities.iter().zip(metadata) {
            let changed = transaction.execute(
                "INSERT INTO entities(
                    id, case_id, entity_type, canonical_value, display_value, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    entity_type = excluded.entity_type,
                    canonical_value = excluded.canonical_value,
                    display_value = excluded.display_value,
                    metadata_json = excluded.metadata_json
                 WHERE entities.case_id = excluded.case_id",
                params![
                    entity.id.as_str(),
                    entity.case_id.as_str(),
                    entity.entity_type.as_str(),
                    entity.canonical_value,
                    entity.display_value,
                    metadata_json,
                ],
            )?;
            if changed != 1 {
                return Err(DatabaseError::IdentityMismatch);
            }
            transaction.execute(
                "INSERT INTO projection_entities(entity_id, case_id) VALUES (?1, ?2)
                 ON CONFLICT(entity_id) DO UPDATE SET case_id = excluded.case_id",
                params![entity.id.as_str(), graph.case_id.as_str()],
            )?;
        }
        for link in &graph.entity_evidence {
            transaction.execute(
                "INSERT INTO entity_evidence(entity_id, evidence_id, role) VALUES (?1, ?2, ?3)",
                params![
                    link.entity_id.as_str(),
                    link.evidence_id.as_str(),
                    link.role.as_str()
                ],
            )?;
        }
        for edge in &graph.edges {
            transaction.execute(
                "INSERT INTO edges(
                    id, source_entity_id, target_entity_id, relationship, evidence_id, confidence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    edge.id.as_str(),
                    edge.source_entity_id.as_str(),
                    edge.target_entity_id.as_str(),
                    edge.relationship.as_str(),
                    edge.evidence_id.as_str(),
                    edge.confidence.value(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO projection_edges(edge_id, case_id) VALUES (?1, ?2)",
                params![edge.id.as_str(), graph.case_id.as_str()],
            )?;
        }
        for (event, timestamp_utc) in chronology.events.iter().zip(normalized_timestamps) {
            transaction.execute(
                "INSERT INTO events(
                    id, case_id, timestamp_utc, timestamp_type, reliability, event_type,
                    artifact_id, evidence_id, summary
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    event.id.as_str(),
                    event.case_id.as_str(),
                    timestamp_utc,
                    event.timestamp_type,
                    event.reliability.as_str(),
                    event.event_type,
                    event.artifact_id.as_ref().map(ArtifactId::as_str),
                    event.evidence_id.as_ref().map(tf_model::EvidenceId::as_str),
                    event.summary,
                ],
            )?;
            transaction.execute(
                "INSERT INTO projection_events(event_id, case_id) VALUES (?1, ?2)",
                params![event.id.as_str(), graph.case_id.as_str()],
            )?;
        }
        transaction.execute(
            "INSERT INTO case_projections(case_id, projection_version, source_analysis_run_id)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(case_id) DO UPDATE SET
                projection_version = excluded.projection_version,
                source_analysis_run_id = excluded.source_analysis_run_id",
            params![
                graph.case_id.as_str(),
                i64::from(graph.projection_version),
                expected_run,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_case_graph(&self, case_id: &CaseId) -> Result<Option<CaseGraph>, DatabaseError> {
        let connection = self.lock()?;
        let state = projection_state(&connection, case_id)?;
        let Some((projection_version, source_analysis_run_id)) = state else {
            return Ok(None);
        };
        let entities = {
            let mut statement = connection.prepare(
                "SELECT id, case_id, entity_type, canonical_value, display_value, metadata_json
                 FROM entities WHERE case_id = ?1 ORDER BY entity_type, canonical_value, id",
            )?;
            statement
                .query_map(params![case_id.as_str()], map_entity)?
                .collect::<Result<Vec<_>, _>>()?
        };
        let edges = {
            let mut statement = connection.prepare(
                "SELECT e.id, e.source_entity_id, e.target_entity_id, e.relationship,
                        e.evidence_id, e.confidence
                 FROM edges e JOIN entities source ON source.id = e.source_entity_id
                 WHERE source.case_id = ?1
                 ORDER BY e.relationship, e.source_entity_id, e.target_entity_id, e.id",
            )?;
            statement
                .query_map(params![case_id.as_str()], map_edge)?
                .collect::<Result<Vec<_>, _>>()?
        };
        let entity_evidence = {
            let mut statement = connection.prepare(
                "SELECT ee.entity_id, ee.evidence_id, ee.role
                 FROM entity_evidence ee JOIN entities e ON e.id = ee.entity_id
                 WHERE e.case_id = ?1 ORDER BY ee.entity_id, ee.evidence_id",
            )?;
            statement
                .query_map(params![case_id.as_str()], map_entity_evidence)?
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(Some(CaseGraph {
            case_id: case_id.clone(),
            projection_version,
            source_analysis_run_id,
            entities,
            edges,
            entity_evidence,
        }))
    }

    pub fn get_case_chronology(
        &self,
        case_id: &CaseId,
    ) -> Result<Option<CaseChronology>, DatabaseError> {
        let connection = self.lock()?;
        let state = projection_state(&connection, case_id)?;
        let Some((projection_version, source_analysis_run_id)) = state else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT id, case_id, timestamp_utc, timestamp_type, reliability, event_type,
                    artifact_id, evidence_id, summary
             FROM events WHERE case_id = ?1
             ORDER BY timestamp_utc, event_type, id",
        )?;
        let mut events = statement
            .query_map(params![case_id.as_str()], map_event)?
            .collect::<Result<Vec<_>, _>>()?;
        events.sort_by(|left, right| {
            parse_timestamp(&left.timestamp_utc)
                .cmp(&parse_timestamp(&right.timestamp_utc))
                .then_with(|| left.timestamp_utc.cmp(&right.timestamp_utc))
                .then_with(|| left.event_type.cmp(&right.event_type))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Some(CaseChronology {
            case_id: case_id.clone(),
            projection_version,
            source_analysis_run_id,
            events,
        }))
    }
}

fn validate_projection_models(
    graph: &CaseGraph,
    chronology: &CaseChronology,
) -> Result<(), DatabaseError> {
    let entity_ids = graph
        .entities
        .iter()
        .map(|entity| &entity.id)
        .collect::<BTreeSet<_>>();
    let edge_ids = graph
        .edges
        .iter()
        .map(|edge| &edge.id)
        .collect::<BTreeSet<_>>();
    let event_ids = chronology
        .events
        .iter()
        .map(|event| &event.id)
        .collect::<BTreeSet<_>>();
    let link_keys = graph
        .entity_evidence
        .iter()
        .map(|link| (&link.entity_id, &link.evidence_id))
        .collect::<BTreeSet<_>>();
    if graph.projection_version == 0
        || graph.case_id != chronology.case_id
        || graph.projection_version != chronology.projection_version
        || graph.source_analysis_run_id != chronology.source_analysis_run_id
        || entity_ids.len() != graph.entities.len()
        || edge_ids.len() != graph.edges.len()
        || event_ids.len() != chronology.events.len()
        || link_keys.len() != graph.entity_evidence.len()
        || graph.entities.iter().any(|entity| {
            entity.case_id != graph.case_id
                || entity.canonical_value.trim().is_empty()
                || entity.display_value.trim().is_empty()
        })
        || graph.edges.iter().any(|edge| {
            !entity_ids.contains(&edge.source_entity_id)
                || !entity_ids.contains(&edge.target_entity_id)
        })
        || graph
            .entity_evidence
            .iter()
            .any(|link| !entity_ids.contains(&link.entity_id))
        || chronology.events.iter().any(|event| {
            event.case_id != graph.case_id
                || event.timestamp_utc.is_empty()
                || event.timestamp_type.trim().is_empty()
                || event.event_type.trim().is_empty()
                || event.summary.trim().is_empty()
        })
    {
        return Err(DatabaseError::IdentityMismatch);
    }
    Ok(())
}

fn validate_projection_links(
    transaction: &rusqlite::Transaction<'_>,
    graph: &CaseGraph,
    chronology: &CaseChronology,
) -> Result<(), DatabaseError> {
    let source_run = graph
        .source_analysis_run_id
        .as_ref()
        .map(AnalysisRunId::as_str);
    for evidence_id in graph
        .edges
        .iter()
        .map(|edge| &edge.evidence_id)
        .chain(graph.entity_evidence.iter().map(|link| &link.evidence_id))
        .chain(
            chronology
                .events
                .iter()
                .filter_map(|event| event.evidence_id.as_ref()),
        )
    {
        let valid: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM evidence e
                JOIN provenance p ON p.id = e.provenance_id
                JOIN artifacts a ON a.id = e.artifact_id
                WHERE e.id = ?1 AND a.case_id = ?2 AND p.analysis_run_id = ?3
             )",
            params![evidence_id.as_str(), graph.case_id.as_str(), source_run],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(DatabaseError::IdentityMismatch);
        }
    }
    for artifact_id in chronology
        .events
        .iter()
        .filter_map(|event| event.artifact_id.as_ref())
    {
        let valid: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = ?1 AND case_id = ?2)",
            params![artifact_id.as_str(), graph.case_id.as_str()],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(DatabaseError::IdentityMismatch);
        }
    }
    Ok(())
}

fn projection_state(
    connection: &rusqlite::Connection,
    case_id: &CaseId,
) -> Result<Option<(u32, Option<AnalysisRunId>)>, DatabaseError> {
    connection
        .query_row(
            "SELECT cp.projection_version, cp.source_analysis_run_id
             FROM case_projections cp
             WHERE cp.case_id = ?1
               AND COALESCE(cp.source_analysis_run_id, '') = COALESCE((
                    SELECT r.id FROM analysis_runs r
                    WHERE r.artifact_id = (
                        SELECT a.id FROM artifacts a WHERE a.case_id = cp.case_id
                        ORDER BY a.created_at, a.id LIMIT 1
                    )
                     ORDER BY julianday(r.started_at) DESC, r.id DESC LIMIT 1
               ), '')",
            params![case_id.as_str()],
            |row| {
                let version = row.get::<_, i64>(0)?;
                let source = row.get::<_, Option<String>>(1)?;
                Ok((
                    u32::try_from(version)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, version))?,
                    source
                        .as_deref()
                        .map(|value| parse_text(1, value))
                        .transpose()?,
                ))
            },
        )
        .optional()
        .map_err(Into::into)
}

fn map_entity(row: &Row<'_>) -> Result<Entity, rusqlite::Error> {
    Ok(Entity {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        case_id: parse_text(1, &row.get::<_, String>(1)?)?,
        entity_type: parse_text(2, &row.get::<_, String>(2)?)?,
        canonical_value: row.get(3)?,
        display_value: row.get(4)?,
        metadata: parse_json(5, &row.get::<_, String>(5)?)?,
    })
}

fn map_edge(row: &Row<'_>) -> Result<Edge, rusqlite::Error> {
    let confidence = row.get::<_, f32>(5)?;
    Ok(Edge {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        source_entity_id: parse_text(1, &row.get::<_, String>(1)?)?,
        target_entity_id: parse_text(2, &row.get::<_, String>(2)?)?,
        relationship: parse_text(3, &row.get::<_, String>(3)?)?,
        evidence_id: parse_text(4, &row.get::<_, String>(4)?)?,
        confidence: tf_model::Confidence::new(confidence).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Real,
                Box::new(error),
            )
        })?,
    })
}

fn map_entity_evidence(row: &Row<'_>) -> Result<EntityEvidence, rusqlite::Error> {
    Ok(EntityEvidence {
        entity_id: parse_text(0, &row.get::<_, String>(0)?)?,
        evidence_id: parse_text(1, &row.get::<_, String>(1)?)?,
        role: parse_text(2, &row.get::<_, String>(2)?)?,
    })
}

fn map_event(row: &Row<'_>) -> Result<EvidenceEvent, rusqlite::Error> {
    Ok(EvidenceEvent {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        case_id: parse_text(1, &row.get::<_, String>(1)?)?,
        timestamp_utc: row.get(2)?,
        timestamp_type: row.get(3)?,
        reliability: parse_text(4, &row.get::<_, String>(4)?)?,
        event_type: row.get(5)?,
        artifact_id: row
            .get::<_, Option<String>>(6)?
            .as_deref()
            .map(|value| parse_text(6, value))
            .transpose()?,
        evidence_id: row
            .get::<_, Option<String>>(7)?
            .as_deref()
            .map(|value| parse_text(7, value))
            .transpose()?,
        summary: row.get(8)?,
    })
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn normalize_timestamp(value: &str) -> Result<String, DatabaseError> {
    parse_timestamp(value)
        .ok_or(DatabaseError::Validation("event timestamp"))?
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| DatabaseError::Validation("event timestamp"))
}
