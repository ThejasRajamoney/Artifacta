use rusqlite::{OptionalExtension, Row, params};
use tf_model::{
    Bookmark, BookmarkId, CaseId, EdgeId, EntityId, EventId, EvidenceId, FindingId,
    NavigationTarget,
};

use super::{CaseDatabase, DatabaseError, parse_text};

pub const MAX_BOOKMARK_LABEL_BYTES: usize = 256;

impl CaseDatabase {
    pub fn insert_bookmark(&self, bookmark: &Bookmark) -> Result<(), DatabaseError> {
        validate_bookmark(bookmark)?;
        let connection = self.lock()?;
        validate_target_case(&connection, &bookmark.case_id, &bookmark.target)?;
        connection.execute(
            "INSERT INTO bookmarks(
                id, case_id, target_type, target_id, label, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                bookmark.id.as_str(),
                bookmark.case_id.as_str(),
                bookmark.target.target_type(),
                bookmark.target.target_id(),
                bookmark.label,
                bookmark.created_at,
                bookmark.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_bookmark(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
    ) -> Result<Option<Bookmark>, DatabaseError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT id, case_id, target_type, target_id, label, created_at, updated_at
                 FROM bookmarks WHERE id = ?1 AND case_id = ?2",
                params![bookmark_id.as_str(), case_id.as_str()],
                map_bookmark,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_bookmarks(&self, case_id: &CaseId) -> Result<Vec<Bookmark>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, case_id, target_type, target_id, label, created_at, updated_at
             FROM bookmarks WHERE case_id = ?1 ORDER BY created_at, id",
        )?;
        statement
            .query_map(params![case_id.as_str()], map_bookmark)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn update_bookmark_label(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
        label: Option<&str>,
        updated_at: &str,
    ) -> Result<Bookmark, DatabaseError> {
        validate_label(label)?;
        validate_timestamp(updated_at)?;
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE bookmarks SET label = ?1, updated_at = ?2
             WHERE id = ?3 AND case_id = ?4",
            params![label, updated_at, bookmark_id.as_str(), case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        connection
            .query_row(
                "SELECT id, case_id, target_type, target_id, label, created_at, updated_at
                 FROM bookmarks WHERE id = ?1",
                params![bookmark_id.as_str()],
                map_bookmark,
            )
            .map_err(Into::into)
    }

    pub fn delete_bookmark(
        &self,
        case_id: &CaseId,
        bookmark_id: &BookmarkId,
    ) -> Result<(), DatabaseError> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "DELETE FROM bookmarks WHERE id = ?1 AND case_id = ?2",
            params![bookmark_id.as_str(), case_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }
}

fn validate_bookmark(bookmark: &Bookmark) -> Result<(), DatabaseError> {
    validate_label(bookmark.label.as_deref())?;
    validate_timestamp(&bookmark.created_at)?;
    validate_timestamp(&bookmark.updated_at)?;
    if bookmark.created_at > bookmark.updated_at {
        return Err(DatabaseError::Validation("bookmark timestamps"));
    }
    Ok(())
}

fn validate_label(label: Option<&str>) -> Result<(), DatabaseError> {
    if label.is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_BOOKMARK_LABEL_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        Err(DatabaseError::Validation("bookmark label"))
    } else {
        Ok(())
    }
}

fn validate_timestamp(value: &str) -> Result<(), DatabaseError> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        Err(DatabaseError::Validation("bookmark timestamp"))
    } else {
        Ok(())
    }
}

fn validate_target_case(
    connection: &rusqlite::Connection,
    case_id: &CaseId,
    target: &NavigationTarget,
) -> Result<(), DatabaseError> {
    let valid: bool = match target {
        NavigationTarget::Evidence { evidence_id } => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM evidence e JOIN artifacts a ON a.id = e.artifact_id
                WHERE e.id = ?1 AND a.case_id = ?2
             )",
            params![evidence_id.as_str(), case_id.as_str()],
            |row| row.get(0),
        )?,
        NavigationTarget::Finding { finding_id } => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM findings f JOIN artifacts a ON a.id = f.artifact_id
                WHERE f.id = ?1 AND a.case_id = ?2
             )",
            params![finding_id.as_str(), case_id.as_str()],
            |row| row.get(0),
        )?,
        NavigationTarget::Entity { entity_id } => connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM entities WHERE id = ?1 AND case_id = ?2)",
            params![entity_id.as_str(), case_id.as_str()],
            |row| row.get(0),
        )?,
        NavigationTarget::Edge { edge_id } => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM edges edge
                JOIN entities source ON source.id = edge.source_entity_id
                JOIN entities target ON target.id = edge.target_entity_id
                WHERE edge.id = ?1 AND source.case_id = ?2 AND target.case_id = ?2
             )",
            params![edge_id.as_str(), case_id.as_str()],
            |row| row.get(0),
        )?,
        NavigationTarget::Event { event_id } => connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE id = ?1 AND case_id = ?2)",
            params![event_id.as_str(), case_id.as_str()],
            |row| row.get(0),
        )?,
    };
    if valid {
        Ok(())
    } else {
        Err(DatabaseError::IdentityMismatch)
    }
}

fn map_bookmark(row: &Row<'_>) -> Result<Bookmark, rusqlite::Error> {
    let target_type = row.get::<_, String>(2)?;
    let target_id = row.get::<_, String>(3)?;
    let target = match target_type.as_str() {
        "evidence" => NavigationTarget::Evidence {
            evidence_id: parse_text::<EvidenceId>(3, &target_id)?,
        },
        "finding" => NavigationTarget::Finding {
            finding_id: parse_text::<FindingId>(3, &target_id)?,
        },
        "entity" => NavigationTarget::Entity {
            entity_id: parse_text::<EntityId>(3, &target_id)?,
        },
        "edge" => NavigationTarget::Edge {
            edge_id: parse_text::<EdgeId>(3, &target_id)?,
        },
        "event" => NavigationTarget::Event {
            event_id: parse_text::<EventId>(3, &target_id)?,
        },
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                "unsupported bookmark target type".into(),
            ));
        }
    };
    Ok(Bookmark {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        case_id: parse_text(1, &row.get::<_, String>(1)?)?,
        target,
        label: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}
