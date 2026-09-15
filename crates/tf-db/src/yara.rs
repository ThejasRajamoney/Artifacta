use rusqlite::{OptionalExtension, params};
use tf_model::{YaraPack, YaraPackId, YaraRuleMetadata};

use super::{CaseDatabase, DatabaseError, parse_text, sqlite_integer};

#[derive(Debug, Clone, PartialEq)]
pub struct StoredYaraPack {
    pub pack: YaraPack,
    pub storage_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedYaraPack {
    pub sha256: String,
    pub storage_path: String,
    pub shared: bool,
}

impl CaseDatabase {
    pub fn insert_yara_pack(
        &self,
        pack: &YaraPack,
        rules: &[YaraRuleMetadata],
        storage_path: &str,
        size_bytes: u64,
    ) -> Result<(), DatabaseError> {
        validate_pack(pack, rules, storage_path, size_bytes)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT sha256 FROM yara_packs WHERE name = ?1 AND version = ?2",
                params![pack.name, pack.version],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(hash) = existing {
            if !hash.eq_ignore_ascii_case(&pack.sha256) {
                return Err(DatabaseError::YaraPackIdentityConflict);
            }
            return Err(DatabaseError::Validation("YARA pack already exists"));
        }
        transaction.execute(
            "INSERT INTO yara_packs
                (id, sha256, name, version, source, license, imported_at, enabled,
                 storage_path, size_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                pack.id.as_str(),
                pack.sha256.to_ascii_lowercase(),
                pack.name,
                pack.version,
                pack.source,
                pack.license,
                pack.imported_at,
                pack.enabled,
                storage_path,
                sqlite_integer(size_bytes)?,
            ],
        )?;
        for rule in rules {
            transaction.execute(
                "INSERT INTO yara_pack_rules
                    (pack_id, namespace, identifier, tags_json, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    pack.id.as_str(),
                    rule.namespace,
                    rule.identifier,
                    serde_json::to_string(&rule.tags)?,
                    serde_json::to_string(&rule.metadata)?,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_yara_packs(&self) -> Result<Vec<YaraPack>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, sha256, name, version, source, license, imported_at, enabled,
                    (SELECT COUNT(*) FROM yara_pack_rules r WHERE r.pack_id = yara_packs.id)
             FROM yara_packs ORDER BY name COLLATE NOCASE, version, id",
        )?;
        statement
            .query_map([], map_pack)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn enabled_yara_packs(&self) -> Result<Vec<StoredYaraPack>, DatabaseError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, sha256, name, version, source, license, imported_at, enabled,
                    (SELECT COUNT(*) FROM yara_pack_rules r WHERE r.pack_id = yara_packs.id),
                    storage_path, size_bytes
             FROM yara_packs WHERE enabled = 1 ORDER BY name COLLATE NOCASE, version, id",
        )?;
        statement
            .query_map([], |row| {
                let size = row.get::<_, i64>(10)?;
                Ok(StoredYaraPack {
                    pack: map_pack(row)?,
                    storage_path: row.get(9)?,
                    size_bytes: u64::try_from(size)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(10, size))?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn set_yara_pack_enabled(
        &self,
        pack_id: &YaraPackId,
        enabled: bool,
    ) -> Result<YaraPack, DatabaseError> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE yara_packs SET enabled = ?1 WHERE id = ?2",
            params![enabled, pack_id.as_str()],
        )?;
        if changed != 1 {
            return Err(DatabaseError::NotFound);
        }
        connection
            .query_row(
                "SELECT id, sha256, name, version, source, license, imported_at, enabled,
                        (SELECT COUNT(*) FROM yara_pack_rules r WHERE r.pack_id = yara_packs.id)
                 FROM yara_packs WHERE id = ?1",
                params![pack_id.as_str()],
                map_pack,
            )
            .map_err(Into::into)
    }

    pub fn delete_yara_pack(&self, pack_id: &YaraPackId) -> Result<DeletedYaraPack, DatabaseError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let (sha256, storage_path) = transaction
            .query_row(
                "SELECT sha256, storage_path FROM yara_packs WHERE id = ?1",
                params![pack_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(DatabaseError::NotFound)?;
        transaction.execute(
            "DELETE FROM yara_packs WHERE id = ?1",
            params![pack_id.as_str()],
        )?;
        let shared: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM yara_packs WHERE storage_path = ?1)",
            params![storage_path],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(DeletedYaraPack {
            sha256,
            storage_path,
            shared,
        })
    }
}

fn map_pack(row: &rusqlite::Row<'_>) -> Result<YaraPack, rusqlite::Error> {
    let rule_count = row.get::<_, i64>(8)?;
    Ok(YaraPack {
        id: parse_text(0, &row.get::<_, String>(0)?)?,
        sha256: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        source: row.get(4)?,
        license: row.get(5)?,
        imported_at: row.get(6)?,
        enabled: row.get(7)?,
        rule_count: u32::try_from(rule_count)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(8, rule_count))?,
    })
}

fn validate_pack(
    pack: &YaraPack,
    rules: &[YaraRuleMetadata],
    storage_path: &str,
    size_bytes: u64,
) -> Result<(), DatabaseError> {
    let valid_hash =
        pack.sha256.len() == 64 && pack.sha256.bytes().all(|byte| byte.is_ascii_hexdigit());
    let valid_text = |value: &str, max: usize| {
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    let identities = rules
        .iter()
        .map(|rule| (&rule.namespace, &rule.identifier))
        .collect::<std::collections::BTreeSet<_>>();
    if !valid_hash
        || !valid_text(&pack.name, 256)
        || !valid_text(&pack.version, 128)
        || !valid_text(&pack.source, 1024)
        || !valid_text(&pack.license, 256)
        || pack.imported_at.is_empty()
        || storage_path.is_empty()
        || storage_path.len() > 4096
        || size_bytes == 0
        || size_bytes > tf_protocol::MAX_YARA_PACK_BYTES as u64
        || rules.is_empty()
        || usize::try_from(pack.rule_count).ok() != Some(rules.len())
        || identities.len() != rules.len()
    {
        return Err(DatabaseError::Validation("YARA pack"));
    }
    for rule in rules {
        if !valid_text(&rule.namespace, 256)
            || !valid_text(&rule.identifier, 256)
            || serde_json::to_vec(&rule.tags)?.len() > 64 * 1024
            || serde_json::to_vec(&rule.metadata)?.len() > 256 * 1024
        {
            return Err(DatabaseError::Validation("YARA rule metadata"));
        }
    }
    Ok(())
}
