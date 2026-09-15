CREATE TABLE yara_packs (
    id TEXT PRIMARY KEY NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 1024),
    license TEXT NOT NULL CHECK (length(license) BETWEEN 1 AND 256),
    imported_at TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    storage_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 524288),
    UNIQUE (name, version)
) STRICT;

CREATE TABLE yara_pack_rules (
    pack_id TEXT NOT NULL REFERENCES yara_packs(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 256),
    identifier TEXT NOT NULL CHECK (length(identifier) BETWEEN 1 AND 256),
    tags_json TEXT NOT NULL CHECK (json_valid(tags_json)),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    PRIMARY KEY (pack_id, namespace, identifier)
) STRICT, WITHOUT ROWID;

CREATE INDEX yara_packs_enabled_hash ON yara_packs(enabled, sha256);
CREATE INDEX yara_packs_identity ON yara_packs(name, version);
CREATE INDEX provenance_run_analyzer ON provenance(analysis_run_id, analyzer, id);
CREATE INDEX evidence_provenance_kind ON evidence(provenance_id, kind, id);

PRAGMA user_version = 4;
