CREATE TABLE bookmarks (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (
        target_type IN ('evidence', 'finding', 'entity', 'edge', 'event')
    ),
    target_id TEXT NOT NULL,
    label TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 256),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (case_id, target_type, target_id)
) STRICT;

CREATE INDEX bookmarks_case_created
    ON bookmarks(case_id, created_at, id);

-- v7 expands the controlled graph vocabulary. Recreate only the affected guards so a
-- database already migrated to v6 upgrades without rebuilding authoritative evidence.
DROP TRIGGER entities_controlled_insert;
DROP TRIGGER entities_controlled_update;
DROP TRIGGER edges_controlled_insert;
DROP TRIGGER edges_controlled_update;
DROP TRIGGER events_controlled_insert;
DROP TRIGGER events_controlled_update;

CREATE TRIGGER entities_controlled_insert
BEFORE INSERT ON entities
WHEN NEW.entity_type NOT IN (
    'artifact', 'section', 'imported_api', 'export', 'url', 'domain', 'ip_address',
    'file_path', 'registry_path', 'registry_key', 'command_string', 'certificate',
    'signer', 'yara_rule', 'finding', 'network_flow', 'host', 'process'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported entity type');
END;

CREATE TRIGGER entities_controlled_update
BEFORE UPDATE OF entity_type ON entities
WHEN NEW.entity_type NOT IN (
    'artifact', 'section', 'imported_api', 'export', 'url', 'domain', 'ip_address',
    'file_path', 'registry_path', 'registry_key', 'command_string', 'certificate',
    'signer', 'yara_rule', 'finding', 'network_flow', 'host', 'process'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported entity type');
END;

CREATE TRIGGER edges_controlled_insert
BEFORE INSERT ON edges
WHEN NEW.relationship NOT IN (
    'contains', 'imports', 'exports', 'contains_indicator', 'references_path',
    'signed_by', 'uses_certificate', 'matched_rule', 'supports_finding',
    'contradicts_finding', 'derived_from', 'resolves_to', 'communicates_with'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported relationship');
END;

CREATE TRIGGER edges_controlled_update
BEFORE UPDATE OF relationship ON edges
WHEN NEW.relationship NOT IN (
    'contains', 'imports', 'exports', 'contains_indicator', 'references_path',
    'signed_by', 'uses_certificate', 'matched_rule', 'supports_finding',
    'contradicts_finding', 'derived_from', 'resolves_to', 'communicates_with'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported relationship');
END;

CREATE TRIGGER events_controlled_insert
BEFORE INSERT ON events
WHEN NEW.reliability NOT IN (
    'attacker_controlled', 'filesystem_metadata', 'cryptographically_bound',
    'application_recorded', 'application_generated', 'imported_telemetry'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported timestamp reliability');
END;

CREATE TRIGGER events_controlled_update
BEFORE UPDATE OF reliability ON events
WHEN NEW.reliability NOT IN (
    'attacker_controlled', 'filesystem_metadata', 'cryptographically_bound',
    'application_recorded', 'application_generated', 'imported_telemetry'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported timestamp reliability');
END;

PRAGMA user_version = 7;
