-- Existing graph and chronology rows predate projection ownership metadata and may be
-- authoritative. Preserve them; only rows recorded in the ownership tables below may be rebuilt.

CREATE TABLE entity_evidence (
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('supports', 'context', 'contradicts')),
    PRIMARY KEY (entity_id, evidence_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE case_projections (
    case_id TEXT PRIMARY KEY NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    projection_version INTEGER NOT NULL CHECK (projection_version > 0),
    source_analysis_run_id TEXT REFERENCES analysis_runs(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE projection_entities (
    entity_id TEXT PRIMARY KEY NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE projection_edges (
    edge_id TEXT PRIMARY KEY NOT NULL REFERENCES edges(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE projection_events (
    event_id TEXT PRIMARY KEY NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX edges_source_entity_id ON edges(source_entity_id);
CREATE INDEX edges_target_entity_id ON edges(target_entity_id);
CREATE INDEX entity_evidence_evidence_id ON entity_evidence(evidence_id);
CREATE INDEX events_case_order
    ON events(case_id, timestamp_utc, event_type, id);

CREATE TRIGGER entities_controlled_insert
BEFORE INSERT ON entities
WHEN NEW.entity_type NOT IN (
    'artifact', 'section', 'imported_api', 'export', 'url', 'domain', 'ip_address',
    'file_path', 'command_string', 'certificate', 'signer', 'yara_rule', 'finding',
    'network_flow', 'host', 'process'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported entity type');
END;

CREATE TRIGGER entities_controlled_update
BEFORE UPDATE OF entity_type ON entities
WHEN NEW.entity_type NOT IN (
    'artifact', 'section', 'imported_api', 'export', 'url', 'domain', 'ip_address',
    'file_path', 'command_string', 'certificate', 'signer', 'yara_rule', 'finding',
    'network_flow', 'host', 'process'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported entity type');
END;

CREATE TRIGGER edges_controlled_insert
BEFORE INSERT ON edges
WHEN NEW.relationship NOT IN (
    'contains', 'imports', 'exports', 'contains_indicator', 'references_path',
    'signed_by', 'matched_rule', 'supports_finding', 'contradicts_finding',
    'derived_from', 'resolves_to', 'communicates_with'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported relationship');
END;

CREATE TRIGGER edges_controlled_update
BEFORE UPDATE OF relationship ON edges
WHEN NEW.relationship NOT IN (
    'contains', 'imports', 'exports', 'contains_indicator', 'references_path',
    'signed_by', 'matched_rule', 'supports_finding', 'contradicts_finding',
    'derived_from', 'resolves_to', 'communicates_with'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported relationship');
END;

CREATE TRIGGER events_controlled_insert
BEFORE INSERT ON events
WHEN NEW.reliability NOT IN (
    'attacker_controlled', 'filesystem_metadata', 'cryptographically_bound',
    'application_recorded', 'imported_telemetry'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported timestamp reliability');
END;

CREATE TRIGGER events_controlled_update
BEFORE UPDATE OF reliability ON events
WHEN NEW.reliability NOT IN (
    'attacker_controlled', 'filesystem_metadata', 'cryptographically_bound',
    'application_recorded', 'imported_telemetry'
)
BEGIN
    SELECT RAISE(ABORT, 'unsupported timestamp reliability');
END;

PRAGMA user_version = 6;
