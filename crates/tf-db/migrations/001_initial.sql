CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    app_version TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'complete', 'archived', 'error'))
) STRICT;

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    parent_artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    sha1 TEXT NOT NULL CHECK (length(sha1) = 40),
    md5 TEXT NOT NULL CHECK (length(md5) = 32),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    kind TEXT NOT NULL,
    mime TEXT,
    original_name TEXT NOT NULL,
    store_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (case_id, sha256)
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_locations (
    id TEXT PRIMARY KEY NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    source_path TEXT,
    modified_at_utc TEXT,
    created_at_utc TEXT,
    ingested_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS analysis_runs (
    id TEXT PRIMARY KEY NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    analyzer TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    error_code TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS provenance (
    id TEXT PRIMARY KEY NOT NULL,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    analyzer TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    rule_id TEXT,
    rule_version TEXT,
    rule_pack_sha256 TEXT,
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    parameters_json TEXT NOT NULL CHECK (json_valid(parameters_json))
) STRICT;

CREATE TABLE IF NOT EXISTS blobs (
    id TEXT PRIMARY KEY NOT NULL,
    sha256 TEXT NOT NULL UNIQUE CHECK (length(sha256) = 64),
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    store_path TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    provenance_id TEXT NOT NULL REFERENCES provenance(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    class TEXT NOT NULL,
    locator_json TEXT NOT NULL CHECK (json_valid(locator_json)),
    value_json TEXT NOT NULL CHECK (json_valid(value_json)),
    preview_text TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    confidence_band TEXT NOT NULL,
    explanation_template_id TEXT NOT NULL,
    state TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    UNIQUE (case_id, entity_type, canonical_value)
) STRICT;

CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY NOT NULL,
    source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0)
) STRICT;

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY NOT NULL,
    engine TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    license TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    UNIQUE (engine, rule_id, version)
) STRICT;

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    timestamp_utc TEXT NOT NULL,
    timestamp_type TEXT NOT NULL,
    reliability TEXT NOT NULL,
    event_type TEXT NOT NULL,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    summary TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
    finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64)
) STRICT;

CREATE INDEX IF NOT EXISTS artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS artifact_locations_artifact_id ON artifact_locations(artifact_id);
CREATE INDEX IF NOT EXISTS analysis_runs_artifact_id ON analysis_runs(artifact_id);
CREATE INDEX IF NOT EXISTS provenance_analysis_run_id ON provenance(analysis_run_id);
CREATE INDEX IF NOT EXISTS evidence_artifact_id ON evidence(artifact_id);
CREATE INDEX IF NOT EXISTS findings_artifact_id ON findings(artifact_id);
CREATE INDEX IF NOT EXISTS entities_case_id ON entities(case_id);
CREATE INDEX IF NOT EXISTS events_case_timestamp_utc ON events(case_id, timestamp_utc);

PRAGMA user_version = 1;
