CREATE TABLE report_manifests (
    id TEXT PRIMARY KEY NOT NULL,
    report_id TEXT NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    generated_at TEXT NOT NULL,
    path TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    snapshot_sha256 TEXT NOT NULL CHECK (length(snapshot_sha256) = 64),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64)
) STRICT;

CREATE INDEX report_manifests_case_generated
    ON report_manifests(case_id, generated_at DESC, id DESC);

PRAGMA user_version = 8;
