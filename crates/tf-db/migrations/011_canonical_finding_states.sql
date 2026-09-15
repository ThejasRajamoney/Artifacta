-- Persist the public v1 finding vocabulary instead of relying on read-time aliases.
UPDATE findings SET state = 'new' WHERE state = 'open';
UPDATE findings SET state = 'reviewed' WHERE state = 'acknowledged';

UPDATE entities
SET metadata_json = json_set(
    metadata_json,
    '$.state',
    CASE json_extract(metadata_json, '$.state')
        WHEN 'open' THEN 'new'
        WHEN 'acknowledged' THEN 'reviewed'
    END
)
WHERE entity_type = 'finding'
  AND json_extract(metadata_json, '$.state') IN ('open', 'acknowledged');

-- Complete the child-key indexes used by cascades and SET NULL operations.
CREATE INDEX IF NOT EXISTS artifacts_parent_artifact_id ON artifacts(parent_artifact_id);
CREATE INDEX IF NOT EXISTS case_projections_source_analysis_run_id
    ON case_projections(source_analysis_run_id);
CREATE INDEX IF NOT EXISTS reports_case_id ON reports(case_id);

PRAGMA user_version = 11;
