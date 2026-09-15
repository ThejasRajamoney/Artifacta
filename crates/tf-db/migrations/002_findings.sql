ALTER TABLE findings ADD COLUMN analysis_run_id TEXT REFERENCES analysis_runs(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN rule_version TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE findings ADD COLUMN observation TEXT NOT NULL DEFAULT 'A prior Artifacta version recorded this finding.';
ALTER TABLE findings ADD COLUMN why_it_matters TEXT NOT NULL DEFAULT 'Review the linked evidence in its original context.';
ALTER TABLE findings ADD COLUMN limitations TEXT NOT NULL DEFAULT 'Detailed rule explanation metadata was not stored by the prior schema.';

-- v1 findings were artifact-scoped. Associate them with the latest completed run that could
-- have produced them while preserving genuinely orphaned legacy rows as unscoped data.
UPDATE findings
SET analysis_run_id = (
    SELECT analysis_runs.id
    FROM analysis_runs
    WHERE analysis_runs.artifact_id = findings.artifact_id
      AND analysis_runs.status = 'complete'
      AND analysis_runs.finished_at IS NOT NULL
    ORDER BY julianday(analysis_runs.started_at) DESC, analysis_runs.id DESC
    LIMIT 1
);

UPDATE findings
SET rule_version = COALESCE(
    (
        SELECT rules.version
        FROM rules
        WHERE rules.rule_id = findings.rule_id
        ORDER BY rules.version DESC, rules.id ASC
        LIMIT 1
    ),
    'legacy'
);

CREATE INDEX IF NOT EXISTS findings_analysis_run_id ON findings(analysis_run_id);

PRAGMA user_version = 2;
