ALTER TABLE cases ADD COLUMN pre_archive_status TEXT
    CHECK (pre_archive_status IS NULL OR pre_archive_status IN ('active', 'complete', 'error'));

CREATE TABLE search_terms (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE CASCADE,
    analysis_run_id TEXT REFERENCES analysis_runs(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    field TEXT NOT NULL CHECK (field IN (
        'sha256', 'sha1', 'md5', 'case_title', 'import', 'indicator', 'certificate',
        'signer', 'rule_id', 'finding_title', 'finding_category', 'evidence_value'
    )),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
    normalized_value TEXT NOT NULL CHECK (length(normalized_value) BETWEEN 1 AND 2048)
) STRICT;

CREATE INDEX search_terms_lookup
    ON search_terms(field, normalized_value, case_id, id);
CREATE INDEX search_terms_case_id ON search_terms(case_id);
CREATE INDEX artifacts_sha256 ON artifacts(sha256);
CREATE INDEX artifacts_sha1 ON artifacts(sha1);
CREATE INDEX artifacts_md5 ON artifacts(md5);
CREATE INDEX cases_title_nocase ON cases(title COLLATE NOCASE);
CREATE INDEX findings_rule_id ON findings(rule_id);
CREATE INDEX findings_title_nocase ON findings(title COLLATE NOCASE);
CREATE INDEX findings_category_nocase ON findings(category COLLATE NOCASE);
CREATE INDEX evidence_kind ON evidence(kind);
CREATE INDEX notes_case_updated_at ON notes(case_id, updated_at DESC, id DESC);
CREATE INDEX analysis_runs_artifact_started
    ON analysis_runs(artifact_id, started_at DESC, id DESC);

INSERT INTO search_terms(case_id, field, value, normalized_value)
SELECT id, 'case_title', substr(title, 1, 2048), lower(substr(title, 1, 2048))
FROM cases WHERE length(title) > 0;

INSERT INTO search_terms(case_id, artifact_id, field, value, normalized_value)
SELECT case_id, id, 'sha256', sha256, lower(sha256) FROM artifacts
UNION ALL
SELECT case_id, id, 'sha1', sha1, lower(sha1) FROM artifacts
UNION ALL
SELECT case_id, id, 'md5', md5, lower(md5) FROM artifacts;

INSERT INTO search_terms(
    case_id, artifact_id, analysis_run_id, finding_id, field, value, normalized_value
)
SELECT a.case_id, f.artifact_id, f.analysis_run_id, f.id, 'rule_id',
       substr(f.rule_id, 1, 2048), lower(substr(f.rule_id, 1, 2048))
FROM findings f JOIN artifacts a ON a.id = f.artifact_id
UNION ALL
SELECT a.case_id, f.artifact_id, f.analysis_run_id, f.id, 'finding_title',
       substr(f.title, 1, 2048), lower(substr(f.title, 1, 2048))
FROM findings f JOIN artifacts a ON a.id = f.artifact_id
UNION ALL
SELECT a.case_id, f.artifact_id, f.analysis_run_id, f.id, 'finding_category',
       substr(f.category, 1, 2048), lower(substr(f.category, 1, 2048))
FROM findings f JOIN artifacts a ON a.id = f.artifact_id;

-- JSON is scanned once during migration. Runtime search uses only search_terms.
INSERT INTO search_terms(
    case_id, artifact_id, analysis_run_id, evidence_id, field, value, normalized_value
)
SELECT a.case_id, e.artifact_id, p.analysis_run_id, e.id,
       CASE
           WHEN e.kind IN ('pe.import', 'pe.delay_import') THEN 'import'
           WHEN e.kind = 'pe.indicator' THEN 'indicator'
           WHEN e.kind = 'pe.authenticode' AND j.fullkey LIKE '%signers%' THEN 'signer'
           WHEN e.kind = 'pe.authenticode' AND j.fullkey LIKE '%certificates%' THEN 'certificate'
           ELSE 'evidence_value'
       END,
       substr(CAST(j.atom AS TEXT), 1, 2048),
       lower(substr(CAST(j.atom AS TEXT), 1, 2048))
FROM evidence e
JOIN artifacts a ON a.id = e.artifact_id
JOIN provenance p ON p.id = e.provenance_id
JOIN json_tree(e.value_json) j
WHERE j.atom IS NOT NULL AND length(CAST(j.atom AS TEXT)) BETWEEN 1 AND 2048;

PRAGMA user_version = 3;
