-- SQLite requires explicit indexes on child keys for efficient cascades.
CREATE INDEX search_terms_artifact_id ON search_terms(artifact_id);
CREATE INDEX search_terms_analysis_run_id ON search_terms(analysis_run_id);
CREATE INDEX search_terms_evidence_id ON search_terms(evidence_id);
CREATE INDEX search_terms_finding_id ON search_terms(finding_id);
CREATE INDEX finding_evidence_evidence_id ON finding_evidence(evidence_id);
CREATE INDEX edges_evidence_id ON edges(evidence_id);
CREATE INDEX events_artifact_id ON events(artifact_id);
CREATE INDEX events_evidence_id ON events(evidence_id);
CREATE INDEX notes_entity_id ON notes(entity_id);
CREATE INDEX notes_finding_id ON notes(finding_id);
CREATE INDEX projection_entities_case_id ON projection_entities(case_id);
CREATE INDEX projection_edges_case_id ON projection_edges(case_id);
CREATE INDEX projection_events_case_id ON projection_events(case_id);

PRAGMA user_version = 10;
