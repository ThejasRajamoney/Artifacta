-- v6-v8 treated graph and chronology rows for a case with case_projections state as derived.
-- Record that ownership explicitly so subsequent rebuilds never delete unclassified legacy rows.
CREATE TABLE IF NOT EXISTS projection_entities (
    entity_id TEXT PRIMARY KEY NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS projection_edges (
    edge_id TEXT PRIMARY KEY NOT NULL REFERENCES edges(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS projection_events (
    event_id TEXT PRIMARY KEY NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO projection_entities(entity_id, case_id)
SELECT e.id, e.case_id
FROM entities e
JOIN case_projections cp ON cp.case_id = e.case_id;

INSERT OR IGNORE INTO projection_edges(edge_id, case_id)
SELECT edge.id, source.case_id
FROM edges edge
JOIN entities source ON source.id = edge.source_entity_id
JOIN case_projections cp ON cp.case_id = source.case_id;

INSERT OR IGNORE INTO projection_events(event_id, case_id)
SELECT event.id, event.case_id
FROM events event
JOIN case_projections cp ON cp.case_id = event.case_id;

-- Older replacement code could leave bookmarks pointing at deleted derived rows.
DELETE FROM bookmarks
WHERE (target_type = 'entity' AND NOT EXISTS (
           SELECT 1 FROM entities WHERE entities.id = bookmarks.target_id
      ))
   OR (target_type = 'edge' AND NOT EXISTS (
           SELECT 1 FROM edges WHERE edges.id = bookmarks.target_id
      ))
   OR (target_type = 'event' AND NOT EXISTS (
           SELECT 1 FROM events WHERE events.id = bookmarks.target_id
      ));

PRAGMA user_version = 9;
