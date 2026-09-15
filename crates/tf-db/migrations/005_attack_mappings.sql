ALTER TABLE findings ADD COLUMN attack_mappings_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(attack_mappings_json) AND json_type(attack_mappings_json) = 'array');

PRAGMA user_version = 5;
