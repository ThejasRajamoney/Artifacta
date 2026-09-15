# YARA Integration

## What YARA-X Provides

Artifacta integrates [YARA-X](https://github.com/Nike-Swoosh/YARA-X), a high-performance
YARA implementation, for custom rule-based scanning. YARA rules let you define patterns
to match against artifact contents, extending Artifacta's built-in detection capabilities.

YARA matches produce evidence records and findings that appear alongside built-in
analysis results.

## Adding YARA Rule Files

1. Open the YARA management panel from the toolbar.
2. Click **Add Rule Pack**.
3. Select a `.yar` or `.yara` file from the file dialog.
4. The file is validated, compiled, and stored as a content-addressed pack.

Rule packs are stored locally under the application data directory. Each pack is:

- Bounded and validated in a disposable YARA worker
- Hashed and content-addressed
- Stored without raw source paths in the database

## Removing YARA Packs

1. Open the YARA management panel.
2. Select the pack to remove.
3. Click **Remove**.

Pack files are retained until no case references remain. Deletion is best-effort and
is reported as deferred if the file cannot be immediately removed.

## YARA Evidence in Reports

When a YARA rule matches, the following appears in the report:

- A `yara_match` finding with the rule name and matched patterns
- Evidence records containing matched strings and rule metadata
- Graph edges linking the artifact to the matched YARA rule entity

## Limitations

- **Static only** -- YARA-X scans file contents at rest. It does not perform dynamic
  analysis, emulator-based detection, or behavioral analysis.
- **No includes** -- YARA `include` directives are disabled. Each rule file must be
  self-contained.
- **No modules** -- YARA modules (e.g., `pe`, `math`, `cuckoo`) are not available.
  Rules must use only string matching and basic condition logic.
- **No remote rules** -- Rule files are loaded from the local filesystem. There is
  no mechanism to fetch rules from a remote server.
- **Compilation errors** -- Invalid rules are rejected at import time. The YARA worker
  validates rules before storage.

## Rule Format

Artifacta supports standard YARA-X syntax. A minimal rule example:

```yara
rule example_pattern {
    strings:
        $s1 = "suspicious_string"
    condition:
        $s1
}
```

Rules can include metadata fields. The `category`, `traceforge_category`, `correlates_with`,
`traceforge_rule_id`, and `tags` fields are used by the correlation engine for finding
de-duplication and scoring.
