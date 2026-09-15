# Privacy

## No Telemetry

Artifacta collects no telemetry. There are no analytics events, crash reports,
usage statistics, or phone-home behavior. The application does not contain any
telemetry SDK or tracking code.

## No Data Collection

Artifacta does not collect, transmit, or store any data externally. There is:

- No cloud sync
- No account registration
- No remote analytics
- No feature usage tracking
- No crash reporting service

## Local Storage Only

All data is stored locally on your device:

| Data | Location |
|---|---|
| Application | Installation directory |
| Cases and database | `%LOCALAPPDATA%\Artifacta\` (or equivalent per-user path) |
| Artifact objects | Content-addressed store under application data |
| YARA packs | Content-addressed store under application data |
| Worker scratch | `%LOCALAPPDATA%\Artifacta\worker-scratch\` (cleaned up after use) |
| Reports | User-selected export destination |

## What Data Stays on Device

Everything. Specifically:

- **Artifacts** -- Original files are copied into the local store. Original acquisition
  paths are recorded in the database but never sent anywhere.
- **Analysis results** -- All findings, evidence, and graph data remain in the local
  SQLite database.
- **YARA rules** -- Rule packs are stored locally. Rule source paths stay in the
  host/worker request layer and are not exposed externally.
- **Notes** -- Analyst notes are stored in the local database.
- **Reports** -- Generated locally to user-selected paths. No upload mechanism exists.

## What Reports Disclose

When you export a report, it becomes a portable disclosure boundary. Reports contain:

- Artifact names, hashes, and metadata
- Findings and evidence
- Matched strings, certificate fields, and rule metadata
- Analyst notes

Reports do **not** contain:

- Artifact store paths
- Original acquisition paths
- Analyzer parameters

Recipients and destination access control are your responsibility. Artifact-derived
URLs in reports are inert text in Artifacta's HTML but may be made interactive by
other viewers.

## Network Behavior

The production application contains no network client code. The CSP, renderer
capabilities, and automated policy tests enforce this.

The one exception is the **installer**: on systems without WebView2, the NSIS
installer may download Microsoft WebView2 components. This is installer-time
traffic, not runtime behavior, and should be considered for offline deployment.

## Database Security

The local SQLite database is not encrypted, authenticated, or protected from
another process with the same user's filesystem rights. Local tampering can cause
startup failure, data loss, or misleading state. Artifact hashes and relational
validation detect specific integrity failures.

Backups must treat the database, WAL, SHM, artifact objects, YARA packs, and
notes as one sensitive set.
