# Chronology

## What the Chronology Shows

The chronology presents a timeline of timestamped events associated with an artifact.
It helps you understand the temporal context of the file, including when it was
apparently created, compiled, modified, or signed.

## Time Sources

Artifacta extracts timestamps from multiple sources:

| Source | Description |
|---|---|
| **PE timestamps** | `TimeDateStamp` in the PE header, `TimeDateStamp` in the debug directory |
| **Authenticode** | Signing timestamps from Authenticode signatures |
| **Version data** | `FileVersion`, `ProductVersion`, `OriginalFilename` from VS_FIXEDFILEINFO |
| **Metadata** | Other embedded timestamps from resources or data directories |

## Reliability Model

Each chronology event has a reliability rating:

| Rating | Meaning |
|---|---|
| `trusted` | Cryptographically signed timestamp (e.g., Authenticode signing time) |
| `high` | Strong corroborating evidence supporting the timestamp |
| `medium` | Plausible but uncorroborated timestamp |
| `low` | Easily tampered timestamp (e.g., PE header fields) |

PE header timestamps (`TimeDateStamp`) are **low reliability** by default because they
can be trivially modified by tools or malware. Authenticode signing timestamps are
**trusted** because they are provided by a trusted timestamping authority and are
cryptographically bound to the signature.

## Filtering

The chronology view supports filtering by:

- **Event type** -- Filter to specific categories of events
- **Time range** -- Focus on a specific date range
- **Reliability** -- Show only events above a minimum reliability threshold

## Chronology Events in Reports

Chronology events are included in exported reports. Each event contains:

- Event ID
- Timestamp (UTC)
- Timestamp type (source)
- Reliability rating
- Event type
- Summary description
- Linked artifact and evidence IDs (when applicable)

The report also includes a `chronology_reliability` summary showing counts by reliability
level, giving you a quick view of how trustworthy the timeline is overall.
