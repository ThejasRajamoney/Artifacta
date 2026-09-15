# Findings

## What a Finding Is

A finding is a deterministic, non-verdict observation produced by Artifacta's built-in
rule engine or YARA scans. Every finding must cite inspectable evidence. Findings are
static triage context -- they do not prove intent or runtime behavior.

Artifacta does not provide "malware detected" or "safe" verdicts. Findings describe
what the static analysis observed, not what a file will do.

## Finding Categories

Each finding belongs to a category describing the type of observation:

| Category | Description |
|---|---|
| `section_characteristics` | PE section flags and layout anomalies |
| `section_naming` | Unusual or suspicious section names |
| `entry_point` | Entry point location and characteristics |
| `process_injection` | Indicators of process injection techniques |
| `credential_access` | Patterns associated with credential harvesting |
| `persistence` | Registry, service, or startup persistence mechanisms |
| `network_execution` | Network-related API usage patterns |
| `execution_context` | Execution context and environment indicators |
| `authenticode` | Signature validation and chain status |
| `command_indicator` | Suspicious command-line strings |
| `url_indicator` | Embedded URL indicators |
| `registry_indicator` | Registry key or path indicators |
| `path_indicator` | File system path indicators |
| `runtime_context` | Runtime environment context |
| `analysis_coverage` | Gaps in analysis coverage |
| `analysis_quality` | Quality signals in the analysis |
| `anti_debugging` | Anti-debugging or anti-analysis techniques |
| `command_execution` | Command execution patterns |
| `dynamic_api_resolution` | Dynamic API loading or resolution |
| `packed_obfuscated` | Packing or obfuscation indicators |
| `load_config` | Load configuration directory anomalies |
| `manifest` | Application manifest issues |
| `debug_metadata` | Debug directory and metadata |
| `yara_match` | Match from a YARA rule |

## Severity

Findings are assigned one of four severity levels:

| Severity | Meaning |
|---|---|
| `contextual` | Informational context, no elevated concern |
| `low` | Minor anomaly, low priority |
| `medium` | Notable observation, worth reviewing |
| `high` | Strong signal, high priority for review |

## Confidence

Each finding has a confidence score (0.0 to 1.0) and a confidence band:

| Band | Range | Meaning |
|---|---|---|
| `tentative` | Low scores | Weak or indirect signal |
| `moderate` | Mid scores | Supported by evidence but not definitive |
| `strong` | High scores | Directly supported by strong evidence |

## Evidence Links

Every finding links to one or more evidence records. Each evidence record includes:

- **ID** -- Unique identifier
- **Kind** -- The type of evidence (e.g., `import`, `string`, `section`, `certificate`)
- **Class** -- Whether the observation was `observed`, `inferred`, or `unknown`
- **Locator** -- Position within the artifact (e.g., section index, string offset)
- **Value** -- The evidence value

Click an evidence link to jump directly to the supporting evidence in the Evidence view.

## Finding States

Findings can be triaged by the analyst:

| State | Meaning |
|---|---|
| `new` | Default state, not yet reviewed |
| `reviewed` | Reviewed and noted |
| `accepted` | Reviewed and determined to be relevant |
| `dismissed` | Reviewed and determined not relevant |

## Explanation Templates

Each finding links to an explanation template that provides:

- A plain-language description of the observation
- Why it matters in the context of the artifact
- Limitations of the observation
- Caveated MITRE ATT&CK static-capability mappings where applicable

## Viewing Findings in the UI

The **Findings** view shows all findings for the current artifact, sorted by severity.
Each finding card displays:

- Title and category
- Severity badge and confidence band
- Linked evidence count
- State (new, reviewed, accepted, dismissed)

Click a finding to expand it and see the full explanation and evidence links.
