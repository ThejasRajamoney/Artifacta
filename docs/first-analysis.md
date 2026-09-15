# First Analysis Walkthrough

This guide walks you through analyzing your first file with Artifacta 1.0.0.

## Opening a File

There are two ways to begin an analysis:

### Drag and Drop

1. Drag a PE file (`.exe`, `.dll`, `.sys`) from Windows Explorer into the Artifacta window.
2. Artifacta immediately begins an auto-analysis on the dropped file.

### Analyze Button

1. Click the **Analyze** button in the toolbar.
2. Select a file from the native Windows file dialog.
3. Analysis begins automatically after selection.

## What Happens During Analysis

When a file is dropped or selected:

1. **Intake** -- The file is copied into Artifacta's content-addressed store. SHA-256, SHA-1, and MD5 hashes are computed. The original is never modified.
2. **PE Validation** -- Byte-based PE32/PE32+ validation runs independently of file extension.
3. **Worker Analysis** -- A disposable Rust PE worker extracts headers, sections, imports, exports, resources, strings, indicators, and more.
4. **Deterministic Rules** -- Built-in rules evaluate the extracted evidence and produce findings.
5. **YARA Scanning** -- If YARA rule packs are loaded, the artifact is scanned against them.

The entire process runs locally with no network access.

## Understanding the Quick Check Result

After analysis completes, the **Quick Check** panel shows a triage summary:

| Band | Meaning |
|---|---|
| **No strong indicators** | No elevated signals detected |
| **Review** | Minor anomalies; worth a look |
| **Suspicious** | Multiple elevated signals across evidence families |
| **High suspicion** | Strong indicators across several evidence families |

See [Quick Check](quick-check.md) for full details on how the band is calculated.

## What the Findings Mean

Below the Quick Check, you will see a list of **findings**. Each finding has:

- **Title** -- A plain-language description of what was observed.
- **Severity** -- Contextual, low, medium, or high.
- **Confidence** -- Tentative, moderate, or strong.
- **Category** -- The type of observation (e.g., section characteristics, import patterns, indicators).
- **Linked evidence** -- Clickable references to the exact evidence supporting the finding.

> **Important:** Findings are static triage context. They do not prove intent or runtime behavior.
> Artifacta does not provide a "malware detected" or "safe" verdict.

## Navigating the Interface

- **Overview** -- Artifact metadata, hashes, and the Quick Check summary.
- **Findings** -- All deterministic findings with severity and evidence links.
- **Imports** -- Imported APIs and their sources.
- **Strings** -- Extracted strings (with high-entropy strings separated from the default view).
- **Sections** -- PE section headers and characteristics.
- **Signature** -- Authenticode signature and chain details.
- **Evidence** -- Raw evidence records with provenance.
- **Graph** -- Investigation graph showing entity relationships.
- **Chronology** -- Timeline of timestamped events.

## Next Steps

- Add [YARA rule packs](yara.md) for custom scanning.
- Export a [report](reports.md) for your records.
- Review the [Security Model](security-model.md) to understand how your data is handled.
