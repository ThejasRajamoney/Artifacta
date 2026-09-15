# Reports

## What Reports Contain

An Artifacta report is a portable, self-contained export of an analysis case. Reports
include:

- **Case metadata** -- Case ID, title, creation/update times, application version
- **Artifact details** -- File name, kind, size, hashes (SHA-256, SHA-1, MD5)
- **Analysis run** -- Analyzer version, status, timestamps
- **Findings** -- All findings with severity, confidence, explanations, and evidence links
- **Evidence** -- Evidence records grouped by kind, with locators and values
- **Chronology** -- Timestamped events with reliability ratings
- **YARA matches** -- Matched rules and their evidence
- **Notes** -- Analyst-authored notes
- **Bookmarks** -- Saved navigation points
- **Methodology and limitations** -- What was analyzed and what was not

Reports intentionally **omit** artifact store paths, original acquisition paths, and
analyzer parameters to reduce information disclosure.

## Generating Reports

1. Open a case in Artifacta.
2. Click **Export Report** in the toolbar.
3. Choose the format (HTML, JSON, or PDF).
4. Choose the destination folder.
5. Artifacta generates the report and writes it to the selected location.

## HTML Reports

HTML reports are self-contained static files. They:

- Require no external resources, scripts, or stylesheets
- Escape all attacker-controlled text
- Contain no inline scripts
- Contain no HTTP(S) references to external resources
- Include an embedded snapshot reference for integrity verification

Open HTML reports in any web browser. They are designed to be safe to view locally.

## JSON Reports

JSON reports are deterministic. Given the same input data, the output bytes are
identical. This enables reproducibility and automated verification.

JSON reports conform to the report schema (`schemas/report.schema.json`) and include:

- All case, artifact, finding, evidence, and chronology data
- An integrity reference with the snapshot SHA-256
- A manifest of sorted record digests

## PDF Reports

PDF reports contain the same bounded report snapshot rendered through the
self-contained HTML representation. The desktop host uses an isolated local
Microsoft Edge profile, performs no intentional network access, enforces a
30-second conversion deadline and report-size limit, and rejects output that is
not a PDF document. Microsoft Edge is required for PDF export.

## Manifest Verification

Reports include an integrity manifest for verification:

1. The report contains a canonical snapshot (compact typed JSON with `generated_at`
   and the `integrity` object removed).
2. The snapshot SHA-256 is stored in `integrity.snapshot_sha256`.
3. A sorted manifest of record digests is included.

To verify a JSON report, recompute the canonical snapshot from the report data and
compare the hash. See `schemas/manifest.schema.json` for the manifest format.

## Report Hash Integrity

The integrity reference contains:

- `hash_algorithm` -- Always `sha256`
- `snapshot_sha256` -- Hash of the canonical snapshot
- `manifest_schema_version` -- Version of the manifest schema
- `external_manifest` -- Optional reference to an external manifest file

## Limitations

- HTML and PDF reports can be checked for exact bytes and snapshot references, but
  cannot be losslessly reconstructed into canonical JSON records. This verification
  result is explicitly `unsupported`, not `verified`.
- Verification does not establish authorship, authenticity, intent, or safety.
- Reports are a **disclosure boundary**. Recipients and destination access control
  are the user's responsibility.
