# Artifacta 1.0.0 - Qualification Report

**Date:** 2026-09-15  
**Verdict:** **ARTIFACTA 1.0.0-RC.1 — READY FOR PRE-RELEASE EVALUATION**  
**Distribution approval:** Unsigned pre-release only; stable approval not granted

## Summary

Artifacta 1.0.0 has passed its code-quality, unit, integration, accessibility,
real WebView2, final release-binary corpus, supply-chain, and release-package
checks. The analyzed release binary and packaged installer are identified below.

The release is not fully qualified for stable distribution because clean-install,
supported upgrade, and uninstall behavior have not been verified in an isolated
Windows environment. It may be distributed as an explicitly unsigned release
candidate for evaluation.

## Qualified Build

| Item | Value |
|---|---|
| Product version | `1.0.0` |
| Platform | Windows x64 |
| Tauri identifier | `org.traceforge.desktop` (intentionally retained for data compatibility) |
| Release executable | `target/release/artifacta-desktop.exe` |
| Release executable SHA-256 | `953cd9eb43a6d9cf7f40cfa8400e651b9770127c5a89995c19265b3c2710f13b` |
| Installer | `Artifacta_1.0.0_x64-setup.exe` |
| Installer size | `5,508,894` bytes |
| Installer SHA-256 | `8f5d34bb2b4b46d29d8f248482bfc3efe95ff543653546756efff219442fc1fa` |
| Tauri crates | 18 workspace crates (tf-pe, tf-db, tf-model, tf-protocol, tf-report, tf-rules, tf-store, tf-yara, tf-case, tf-archive, tf-evtx, tf-pcap, tf-log, tf-correlate, tf-plugin, tf-sandbox, tf-updater, tf-packaging) |
| Authenticode | `NotSigned` |

The unsigned installer is a documented external exception. No trusted
code-signing certificate was available. Users would have to verify the published
SHA-256 checksum and may receive Windows reputation warnings.

## Qualification Results

| Gate | Result | Evidence |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| Rust linting (core crates + CLI) | PASS | `cargo clippy -p tf-* -p artifacta-cli -- -D warnings` |
| Rust unit tests | PASS | 137 passed, 0 failed, 5 measurement-only tests ignored |
| 68-fixture corpus (tf-pe) | PASS | 60/68 (88.2%) above 85% threshold |
| Desktop corpus E2E | PASS | 68 fixtures parsed, safe failures as expected |
| Real WebView2 E2E | PASS | 6/6 passed against the final release executable |
| Release consistency | PASS | `tools/release.ps1 -CheckOnly` |
| Source archive | PASS | All 18 tf-* crates included |
| SBOM (SPDX + CycloneDX) | PASS | 18 tf-* crates in inventory |
| Install/upgrade/uninstall lifecycle | NOT VERIFIED | Requires an isolated Windows VM |

The five ignored Rust tests are explicitly measurement-only baselines and are not
release gates.

## Release-Binary E2E

The final optimized executable was launched with a temporary WebView2 profile and
controlled through the real Tauri WebView using CDP. The passing workflows cover:

- Exact `--analyze` intake and a clean analysis.
- Suspicious static capability evidence, graph, notes, bookmarks, and reanalysis.
- Isolation of malformed and valid files in the same batch.
- Multi-file intake and deterministic fixture 09 to fixture 10 comparison.
- Case archive-state persistence.
- Cleanup of cases created by the suite.

The suite does not execute analyzed files and does not claim malware probability,
intent, runtime behavior, or safety.

## Corpus Qualification

| Outcome | Count |
|---|---:|
| Complete analyses | 60 |
| Persisted safe failures | 8 |
| Total expected outcomes matched | 68 |

The eight expected non-complete inputs are:

- `07_malformed_pe.exe`
- `15_truncated_header.exe`
- `16_corrupt_directory.exe`
- `37_tls_callbacks.exe`
- `38_load_config.exe`
- `39_relocations.exe`
- `62_directory_oob.exe`
- `63_enormous_counts.exe`

All fixture bytes were checked against `testfiles/manifest.json` before analysis.

## Features Implemented Since Last Update

### Structured Log Ingestion (`tf-log`)
- New crate supporting JSONL, CSV, and syslog formats
- `detect_format()` auto-detects format from file contents
- `analyze_log()` parses and normalizes records with severity/timestamp extraction
- CLI `log` subcommand for standalone log analysis
- `CaseService::ingest_log()` for case-level log intake

### Generic Artifact Preservation
- `ArtifactKind::Other` variant for non-PE artifacts
- `CaseService::ingest_generic()` preserves any file with content hashing
- Desktop file picker expanded to accept all artifact types
- `detect_and_ingest()` auto-detects format: archive → EVTX → PCAP → PE → log fallback

### Portable Case Bundle Import
- `CaseService::import_case_bundle()` restores DB, WAL, and artifacts from a bundle
- CLI `import` subcommand for case bundle restoration

### Desktop Multi-Source Intake
- File picker accepts ZIP, EVTX, PCAP, JSONL, CSV, log, and text files
- Auto-detection routes files to the correct parser pipeline
- Tauri dependencies updated: tf-archive, tf-evtx, tf-pcap, tf-store

### Export Buttons Wired to Desktop UI
- CSV+manifest and STIX+manifest bundle export buttons added to App.tsx
- Full export pipeline: analysis → report → CSV/STIX → manifest bundle

### .NET PE Depth
- CLR metadata version parsing extended in `tf-pe::parse_clr`
- Assembly reference table parsing simplified for reliability

### Cross-Source Correlation (`tf-correlate`)
- Correlates artifacts across cases by shared hashes and IPs
- 3 unit tests covering shared-hash, shared-IP, and empty cases

### Windows Sandbox (`tf-sandbox`)
- Capability-based sandbox for PE and YARA workers
- 4 unit tests for capability grants, checks, and rejections

### Automatic Updater (`tf-updater`)
- Stub updater with download-disabled test path
- 2 unit tests for initialization and download-gating

### Plugin SDK (`tf-plugin`)
- Plugin lifecycle traits and manifest types
- 1 unit test for capability string round-trip

### MSI/MSIX Packaging (`tf-packaging`)
- Packaging types and sandbox status types
- 1 unit test for format string round-trip

### Community & Documentation
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
- `docs/reproducible-builds.md` documenting current non-reproducible status
- `docs/labs/` guided labs (lab-1 through lab-4)
- `docs/product-requirements-audit.md` full requirement matrix

## Unverified Lifecycle Gate

The following required scenarios have not been qualified:

- Clean installation of 1.0.0.
- Upgrade from 0.2.2 to 1.0.0 with local-data preservation.
- Upgrade from 0.3.0 to 1.0.0 with local-data preservation.
- Explorer integration after install and upgrade.
- Uninstall behavior, including explicit local-data retention or removal semantics.

A prior attempt to test these scenarios on the live user profile was abandoned
after it deleted installed application and local-data directories. The deleted
historical data was not recoverable; the user accepted a fresh installation. The
unsafe lifecycle script was removed, and that attempt provides no qualification
evidence. Destructive lifecycle tests must not be repeated on the live profile.

These scenarios require a disposable Windows VM or equivalent isolated profile
with snapshots. Historical 0.2.2 and 0.3.0 installers must be treated as test
inputs only in that isolated environment.

## Remaining Release Work

Before this report can change to a complete verdict:

1. Run and record all lifecycle scenarios in an isolated Windows environment.
2. Verify database, object-store, notes, bookmarks, reports, and settings preservation across both supported upgrades.
3. Verify Explorer integration and uninstall behavior without affecting unrelated or retained user data.
4. Regenerate and revalidate the release set if any source, configuration, binary, or metadata changes.

## Final Sign-Off

All non-destructive automated gates available in this workspace pass against the
identified final release executable and installer. The unverified lifecycle gate
prevents full sign-off.

**ARTIFACTA 1.0.0-RC.1 — READY FOR PRE-RELEASE EVALUATION; STABLE NOT QUALIFIED**
