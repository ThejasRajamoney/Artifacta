# Changelog

All notable user-visible changes are recorded here.

## [1.0.0-rc.1] - 2026-09-15

- Published the first unsigned 1.0.0 release candidate (`v1.0.0-rc.1`) for
  evaluation. Stable distribution remains pending isolated Windows
  install/upgrade/uninstall qualification.
- Multi-artifact intake: PE32/PE32+, .NET metadata, ZIP archives with PE child
  extraction, EVTX, PCAP/PCAPNG, JSONL/CSV/syslog, and generic hashed artifacts.
- Headless CLI (`analyze`, `list`, `show`, `search`, `export`, `compare`,
  `bundle`, `import`, `archive`, `evtx`, `pcap`, `log`, `ingest`).
- CSV and STIX 2.1 exports wired to the desktop UI, portable case-bundle
  export and import, and cross-source correlation.
- Plugin SDK, Windows Sandbox handoff, automatic-updater stub (disabled),
  and MSI/MSIX packaging stubs.
- SPDX 2.3 and CycloneDX 1.6 SBOMs, guided labs, and CI pull-request, nightly,
  and release workflows.

## [1.0.0] - Unreleased

- Prepared the Artifacta 1.0.0 release candidate as a free, local-first Windows
  suspicious-file static triage and investigation desktop application. Public
  distribution remains subject to the documented qualification gates.
- Added progressive analysis stages with real-time stage reporting.
- Added Windows Explorer "Inspect with Artifacta" right-click context menu.
- Expanded test corpus to 68 deterministic inert PE fixtures with full manifest.
- Added provenance parameter completeness tracking for deterministic reproduction.
- Added PDF reports with optional integrity manifests and transactional report
  record persistence.
- Added public website (apps/website/) with download, security, and docs pages.
- Added comprehensive public documentation suite (12 docs covering installation,
  analysis, findings, graph, chronology, YARA, reports, troubleshooting, security).
- Bumped all version references to 1.0.0.
- Brand cleanup: TraceForge references replaced with Artifacta in user-facing content.

## [0.3.0] - 2026-08-25

- Completed the substantially implemented P1 local suspicious-file triage
  workflow across investigation, evidence, findings, comparison, and reports.
- Added release consistency checks and a source/SPDX/checksum metadata generator
  for exact Windows NSIS release artifacts.
- Included the Apache license in bundles and disabled installer downgrades.
- Kept the runtime updater disabled and made unsigned release state explicit.

## [0.2.2]

- Hardened Authenticode verification, indicator extraction, overlay handling,
  malformed-section reporting, correlation rules, and comparison presentation.
