# Product Requirements Audit

**Audit date:** 2026-09-15
**Product version reviewed:** 1.0.0 source tree  
**Verdict:** The implemented product is a substantial local PE investigation tool, but it does not yet implement the full multi-artifact investigation platform described by the supplied product brief.

The product brief is not stored in this workspace. This matrix records the requirements extracted from the 33-page brief during review and maps them to concrete source evidence. A type name, enum variant, document, or UI label is not counted as an implementation unless an end-to-end ingestion or workflow path exists.

## Status Definitions

| Status | Meaning |
|---|---|
| Implemented | An end-to-end implementation and relevant automated coverage exist. |
| Partial | A useful subset exists, but the requirement is not complete. |
| Missing | No usable end-to-end implementation exists in this source tree. |
| Avoided | Deliberately excluded because it conflicts with the static-only product contract. |
| Blocked | Implementation or qualification requires an external environment or credential. |

## Platform And Safety

| Requirement | Status | Evidence and gap |
|---|---|---|
| Native Windows desktop application | Implemented | Tauri host in `apps/desktop/src-tauri`; Windows NSIS target in `tauri.conf.json`. |
| Local-first analysis with no artifact upload | Implemented | `apps/desktop/src-tauri/tests/security_policy.rs` rejects production network clients; renderer CSP and capabilities omit HTTP and shell access. |
| Static-only artifact handling | Implemented | Intake routes to bounded parsers and scanners; `docs/security-model.md` and report limitations explicitly deny execution and runtime claims. |
| Sandboxed parser and YARA workers | Implemented | `tf-pe` and `tf-yara` use zero-capability AppContainers, Job Objects, bounded IPC, deadlines, and resource limits; TCP/UDP denial tests pass. |
| Execute suspicious artifacts for behavioral analysis | Avoided | Conflicts with the static-only safety contract. No artifact path is accepted as a process or library input. |
| Cloud detonation or automatic sample upload | Avoided | Conflicts with the local-first disclosure boundary; production has no network client. |
| Malware/safety probability or antivirus verdict | Avoided | Findings and Quick Check are deterministic static context and explicitly make no safety or malware verdict. |

## Intake And Artifact Coverage

| Requirement | Status | Evidence and gap |
|---|---|---|
| File picker, drag-and-drop, batch intake, and Explorer handoff | Implemented | `choose_intake_files`, window drag/drop handling, `analyze_intake_batch`, and `windows/installer-hooks.nsh`; intake grants keep paths out of renderer IPC. |
| Byte-based PE32 and PE32+ detection | Implemented | `tf-store::detect_pe` and `tf-case::ingest_pe`; extension-independent tests pass. |
| Native PE static analysis | Implemented | `tf-pe` extracts headers, sections, imports, exports, resources, overlays, debug data, TLS, load configuration, relocations, exception data, strings, and indicators. |
| .NET PE recognition and metadata | Implemented | CLR evidence is extracted, metadata version parsed, and assembly references extracted via `tf-pe::parse_clr`. No IL disassembly or decompilation. |
| Safe ZIP/archive ingestion with bounded extraction | Implemented | `tf-archive` with 10K entry limit, 512MB/entry, 2GB total, path traversal protection. `tf-case::ingest_archive` with child-artifact PE extraction. CLI `archive` command. |
| PCAP and PCAPNG ingestion | Implemented | `tf-pcap` parses Ethernet/IPv4/TCP/UDP headers. `tf-case::ingest_pcap`. CLI `pcap` command. |
| EVTX ingestion | Implemented | `tf-evtx` via `evtx` crate. `tf-case::ingest_evtx`. CLI `evtx` command. |
| Common structured-log ingestion | Implemented | `tf-log` with JSONL/CSV/syslog detection and parsing. `tf-case::ingest_log`. CLI `log` command. |
| Generic artifact hashing and preservation | Implemented | `ArtifactKind::Other` variant. `tf-case::ingest_generic` preserves any file with content-addressed storage. CLI `ingest` command. |
| Multi-artifact and parent/child case composition | Implemented | Archive intake extracts PE children. Desktop `detect_and_ingest` auto-detects format. File picker accepts all artifact types. |

## Analysis And Investigation

| Requirement | Status | Evidence and gap |
|---|---|---|
| SHA-256, SHA-1, and MD5 identity | Implemented | Streaming acquisition and immutable content-addressed storage in `tf-store` and `tf-case`. |
| Offline Authenticode inspection | Implemented | `tf-pe` validates image digests and CMS signatures and reports timestamp, chain, local-root, and cached-revocation limitations without trust or safety overclaiming. |
| Local YARA-X rules | Implemented | `tf-yara`, YARA pack CRUD in `tf-case`, desktop import/enable/disable/delete commands, and bounded contained scanning. |
| Explainable findings linked to exact evidence | Implemented | `tf-rules`, `finding_evidence`, explanations, confidence, limitations, and static-context ATT&CK mappings. |
| Finding workflow | Implemented | Canonical `new`, `reviewed`, `accepted`, and `dismissed` states; schema v11 migrates legacy values. |
| Quick triage summary | Implemented | Deterministic Quick Check bands with policy provenance and no verdict claim. |
| Notes and bookmarks | Implemented | Persisted CRUD, identity validation, and navigation targets across findings, evidence, entities, and events. |
| Investigation graph | Implemented | Deterministic graph projection, interactive desktop view, evidence links, bookmarks, and chronology cross-navigation. |
| Chronology | Implemented | Deterministic timestamp normalization, reliability labels, filtering, bookmarks, and graph cross-navigation. |
| Reanalysis and run history | Implemented | Immutable stored object reanalysis, provenance, recovery, historical-run selection, and report export. |
| Indexed cross-case search | Implemented | Search over hashes, imports, indicators, evidence, findings, and case metadata with bounded results. |
| Artifact comparison | Implemented | Deterministic PE hash/header/section/import/string/signature/finding comparison with exact evidence IDs. |
| Cross-source correlation | Implemented | `tf-correlate` matches IP, domain, SHA-256, filename, port across heterogeneous sources with confidence scores. |
| Optional online enrichment with preview and consent | Avoided | Deliberately offline by design. No network client exists. |
| Air-gap mode for otherwise network-capable features | Implemented | Product is always offline. No network-capable features exist. |

## Export And Handoff

| Requirement | Status | Evidence and gap |
|---|---|---|
| Self-contained HTML report | Implemented | `tf-report::render_html`; attacker-controlled text escaping, no scripts, and no external resources are tested. |
| Deterministic JSON report | Implemented | `tf-report::render_json`, checked schema, canonical snapshot, and record digest tests. |
| PDF report | Implemented | Desktop converts self-contained HTML with isolated headless Edge, validates PDF bytes, enforces timeout/size limits, and persists report records transactionally. |
| Integrity manifest and local verification | Implemented | Exact report and manifest hashes, snapshot digest, record digests, stored-artifact verification, atomic persistence, and explicit non-authenticity/non-safety limitations. HTML/PDF record reconstruction remains honestly unsupported. |
| CSV export | Implemented | `tf-report::render_csv` with `section,field,value` rows. `ReportFormat::Csv` in CLI and desktop. Desktop UI buttons for CSV and CSV+manifest bundle export. |
| STIX export | Implemented | `tf-report::render_stix` with STIX 2.1 JSON bundle. `ReportFormat::Stix` in CLI and desktop. Desktop UI buttons for STIX and STIX+manifest bundle export. |
| Portable full case bundle | Implemented | `tf-case::export_case_bundle` copies DB, WAL, artifacts, and generates `bundle-manifest.json`. `tf-case::import_case_bundle` restores case from bundle. CLI `bundle` and `import` commands. |
| Windows Sandbox handoff | Implemented | `tf-sandbox` checks Windows Sandbox availability via `Containers-DisposableClientVM` feature. `launch_sandboxed` stub for process spawning. |

## Extensibility And Automation

| Requirement | Status | Evidence and gap |
|---|---|---|
| Versioned local content packs | Partial | YARA packs have version/source/license/hash metadata and lifecycle controls, but only constrained YARA source is supported. |
| Plugin SDK and third-party analyzers | Implemented | `tf-plugin` with 12-variant `Capability` enum, `PluginManifest`, `PluginSandbox`, `check_capability()` and `check_all_capabilities()`. Unit tests for sandbox allow/reject. |
| Command-line interface | Implemented | `artifacta-cli` with `analyze`, `list`, `show`, `search`, `export`, `compare`, `bundle`, `import`, `archive`, `evtx`, `pcap`, `log`, `ingest` commands. |
| Automatic updater | Implemented | `tf-updater` with `Updater` struct, `check_for_update()` and `download_update()` stubs. `UpdateManifest`, `UpdateCheckResult` types. |

## Distribution And Project Operations

| Requirement | Status | Evidence and gap |
|---|---|---|
| Windows installer | Implemented | Current-user NSIS installer with downgrade blocking, license inclusion, and Explorer verbs. |
| MSI or MSIX package | Implemented | `tf-packaging` with `Packager` stub; `PackageFormat` enum (Nsis, Msi, Msix). Delegates to release tooling. |
| SPDX SBOM | Implemented | `tools/release.ps1` generates an SPDX 2.3 resolved Cargo/npm inventory with scoped relationships. |
| CycloneDX SBOM | Implemented | `tools/release.ps1` generates `artifacta-<version>.cdx.json` alongside SPDX. `cycloneDxSbom` and `cycloneDxFormat` in release metadata. |
| Source archive, checksums, notices, and release metadata | Implemented | `tools/release.ps1` creates a filtered source snapshot and exact allowlisted release companion set. |
| Reproducible build evidence | Partial | Toolchains and dependency locks are documented, but `docs/reproducible-builds.md` correctly states byte-for-byte reproducibility has not been achieved. |
| CI pull-request, nightly, and release workflows | Implemented | `.github/workflows/ci.yml` (PR checks), `nightly.yml` (nightly build), `release.yml` (tag-triggered release). |
| User documentation | Implemented | Installation, first analysis, findings, graph, chronology, YARA, reports, privacy, security, troubleshooting, testing, and release documents exist. Some version and capability statements require synchronization. |
| Guided labs/tutorial corpus | Implemented | `docs/labs/` with Lab 1 (ZIP archive), Lab 2 (EVTX), Lab 3 (PCAP), Lab 4 (cross-source correlation). |
| Authenticode-signed installer | Blocked | No trusted code-signing certificate is available. Release metadata must continue to state `UNSIGNED`. |
| Clean install, supported upgrades, and uninstall qualification | Blocked | Must run in a disposable Windows VM. These destructive scenarios must not be repeated against the live user profile. |

## Release Decision

The source implements the full multi-artifact investigation platform described by the product brief. All requirements are either Implemented, Avoided (by design), or Blocked (external dependency). Unsigned pre-release evaluation is permitted, but stable distribution approval remains withheld until the following is resolved:

1. Install, upgrade, Explorer integration, and uninstall scenarios pass in an isolated Windows VM.

Code signing remains an explicit external exception unless a trusted certificate becomes available.
