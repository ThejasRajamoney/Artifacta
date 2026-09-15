# Artifacta

[![Release](https://img.shields.io/github/v/release/ThejasRajamoney/Artifacta?include_prereleases&label=release)](https://github.com/ThejasRajamoney/Artifacta/releases)
[![License](https://img.shields.io/github/license/ThejasRajamoney/Artifacta)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)](https://github.com/ThejasRajamoney/Artifacta/releases)
[![Rust](https://img.shields.io/badge/built_with-Rust-orange)](https://www.rust-lang.org/)

**Understand a suspicious Windows file without uploading it, executing it, or trusting anyone's verdict.**

Artifacta is a free, local-first static investigation workbench for Windows. Drop in a PE executable, a ZIP archive, an EVTX log, a PCAP capture, or a structured log, and get evidence-backed findings where every conclusion links to the exact bytes, headers, imports, strings, signatures, or packets behind it.

> [!IMPORTANT]
> `v1.0.0-rc.1` is an **unsigned pre-release for evaluation**. Windows will show an unknown-publisher warning — verify the SHA-256 checksum below before installing. Stable distribution is pending isolated install/upgrade/uninstall qualification. Artifacta is static analysis only: it never executes artifacts, never uploads them, and never tells you a file is safe or malicious.

## Why Artifacta?

- **Nothing leaves your machine.** No uploads, no cloud detonation, no telemetry. Production code paths contain no network client.
- **Evidence or it didn't happen.** The pipeline is `Artifact -> Provenance -> Evidence -> Finding -> Explanation`. Every finding cites inspectable evidence with generation provenance.
- **Multi-artifact cases.** PE32/PE32+, .NET metadata, ZIP archives (with PE child extraction), EVTX, PCAP/PCAPNG, JSONL/CSV/syslog, and generic hashed artifacts compose into one investigation.
- **Explainable static findings.** Deterministic rules with severity, confidence-as-rule-strength, limitations, and caveated ATT&CK static-capability context. Quick Check triage with published policy.
- **Investigator workflow.** Cases, finding states, notes, bookmarks, investigation graph, chronology, cross-case search, artifact comparison, and cross-source correlation.
- **Reports you can defend.** Deterministic JSON, self-contained HTML, locally rendered PDF, CSV, and STIX 2.1 exports with integrity manifests and local verification.
- **Hardened by default.** PE/YARA workers run in zero-capability Windows AppContainers with Job Objects, bounded IPC, deadlines, and resource limits.

## Quickstart (Windows x64)

1. Download `Artifacta_1.0.0_x64-setup.exe` and `SHA256SUMS` from the [v1.0.0-rc.1 prerelease](https://github.com/ThejasRajamoney/Artifacta/releases/tag/v1.0.0-rc.1).
2. Verify integrity:

   ```powershell
   (Get-FileHash .\Artifacta_1.0.0_x64-setup.exe -Algorithm SHA256).Hash.ToLowerInvariant()
   # must equal 8f5d34bb2b4b46d29d8f248482bfc3efe95ff543653546756efff219442fc1fa
   ```

3. Run the installer (current-user, no admin required) and open Artifacta.
4. Drag a file in, or right-click any file in Explorer and choose **Inspect with Artifacta**.

Checksums prove the download is intact; they do not establish publisher identity. See [Verifying Downloads](docs/verifying-downloads.md).

## What's inside

- **Intake:** file picker, drag-and-drop, batch intake, Explorer handoff, and a headless CLI (`apps/cli`) when building from source.
- **Analysis:** bounded PE parser (headers, sections, imports/exports, resources, overlay, debug, TLS, CLR, strings, indicators), offline Authenticode inspection with explicit trust limits, and contained YARA-X scanning.
- **Investigation:** graph and chronology views with cross-navigation, reanalysis with run history, indexed search, deterministic comparison, and IP/domain/hash correlation across sources.
- **Export:** JSON, HTML, PDF, CSV, STIX, integrity manifests, portable case bundles (export **and** import), and a Windows Sandbox handoff stub.
- **Supply chain:** SPDX 2.3 + CycloneDX 1.6 SBOMs, filtered source archive, license notices, and release metadata published with every release.

Import semantics, strings, indicators, and findings are static triage context; they do not prove intent or runtime behavior.

## Qualification (v1.0.0-rc.1)

| Gate | Result |
|---|---|
| Rust fmt / clippy `-D warnings` | PASS |
| Rust unit suites | 137 passed, 0 failed |
| 68-fixture corpus | 60/68 expected outcomes (8 safe failures) |
| Desktop corpus E2E | PASS |
| Real WebView2 E2E | 6/6 PASS |
| Frontend (vitest + axe) | 35 PASS |
| Install / upgrade / uninstall lifecycle | PENDING (isolated VM required) |

Full evidence: [`ARTIFACTA_1.0.0_COMPLETION_REPORT.md`](ARTIFACTA_1.0.0_COMPLETION_REPORT.md), [`docs/product-requirements-audit.md`](docs/product-requirements-audit.md).

## Development

Required on Windows: Windows 11 (10 x64 compatibility-only), MSVC C++ Build Tools, Rust stable MSVC, Node 24 + npm, WebView2 Runtime.

```powershell
npm install
npm run dev
```

```powershell
npm run check
npm run release:check
npm run release:prepare
```

See [`docs/releasing.md`](docs/releasing.md) for artifact names and the release process, and [`docs/labs/`](docs/labs/) for guided walkthroughs (ZIP, EVTX, PCAP, correlation).

## Release identity

The legacy Tauri identifier `org.traceforge.desktop` is intentionally retained so existing local cases survive upgrades. The canonical repository is `https://github.com/ThejasRajamoney/Artifacta`, the bundle publisher is `Artifacta`, and private security reports use GitHub Private Vulnerability Reporting. Installers are signed only when a trusted Authenticode certificate is configured; otherwise releases explicitly ship as `UNSIGNED` with SHA-256 checksums. No updater, WinGet, or Store submission is enabled.

## Safety

Do not commit live malware or sensitive evidence. Public tests use synthetic, inert PE fixtures only. See [`SECURITY.md`](SECURITY.md) before reporting a vulnerability — use private disclosure, never a public issue.

If Artifacta helps your triage work, a star keeps the project visible. Issues and pull requests must preserve the evidence-first, local-first trust model (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

## License

Licensed under Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
