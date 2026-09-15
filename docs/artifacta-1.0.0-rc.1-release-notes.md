# Artifacta 1.0.0 RC.1

Artifacta 1.0.0 RC.1 is an unsigned Windows x64 pre-release for evaluation.
It is not the lifecycle-qualified stable 1.0.0 release.

## Highlights

- Local, static analysis for PE32, PE32+, .NET PE, ZIP, EVTX, PCAP/PCAPNG,
  JSONL, CSV, syslog, and generic artifacts.
- Explainable findings linked to exact evidence, deterministic Quick Check,
  investigation graph, chronology, notes, bookmarks, comparison, and search.
- JSON, HTML, PDF, CSV, STIX, integrity-manifest, and portable case-bundle
  export workflows.
- Desktop and command-line interfaces with local content-addressed storage.
- SPDX 2.3 and CycloneDX 1.6 software bills of materials.

## Qualification

- Rust formatting and lint checks pass.
- Rust unit and integration suites pass, excluding documented measurement-only
  tests.
- All 68 corpus fixtures match their expected complete or safe-failure outcome.
- 35 frontend tests pass.
- 6/6 real WebView2 workflows pass against the packaged release executable.

## Important Limitations

- The installer is not Authenticode-signed. Windows may display reputation or
  publisher warnings. Verify it against the accompanying `SHA256SUMS` file.
- Clean install, upgrades from 0.2.2 and 0.3.0, Explorer integration, and
  uninstall behavior still require qualification in a disposable Windows VM.
- The application performs static analysis only. It does not execute or upload
  analyzed artifacts and does not provide a malware, safety, attribution, or
  observed-runtime verdict.
- The automatic updater is disabled for this release candidate.

## Installer

- File: `Artifacta_1.0.0_x64-setup.exe`
- SHA-256: `8f5d34bb2b4b46d29d8f248482bfc3efe95ff543653546756efff219442fc1fa`
- Authenticode status: `NotSigned`

Report security issues privately through the repository security-advisory
channel rather than a public issue.
