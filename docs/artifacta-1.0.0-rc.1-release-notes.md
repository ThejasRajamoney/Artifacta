# Artifacta v1.0.0-rc.1 — unsigned pre-release for evaluation

**Understand a suspicious Windows file without uploading it, executing it, or trusting anyone's verdict.**

Artifacta is a free, local-first static investigation workbench. Drop in a PE executable, a ZIP archive, an EVTX log, a PCAP capture, or a structured log, and get evidence-backed findings where every conclusion links to the exact bytes, headers, imports, strings, signatures, or packets behind it.

If it helps your triage work, star the repo — it keeps the project visible.

## What's inside

- **Multi-artifact intake** — PE32/PE32+, .NET metadata, ZIP archives with PE child extraction, EVTX, PCAP/PCAPNG, JSONL/CSV/syslog, and generic hashed artifacts in one case.
- **Explainable findings** — deterministic rules with severity, confidence-as-rule-strength, limitations, exact evidence links, and caveated ATT&CK static-capability context. No malware verdicts, no safety claims, ever.
- **Investigator workflow** — cases, finding states, notes, bookmarks, investigation graph, chronology, cross-case search, artifact comparison, and cross-source correlation.
- **Reports you can defend** — deterministic JSON, self-contained HTML, locally rendered PDF, CSV, and STIX 2.1, all with integrity manifests and local verification.
- **Desktop + headless CLI**, content-addressed local storage, plugin SDK, Windows Sandbox handoff stub, and guided labs.
- **Supply chain** — SPDX 2.3 + CycloneDX 1.6 SBOMs, filtered source archive, and release metadata in every release.

## Qualification

| Gate | Result |
|---|---|
| Rust fmt / clippy `-D warnings` | PASS |
| Rust suites | 137 passed, 0 failed |
| 68-fixture corpus | 60/68 expected outcomes (8 documented safe failures) |
| Desktop corpus E2E | PASS |
| Real WebView2 E2E | 6/6 PASS |
| Frontend (vitest + axe) | 35 PASS |

## Verify before installing

The installer is **not Authenticode-signed** (no trusted certificate available). Windows will show an unknown-publisher warning. Verify integrity first:

```powershell
(Get-FileHash .\Artifacta_1.0.0_x64-setup.exe -Algorithm SHA256).Hash.ToLowerInvariant()
# must equal 8f5d34bb2b4b46d29d8f248482bfc3efe95ff543653546756efff219442fc1fa
```

Or verify every asset against `SHA256SUMS`. Checksums prove the download is intact; they do not establish publisher identity.

## Know the limits

- **Static analysis only.** Artifacta never executes artifacts, never uploads them, and never provides malware, safety, attribution, or observed-runtime verdicts. It is not an antivirus.
- **Stable distribution is pending** isolated Windows install/upgrade/uninstall qualification in a disposable VM. This RC must not be presented as the qualified stable 1.0.0.
- **Updater is disabled.** WinGet/Store submission is out of scope.
- Found a security issue? Report it privately via GitHub Private Vulnerability Reporting — never a public issue.

## Assets

| File | Purpose |
|---|---|
| `Artifacta_1.0.0_x64-setup.exe` | Windows x64 installer (current-user, no admin) |
| `Artifacta_1.0.0_x64-setup.exe.sha256` | Installer checksum sidecar |
| `SHA256SUMS` | Checksums for every asset |
| `SIGNING-STATUS.txt` | Explicit unsigned status |
| `artifacta-1.0.0-source.tar.gz` | Filtered source snapshot |
| `artifacta-1.0.0.spdx.json` / `artifacta-1.0.0.cdx.json` | SPDX 2.3 / CycloneDX 1.6 SBOMs |
| `release-metadata.json`, `LICENSE.txt`, `NOTICE.txt` | Release identity and license notices |

Full evidence: `ARTIFACTA_1.0.0_COMPLETION_REPORT.md` and `docs/product-requirements-audit.md` in the source tree.
