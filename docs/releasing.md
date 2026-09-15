# Releasing Artifacta

## Version boundaries

The application, npm workspace, Rust workspace packages, Tauri configuration,
fuzz workspace package references, and UI fallback share the release version.
`tools/release.ps1 -CheckOnly` verifies these references.

The following are independent compatibility or semantic policy versions and do
not change merely because the application version changes:

- Worker protocol: `1`.
- Report schema: `4`; report manifest schema: `1`.
- SQLite schema: `11`.
- Built-in rule engine: `2.2.0`; quick-check policy: `1.0.0`.

The Tauri identifier `org.traceforge.desktop` is also intentional legacy state.
It preserves the application-local storage namespace from the TraceForge name.
Changing it can orphan existing cases and requires an explicit migration and
installer identity review.

## Local artifacts

Run from the repository root:

```powershell
npm run release:check
npm run release:prepare
```

The second command builds an isolated temporary staging directory and replaces
`release/1.0.0/` only after its exact artifact allowlist is complete. The npm
wrapper supplies the exact 1.0.0 NSIS installer; direct script invocations must
pass `-InstallerPath` explicitly. A rerun without `-InstallerPath` cannot retain
an installer or installer hash from an earlier run. An existing output containing
any unknown file or directory is rejected rather than recursively replaced. The
output contains an SPDX 2.3 JSON SBOM, source `tar.gz`, release metadata,
`LICENSE.txt`, `NOTICE.txt`, explicit signing status, and `SHA256SUMS`.

In a Git checkout release preparation fails if tracked or untracked source is
dirty, archives `HEAD`, and records the full commit in release metadata. This
keeps the source archive and lockfile-derived SBOM tied to the clean source used
for the installer build. Snapshot fallback copies a fixed, filtered source set
into a separate staging tree and rejects dependency/build/release trees,
reparse points, environment files, credentials, and common key/certificate
formats. It retains the inert corpus manifest, documentation, and encoded `.exe.hex`
fixtures but omits raw `testfiles/*.exe`, which Windows antivirus can intentionally
prevent a non-Git archiver from reading. Git release archives include all safe tracked paths
directly from Git objects. Pass `-InstallerPath` after a separate Tauri build to
add the exact `Artifacta_1.0.0_x64-setup.exe` and its `.sha256` sidecar.

The SBOM is a conservative resolved Cargo/npm inventory. Artifacta and its
desktop package are identified as applications, internal crates and third-party
packages are identified as libraries, and SPDX relationships distinguish
contained packages, runtime dependencies, Cargo build dependencies, and
development dependencies. npm's lockfile has no separate build scope, so npm
development scope includes build and test tooling; runtime relationships can be
transitive and are not claims that every package is a direct dependency.

## GitHub release

This source snapshot does not contain an automated GitHub release workflow.
Before publication, a reviewed workflow must reproduce the documented Node 24
frontend checks/tests/build, full Rust workspace tests, formatting, strict
clippy, schema, golden, corpus, privacy, and NSIS release-package gates. Build
jobs should be read-only; any publication job should consume only the exact
qualified artifact set and use least-privilege `contents: write` permission.

Pre-releases (tags like `v1.0.0-rc.1`) may be published for evaluation once the
completion report records all non-destructive qualification gates as passing
against the exact shipped binary and installer. Stable releases additionally
require isolated Windows install, upgrade, Explorer-integration, and uninstall
qualification plus explicit release approval, and must not occur until the
completion report grants distribution approval.

The canonical repository is `https://github.com/artifacta/artifacta`, the Windows
bundle publisher is `Artifacta`, and private security reports use
`https://github.com/artifacta/artifacta/security/advisories/new`. Release
automation must not configure signing or the updater implicitly. The release tool inspects Authenticode
and emits `SIGNING-STATUS.txt`; without a trusted certificate the installer is
explicitly marked `UNSIGNED`, never simulated as signed, and must be verified
using its published SHA-256 checksum. WinGet and Microsoft Store submission are
outside this workflow.
