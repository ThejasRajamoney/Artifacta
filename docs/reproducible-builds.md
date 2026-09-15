# Reproducible Builds

Artifacta aims for reproducible builds so independent verifiers can confirm
that a published installer was produced from the corresponding source archive.

## Current Status

Artifacta 1.0.0 is **not fully reproducible**. The workspace has no Git
metadata, so the source archive is a filtered filesystem snapshot rather than a
commit-anchored archive. The Rust compiler, NSIS toolchain, and Tauri bundler
introduce non-deterministic elements (timestamps, paths, compiler metadata)
that prevent byte-identical installer output across machines.

## What Is Verified

- All source files, lockfiles, and configuration are committed and pinned.
- `Cargo.lock` and `package-lock.json` pin exact dependency versions.
- `rust-toolchain.toml` pins the Rust toolchain to `1.98.0`.
- `tools/release.ps1` validates version consistency across all manifests.
- The SPDX SBOM records every resolved dependency with exact versions.
- `SHA256SUMS` provides content-addressed integrity for every release artifact.
- The source archive excludes build outputs, caches, secrets, and executable
  fixtures; it retains encoded `.hex` fixtures, documentation, and manifests.

## How to Verify

1. Obtain the published `artifacta-1.0.0-source.tar.gz` and
   `artifacta-1.0.0.spdx.json` from `release/1.0.0/`.
2. Install Rust `1.98.0` (MSVC) and Node.js `>=24 <25`.
3. Run `npm install` and `npm run build`.
4. Compare the resulting `target/release/artifacta-desktop.exe` hash against the
   published `SHA256SUMS`.

Exact byte-identical output is not yet expected. Verification confirms that the
source builds successfully, produces the same product version, and the SBOM
matches the resolved dependency graph.

## Future Work

- Anchor source archives to Git commits for audit traceability.
- Investigate `cargo build --reproducible` and Tauri determinism options.
- Timestamp-free NSIS installer output.
- Automated reproducibility CI job comparing builder output against published
  checksums.
