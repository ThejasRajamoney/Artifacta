# Verifying Downloads

## SHA-256 Checksums

Every Artifacta release includes a `SHA256SUMS` file containing SHA-256 hashes for
all release artifacts. Use these to verify file integrity after download.

## SHA256SUMS File

The `SHA256SUMS` file contains one line per artifact in the format:

```
<sha256hex>  <filename>
```

Example:

```
a1b2c3d4e5f6...  Artifacta_1.0.0_x64-setup.exe
f6e5d4c3b2a1...  Artifacta_1.0.0_source.tar.gz
```

## PowerShell Verification

### Verify the installer

```powershell
# Read the expected hash
$expected = (Get-Content SHA256SUMS | Select-String "Artifacta_1.0.0_x64-setup.exe").Line.Split()[0]

# Compute the actual hash
$actual = (Get-FileHash .\Artifacta_1.0.0_x64-setup.exe -Algorithm SHA256).Hash

# Compare
if ($expected -eq $actual) {
    Write-Host "Checksum OK" -ForegroundColor Green
} else {
    Write-Host "Checksum MISMATCH" -ForegroundColor Red
}
```

### Verify the SBOM

```powershell
$expected = (Get-Content SHA256SUMS | Select-String "spdx-sbom.json").Line.Split()[0]
$actual = (Get-FileHash .\spdx-sbom.json -Algorithm SHA256).Hash
if ($expected -eq $actual) { "OK" } else { "MISMATCH" }
```

## What Checksums Prove

Checksums verify **file integrity** -- that the file you downloaded is byte-for-byte
identical to the file that was published. They confirm the file was not corrupted
during transfer or tampered with in transit.

## What Checksums Do NOT Prove

Checksums do **not** prove **authenticity**. Anyone who can modify the file can also
update the checksum file. Checksums protect against accidental corruption, not a
compromised distribution channel.

For authenticity, you would need cryptographic code signing (Authenticode), which is
not yet implemented for Artifacta releases.

## Code Signing Status

Artifacta releases are currently **unsigned**. The release tooling inspects Authenticode
and emits a `SIGNING-STATUS.txt` file, but without external signing the installer is
explicitly marked `UNSIGNED`.

This means:

- Windows SmartScreen may show a warning when running the installer
- There is no cryptographic proof of publisher identity
- Checksum verification is the primary integrity mechanism

## SBOM Verification

The release includes an SPDX 2.3 JSON SBOM (`spdx-sbom.json`) documenting the
complete dependency tree. You can verify the SBOM hash against `SHA256SUMS` and
review it to understand exactly what components are included in the release.

The SBOM is a conservative resolved Cargo/npm inventory. It identifies applications,
internal packages, and third-party libraries with explicit relationship types.
