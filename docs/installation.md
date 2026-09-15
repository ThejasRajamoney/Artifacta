# Installation Guide

This guide covers installing Artifacta 1.0.0 on Windows.

## System Requirements

| Requirement | Minimum |
|---|---|
| Operating system | Windows 10 x64 (compatibility) or Windows 11 (recommended) |
| RAM | 4 GB |
| Disk space | 500 MB |
| Runtime | WebView2 Runtime (installed automatically if missing) |

## Downloading

Download `Artifacta_1.0.0_x64-setup.exe` and `SHA256SUMS` from the
[GitHub Releases](https://github.com/ThejasRajamoney/Artifacta/releases) page.

> **Note:** The installer is currently **unsigned**. See [Verifying Downloads](verifying-downloads.md)
> for details on checksum verification and code signing status.

## Verifying the Checksum

Before installing, verify the file integrity using the SHA-256 checksum:

```powershell
# Get the expected hash from SHA256SUMS
Get-Content SHA256SUMS

# Compute the actual hash
Get-FileHash .\Artifacta_1.0.0_x64-setup.exe -Algorithm SHA256
```

Compare the two values. They must match exactly. See [Verifying Downloads](verifying-downloads.md)
for more detail on what checksums prove and what they do not prove.

## Installing

1. Run `Artifacta_1.0.0_x64-setup.exe`.
2. Follow the installer prompts.
3. The installer requires no administrator privileges (current-user install mode).

The installer blocks version downgrades and includes the project license.

## Silent Install

For unattended deployment:

```powershell
.\Artifacta_1.0.0_x64-setup.exe /S
```

## Explorer Integration

After installation, you can right-click any file in Windows Explorer and select
**Inspect with Artifacta** to open it directly in the application.

## Uninstalling

Use **Apps & Features** in Windows Settings, or run the uninstaller from the
installation directory. Your case data and artifacts are stored separately and
are not removed by the uninstaller.

The uninstaller asks the installed binary to delete the stable PE and YARA AppContainer profiles
with the documented Windows API. Cleanup is best-effort so an active worker cannot break uninstall;
Windows may retain a profile that is still in use.

## WebView2

The installer uses the WebView2 `downloadBootstrapper` mode. On systems without
the required runtime, the installer may download Microsoft WebView2 components.
This installer-time network traffic is distinct from Artifacta's runtime behavior
and should be considered for offline deployment planning.
