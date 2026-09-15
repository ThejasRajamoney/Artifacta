# TraceForge validation corpus

This corpus contains **synthetic, non-malicious PE fixtures** designed to exercise TraceForge Analysis v2.
No live malware is included. `06_malware_like_INERT.exe` contains suspicious imports and strings but no malicious implementation.

## Files

### 01_signed_selfsigned_valid.exe — normal signed EXE
- SHA-256: `5d3b8afadfa447dd774d66fd7920c2e62fbc9e813f3a8fcbee00ef9a00319a83`
- Size: 3440 bytes
- Expected:
  - PE64
  - embedded Authenticode certificate table present
  - CMS signature should be cryptographically verifiable
  - self-signed publisher should NOT be treated as trusted
  - 3 imported functions
  - benign URL
- Notes: Cryptographically self-signed synthetic fixture; publisher trust should not be inferred.

### 02_normal_unsigned.exe — normal unsigned EXE
- SHA-256: `632c080f7e6a87283befdc1e6aa8cdafaaeed24e8bf262dfcb89badaedbe4f5f`
- Size: 2048 bytes
- Expected:
  - PE64
  - no Authenticode certificate
  - ordinary imports
  - low-noise strings

### 03_dotnet_managed.exe.hex — .NET app
- SHA-256: `f2c093e9e88265ba3f13e97ee11178d91debba512e6e93f909f95e6d072e615d`
- Size: 3072 bytes
- Storage: ASCII hex decoded in memory for tests; size and hashes describe the decoded PE bytes.
- Expected:
  - PE64
  - CLR data directory present
  - BSJB metadata root
  - mscoree.dll!_CorExeMain
  - managed-style strings

### 04_qt_app.exe — Qt app
- SHA-256: `aa728f9e13f190500a6e8571a3111b7cbac88b2d94d4b0a77692e834431792f8`
- Size: 2560 bytes
- Expected:
  - PE64
  - Qt5Core/Qt5Network/Qt5Widgets imports
  - network URL indicator
  - CreateProcessW contextual capability

### 05_packed_benign.exe — packed benign sample
- SHA-256: `d1735edf4b9901d555ca9ec9b430dd297a8a7f65dd0ff5251341e9d393426d5e`
- Size: 133632 bytes
- Expected:
  - PE64
  - large high-entropy .packed section
  - VirtualProtect import
  - should be suspicious/packed context but NOT malware verdict
- Notes: Contains deterministic random bytes only; no unpacking or malicious code.

### 06_malware_like_INERT.exe — known-malware-style SAFE fixture
- SHA-256: `0779d3beef44059e07b5e73c04835cf4cc502bbb4c4ed064cf0a8dcf220c4a8f`
- Size: 2560 bytes
- Expected:
  - PE64
  - process injection primitive imports
  - persistence/service imports
  - network imports
  - anti-debug import
  - PowerShell/command/registry/URL indicators
  - should generate multiple capability findings
- Notes: INERT synthetic fixture: imports and strings only. It does not implement or execute malicious behavior.

### 07_malformed_pe.exe — malformed PE
- SHA-256: `8397a4103a30279a8abe853a86eed5bbba21b8b64a9f1fb4a82759481d7418fe`
- Size: 700 bytes
- Expected:
  - MZ and PE signatures present
  - section points far beyond EOF
  - analyzer should fail safely / record coverage error
  - must not crash worker

### 08_ctf_reversing.exe — CTF reversing binary
- SHA-256: `92a29f93732a1cd75af7e42cf2ac098209535b3d2068b23c01cb462b90f05930`
- Size: 3072 bytes
- Expected:
  - PE64
  - flag is XOR-encoded, not present in plaintext
  - XOR key 0x5A stored near encoded blob
  - Correct/Wrong/flag-format clues
  - IsDebuggerPresent import
- Notes: Expected decoded flag: TRIVARNA{traceforge_static_re_fixture}

### 09_compare_app_v1.exe — artifact comparison v1
- SHA-256: `b9ad2a1724fbf7bafdbd458a97277a0a4a58a3d9aec9caf6cdf5623b6ebb7f9a`
- Size: 2048 bytes
- Expected:
  - PE64
  - baseline imports/strings
  - version=1.0

### 10_compare_app_v2.exe — artifact comparison v2
- SHA-256: `1dea6bb73232acc346f50ce44962d4b0801faef5d97dfd59523abb300ecf63ab`
- Size: 2048 bytes
- Expected:
  - PE64
  - adds CreateProcessW
  - adds WinHttpSendRequest
  - changes URL/version
  - adds powershell.exe string

## Suggested regression checks

1. Analyze each file from a fresh case.
2. Confirm the worker never executes the artifact.
3. Confirm malformed input fails safely without a worker/app crash.
4. Confirm the self-signed fixture separates **cryptographic signature validity** from **publisher trust**.
5. Confirm the packed-like fixture is treated as contextual/suspicious, not automatically malicious.
6. Confirm the inert malware-like fixture produces stronger multi-evidence capability findings.
7. Confirm the CTF fixture exposes clues but does not reveal the XOR-encoded flag as a normal plaintext string.
8. Compare `09_compare_app_v1.exe` with `10_compare_app_v2.exe` and verify added/removed/changed evidence.
9. Verify fixtures 11-68 parse correctly and exercise their intended parser/rule paths.

### PE Format (11-16)
- `11_pe32_minimal.exe` — Bare minimum PE32
- `12_pe64_minimal.exe` — Bare minimum PE64
- `13_pe32_plus.exe` — PE32+ with low image base
- `14_unusual_alignment.exe` — Non-standard section alignment
- `15_truncated_header.exe` — Truncated optional header (should fail safely)
- `16_corrupt_directory.exe` — Invalid directory entry beyond EOF

### Compiler/Runtime (17-24)
- `17_msvc_like.exe` — MSVC-style imports (kernel32, msvcrt)
- `18_mingw_like.exe` — MinGW-style (libgcc, msvcrt)
- `19_rust_like.exe` — Rust-like patterns
- `20_go_like.exe` — Go-like patterns
- `21_dotnet_v2.exe` — .NET v2 CLR
- `22_dotnet_v4.exe` — .NET v4 CLR
- `23_qt_network.exe` — Qt with network imports
- `24_qt_widgets.exe` — Qt with widget imports

### Signature (25-30)
- `25_unsigned_normal.exe` — Normal unsigned
- `26_selfsigned_cert.exe` — Has embedded certificate table
- `27_invalid_digest.exe` — Invalid image digest
- `28_invalid_cms.exe` — Malformed CMS signature
- `29_multiple_certs.exe` — Multiple WIN_CERTIFICATE entries
- `30_no_certificate_table.exe` — No certificate table

### Structural (31-42)
- `31_writable_executable.exe` — W+X section permissions
- `32_high_entropy_section.exe` — High entropy in .text
- `33_high_entropy_resource.exe` — High entropy in resources
- `34_overlay_data.exe` — Data appended after sections
- `35_certificate_tail.exe` — Certificate after EOF
- `36_unusual_section_names.exe` — Non-standard section names
- `37_tls_callbacks.exe` — TLS callback array
- `38_load_config.exe` — Load config directory
- `39_relocations.exe` — Relocation table
- `40_export_table.exe` — DLL with exports
- `41_no_imports.exe` — PE with no imports
- `42_large_import_table.exe` — Many imports

### Capability (43-50)
- `43_process_injection.exe` — VirtualAllocEx+WriteProcessMemory+CreateRemoteThread
- `44_near_miss_injection.exe` — Similar but missing one function
- `45_run_persistence.exe` — Run key registry APIs
- `46_service_persistence.exe` — OpenSCManager+CreateService
- `47_network_exec.exe` — URLDownloadToFile+ShellExecute
- `48_network_only.exe` — URLDownload without execution
- `49_exec_only.exe` — ShellExecute without network
- `50_admin_manifest.exe` — requireAdministrator manifest

### Edge Cases (51-58)
- `51_entropy_noise.exe` — Random dotted strings
- `52_false_dll_domain.exe` — .dll false positive domain
- `53_false_exe_domain.exe` — .exe false positive domain
- `54_unicode_strings.exe` — Unicode string indicators
- `55_ipv4_indicator.exe` — Embedded IPv4
- `56_invalid_ipv4.exe` — Invalid IPv4 addresses
- `57_registry_paths.exe` — Registry path strings
- `58_windows_paths.exe` — Windows file paths

### YARA (59-60)
- `59_yara_positive.exe` — Contains known YARA match pattern
- `60_yara_negative.exe` — No YARA matches

### Malformed (61-64)
- `61_section_oob.exe` — Section points beyond EOF
- `62_directory_oob.exe` — Directory entry beyond EOF
- `63_enormous_counts.exe` — Huge import/section counts
- `64_overlapping_sections.exe` — Overlapping section ranges

### Comparison (65-66)
- `65_compare_v1.exe` — Version 1.0 with /v1 URL
- `66_compare_v2.exe` — Version 2.0 with /v2 URL

### CTF/RE (67-68)
- `67_xor_clue.exe` — XOR-encoded data pattern
- `68_anti_debug.exe` — IsDebuggerPresent + CheckRemoteDebuggerPresent

These files are parser/test fixtures, not production applications. They are intentionally minimal and may not execute normally on Windows. The encoded `.hex` fixture must remain encoded on disk; tests and development tooling decode it only in memory.
