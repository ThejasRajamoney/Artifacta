# Troubleshooting

## App Won't Start

**Symptoms:** Double-clicking the installer or shortcut produces no window.

**Solutions:**

1. **Check WebView2** -- Artifacta requires the Microsoft Edge WebView2 Runtime.
   The installer attempts to download it automatically, but offline systems need
   it pre-installed. Download from [Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).
2. **Check Windows version** -- Windows 10 x64 or Windows 11 is required. 32-bit
   Windows is not supported.
3. **Check system resources** -- Ensure at least 4 GB RAM is available.
4. **Check antivirus** -- Some antivirus software may block unsigned executables.
   Check your antivirus logs for blocked execution events.

## File Won't Analyze

**Symptoms:** Dropping or selecting a file produces no analysis results.

**Solutions:**

1. **File too large** -- Artifacta has a 256 MiB hard limit on artifact intake.
   Files larger than this are rejected.
2. **Not a PE file** -- Artifacta only analyzes PE32 and PE32+ executables. Non-PE
   files (scripts, documents, archives) are not supported.
3. **Empty file** -- Zero-byte files are rejected during intake.
4. **File permissions** -- Ensure the file is readable and not locked by another process.

## Analysis Takes Too Long

**Symptoms:** Analysis hangs or takes longer than expected.

**Solutions:**

1. **Worker timeout** -- The PE worker has a 15-second wall-time deadline. If analysis
   exceeds this, the worker is terminated and an error is reported.
2. **Large files** -- Very large PE files with many sections or imports take longer
   to parse. This is expected behavior.
3. **System load** -- High CPU or disk I/O can slow analysis. Close other applications
   and retry.
4. **YARA compilation** -- First-time YARA rule compilation can take a few seconds.
   Subsequent scans use cached compiled rules.

## YARA Rules Not Loading

**Symptoms:** YARA packs do not appear in the management panel or do not produce matches.

**Solutions:**

1. **Syntax errors** -- Invalid YARA rules are rejected at import time. Check the
   error message for details on what failed.
2. **Includes disabled** -- YARA `include` directives are not supported. Each rule
   file must be self-contained.
3. **Modules disabled** -- YARA modules (`pe`, `math`, `cuckoo`, etc.) are not
   available. Rules using modules will fail to compile.
4. **Pack not referenced** -- Ensure the YARA pack is active and associated with
   the current case.

## Export Fails

**Symptoms:** Report export produces an error or empty file.

**Solutions:**

1. **Destination permissions** -- Ensure the destination folder is writable.
2. **Path too long** -- Windows has path length limits. Choose a shorter destination
   path.
3. **Disk space** -- Ensure sufficient disk space for the report file.
4. **Concurrent access** -- Close other applications that may have the destination
   file open.

## Database Errors

**Symptoms:** Application shows database errors or fails to load cases.

**Solutions:**

1. **Corrupted database** -- The SQLite database (`traceforge.db`) is located in
   the application data directory. If corrupted, Artifacta will report the error
   on startup.
2. **Concurrent access** -- Do not open the database file directly with other
   tools while Artifacta is running.
3. **Disk full** -- SQLite requires free disk space for WAL mode. Ensure adequate
   disk space.
4. **Migration failure** -- If a schema migration fails, the database may be in
   an inconsistent state. Back up the database file and contact support.
