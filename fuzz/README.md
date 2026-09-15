# Fuzzing

The fuzz package is excluded from the production workspace and uses nightly Rust only.
All targets consume bytes in-process; the PE target writes a bounded temporary file because
the production parser intentionally accepts a file handle. It never executes an artifact.

Install once:

```powershell
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
```

The supported fuzz host is Linux, matching nightly CI. The targets compile on Windows MSVC,
but executing an instrumented binary there also requires a compatible LLVM sanitizer runtime.

Short local smoke checks (30 seconds each):

```powershell
cargo +nightly fuzz run protocol -- -max_total_time=30
cargo +nightly fuzz run model_contracts -- -max_total_time=30
cargo +nightly fuzz run pe_static -- -max_total_time=30 -max_len=2097152
cargo +nightly fuzz run report_manifest -- -max_total_time=30
```

Nightly CI gives each target 10 minutes. Seed PE runs from the existing inert corpus without
copying fixtures:

```powershell
cargo +nightly fuzz run pe_static testfiles -- -max_total_time=600 -max_len=2097152
```

Coverage boundaries:

- `protocol` covers bounded NDJSON deserialization for PE and YARA request/record contracts.
- `model_contracts` covers evidence, findings, entities, edges, and events.
- `pe_static` reaches PE headers/directories, strings, IOC extraction, CLR, resources, and
  Authenticode structure through the production parser implementation.
- `report_manifest` covers manifest deserialization and defensive report/manifest verification.
- Report construction, database projection, and YARA compilation require internally consistent
  object graphs or separate containment and are exercised by deterministic tests instead of
  accepting arbitrary fuzz bytes through redesigned production APIs.

Crashes under `fuzz/artifacts/` may contain mutated corpus bytes. Review them as untrusted and
never replace the permanent inert corpus with an unexplained generated input.
