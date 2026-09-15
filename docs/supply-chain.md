# Supply-Chain Audit — Artifacta 1.0.0

## Workspace Crates

| Crate | Purpose |
|---|---|
| `artifacta-desktop` | Tauri desktop host; wires crates into the UI |
| `tf-model` | Canonical evidence and investigation domain model |
| `tf-protocol` | Versioned bounded worker protocol definitions |
| `tf-pe` | Disposable PE analyzer and bounded process runner |
| `tf-case` | Case orchestration, comparison, and projection |
| `tf-db` | SQLite persistence layer |
| `tf-report` | Deterministic redacted report rendering |
| `tf-rules` | Deterministic local evidence rules |
| `tf-store` | Artifact content-addressed storage with hash verification |
| `tf-yara` | Local YARA-X library and bounded disposable scanner |
| `tf-model` | Domain model shared by all crates |

All 10 workspace crates plus the desktop host share version `1.0.0` via
`[workspace.package]` in the root `Cargo.toml`.

## Dependency Categories

### Cryptography & Hashing
- `rsa` 0.9.8 — public-key Authenticode verification (no private-key ops)
- `cms` 0.2.3 — CMS/PKCS#7 signature parsing
- `x509-cert` 0.2.5 — X.509 certificate chain parsing
- `der` 0.7.10 — ASN.1 DER encoding
- `const-oid` 0.9.6 — OID constants
- `sha1` 0.10.6, `sha2` 0.10.9, `md-5` 0.10.6 — hash functions

### PE Parsing
- `tf-pe` — custom zero-copy PE parser with corpus tests
- `windows-sys` 0.61.2 — Windows API bindings (process/job/crypto)

### YARA
- `yara-x` 1.20.0 — YARA-X rule scanning engine (Wasmtime-based)

### Persistence
- `rusqlite` 0.40.2 — SQLite (bundled, no system dependency)

### Serialization & Schema
- `serde` 1.0.229, `serde_json` 1.0.151 — JSON serialization
- `schemars` 1.0.4 — JSON Schema generation

### UI
- `tauri` 2.11.5, `@tauri-apps/api` 2.11.1 — desktop shell
- `react` 19.2.8, `react-dom` 19.2.8 — UI framework
- `cytoscape` — graph visualization

### CLI & Utilities
- `thiserror` 2.0.20 — error types
- `time` 0.3.55 — date/time formatting
- `ulid` 1.2.1 — unique lexicographic IDs
- `tempfile` 3.23.0 — temporary files

## Audit Process

### Dependency Pinning
All Cargo dependencies are pinned in `Cargo.lock` (7015 lines). The lockfile
uses `version = 4` format. Every crate entry includes a `checksum` field. The
`Cargo.toml` uses exact version specifiers (`=0.2.3`) for security-sensitive
crates (cms, const-oid, der, x509-cert).

### Audit Configuration
`.cargo/audit.toml` configures `cargo-audit` with three reviewed exceptions:

- **RUSTSEC-2023-0071** (rsa Marvin attack): Affects private-key operations
  only. Artifacta uses RSA solely for public-key Authenticode verification.
- **RUSTSEC-2026-0222** (wasmtime via yara-x): No patched 45.x release
  available. Artifacta does not create cross-engine Wasmtime stores.
- **RUSTSEC-2026-0269** (wasmtime-wasi filesystem escape): The advisory is in
  `wasmtime-wasi`. Artifacta's resolved YARA-X graph includes neither
  `wasmtime-wasi` nor `cap-std`, grants scanned rules no WASI filesystem, and has
  a security-policy test that fails if either dependency appears.

### Config Hardening
No `.cargo/config.toml` exists. Security is enforced through:
- `Cargo.lock` commit pinning
- Exact version specifiers for crypto crates
- Local `cargo audit` review using `.cargo/audit.toml`
- A security-policy test guarding the reviewed Wasmtime filesystem exception

### Network Isolation
All dependencies are fetched from `registry+https://github.com/rust-lang/crates.io-index`.
No `path` dependencies outside the workspace. No `git` dependencies. Build
does not require network access (all sources in lockfile).

### Known Vulnerabilities
`cargo-audit` is not installed by default. This source snapshot has no CI
workflow, so maintainers must run it as a local release gate.

## Verifying Dependencies

### Check lockfile integrity
```bash
cargo metadata --locked --format-version 1 > /dev/null
```

### Run cargo-audit
```bash
cargo install cargo-audit --locked
cargo audit
```

### Verify pinned versions
```bash
grep 'checksum' Cargo.lock | wc -l  # should equal number of registry packages
```

### Verify no git dependencies
```bash
grep -c 'source = "git+' Cargo.lock  # should be 0
```

### Verify exact crypto pins
```bash
grep -A1 'name = "rsa"' Cargo.lock
grep -A1 'name = "cms"' Cargo.lock
grep -A1 'name = "x509-cert"' Cargo.lock
```

## Known Limitations

1. **Wasmtime transitive dependency**: yara-x pulls in wasmtime 45.x with two
   reviewed advisories. Artifacta creates no cross-engine stores and includes
   neither the vulnerable `wasmtime-wasi` filesystem implementation nor
   `cap-std`. These exceptions must be revisited when YARA-X updates Wasmtime.
2. **No SBOM signature**: The SPDX SBOM is generated but not signed. Verify
   it against `SHA256SUMS` instead.
3. **npm dependencies**: Frontend dependencies are pinned in `package-lock.json`
   but npm's integrity model is weaker than Cargo's checksum-based lockfile.
4. **No reproducible builds**: While `profile.release` uses `codegen-units = 1`
   and `lto = true`, full reproducibility requires identical toolchain versions.
