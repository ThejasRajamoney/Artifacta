# Test infrastructure

## Fast pull-request checks

```powershell
npm ci
npm test
npm run check
npm run frontend:build --workspace @artifacta/desktop
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The Rust suite validates checked schemas, the normalized evidence/finding/entity/edge/event/
report/manifest golden, source privacy policy, and every documented expectation and hash for
the 68-file inert corpus. Antivirus-sensitive fixtures are stored as ASCII hex and decoded, hashed, and
parsed in memory so antivirus exclusions are unnecessary. Frontend tests use jsdom and mocked Tauri IPC; they exercise opaque
intake workflow, evidence navigation/focus, Quick Check actions, ARIA semantics, and axe-core.
They are component/workflow tests, not a real WebView2 or native-picker system test.

## Longer checks

- `docs/parser-oracle.md` describes the independent pefile differential check.
- `fuzz/README.md` separates 30-second local smoke runs from 10-minute nightly runs.
- `docs/performance.md` documents ignored, non-gating measurements.
- Pull-request, nightly, and release workflows are not present in this source
  snapshot. The commands above and the longer checks remain local release gates
  until equivalent reviewed workflows are added.

The permanent corpus contains 68 reproducible synthetic/inert fixtures. Encoded
fixtures have manifest sizes and hashes describing their decoded bytes. No live
malware belongs in any test path.
