# Differential PE parser oracle

`tools/pe_oracle.py` is a development-only differential check. It parses inert files with
both `pefile` and the feature-gated Artifacta parser contract, then compares PE kind,
machine, entry point, image base, section layout, and normal imports. Neither parser
executes the file.

ASCII `.hex` fixtures are decoded in memory for both parsers. The oracle does not write
decoded PE bytes to disk.

```powershell
python -m pip install -r requirements-dev.txt
python tools/pe_oracle.py testfiles/01_signed_selfsigned_valid.exe testfiles/03_dotnet_managed.exe.hex
```

The oracle is deliberately not linked into the application. The `dev-tools` feature is
off by default and CI checks production without relying on Python.

## Intentional differences

- Malformed files rejected by either parser are reported as `SKIP`, not a differential
  failure. Artifacta applies stricter bounded-range and section-count policy.
- Section names use each parser's lossy ASCII representation; non-ASCII spelling is not
  a security contract.
- Import order and duplicate imports are compared because they affect imphash. Delay
  imports are excluded because pefile's normal import API does not represent the same
  contract.
- Rich headers, resources, Authenticode, CLR, strings, IOCs, entropy rounding, overlays,
  and trust are intentionally excluded. Their semantics and safety limits differ from
  pefile and are covered by native tests instead.
- The oracle makes no correctness, malware, trust, or safety claim. Agreement only gives
  an independent regression signal for the listed fields.
