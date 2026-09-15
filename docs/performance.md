# Baseline measurements

Performance checks are ignored, informational tests. They print one JSON object per
measurement and have no pass/fail threshold. This prevents noisy shared-runner timing from
becoming a false regression gate while preserving repeatable parser, projection, search,
report, and comparison workloads.

```powershell
cargo test -p tf-pe tests::measure_parser_baseline -- --ignored --exact --nocapture
cargo test -p tf-case projection::tests::measure_projection_baseline -- --ignored --exact --nocapture
cargo test -p tf-db tests::measure_search_baseline -- --ignored --exact --nocapture
cargo test -p tf-report tests::measure_report_baseline -- --ignored --exact --nocapture
cargo test -p tf-case tests::measure_comparison_baseline -- --ignored --exact --nocapture
```

Record the full environment with results: commit, OS, CPU, available memory, power mode,
Rust version, build profile, and whether endpoint security was scanning the workspace. Compare
like-for-like medians across at least five process invocations. The nightly workflow uploads raw
logs; it does not claim stable benchmark numbers across GitHub-hosted machines.

`performance-baseline.json` contains one honest local smoke measurement from the workload's
introduction. It is provenance for the harness, not a portable target or claimed product speed.
