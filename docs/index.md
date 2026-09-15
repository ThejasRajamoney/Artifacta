# Artifacta 1.0.0 Documentation

Artifacta is a free, local-first Windows security triage application. Inspect suspicious Windows executables locally and trace every conclusion back to inspectable evidence.

> **Disclaimer:** Artifacta does not execute imported artifacts, upload evidence, provide an antivirus verdict, or claim that a file is safe. It is a static triage tool, not malware detection software.

## Table of Contents

### Getting Started

- [Installation](installation.md) -- System requirements, downloading, installing, and uninstalling
- [First Analysis](first-analysis.md) -- Walkthrough of analyzing your first file
- [Troubleshooting](troubleshooting.md) -- Common issues and solutions

### Core Concepts

- [Quick Check](quick-check.md) -- Deterministic triage bands and confidence scoring
- [Findings](findings.md) -- What findings are, categories, severity, and confidence
- [Investigation Graph](graph.md) -- Visualizing entity relationships
- [Chronology](chronology.md) -- Timestamp sources and reliability

### Analysis Features

- [YARA Integration](yara.md) -- Custom YARA rule packs with YARA-X
- [Reports](reports.md) -- Generating HTML, JSON, and PDF case reports
- [Product Requirements Audit](product-requirements-audit.md) -- Implemented, partial, missing, and externally blocked product-brief requirements

### Operations and Security

- [Verifying Downloads](verifying-downloads.md) -- Checksum verification and code signing status
- [Security Model](security-model.md) -- Architecture, worker containment, and egress policy
- [Privacy](privacy.md) -- Data handling, telemetry, and local storage

### Reference

- [Threat Model](threat-model.md) -- Trust boundaries and adversarial assumptions
- [Releasing](releasing.md) -- Release process and artifact generation
- [Performance Baselines](performance-baseline.json) -- Parser and analysis benchmarks
- [Test Infrastructure](testing.md) -- Test suite and CI pipeline
- [Parser Oracle](parser-oracle.md) -- Differential PE parser validation

## Product Contract

```text
Artifact -> Provenance -> Evidence -> Finding -> Explanation
```

Every finding must cite inspectable evidence. Every evidence record must retain its generation provenance.

## License

Licensed under Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
