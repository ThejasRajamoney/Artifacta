# Quick Check

## What It Is

Quick Check is Artifacta's deterministic triage summary. It aggregates active findings
produced by the built-in rule engine and YARA scans into a single, transparent assessment
band with supporting evidence.

Quick Check does **not** provide a verdict. It is a structured summary of what the static
analysis found, not a determination of whether a file is malicious or safe.

## The Four Bands

| Band | Meaning |
|---|---|
| **No strong indicators** | No elevated signals detected across evidence families |
| **Review** | Minor anomalies or a small number of low-severity findings |
| **Suspicious** | Multiple elevated signals across evidence families |
| **High suspicion** | Strong indicators across several evidence families |

The band is determined by the Quick Check policy, which is versioned. The policy version
and SHA-256 hash are included in every report for auditability.

## How Confidence Is Calculated

Quick Check aggregates findings across six independent **evidence families**:

| Family | Description |
|---|---|
| `structure` | PE structural anomalies (section characteristics, entry point, etc.) |
| `capability` | Static capability observations (process injection, persistence, etc.) |
| `indicator` | Extracted indicators (URLs, domains, IPs, registry keys, commands) |
| `signature_integrity` | Authenticode signature status and chain validation |
| `yara` | Matches from loaded YARA rule packs |
| `metadata_anomaly` | Timestamp, version data, and other metadata anomalies |

Each family independently contributes its single strongest scoring signal. The policy
correlates these signals across families to determine the final band. This approach
prevents a single high-severity finding in one family from dominating the assessment.

## Finding Counts

Quick Check reports counts of active findings before correlation and family de-duplication:

- **total** -- All active findings
- **contextual** -- Informational context
- **low** -- Low-severity findings
- **medium** -- Medium-severity findings
- **high** -- High-severity findings

## Top Findings

The Quick Check summary includes up to three **top findings** -- the most significant
findings selected for the summary view. Each top finding shows:

- Finding ID, title, and category
- Severity
- Evidence family it belongs to

## Policy Versioning

The Quick Check policy is versioned independently of the application version.
This allows the triage logic to be refined without changing the application version.

The report includes:

- `policy_version` -- Semantic version of the applied policy
- `policy_sha256` -- Hash of the policy source for exact reproducibility

## What Quick Check Is NOT

- **Not malware detection** -- Quick Check does not classify files as malware or benign.
- **Not a verdict** -- It does not produce a "clean" or "infected" determination.
- **Not a replacement for analysis** -- It is a summary tool to help triage and prioritize.
- **Not dynamic analysis** -- It is based entirely on static evidence.
- **Not real-time protection** -- It analyzes one file at a time on demand.

## Statement

Every Quick Check result includes a plain-language **statement** summarizing the band
and what it means. This statement is generated deterministically from the policy and
findings.
