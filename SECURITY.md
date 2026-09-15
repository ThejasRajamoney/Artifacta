# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.0+  | :white_check_mark: |

Only the latest release of Artifacta receives security updates. Please
upgrade to the newest version before reporting or investigating a
vulnerability.

## Reporting a Vulnerability

Artifacta processes attacker-controlled files. **Do not open a public
issue** for vulnerabilities that could lead to code execution, sandbox
escape, evidence disclosure, signature bypass, unsafe sample execution, or
updater compromise.

Use [GitHub Private Vulnerability Reporting](https://github.com/ThejasRajamoney/Artifacta/security/advisories/new) to
disclose vulnerabilities privately. This ensures only maintainers can see
your report.

### What to include

- A description of the vulnerability and its potential impact.
- Step-by-step instructions to reproduce the issue.
- A minimal inert reproducer (never attach live malware, private case
  data, signing keys, or credentials).
- The version of Artifacta you tested against.
- Any suggested fix, if you have one.

## Response Timeline

| Action | Target |
|--------|--------|
| Acknowledgement of report | 3 business days |
| Initial triage and severity assessment | 7 business days |
| Fix or mitigation for confirmed issues | 30 days for critical/high, 90 days for medium/low |

These are targets, not guarantees. We will keep you informed of progress
through the advisory.

## Safe Harbor

We support responsible disclosure and will not pursue legal action against
researchers who:

- Make a good faith effort to avoid privacy violations, data destruction,
  or service disruption.
- Only interact with accounts you own or with explicit permission of the
  account holder.
- Do not exploit a vulnerability beyond what is necessary to confirm its
  existence.
- Report promptly and do not publicly disclose the issue before a fix is
  available.

## Scope

**In scope:**

- Code execution through crafted input files.
- Sandbox escape or privilege escalation.
- Memory safety issues (use-after-free, buffer overflow, etc.).
- Cryptographic weaknesses affecting Authenticode verification.
- Supply-chain risks in build or update mechanisms.
- Evidence disclosure or data exfiltration.

**Out of scope:**

- Denial of service against the local application.
- Social engineering or phishing.
- Issues in third-party dependencies not directly used by Artifacta's
  trust boundaries.
- Theoretical attacks requiring physical access to the host machine.
