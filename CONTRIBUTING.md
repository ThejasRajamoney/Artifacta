# Contributing

Contributions must preserve Artifacta's evidence-first and local-first trust
model.

- Do not add telemetry, automatic uploads, or network access to analyzers.
- Do not add claims such as "safe", "clean", or "malware detected" without a
  fact that supports that exact language.
- Every finding rule requires positive and negative inert fixtures.
- Every reported byte location must be bounds checked.
- Never commit real malware or proprietary evidence.
- Keep dependencies pinned and record third-party license information.

Run frontend, Rust, Python, schema, and rule checks relevant to your change
before opening a pull request.
