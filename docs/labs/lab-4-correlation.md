# Lab 4: Cross-Source Correlation

## Objective

Understand how Artifacta can correlate evidence across different artifact types.

## Prerequisites

- Artifacta 1.0.0 installed
- Multiple analyzed cases (PE, EVTX, PCAP)

## Concepts

### Correlation Keys

Artifacta can correlate across cases using:
- **IP Addresses** - Shared network endpoints
- **Domains** - Shared domain names
- **File Hashes** - Identical files (SHA-256)
- **File Names** - Matching filenames
- **Ports** - Shared network ports

### Confidence Scores

Each correlation hit has a confidence score:
- 1.0 - Exact match (e.g., identical SHA-256)
- 0.9 - High confidence (e.g., shared IP address)
- 0.85 - Medium-high (e.g., shared domain)
- 0.5 - Medium (e.g., shared filename)
- 0.4 - Lower (e.g., shared port)

## Example Scenario

1. Analyze a suspicious PE file
2. Analyze a PCAP capture from the same timeframe
3. Analyze EVTX logs from the same system

If the PE file communicates with an IP found in the PCAP, and that IP appears in security events in the EVTX, Artifacta can highlight these connections.

## Future Directions

The correlation engine provides the foundation for:
- Automated cross-case analysis
- Incident response workflows
- Threat intelligence integration
