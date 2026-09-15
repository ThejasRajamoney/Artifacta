# Investigation Graph

## What the Graph Shows

The investigation graph visualizes relationships between entities extracted during
artifact analysis. Entities are connected by edges that represent observable
relationships derived from static analysis. The graph helps you understand how
different parts of an artifact relate to each other.

The graph is derived from static evidence. It does not represent runtime behavior.

## Entity Types

| Type | Description |
|---|---|
| `artifact` | The analyzed file and its metadata |
| `section` | PE sections (e.g., `.text`, `.rdata`) |
| `imported_api` | Imported API functions and their source libraries |
| `export` | Exported functions |
| `url` | Embedded URL strings |
| `domain` | Domain name strings |
| `ip_address` | IP address strings |
| `file_path` | File system path strings |
| `registry_path` | Registry path strings |
| `registry_key` | Registry key strings |
| `command_string` | Command-line strings |
| `certificate` | Certificate objects from the signature chain |
| `signer` | Signer identity from Authenticode signatures |
| `yara_rule` | Matched YARA rules |
| `finding` | Findings produced by the rule engine |
| `network_flow` | Network flow indicators (reserved for future use) |
| `host` | Host indicators (reserved for future use) |
| `process` | Process indicators (reserved for future use) |

## Edge Types (Relationships)

| Relationship | Meaning |
|---|---|
| `contains` | Parent contains child (e.g., artifact contains section) |
| `imports` | Artifact imports an API |
| `exports` | Artifact exports a function |
| `contains_indicator` | Artifact contains an indicator entity |
| `references_path` | Entity references a file path |
| `signed_by` | Artifact is signed by a signer |
| `uses_certificate` | Signature uses a certificate |
| `matched_rule` | Artifact matched a YARA rule |
| `supports_finding` | Evidence supports a finding |
| `contradicts_finding` | Evidence contradicts a finding |
| `derived_from` | Entity is derived from another entity |
| `resolves_to` | Name resolves to an address |
| `communicates_with` | Communication relationship (reserved) |

## Navigation

### Pan

Click and drag on the background to pan the view.

### Zoom

Use the mouse wheel to zoom in and out. Pinch to zoom on touch devices.

### Search

Use the search bar to filter entities by name, type, or value. Matching entities
are highlighted in the graph.

### Filter

Toggle entity types on or off using the filter panel. This reduces clutter when
focusing on specific relationship types.

### Focus on Node

Click a node to focus on it. Connected edges and neighboring nodes are highlighted.
The side panel shows entity details and linked evidence.

### Fit to Screen

Click the **Fit** button to reset the view and fit all visible nodes within the viewport.
