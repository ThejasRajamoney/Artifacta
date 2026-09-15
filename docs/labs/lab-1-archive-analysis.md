# Lab 1: ZIP Archive Analysis

## Objective

Analyze a ZIP archive containing multiple PE files and understand how Artifacta handles child artifacts.

## Prerequisites

- Artifacta 1.0.0 installed
- A ZIP file containing one or more PE files (.exe, .dll, .sys)

## Steps

### 1. Using the Desktop UI

1. Drag a ZIP file into the Artifacta window
2. Artifacta will:
   - Create a parent case for the archive
   - Extract each entry from the archive
   - Automatically analyze any PE files found
   - Create child cases for each PE file
3. Navigate between the parent archive case and child PE cases

### 2. Using the CLI

```bash
# Analyze a ZIP archive
artifacta-cli archive C:\path\to\archive.zip

# Output shows:
# - Archive case ID
# - Number of entries extracted
# - Total extracted size
# - Number of PE files found and analyzed
```

### 3. Understanding the Results

The parent archive case shows:
- Archive metadata (name, SHA-256, size)
- Entry listing with sizes
- Child case references

Each child case contains the full PE analysis as if the file were analyzed individually.

## Security Notes

- Archives are extracted with path traversal protection
- Maximum 10,000 entries per archive
- Maximum 512 MB per entry
- Maximum 2 GB total extracted size
- Only PE files (detected by MZ header) are automatically analyzed
