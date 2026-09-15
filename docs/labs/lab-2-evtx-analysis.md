# Lab 2: Windows Event Log (EVTX) Analysis

## Objective

Analyze Windows Event Log files to extract event metadata and provider information.

## Prerequisites

- Artifacta 1.0.0 installed
- An .evtx file from a Windows system

## Steps

### 1. Obtaining EVTX Files

Windows Event Logs are stored in:
```
C:\Windows\System32\winevt\Logs\
```

Common logs to analyze:
- `Security.evtx` - Authentication and authorization events
- `System.evtx` - System service events
- `Application.evtx` - Application events
- `Microsoft-Windows-PowerShell%4Operational.evtx` - PowerShell execution

### 2. Using the Desktop UI

1. Drag an .evtx file into the Artifacta window
2. Artifacta parses the binary EVTX format
3. View the normalized event data

### 3. Using the CLI

```bash
# Analyze an EVTX file
artifacta-cli evtx C:\path\to\Security.evtx

# Output shows:
# - Case ID
# - Total events parsed
# - Number of unique providers
```

### 4. Understanding EVTX Analysis

Artifacta extracts:
- Event Record IDs
- Timestamps
- Provider names
- JSON representation of each event

The analysis is read-only and does not modify the source log file.

## Limitations

- Maximum 100,000 events per file
- Events are parsed to JSON but not deeply interpreted
- No correlation with other artifact types (yet)
