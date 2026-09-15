# Lab 3: Network Capture (PCAP) Analysis

## Objective

Analyze PCAP/PCAPNG network captures to extract protocol and connection information.

## Prerequisites

- Artifacta 1.0.0 installed
- A .pcap or .pcapng file from a network capture

## Steps

### 1. Obtaining PCAP Files

Network captures can be obtained using:
- Wireshark
- tcpdump
- tshark
- NetworkMiner

### 2. Using the Desktop UI

1. Drag a .pcap or .pcapng file into the Artifacta window
2. Artifacta parses the capture format
3. View extracted packet metadata

### 3. Using the CLI

```bash
# Analyze a PCAP file
artifacta-cli pcap C:\path\to\capture.pcap

# Output shows:
# - Case ID
# - Total packets
# - Protocols detected
# - Source IP addresses
# - Destination IP addresses
```

### 4. Understanding PCAP Analysis

Artifacta extracts per packet:
- Packet index
- Captured vs original length
- Protocol (TCP, UDP, ICMP, ARP, IPv6)
- Source and destination IP addresses
- Source and destination ports (for TCP/UDP)

### 5. Protocol Summary

The summary shows:
- All unique protocols found
- All unique source IP addresses
- All unique destination IP addresses

## Limitations

- Maximum 100,000 packets per file
- Only Ethernet frames are parsed (no raw IP or cooked captures)
- No deep packet inspection or payload analysis
- No stream reassembly
