#![forbid(unsafe_code)]

use std::fs::File;
use std::io::BufReader;

use pcap_parser::{create_reader, PcapBlockOwned};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_PACKETS: usize = 100_000;

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("failed to open PCAP file: {0}")]
    Open(#[source] std::io::Error),
    #[error("PCAP parse error: {0}")]
    Parse(String),
    #[error("PCAP file contains no packets")]
    Empty,
    #[error("PCAP file exceeds the maximum packet limit of {MAX_PACKETS}")]
    TooManyPackets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedPacket {
    pub index: usize,
    pub captured_len: u32,
    pub original_len: u32,
    pub protocol: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysis {
    pub total_packets: usize,
    pub packets: Vec<NormalizedPacket>,
    pub summary: PcapSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapSummary {
    pub protocols: Vec<String>,
    pub src_ips: Vec<String>,
    pub dst_ips: Vec<String>,
}

pub fn is_pcap_bytes(bytes: &[u8]) -> bool {
    is_pcap_magic(bytes) || is_pcapng_magic(bytes)
}

pub fn is_pcap_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1
}

pub fn is_pcapng_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic == 0x0a0d0d0a
}

pub fn analyze_pcap_file(path: impl AsRef<std::path::Path>) -> Result<PcapAnalysis, PcapError> {
    let file = File::open(path.as_ref()).map_err(PcapError::Open)?;
    let reader = BufReader::new(file);
    analyze_pcap(reader)
}

pub fn analyze_pcap<R: std::io::Read + Send + 'static>(
    reader: R,
) -> Result<PcapAnalysis, PcapError> {
    let mut pcap_reader =
        create_reader(65536, reader).map_err(|e| PcapError::Parse(format!("{:?}", e)))?;

    let mut packets = Vec::new();
    let mut seen_protocols = std::collections::HashSet::new();
    let mut seen_src_ips = std::collections::HashSet::new();
    let mut seen_dst_ips = std::collections::HashSet::new();

    let mut index = 0;
    loop {
        if packets.len() >= MAX_PACKETS {
            return Err(PcapError::TooManyPackets);
        }
        match pcap_reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::Legacy(ref block) = block {
                    let captured_len = block.caplen;
                    let original_len = block.origlen;
                    let data = block.data;

                    let (protocol, src_ip, dst_ip, src_port, dst_port) = parse_ethernet(data);

                    if let Some(ref p) = protocol {
                        seen_protocols.insert(p.clone());
                    }
                    if let Some(ref ip) = src_ip {
                        seen_src_ips.insert(ip.clone());
                    }
                    if let Some(ref ip) = dst_ip {
                        seen_dst_ips.insert(ip.clone());
                    }

                    packets.push(NormalizedPacket {
                        index,
                        captured_len,
                        original_len,
                        protocol,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    });
                    index += 1;
                }
                pcap_reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap_or(());
            }
            Err(_) => break,
        }
    }

    if packets.is_empty() {
        return Err(PcapError::Empty);
    }

    let mut protocols: Vec<String> = seen_protocols.into_iter().collect();
    protocols.sort();
    let mut src_ips: Vec<String> = seen_src_ips.into_iter().collect();
    src_ips.sort();
    let mut dst_ips: Vec<String> = seen_dst_ips.into_iter().collect();
    dst_ips.sort();

    Ok(PcapAnalysis {
        total_packets: packets.len(),
        packets,
        summary: PcapSummary {
            protocols,
            src_ips,
            dst_ips,
        },
    })
}

type ParsedPacket = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u16>,
    Option<u16>,
);

fn parse_ethernet(data: &[u8]) -> ParsedPacket {
    if data.len() < 14 {
        return (None, None, None, None, None);
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    match ethertype {
        0x0800 => parse_ipv4(&data[14..]),
        0x0806 => (Some("ARP".to_owned()), None, None, None, None),
        0x86DD => (Some("IPv6".to_owned()), None, None, None, None),
        _ => (None, None, None, None, None),
    }
}

fn parse_ipv4(data: &[u8]) -> ParsedPacket {
    if data.len() < 20 {
        return (None, None, None, None, None);
    }
    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    let proto_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Other",
    };

    let ihl = (data[0] & 0x0f) as usize * 4;
    let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && data.len() >= ihl + 4 {
        let sp = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
        let dp = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
        (Some(sp), Some(dp))
    } else {
        (None, None)
    };

    (
        Some(proto_name.to_owned()),
        Some(src_ip),
        Some(dst_ip),
        src_port,
        dst_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pcap_magic_bytes() {
        assert!(is_pcap_bytes(&0xa1b2c3d4u32.to_le_bytes()));
        assert!(is_pcap_bytes(&0xd4c3b2a1u32.to_le_bytes()));
        assert!(is_pcap_bytes(&0x0a0d0d0au32.to_le_bytes()));
        assert!(!is_pcap_bytes(b"MZ\x00\x00"));
        assert!(!is_pcap_bytes(&[]));
    }
}
