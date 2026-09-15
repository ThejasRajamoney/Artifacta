#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{BufReader, Read, Seek};

use evtx::EvtxParser;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_EVENTS: usize = 100_000;

#[derive(Debug, Error)]
pub enum EvtxError {
    #[error("failed to open EVTX file: {0}")]
    Open(#[source] std::io::Error),
    #[error("EVTX parse error: {0}")]
    Parse(String),
    #[error("EVTX file contains no events")]
    Empty,
    #[error("EVTX file exceeds the maximum event limit of {MAX_EVENTS}")]
    TooManyEvents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_record_id: u64,
    pub timestamp: String,
    pub json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxAnalysis {
    pub total_events: usize,
    pub events: Vec<NormalizedEvent>,
    pub summary: EventSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub providers: Vec<String>,
}

pub fn is_evtx_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0] == b'E'
        && bytes[1] == b'l'
        && bytes[2] == b'f'
        && bytes[3] == b'F'
        && bytes[4] == b'i'
        && bytes[5] == b'l'
        && bytes[6] == b'e'
        && bytes[7] == b'\0'
}

pub fn analyze_evtx<R: Read + Seek>(reader: R) -> Result<EvtxAnalysis, EvtxError> {
    let mut parser =
        EvtxParser::from_read_seek(reader).map_err(|e| EvtxError::Parse(e.to_string()))?;

    let mut events = Vec::new();
    let mut seen_providers = std::collections::HashSet::new();

    for result in parser.records_json_value() {
        if events.len() >= MAX_EVENTS {
            return Err(EvtxError::TooManyEvents);
        }
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let timestamp = record.timestamp.to_string();
        let event_record_id = record.event_record_id;

        if let Some(system) = record.data.get("System") {
            if let Some(provider) = system.get("Provider") {
                if let Some(name) = provider.get("@Name").and_then(|v| v.as_str()) {
                    seen_providers.insert(name.to_owned());
                }
            }
        }

        events.push(NormalizedEvent {
            event_record_id,
            timestamp,
            json: Some(record.data),
        });
    }

    if events.is_empty() {
        return Err(EvtxError::Empty);
    }

    let mut providers: Vec<String> = seen_providers.into_iter().collect();
    providers.sort();

    Ok(EvtxAnalysis {
        total_events: events.len(),
        events,
        summary: EventSummary { providers },
    })
}

pub fn analyze_evtx_file(path: impl AsRef<std::path::Path>) -> Result<EvtxAnalysis, EvtxError> {
    let file = File::open(path.as_ref()).map_err(EvtxError::Open)?;
    let reader = BufReader::new(file);
    analyze_evtx(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_evtx_magic_bytes() {
        assert!(is_evtx_bytes(b"ElfFile\0rest"));
        assert!(!is_evtx_bytes(b"MZ\x00\x00"));
        assert!(!is_evtx_bytes(b"PK\x03\x04"));
        assert!(!is_evtx_bytes(&[]));
    }
}
