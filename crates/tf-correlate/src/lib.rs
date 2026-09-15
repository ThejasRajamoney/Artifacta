#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("correlation input is empty")]
    EmptyInput,
    #[error("no correlations found")]
    NoCorrelations,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CorrelationKey {
    IpAddress(String),
    Domain(String),
    Sha256(String),
    FileName(String),
    Port(u16),
    TimestampWindow { start: String, end: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationHit {
    pub key: CorrelationKey,
    pub source_case_id: String,
    pub target_case_id: String,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub hits: Vec<CorrelationHit>,
    pub summary: CorrelationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSummary {
    pub total_hits: usize,
    pub ip_hits: usize,
    pub domain_hits: usize,
    pub hash_hits: usize,
    pub file_hits: usize,
    pub port_hits: usize,
}

pub struct Correlator;

impl Correlator {
    pub fn correlate(
        source: &CaseCorrelationData,
        target: &CaseCorrelationData,
    ) -> CorrelationResult {
        let mut hits = Vec::new();

        for src_ip in &source.ip_addresses {
            for tgt_ip in &target.ip_addresses {
                if src_ip == tgt_ip {
                    hits.push(CorrelationHit {
                        key: CorrelationKey::IpAddress(src_ip.clone()),
                        source_case_id: source.case_id.clone(),
                        target_case_id: target.case_id.clone(),
                        confidence: 0.9,
                        description: format!("Shared IP address: {}", src_ip),
                    });
                }
            }
        }

        for src_domain in &source.domains {
            for tgt_domain in &target.domains {
                if src_domain == tgt_domain {
                    hits.push(CorrelationHit {
                        key: CorrelationKey::Domain(src_domain.clone()),
                        source_case_id: source.case_id.clone(),
                        target_case_id: target.case_id.clone(),
                        confidence: 0.85,
                        description: format!("Shared domain: {}", src_domain),
                    });
                }
            }
        }

        for src_hash in &source.file_hashes {
            for tgt_hash in &target.file_hashes {
                if src_hash == tgt_hash {
                    hits.push(CorrelationHit {
                        key: CorrelationKey::Sha256(src_hash.clone()),
                        source_case_id: source.case_id.clone(),
                        target_case_id: target.case_id.clone(),
                        confidence: 1.0,
                        description: format!("Shared file hash: {}", &src_hash[..16]),
                    });
                }
            }
        }

        for src_file in &source.file_names {
            for tgt_file in &target.file_names {
                if src_file == tgt_file {
                    hits.push(CorrelationHit {
                        key: CorrelationKey::FileName(src_file.clone()),
                        source_case_id: source.case_id.clone(),
                        target_case_id: target.case_id.clone(),
                        confidence: 0.5,
                        description: format!("Shared file name: {}", src_file),
                    });
                }
            }
        }

        for src_port in &source.ports {
            for tgt_port in &target.ports {
                if src_port == tgt_port {
                    hits.push(CorrelationHit {
                        key: CorrelationKey::Port(*src_port),
                        source_case_id: source.case_id.clone(),
                        target_case_id: target.case_id.clone(),
                        confidence: 0.4,
                        description: format!("Shared port: {}", src_port),
                    });
                }
            }
        }

        let summary = CorrelationSummary {
            total_hits: hits.len(),
            ip_hits: hits
                .iter()
                .filter(|h| matches!(h.key, CorrelationKey::IpAddress(_)))
                .count(),
            domain_hits: hits
                .iter()
                .filter(|h| matches!(h.key, CorrelationKey::Domain(_)))
                .count(),
            hash_hits: hits
                .iter()
                .filter(|h| matches!(h.key, CorrelationKey::Sha256(_)))
                .count(),
            file_hits: hits
                .iter()
                .filter(|h| matches!(h.key, CorrelationKey::FileName(_)))
                .count(),
            port_hits: hits
                .iter()
                .filter(|h| matches!(h.key, CorrelationKey::Port(_)))
                .count(),
        };

        CorrelationResult { hits, summary }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CaseCorrelationData {
    pub case_id: String,
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub file_hashes: Vec<String>,
    pub file_names: Vec<String>,
    pub ports: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_shared_ip() {
        let source = CaseCorrelationData {
            case_id: "case-1".to_owned(),
            ip_addresses: vec!["192.168.1.1".to_owned()],
            ..Default::default()
        };
        let target = CaseCorrelationData {
            case_id: "case-2".to_owned(),
            ip_addresses: vec!["192.168.1.1".to_owned()],
            ..Default::default()
        };
        let result = Correlator::correlate(&source, &target);
        assert_eq!(result.summary.ip_hits, 1);
        assert_eq!(result.hits[0].confidence, 0.9);
    }

    #[test]
    fn correlates_shared_hash() {
        let hash = "a".repeat(64);
        let source = CaseCorrelationData {
            case_id: "case-1".to_owned(),
            file_hashes: vec![hash.clone()],
            ..Default::default()
        };
        let target = CaseCorrelationData {
            case_id: "case-2".to_owned(),
            file_hashes: vec![hash],
            ..Default::default()
        };
        let result = Correlator::correlate(&source, &target);
        assert_eq!(result.summary.hash_hits, 1);
        assert_eq!(result.hits[0].confidence, 1.0);
    }

    #[test]
    fn no_correlations_returns_empty() {
        let source = CaseCorrelationData {
            case_id: "case-1".to_owned(),
            ip_addresses: vec!["10.0.0.1".to_owned()],
            ..Default::default()
        };
        let target = CaseCorrelationData {
            case_id: "case-2".to_owned(),
            ip_addresses: vec!["10.0.0.2".to_owned()],
            ..Default::default()
        };
        let result = Correlator::correlate(&source, &target);
        assert_eq!(result.summary.total_hits, 0);
    }
}
