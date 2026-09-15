#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_RECORDS: usize = 100_000;
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("log file is empty")]
    Empty,
    #[error("log file exceeds the maximum record limit of {MAX_RECORDS}")]
    TooManyRecords,
    #[error("log line exceeds the maximum length of {MAX_LINE_BYTES} bytes")]
    LineTooLong,
    #[error("CSV parse error: {0}")]
    Csv(String),
    #[error("JSON parse error: {0}")]
    Json(String),
    #[error("unknown log format")]
    UnknownFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Jsonl,
    Csv,
    Syslog,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRecord {
    pub index: usize,
    pub timestamp: Option<String>,
    pub level: Option<String>,
    pub message: String,
    pub source: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnalysis {
    pub format: LogFormat,
    pub total_records: usize,
    pub records: Vec<NormalizedRecord>,
    pub summary: LogSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSummary {
    pub levels: Vec<String>,
    pub sources: Vec<String>,
}

pub fn detect_format(bytes: &[u8]) -> LogFormat {
    if bytes.len() < 4 {
        return LogFormat::Unknown;
    }
    if bytes[0] == b'{' {
        return LogFormat::Jsonl;
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    if bytes[0] == b'<' || text.contains(" <") {
        return LogFormat::Syslog;
    }
    if bytes[0] == b'"' || (bytes[0].is_ascii_alphabetic() && bytes.contains(&b',')) {
        return LogFormat::Csv;
    }
    LogFormat::Unknown
}

pub fn analyze_log<R: Read>(reader: R, format: Option<LogFormat>) -> Result<LogAnalysis, LogError> {
    let buf = BufReader::new(reader);
    let mut all_lines: Vec<String> = Vec::new();
    let mut detected_format = format.unwrap_or(LogFormat::Unknown);

    for line_result in buf.lines() {
        let line = line_result.map_err(|e| LogError::Json(e.to_string()))?;
        if line.len() > MAX_LINE_BYTES {
            return Err(LogError::LineTooLong);
        }
        if line.trim().is_empty() {
            continue;
        }
        all_lines.push(line);
        if all_lines.len() >= MAX_RECORDS {
            return Err(LogError::TooManyRecords);
        }
    }

    if all_lines.is_empty() {
        return Err(LogError::Empty);
    }

    if detected_format == LogFormat::Unknown {
        detected_format = detect_format(all_lines[0].as_bytes());
    }

    let mut records = Vec::new();
    let mut seen_levels = std::collections::HashSet::new();
    let mut seen_sources = std::collections::HashSet::new();

    match detected_format {
        LogFormat::Jsonl => {
            for (idx, line) in all_lines.iter().enumerate() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    let timestamp = val
                        .get("timestamp")
                        .or_else(|| val.get("time"))
                        .or_else(|| val.get("@timestamp"))
                        .or_else(|| val.get("ts"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let level = val
                        .get("level")
                        .or_else(|| val.get("severity"))
                        .or_else(|| val.get("loglevel"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let message = val
                        .get("message")
                        .or_else(|| val.get("msg"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let source = val
                        .get("source")
                        .or_else(|| val.get("logger"))
                        .or_else(|| val.get("component"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    if let Some(ref l) = level {
                        seen_levels.insert(l.clone());
                    }
                    if let Some(ref s) = source {
                        seen_sources.insert(s.clone());
                    }
                    records.push(NormalizedRecord {
                        index: idx,
                        timestamp,
                        level,
                        message,
                        source,
                        raw: line.clone(),
                    });
                }
            }
        }
        LogFormat::Csv => {
            let combined = all_lines.join("\n");
            let mut rdr = csv::Reader::from_reader(combined.as_bytes());
            if let Ok(headers) = rdr.headers() {
                let headers: Vec<String> = headers.iter().map(String::from).collect();
                for (idx, row_result) in rdr.records().enumerate() {
                    if let Ok(row) = row_result {
                        let get = |name: &str| -> Option<String> {
                            headers
                                .iter()
                                .position(|h| h.eq_ignore_ascii_case(name))
                                .and_then(|i| row.get(i).map(String::from))
                                .filter(|s| !s.is_empty())
                        };
                        let timestamp = get("timestamp")
                            .or_else(|| get("time"))
                            .or_else(|| get("date"));
                        let level = get("level").or_else(|| get("severity"));
                        let message = get("message").or_else(|| get("msg")).unwrap_or_default();
                        let source = get("source").or_else(|| get("logger"));
                        if let Some(ref l) = level {
                            seen_levels.insert(l.clone());
                        }
                        if let Some(ref s) = source {
                            seen_sources.insert(s.clone());
                        }
                        records.push(NormalizedRecord {
                            index: idx,
                            timestamp,
                            level,
                            message,
                            source,
                            raw: all_lines.get(idx + 1).cloned().unwrap_or_default(),
                        });
                    }
                }
            }
        }
        LogFormat::Syslog => {
            for (idx, line) in all_lines.iter().enumerate() {
                let (timestamp, level, message) = parse_syslog_line(line);
                if let Some(ref l) = level {
                    seen_levels.insert(l.clone());
                }
                records.push(NormalizedRecord {
                    index: idx,
                    timestamp,
                    level,
                    message,
                    source: None,
                    raw: line.clone(),
                });
            }
        }
        LogFormat::Unknown => {
            for (idx, line) in all_lines.iter().enumerate() {
                records.push(NormalizedRecord {
                    index: idx,
                    timestamp: None,
                    level: None,
                    message: line.clone(),
                    source: None,
                    raw: line.clone(),
                });
            }
        }
    }

    let mut levels: Vec<String> = seen_levels.into_iter().collect();
    levels.sort();
    let mut sources: Vec<String> = seen_sources.into_iter().collect();
    sources.sort();

    Ok(LogAnalysis {
        format: detected_format,
        total_records: records.len(),
        records,
        summary: LogSummary { levels, sources },
    })
}

fn parse_syslog_line(line: &str) -> (Option<String>, Option<String>, String) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 3 {
        let timestamp = Some(parts[0].to_owned());
        let level_part = parts[1].trim_matches('<').trim_matches('>');
        let level = match level_part.parse::<u32>() {
            Ok(n) if n <= 3 => Some("crit".to_owned()),
            Ok(n) if n <= 4 => Some("err".to_owned()),
            Ok(n) if n <= 5 => Some("warning".to_owned()),
            Ok(n) if n <= 6 => Some("notice".to_owned()),
            Ok(n) if n <= 7 => Some("info".to_owned()),
            _ => Some(level_part.to_owned()),
        };
        (timestamp, level, parts[2].to_owned())
    } else {
        (None, None, line.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jsonl_format() {
        assert_eq!(detect_format(b"{\"level\":\"info\"}"), LogFormat::Jsonl);
    }

    #[test]
    fn detects_csv_format() {
        assert_eq!(detect_format(b"timestamp,level,message\n"), LogFormat::Csv);
    }

    #[test]
    fn detects_syslog_format() {
        assert_eq!(
            detect_format(b"<13>Sep  3 12:00:00 host service: message"),
            LogFormat::Syslog
        );
    }

    #[test]
    fn parses_jsonl() {
        let input = r#"{"timestamp":"2024-01-01","level":"error","message":"fail"}"#;
        let result = analyze_log(input.as_bytes(), None).unwrap();
        assert_eq!(result.format, LogFormat::Jsonl);
        assert_eq!(result.total_records, 1);
        assert_eq!(result.records[0].level.as_deref(), Some("error"));
    }
}
