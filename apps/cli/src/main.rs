#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tf_case::{CaseService, ReportFormat};
use tf_model::{CaseId, CaseSearchRequest, SearchField};

#[derive(Parser)]
#[command(
    name = "artifacta-cli",
    about = "Artifacta headless CLI for static investigation",
    version
)]
struct Cli {
    #[arg(long, help = "Data directory for cases and artifacts")]
    data_dir: Option<String>,
    #[command(subcommand)]
    command: Command,
}

fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("artifacta")
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Analyze a PE file")]
    Analyze {
        #[arg(help = "Path to the PE file to analyze")]
        path: PathBuf,
    },
    #[command(about = "Analyze a ZIP archive (extracts and analyzes PE files)")]
    Archive {
        #[arg(help = "Path to the ZIP archive")]
        path: PathBuf,
    },
    #[command(about = "Analyze a Windows Event Log (EVTX) file")]
    Evtx {
        #[arg(help = "Path to the EVTX file")]
        path: PathBuf,
    },
    #[command(about = "Analyze a PCAP/PCAPNG network capture")]
    Pcap {
        #[arg(help = "Path to the PCAP file")]
        path: PathBuf,
    },
    #[command(about = "Analyze a structured log file (JSONL/CSV/syslog)")]
    Log {
        #[arg(help = "Path to the log file")]
        path: PathBuf,
    },
    #[command(about = "Ingest any file as a generic artifact")]
    Ingest {
        #[arg(help = "Path to the file")]
        path: PathBuf,
    },
    #[command(about = "List all cases")]
    List,
    #[command(about = "Show details for a case")]
    Show {
        #[arg(help = "Case ID")]
        case_id: String,
    },
    #[command(about = "Search across all cases")]
    Search {
        #[arg(help = "Search query")]
        query: String,
        #[arg(long, default_value = "20", help = "Maximum results")]
        limit: u32,
    },
    #[command(about = "Export a case report")]
    Export {
        #[arg(help = "Case ID")]
        case_id: String,
        #[arg(long, help = "Report format: json, csv, html, stix")]
        format: String,
        #[arg(short, long, help = "Output file path")]
        output: PathBuf,
    },
    #[command(about = "Compare two cases")]
    Compare {
        #[arg(help = "Left case ID")]
        left: String,
        #[arg(help = "Right case ID")]
        right: String,
    },
    #[command(about = "Export a portable case bundle")]
    Bundle {
        #[arg(help = "Case ID")]
        case_id: String,
        #[arg(short, long, help = "Output directory for the bundle")]
        output: PathBuf,
    },
    #[command(about = "Import a portable case bundle")]
    Import {
        #[arg(help = "Path to the bundle directory")]
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);
    let cases = CaseService::open(&data_dir)
        .with_context(|| format!("Could not open data directory: {}", data_dir.display()))?;

    match cli.command {
        Command::Analyze { path } => cmd_analyze(&cases, &path),
        Command::Archive { path } => cmd_archive(&cases, &path),
        Command::Evtx { path } => cmd_evtx(&cases, &path),
        Command::Pcap { path } => cmd_pcap(&cases, &path),
        Command::Log { path } => cmd_log(&cases, &path),
        Command::Ingest { path } => cmd_ingest(&cases, &path),
        Command::List => cmd_list(&cases),
        Command::Show { case_id } => cmd_show(&cases, &case_id),
        Command::Search { query, limit } => cmd_search(&cases, &query, limit),
        Command::Export {
            case_id,
            format,
            output,
        } => cmd_export(&cases, &case_id, &format, &output),
        Command::Compare { left, right } => cmd_compare(&cases, &left, &right),
        Command::Bundle { case_id, output } => cmd_bundle(&cases, &case_id, &output),
        Command::Import { path } => cmd_import(&cases, &path),
    }
}

fn cmd_analyze(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Analyzing: {}", path.display());
    let result = cases.ingest_pe(&path).context("Analysis failed")?;
    print_intake_result(cases, &result)
}

fn cmd_archive(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Analyzing archive: {}", path.display());
    let result = cases
        .ingest_archive(&path)
        .context("Archive analysis failed")?;
    println!("Archive case: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Entries:  {}", result.listing.entries.len());
    println!("  Total extracted: {} bytes", result.listing.total_size);
    println!("  PE files found: {}", result.child_cases.len());
    println!();
    for child in &result.child_cases {
        print_intake_result(cases, child)?;
        println!();
    }
    Ok(())
}

fn cmd_evtx(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Analyzing EVTX: {}", path.display());
    let result = cases.ingest_evtx(&path).context("EVTX analysis failed")?;
    println!("Case created: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Size:     {} bytes", result.artifact.size_bytes);
    println!("  Status:   {}", result.case.status.as_str());
    println!();
    println!(
        "Events: {} total across {} providers",
        result.evtx.total_events,
        result.evtx.summary.providers.len()
    );
    Ok(())
}

fn cmd_pcap(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Analyzing PCAP: {}", path.display());
    let result = cases.ingest_pcap(&path).context("PCAP analysis failed")?;
    println!("Case created: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Size:     {} bytes", result.artifact.size_bytes);
    println!("  Status:   {}", result.case.status.as_str());
    println!();
    println!("Packets: {} total", result.pcap.total_packets);
    println!("  Protocols: {}", result.pcap.summary.protocols.join(", "));
    println!("  Source IPs: {}", result.pcap.summary.src_ips.join(", "));
    println!("  Dest IPs: {}", result.pcap.summary.dst_ips.join(", "));
    Ok(())
}

fn cmd_log(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Analyzing log: {}", path.display());
    let result = cases.ingest_log(&path).context("Log analysis failed")?;
    println!("Case created: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Size:     {} bytes", result.artifact.size_bytes);
    println!("  Status:   {}", result.case.status.as_str());
    println!();
    println!(
        "Format: {}",
        match result.log.format {
            tf_log::LogFormat::Jsonl => "JSONL",
            tf_log::LogFormat::Csv => "CSV",
            tf_log::LogFormat::Syslog => "Syslog",
            tf_log::LogFormat::Unknown => "Unknown",
        }
    );
    println!("  Records: {}", result.log.total_records);
    if !result.log.summary.levels.is_empty() {
        println!("  Levels: {}", result.log.summary.levels.join(", "));
    }
    if !result.log.summary.sources.is_empty() {
        println!("  Sources: {}", result.log.summary.sources.join(", "));
    }
    Ok(())
}

fn cmd_ingest(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Ingesting: {}", path.display());
    let result = cases.ingest_generic(&path).context("Ingestion failed")?;
    println!("Case created: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Size:     {} bytes", result.artifact.size_bytes);
    println!("  Status:   {}", result.case.status.as_str());
    Ok(())
}

fn print_intake_result(cases: &CaseService, result: &tf_case::IntakeResult) -> Result<()> {
    println!("Case created: {}", result.case.id.as_str());
    println!("  Artifact: {}", result.artifact.original_name);
    println!("  SHA-256:  {}", result.artifact.sha256);
    println!("  Size:     {} bytes", result.artifact.size_bytes);
    println!("  Status:   {}", result.case.status.as_str());
    println!();

    let analysis = cases
        .get_case_analysis(&result.case.id)
        .context("Could not retrieve analysis")?
        .context("Analysis not found")?;

    println!(
        "Quick Check: {} ({})",
        analysis.quick_check.band.as_str(),
        analysis.quick_check.statement
    );
    println!();

    let finding_count = analysis.findings.len();
    let evidence_count = analysis.evidence.len();
    println!("Findings:  {finding_count}");
    println!("Evidence:  {evidence_count}");

    if finding_count > 0 {
        println!();
        for finding in &analysis.findings {
            let explanation = analysis
                .explanations
                .iter()
                .find(|e| e.finding_id == finding.id);
            let observation = explanation.map(|e| e.observation.as_str()).unwrap_or("");
            println!(
                "  [{}] {} ({})",
                finding.severity.as_str(),
                finding.title,
                finding.category
            );
            if !observation.is_empty() {
                let obs = if observation.len() > 200 {
                    &observation[..200]
                } else {
                    observation
                };
                println!("    {}", obs.replace('\n', " "));
            }
        }
    }
    Ok(())
}

fn cmd_list(cases: &CaseService) -> Result<()> {
    let list = cases.list_cases().context("Could not list cases")?;
    if list.is_empty() {
        println!("No cases found.");
        return Ok(());
    }
    println!(
        "{:<40} {:<30} {:<12} Created",
        "Case ID", "Artifact", "Status"
    );
    println!("{}", "-".repeat(95));
    for case in &list {
        println!(
            "{:<40} {:<30} {:<12} {}",
            case.id.as_str(),
            truncate(&case.title, 28),
            case.status.as_str(),
            case.created_at
        );
    }
    println!("\n{} cases total.", list.len());
    Ok(())
}

fn cmd_show(cases: &CaseService, case_id: &str) -> Result<()> {
    let id: CaseId = case_id.parse().context("Invalid case ID")?;
    let analysis = cases
        .get_case_analysis(&id)
        .context("Could not retrieve case")?
        .context("Case not found")?;

    println!("Case:       {}", analysis.case.id.as_str());
    println!("Title:      {}", analysis.case.title);
    println!("Status:     {}", analysis.case.status.as_str());
    println!("Created:    {}", analysis.case.created_at);
    println!("Updated:    {}", analysis.case.updated_at);
    println!();
    println!("Artifact:   {}", analysis.artifact.original_name);
    println!("Kind:       {}", analysis.artifact.kind.as_str());
    println!("Size:       {} bytes", analysis.artifact.size_bytes);
    println!("SHA-256:    {}", analysis.artifact.sha256);
    println!("SHA-1:      {}", analysis.artifact.sha1);
    println!("MD5:        {}", analysis.artifact.md5);

    println!();
    println!(
        "Quick Check: {} ({})",
        analysis.quick_check.band.as_str(),
        analysis.quick_check.statement
    );

    if let Some(run) = &analysis.analysis_run {
        println!();
        println!("Analysis Run: {}", run.id.as_str());
        println!("  Analyzer:  {} {}", run.analyzer, run.analyzer_version);
        println!("  Status:    {}", run.status.as_str());
        println!("  Started:   {}", run.started_at);
        if let Some(finished) = &run.finished_at {
            println!("  Finished:  {finished}");
        }
        if let Some(error) = &run.error_code {
            println!("  Error:     {error}");
        }
    }

    let finding_count = analysis.findings.len();
    let evidence_count = analysis.evidence.len();
    println!();
    println!("Findings:   {finding_count}");
    println!("Evidence:   {evidence_count}");
    println!("Provenance: {}", analysis.provenances.len());
    println!("Rules:      {}", analysis.rules.len());

    Ok(())
}

fn cmd_search(cases: &CaseService, query: &str, limit: u32) -> Result<()> {
    let request = CaseSearchRequest {
        query: query.to_owned(),
        fields: vec![
            SearchField::Sha256,
            SearchField::Sha1,
            SearchField::Md5,
            SearchField::CaseTitle,
            SearchField::Import,
            SearchField::Indicator,
            SearchField::FindingTitle,
            SearchField::FindingCategory,
            SearchField::EvidenceValue,
        ],
        include_archived: false,
        limit,
    };
    let hits = cases.search_cases(&request).context("Search failed")?;
    if hits.is_empty() {
        println!("No results found for: {query}");
        return Ok(());
    }
    println!(
        "{:<40} {:<30} {:<12} Match",
        "Case ID", "Case Title", "Status"
    );
    println!("{}", "-".repeat(95));
    for hit in &hits {
        println!(
            "{:<40} {:<30} {:<12} {}",
            hit.case_id.as_str(),
            truncate(&hit.case_title, 28),
            hit.case_status.as_str(),
            truncate(&format!("{}={}", hit.field.as_str(), hit.value), 20),
        );
    }
    println!("\n{} results.", hits.len());
    Ok(())
}

fn cmd_export(
    cases: &CaseService,
    case_id: &str,
    format: &str,
    output: &std::path::Path,
) -> Result<()> {
    let id: CaseId = case_id.parse().context("Invalid case ID")?;
    let report_format = match format.to_lowercase().as_str() {
        "json" => ReportFormat::Json,
        "html" => ReportFormat::Html,
        "csv" => ReportFormat::Csv,
        "stix" => ReportFormat::Stix,
        _ => anyhow::bail!("Unsupported format: {format}. Use json, html, csv, or stix."),
    };
    let generated_at = chrono::Utc::now().to_rfc3339();
    let record = cases
        .export_report(&id, report_format, generated_at, output)
        .with_context(|| format!("Export failed for case {case_id}"))?;
    println!("Exported: {}", output.display());
    println!("  Format: {}", record.format);
    println!("  SHA-256: {}", record.sha256);
    Ok(())
}

fn cmd_compare(cases: &CaseService, left: &str, right: &str) -> Result<()> {
    let left_id: CaseId = left.parse().context("Invalid left case ID")?;
    let right_id: CaseId = right.parse().context("Invalid right case ID")?;
    let comparison = cases
        .compare_cases(&left_id, &right_id)
        .context("Comparison failed")?;

    println!("Comparing {left} vs {right}");
    println!();

    fn print_group(label: &str, group: &tf_model::ComparisonGroup) {
        println!("  {label}:");
        println!("    Added:   {}", group.added.len());
        println!("    Removed: {}", group.removed.len());
        println!("    Changed: {}", group.changed.len());
        for entry in &group.added {
            println!("      + {}", entry.key);
        }
        for entry in &group.removed {
            println!("      - {}", entry.key);
        }
        for entry in &group.changed {
            println!("      ~ {}", entry.key);
        }
    }

    println!("Imports:");
    print_group("imports", &comparison.imports);
    println!();
    println!("Strings:");
    print_group("strings", &comparison.strings);
    println!();
    println!("Findings:");
    print_group("findings", &comparison.findings);

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

fn cmd_bundle(cases: &CaseService, case_id: &str, output: &std::path::Path) -> Result<()> {
    let id: CaseId = case_id.parse().context("Invalid case ID")?;
    let result = cases
        .export_case_bundle(&id, output)
        .with_context(|| format!("Bundle export failed for case {case_id}"))?;
    println!("Bundle exported to: {}", result.destination.display());
    println!("  Case:     {}", result.manifest.case_title);
    println!("  Artifact: {}", result.manifest.artifact_name);
    println!("  SHA-256:  {}", result.manifest.artifact_sha256);
    println!("  Objects:  {}", result.manifest.artifacts.len());
    println!(
        "  Manifest: {}",
        output.join("bundle-manifest.json").display()
    );
    Ok(())
}

fn cmd_import(cases: &CaseService, path: &std::path::Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve path: {}", path.display()))?;
    println!("Importing bundle from: {}", path.display());
    let case_id = cases
        .import_case_bundle(&path)
        .context("Bundle import failed")?;
    println!("Bundle imported successfully!");
    println!("  Case ID: {}", case_id.as_str());
    Ok(())
}
