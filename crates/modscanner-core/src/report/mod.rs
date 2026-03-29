use crate::engine::{Finding, Severity};
use crate::scanner::ScanReport;
use owo_colors::OwoColorize;
use serde::Serialize;

/// Print a scan report to the terminal with colors
pub fn print_terminal_report(report: &ScanReport) {
    println!();
    println!("{}", "=== ModScanner Report ===".bold());
    println!("  Path:     {}", report.root_path.display());
    println!("  Scanned:  {} files", report.scanned_files);
    println!("  Duration: {:.2}s", report.duration.as_secs_f64());

    if !report.errors.is_empty() {
        println!("  Errors:   {}", report.errors.len().yellow());
    }

    println!();

    if report.findings.is_empty() {
        println!("  {} No threats detected.", "✓".green().bold());
        println!();
        return;
    }

    let critical = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    println!(
        "  {} findings: {} critical, {} high, {} medium, {} low, {} info",
        report.findings.len().to_string().bold(),
        if critical > 0 {
            critical.to_string().red().bold().to_string()
        } else {
            "0".into()
        },
        if high > 0 {
            high.to_string().red().to_string()
        } else {
            "0".into()
        },
        if medium > 0 {
            medium.to_string().yellow().to_string()
        } else {
            "0".into()
        },
        low,
        info,
    );
    println!();

    for finding in &report.findings {
        let severity_str = match finding.severity {
            Severity::Critical => format!("[{}]", "CRITICAL".red().bold()),
            Severity::High => format!("[{}]", "HIGH".red()),
            Severity::Medium => format!("[{}]", "MEDIUM".yellow()),
            Severity::Low => format!("[{}]", "LOW".dimmed()),
            Severity::Info => format!("[{}]", "INFO".dimmed()),
        };

        let location = if let Some(line) = finding.line_number {
            format!("{}:{}", finding.file_path.display(), line)
        } else {
            format!("{}", finding.file_path.display())
        };

        println!("  {} {}", severity_str, finding.title.bold());
        println!("    File: {}", location.dimmed());
        println!("    {}", finding.description);
        if let Some(rule) = &finding.matched_rule {
            println!("    Rule: {}", rule.dimmed());
        }
        println!();
    }
}

/// JSON-serializable finding
#[derive(Serialize)]
struct JsonFinding {
    engine: &'static str,
    severity: String,
    title: String,
    description: String,
    file: String,
    line: Option<u32>,
    byte_offset: Option<u64>,
    rule: Option<String>,
}

impl From<&Finding> for JsonFinding {
    fn from(f: &Finding) -> Self {
        JsonFinding {
            engine: f.engine_name,
            severity: f.severity.to_string().to_lowercase(),
            title: f.title.clone(),
            description: f.description.clone(),
            file: f.file_path.display().to_string(),
            line: f.line_number,
            byte_offset: f.byte_offset,
            rule: f.matched_rule.clone(),
        }
    }
}

/// JSON-serializable report
#[derive(Serialize)]
struct JsonReport {
    path: String,
    scanned_files: u32,
    skipped_files: u32,
    duration_secs: f64,
    findings: Vec<JsonFinding>,
    errors: Vec<String>,
    summary: JsonSummary,
}

#[derive(Serialize)]
struct JsonSummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

/// Print a scan report as JSON
pub fn print_json_report(report: &ScanReport) {
    let json_report = JsonReport {
        path: report.root_path.display().to_string(),
        scanned_files: report.scanned_files,
        skipped_files: report.skipped_files,
        duration_secs: report.duration.as_secs_f64(),
        findings: report.findings.iter().map(JsonFinding::from).collect(),
        errors: report.errors.clone(),
        summary: JsonSummary {
            critical: report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high: report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info: report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
            total: report.findings.len(),
        },
    };

    println!("{}", serde_json::to_string_pretty(&json_report).unwrap());
}

/// Determine exit code from findings
pub fn exit_code(report: &ScanReport) -> i32 {
    if report
        .findings
        .iter()
        .any(|f| f.severity == Severity::Critical)
    {
        2
    } else if report
        .findings
        .iter()
        .any(|f| f.severity >= Severity::Medium)
    {
        1
    } else {
        0
    }
}
