pub mod binary;
pub mod filetype;
pub mod polyglot;
pub mod static_analysis;
pub mod unicode;

use std::path::PathBuf;

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding from a detection engine
#[derive(Debug, Clone)]
pub struct Finding {
    pub engine_name: &'static str,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file_path: PathBuf,
    pub byte_offset: Option<u64>,
    pub line_number: Option<u32>,
    pub matched_rule: Option<String>,
}

/// Context about a file being scanned, shared across all engines
pub struct FileContext<'a> {
    pub path: &'a std::path::Path,
    pub extension: Option<&'a str>,
    pub size: u64,
    pub data: &'a [u8],
    pub is_text: bool,
}

/// Every detection engine implements this trait
pub trait DetectionEngine: Send + Sync {
    /// Human-readable engine name
    fn name(&self) -> &'static str;

    /// Quick check: should this engine run on this file?
    fn should_scan(&self, ctx: &FileContext) -> bool;

    /// Scan the file and return findings
    fn scan(&self, ctx: &FileContext) -> Vec<Finding>;
}
