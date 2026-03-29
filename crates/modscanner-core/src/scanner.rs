use crate::engine::{DetectionEngine, Finding};
use crate::file_context;
use rayon::prelude::*;
use std::path::Path;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Result of scanning a directory
#[derive(Debug)]
pub struct ScanReport {
    pub root_path: std::path::PathBuf,
    pub scanned_files: u32,
    pub skipped_files: u32,
    pub findings: Vec<Finding>,
    pub duration: Duration,
    pub errors: Vec<String>,
}

/// Skip files with these extensions (large binary assets, not interesting)
const SKIP_EXTENSIONS: &[&str] = &[
    "ogg", "wav", "mp3", "flac", "aac", "wma", "bank", "fsb", // audio
    "dds", "blp", // compiled textures (still scan png/tga/jpg for type spoof)
    "psd", "xcf", // editor files
    "mp4", "avi", "mkv", "webm", // video
    "ttf", "otf", "woff", "woff2", // fonts
];

fn should_skip(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| SKIP_EXTENSIONS.iter().any(|&s| s.eq_ignore_ascii_case(ext)))
}

/// Scan a single file with all engines
fn scan_file(path: &Path, engines: &[Box<dyn DetectionEngine>]) -> (Vec<Finding>, Option<String>) {
    let (data, size) = match file_context::load_file(path) {
        Ok(d) => d,
        Err(e) => return (Vec::new(), Some(format!("{}: {e}", path.display()))),
    };

    let ctx = file_context::build_context(path, data.as_ref(), size);

    let findings: Vec<Finding> = engines
        .iter()
        .filter(|engine| engine.should_scan(&ctx))
        .flat_map(|engine| engine.scan(&ctx))
        .collect();

    (findings, None)
}

/// Scan a directory recursively with the given engines
pub fn scan_directory(root: &Path, engines: &[Box<dyn DetectionEngine>]) -> ScanReport {
    let start = Instant::now();

    let files: Vec<_> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !should_skip(e.path()))
        .map(|e| e.into_path())
        .collect();

    let total_files = files.len() as u32;

    let results: Vec<_> = files
        .par_iter()
        .map(|path| scan_file(path, engines))
        .collect();

    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut scanned = 0u32;

    for (file_findings, error) in results {
        if let Some(err) = error {
            errors.push(err);
        } else {
            scanned += 1;
        }
        findings.extend(file_findings);
    }

    // Sort findings by severity (highest first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    ScanReport {
        root_path: root.to_path_buf(),
        scanned_files: scanned,
        skipped_files: total_files.saturating_sub(scanned),
        findings,
        duration: start.elapsed(),
        errors,
    }
}
