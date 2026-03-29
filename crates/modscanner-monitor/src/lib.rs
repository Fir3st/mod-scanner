use crossbeam_channel::{Receiver, select, tick};
use modscanner_core::engine::DetectionEngine;
use modscanner_core::{report, scanner};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for the watch mode
pub struct WatchConfig {
    /// How long to wait after the last file change before scanning (seconds)
    pub debounce_secs: u64,
    /// Output format
    pub json: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            debounce_secs: 2,
            json: false,
        }
    }
}

/// Start watching directories for changes and scanning when files are modified
pub fn watch(
    paths: &[PathBuf],
    engines: Arc<Vec<Box<dyn DetectionEngine>>>,
    config: WatchConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if paths.is_empty() {
        return Err("No paths to watch".into());
    }

    let (tx, rx) = crossbeam_channel::unbounded();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    for path in paths {
        if path.is_dir() {
            watcher.watch(path, RecursiveMode::Recursive)?;
            log::info!("Watching: {}", path.display());
        }
    }

    run_event_loop(rx, engines, config);

    // Keep watcher alive (it stops when dropped)
    drop(watcher);
    Ok(())
}

fn run_event_loop(
    rx: Receiver<Event>,
    engines: Arc<Vec<Box<dyn DetectionEngine>>>,
    config: WatchConfig,
) {
    let debounce = Duration::from_secs(config.debounce_secs);
    let ticker = tick(Duration::from_millis(500));

    // Track pending directories to scan with their last-modified time
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();

    loop {
        select! {
            recv(rx) -> msg => {
                if let Ok(event) = msg
                    && matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_)
                    ) {
                        for path in &event.paths {
                            // Find the mod root directory (parent of the changed file)
                            if let Some(mod_dir) = find_mod_root(path) {
                                pending.insert(mod_dir, Instant::now());
                            }
                        }
                    }
            }
            recv(ticker) -> _ => {
                // Check if any pending directories have been quiet long enough
                let now = Instant::now();
                let ready: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, last_change)| now.duration_since(**last_change) >= debounce)
                    .map(|(path, _)| path.clone())
                    .collect();

                for dir in ready {
                    pending.remove(&dir);
                    scan_mod_directory(&dir, &engines, config.json);
                }
            }
        }
    }
}

/// Walk up from a file path to find the mod root directory.
/// Heuristic: a mod root is a directory that contains About/About.xml (RimWorld)
/// or a .toc file (WoW), or is 2 levels below an AddOns/ or workshop/content/ directory.
fn find_mod_root(path: &Path) -> Option<PathBuf> {
    let mut current = if path.is_file() {
        path.parent()?.to_path_buf()
    } else {
        path.to_path_buf()
    };

    // Walk up max 5 levels
    for _ in 0..5 {
        // RimWorld: has About/About.xml
        if current.join("About").join("About.xml").exists() {
            return Some(current);
        }

        // WoW: has a .toc file matching dir name
        if let Some(dir_name) = current.file_name().and_then(|n| n.to_str())
            && current.join(format!("{dir_name}.toc")).exists()
        {
            return Some(current);
        }

        // Check if parent is a known mod container
        if let Some(parent) = current.parent() {
            let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if parent_name == "AddOns" || parent_name == "Mods" {
                return Some(current);
            }
            // Steam workshop: parent is a numeric game ID directory
            if parent_name.chars().all(|c| c.is_ascii_digit()) && parent_name.len() >= 3 {
                return Some(current);
            }
        }

        current = current.parent()?.to_path_buf();
    }

    None
}

fn scan_mod_directory(dir: &Path, engines: &[Box<dyn DetectionEngine>], json: bool) {
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    if !json {
        eprintln!(
            "\n[watch] Scanning modified mod: {} ({})",
            dir_name,
            dir.display()
        );
    }

    let r = scanner::scan_directory(dir, engines);

    if json {
        report::print_json_report(&r);
    } else if r.findings.is_empty() {
        eprintln!("[watch] {} - clean ({} files)", dir_name, r.scanned_files);
    } else {
        report::print_terminal_report(&r);
    }
}
