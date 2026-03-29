use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a detected platform installation
#[derive(Debug, Clone)]
pub struct PlatformInstance {
    pub root_path: PathBuf,
    pub variant: String,
}

/// A directory containing mods to scan
#[derive(Debug, Clone)]
pub struct ModDirectory {
    pub path: PathBuf,
    pub game_id: Option<String>,
    pub mod_id: Option<String>,
}

/// Metadata extracted from a mod's manifest
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModMetadata {
    pub name: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    pub game: Option<String>,
    pub description: Option<String>,
}

/// Every platform adapter implements this trait
pub trait Platform: Send + Sync {
    /// Human-readable platform name
    fn name(&self) -> &'static str;

    /// Auto-detect all installations of this platform on the system
    fn detect(&self) -> Vec<PlatformInstance>;

    /// Return mod directories for a given installation
    fn mod_directories(&self, instance: &PlatformInstance) -> Vec<ModDirectory>;

    /// Return paths to watch for real-time monitoring
    fn watch_paths(&self, instance: &PlatformInstance) -> Vec<PathBuf>;

    /// Extract metadata from a mod directory
    fn mod_metadata(&self, dir: &ModDirectory) -> Option<ModMetadata>;
}
