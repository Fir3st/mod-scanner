use modscanner_platform::{ModDirectory, ModMetadata, Platform, PlatformInstance};
use std::path::PathBuf;

pub struct SteamPlatform;

impl SteamPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for SteamPlatform {
    fn name(&self) -> &'static str {
        "Steam Workshop (generic)"
    }

    fn detect(&self) -> Vec<PlatformInstance> {
        Vec::new() // TODO: Phase 5
    }

    fn mod_directories(&self, _instance: &PlatformInstance) -> Vec<ModDirectory> {
        Vec::new()
    }

    fn watch_paths(&self, _instance: &PlatformInstance) -> Vec<PathBuf> {
        Vec::new()
    }

    fn mod_metadata(&self, _dir: &ModDirectory) -> Option<ModMetadata> {
        None
    }
}
