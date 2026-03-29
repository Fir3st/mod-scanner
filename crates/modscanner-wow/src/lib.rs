use modscanner_platform::{ModDirectory, ModMetadata, Platform, PlatformInstance};
use std::path::PathBuf;

pub struct WowPlatform;

impl WowPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for WowPlatform {
    fn name(&self) -> &'static str {
        "World of Warcraft"
    }

    fn detect(&self) -> Vec<PlatformInstance> {
        Vec::new() // TODO: Phase 3
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
