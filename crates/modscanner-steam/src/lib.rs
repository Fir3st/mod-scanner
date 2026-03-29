use modscanner_platform::{ModDirectory, ModMetadata, Platform, PlatformInstance};
use std::path::{Path, PathBuf};

/// Generic Steam Workshop adapter.
/// Discovers all Steam library folders and enumerates games with workshop content.
pub struct SteamPlatform;

impl Default for SteamPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SteamPlatform {
    pub fn new() -> Self {
        Self
    }
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

/// Default Steam root directories per platform
fn default_steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        roots.push(PathBuf::from(r"C:\Program Files (x86)\Steam"));
        roots.push(PathBuf::from(r"C:\Program Files\Steam"));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join("Library/Application Support/Steam"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join(".steam/steam"));
            roots.push(home.join(".local/share/Steam"));
        }
    }

    roots
}

/// Parse Valve's VDF (KeyValues) format to extract library folder paths.
/// This is a simplified parser for libraryfolders.vdf.
fn parse_library_folders(steam_root: &Path) -> Vec<PathBuf> {
    let vdf_path = steam_root.join("steamapps").join("libraryfolders.vdf");
    let content = match std::fs::read_to_string(&vdf_path) {
        Ok(c) => c,
        Err(_) => return vec![steam_root.to_path_buf()],
    };

    let mut paths = vec![steam_root.to_path_buf()];

    // Simple VDF parsing: look for "path" keys
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"path\"") {
            let value = rest.trim().trim_matches('"');
            if !value.is_empty() {
                let path = PathBuf::from(value);
                if path.is_dir() && !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
    }

    paths
}

/// Known game IDs to skip (these have dedicated platform adapters)
const SKIP_GAME_IDS: &[&str] = &[
    "294100", // RimWorld - handled by modscanner-rimworld
];

/// Try to find the game name from appmanifest files
fn find_game_name(steam_root: &Path, app_id: &str) -> Option<String> {
    let manifest = steam_root
        .join("steamapps")
        .join(format!("appmanifest_{app_id}.acf"));

    let content = std::fs::read_to_string(&manifest).ok()?;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"name\"") {
            let value = rest.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

impl Platform for SteamPlatform {
    fn name(&self) -> &'static str {
        "Steam Workshop"
    }

    fn detect(&self) -> Vec<PlatformInstance> {
        let mut instances = Vec::new();

        for steam_root in default_steam_roots() {
            if !steam_root.is_dir() {
                continue;
            }

            let library_paths = parse_library_folders(&steam_root);

            for lib_path in library_paths {
                let workshop_content = lib_path.join("steamapps").join("workshop").join("content");
                if workshop_content.is_dir() {
                    // Check if there are any game IDs with workshop content
                    let has_content = std::fs::read_dir(&workshop_content)
                        .map(|entries| {
                            entries.flatten().any(|e| {
                                e.path().is_dir()
                                    && !SKIP_GAME_IDS
                                        .contains(&e.file_name().to_str().unwrap_or(""))
                            })
                        })
                        .unwrap_or(false);

                    if has_content {
                        instances.push(PlatformInstance {
                            root_path: lib_path,
                            variant: "Steam Library".into(),
                        });
                    }
                }
            }
        }

        instances
    }

    fn mod_directories(&self, instance: &PlatformInstance) -> Vec<ModDirectory> {
        let mut dirs = Vec::new();
        let workshop_content = instance
            .root_path
            .join("steamapps")
            .join("workshop")
            .join("content");

        let game_dirs = match std::fs::read_dir(&workshop_content) {
            Ok(entries) => entries,
            Err(_) => return dirs,
        };

        for game_entry in game_dirs.flatten() {
            let game_path = game_entry.path();
            if !game_path.is_dir() {
                continue;
            }

            let game_id = game_entry.file_name().to_str().unwrap_or("").to_string();
            if SKIP_GAME_IDS.contains(&game_id.as_str()) {
                continue;
            }

            // Each subdirectory is a mod
            if let Ok(mod_entries) = std::fs::read_dir(&game_path) {
                for mod_entry in mod_entries.flatten() {
                    if mod_entry.path().is_dir() {
                        dirs.push(ModDirectory {
                            path: mod_entry.path(),
                            game_id: Some(game_id.clone()),
                            mod_id: mod_entry.file_name().to_str().map(|s| s.to_string()),
                        });
                    }
                }
            }
        }

        dirs
    }

    fn watch_paths(&self, instance: &PlatformInstance) -> Vec<PathBuf> {
        let workshop_content = instance
            .root_path
            .join("steamapps")
            .join("workshop")
            .join("content");

        if workshop_content.is_dir() {
            vec![workshop_content]
        } else {
            Vec::new()
        }
    }

    fn mod_metadata(&self, dir: &ModDirectory) -> Option<ModMetadata> {
        let game_name = dir.game_id.as_ref().and_then(|id| {
            // Try to find game name from parent path
            let workshop_content = dir.path.parent()?.parent()?;
            let steam_root = workshop_content.parent()?.parent()?.parent()?;
            find_game_name(steam_root, id)
        });

        Some(ModMetadata {
            name: dir
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string()),
            author: None,
            version: None,
            game: game_name,
            description: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_name() {
        let platform = SteamPlatform::new();
        assert_eq!(platform.name(), "Steam Workshop");
    }
}
