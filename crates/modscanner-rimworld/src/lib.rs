use modscanner_platform::{ModDirectory, ModMetadata, Platform, PlatformInstance};
use std::path::{Path, PathBuf};

pub struct RimWorldPlatform;

impl Default for RimWorldPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl RimWorldPlatform {
    pub fn new() -> Self {
        Self
    }
}

const RIMWORLD_STEAM_APPID: &str = "294100";

/// Possible Steam library root paths by platform
fn steam_library_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        roots.push(PathBuf::from(r"C:\Program Files (x86)\Steam"));
        roots.push(PathBuf::from(r"C:\Program Files\Steam"));
        // Check additional drives
        for drive in b'D'..=b'Z' {
            roots.push(PathBuf::from(format!("{}:\\SteamLibrary", drive as char)));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs_home() {
            roots.push(home.join("Library/Application Support/Steam"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs_home() {
            roots.push(home.join(".steam/steam"));
            roots.push(home.join(".local/share/Steam"));
        }
    }

    roots
}

/// GOG installation paths
fn gog_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        roots.push(PathBuf::from(r"C:\GOG Games\RimWorld"));
        if let Some(home) = dirs_home() {
            roots.push(home.join("GOG Games/RimWorld"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs_home() {
            roots.push(home.join("Applications/RimWorld.app"));
            roots.push(home.join("GOG Games/RimWorld"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs_home() {
            roots.push(home.join("GOG Games/RimWorld/game"));
        }
    }

    roots
}

fn dirs_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

/// Find Steam workshop content path for RimWorld
fn find_steam_workshop(steam_root: &Path) -> Option<PathBuf> {
    let workshop = steam_root
        .join("steamapps/workshop/content")
        .join(RIMWORLD_STEAM_APPID);
    if workshop.is_dir() {
        Some(workshop)
    } else {
        None
    }
}

/// Find Steam manual mods path (steamapps/common/RimWorld/Mods)
fn find_steam_mods(steam_root: &Path) -> Option<PathBuf> {
    let mods = steam_root.join("steamapps/common/RimWorld/Mods");
    if mods.is_dir() { Some(mods) } else { None }
}

/// Find GOG mods path
fn find_gog_mods(gog_root: &Path) -> Option<PathBuf> {
    let mods = gog_root.join("Mods");
    if mods.is_dir() {
        return Some(mods);
    }
    // macOS .app bundle
    let mods_app = gog_root.join("Contents/Resources/Data/Mods");
    if mods_app.is_dir() {
        return Some(mods_app);
    }
    None
}

/// Parse About.xml to extract mod metadata
fn parse_about_xml(mod_dir: &Path) -> Option<ModMetadata> {
    let about_path = mod_dir.join("About").join("About.xml");
    if !about_path.is_file() {
        return None;
    }

    let content = std::fs::read_to_string(&about_path).ok()?;

    // Simple XML extraction (no dependency on xml crate)
    let name = extract_xml_tag(&content, "name");
    let author = extract_xml_tag(&content, "author");
    let package_id = extract_xml_tag(&content, "packageId");
    let description = extract_xml_tag(&content, "description");

    Some(ModMetadata {
        name,
        author,
        version: package_id,
        game: Some("RimWorld".into()),
        description,
    })
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

impl Platform for RimWorldPlatform {
    fn name(&self) -> &'static str {
        "RimWorld"
    }

    fn detect(&self) -> Vec<PlatformInstance> {
        let mut instances = Vec::new();

        // Steam installations
        for steam_root in steam_library_roots() {
            if !steam_root.is_dir() {
                continue;
            }

            let has_workshop = find_steam_workshop(&steam_root).is_some();
            let has_mods = find_steam_mods(&steam_root).is_some();

            if has_workshop || has_mods {
                instances.push(PlatformInstance {
                    root_path: steam_root,
                    variant: "Steam".into(),
                });
            }
        }

        // GOG installations
        for gog_root in gog_roots() {
            if gog_root.is_dir() && find_gog_mods(&gog_root).is_some() {
                instances.push(PlatformInstance {
                    root_path: gog_root,
                    variant: "GOG".into(),
                });
            }
        }

        instances
    }

    fn mod_directories(&self, instance: &PlatformInstance) -> Vec<ModDirectory> {
        let mut dirs = Vec::new();

        match instance.variant.as_str() {
            "Steam" => {
                // Workshop mods: each subdirectory is a mod
                if let Some(workshop) = find_steam_workshop(&instance.root_path)
                    && let Ok(entries) = std::fs::read_dir(&workshop)
                {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            dirs.push(ModDirectory {
                                path: entry.path(),
                                game_id: Some(RIMWORLD_STEAM_APPID.into()),
                                mod_id: entry.file_name().to_str().map(|s| s.to_string()),
                            });
                        }
                    }
                }

                // Manual mods in the game directory
                if let Some(mods) = find_steam_mods(&instance.root_path)
                    && let Ok(entries) = std::fs::read_dir(&mods)
                {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            dirs.push(ModDirectory {
                                path: entry.path(),
                                game_id: Some(RIMWORLD_STEAM_APPID.into()),
                                mod_id: entry.file_name().to_str().map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
            "GOG" => {
                if let Some(mods) = find_gog_mods(&instance.root_path)
                    && let Ok(entries) = std::fs::read_dir(&mods)
                {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            dirs.push(ModDirectory {
                                path: entry.path(),
                                game_id: None,
                                mod_id: entry.file_name().to_str().map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        dirs
    }

    fn watch_paths(&self, instance: &PlatformInstance) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        match instance.variant.as_str() {
            "Steam" => {
                if let Some(workshop) = find_steam_workshop(&instance.root_path) {
                    paths.push(workshop);
                }
                if let Some(mods) = find_steam_mods(&instance.root_path) {
                    paths.push(mods);
                }
            }
            "GOG" => {
                if let Some(mods) = find_gog_mods(&instance.root_path) {
                    paths.push(mods);
                }
            }
            _ => {}
        }

        paths
    }

    fn mod_metadata(&self, dir: &ModDirectory) -> Option<ModMetadata> {
        parse_about_xml(&dir.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_tag() {
        let xml = r#"
        <ModMetaData>
            <name>Test Mod</name>
            <author>Test Author</author>
            <packageId>test.testmod</packageId>
        </ModMetaData>
        "#;

        assert_eq!(extract_xml_tag(xml, "name"), Some("Test Mod".into()));
        assert_eq!(extract_xml_tag(xml, "author"), Some("Test Author".into()));
        assert_eq!(
            extract_xml_tag(xml, "packageId"),
            Some("test.testmod".into())
        );
        assert_eq!(extract_xml_tag(xml, "missing"), None);
    }

    #[test]
    fn test_platform_name() {
        let platform = RimWorldPlatform::new();
        assert_eq!(platform.name(), "RimWorld");
    }
}
