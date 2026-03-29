use modscanner_platform::{ModDirectory, ModMetadata, Platform, PlatformInstance};
use std::path::{Path, PathBuf};

pub struct WowPlatform;

impl WowPlatform {
    pub fn new() -> Self {
        Self
    }
}

/// WoW edition variants
const WOW_EDITIONS: &[(&str, &str)] = &[
    ("_retail_", "Retail"),
    ("_classic_", "Classic"),
    ("_classic_era_", "Classic Era"),
    ("_ptr_", "PTR"),
    ("_beta_", "Beta"),
];

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

/// Common WoW installation paths
fn wow_install_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        roots.push(PathBuf::from(r"C:\Program Files (x86)\World of Warcraft"));
        roots.push(PathBuf::from(r"C:\Program Files\World of Warcraft"));
        // Common custom install locations
        for drive in b'D'..=b'Z' {
            roots.push(PathBuf::from(format!(
                "{}:\\Games\\World of Warcraft",
                drive as char
            )));
            roots.push(PathBuf::from(format!(
                "{}:\\World of Warcraft",
                drive as char
            )));
        }
    }

    #[cfg(target_os = "macos")]
    {
        roots.push(PathBuf::from("/Applications/World of Warcraft"));
        if let Some(home) = home_dir() {
            roots.push(home.join("Applications/World of Warcraft"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = home_dir() {
            // Lutris / Wine common paths
            roots.push(home.join("Games/world-of-warcraft/drive_c/Program Files (x86)/World of Warcraft"));
            roots.push(home.join(".wine/drive_c/Program Files (x86)/World of Warcraft"));
        }
    }

    roots
}

/// Find all WoW editions (Retail, Classic, etc.) within an installation
fn find_editions(wow_root: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut editions = Vec::new();

    for &(dir_name, label) in WOW_EDITIONS {
        let edition_path = wow_root.join(dir_name);
        let addons_path = edition_path.join("Interface").join("AddOns");
        if addons_path.is_dir() {
            editions.push((edition_path, label));
        }
    }

    editions
}

/// Parse a .toc file to extract addon metadata
fn parse_toc(addon_dir: &Path) -> Option<ModMetadata> {
    let dir_name = addon_dir.file_name()?.to_str()?;

    // Find the TOC file (must match folder name, or try common variants)
    let toc_candidates = vec![
        addon_dir.join(format!("{dir_name}.toc")),
        addon_dir.join(format!("{dir_name}_Mainline.toc")),
        addon_dir.join(format!("{dir_name}_Retail.toc")),
        addon_dir.join(format!("{dir_name}_Classic.toc")),
        addon_dir.join(format!("{dir_name}_Vanilla.toc")),
    ];

    let toc_path = toc_candidates.into_iter().find(|p| p.is_file())?;
    let content = std::fs::read_to_string(&toc_path).ok()?;

    let mut title = None;
    let mut author = None;
    let mut version = None;
    let mut notes = None;

    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("##") {
            continue;
        }

        let line = &line[2..].trim();
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "Title" => title = Some(strip_color_codes(value)),
                "Author" => author = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "Notes" => notes = Some(strip_color_codes(value)),
                _ => {}
            }
        }
    }

    Some(ModMetadata {
        name: title,
        author,
        version,
        game: Some("World of Warcraft".into()),
        description: notes,
    })
}

/// Strip WoW color codes like |cff00ff00 and |r
fn strip_color_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '|' {
            match chars.peek() {
                Some('c') => {
                    // Skip |cXXXXXXXX (10 chars total)
                    for _ in 0..9 {
                        chars.next();
                    }
                }
                Some('r') => {
                    chars.next(); // skip 'r'
                }
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }

    result
}

impl Platform for WowPlatform {
    fn name(&self) -> &'static str {
        "World of Warcraft"
    }

    fn detect(&self) -> Vec<PlatformInstance> {
        let mut instances = Vec::new();

        for wow_root in wow_install_roots() {
            if !wow_root.is_dir() {
                continue;
            }

            let editions = find_editions(&wow_root);
            for (edition_path, label) in editions {
                instances.push(PlatformInstance {
                    root_path: edition_path,
                    variant: label.to_string(),
                });
            }
        }

        instances
    }

    fn mod_directories(&self, instance: &PlatformInstance) -> Vec<ModDirectory> {
        let mut dirs = Vec::new();
        let addons_path = instance.root_path.join("Interface").join("AddOns");

        if let Ok(entries) = std::fs::read_dir(&addons_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(ModDirectory {
                        path,
                        game_id: None,
                        mod_id: entry.file_name().to_str().map(|s| s.to_string()),
                    });
                }
            }
        }

        dirs
    }

    fn watch_paths(&self, instance: &PlatformInstance) -> Vec<PathBuf> {
        let addons = instance.root_path.join("Interface").join("AddOns");
        if addons.is_dir() {
            vec![addons]
        } else {
            Vec::new()
        }
    }

    fn mod_metadata(&self, dir: &ModDirectory) -> Option<ModMetadata> {
        parse_toc(&dir.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_name() {
        let platform = WowPlatform::new();
        assert_eq!(platform.name(), "World of Warcraft");
    }

    #[test]
    fn test_strip_color_codes() {
        assert_eq!(
            strip_color_codes("|cff00ff00Deadly Boss Mods|r"),
            "Deadly Boss Mods"
        );
        assert_eq!(strip_color_codes("No colors here"), "No colors here");
        assert_eq!(
            strip_color_codes("|cffff0000Red|r and |cff00ff00Green|r"),
            "Red and Green"
        );
    }

    #[test]
    fn test_parse_toc_metadata() {
        let dir = std::env::temp_dir().join("test_wow_addon_toc");
        let _ = std::fs::create_dir_all(&dir);
        let toc_content = "## Title: Test Addon\n## Author: TestDev\n## Version: 1.2.3\n## Interface: 110000\n## Notes: A test addon\nTestAddon.lua\n";
        let addon_name = dir.file_name().unwrap().to_str().unwrap();
        std::fs::write(dir.join(format!("{addon_name}.toc")), toc_content).unwrap();

        let meta = parse_toc(&dir).unwrap();
        assert_eq!(meta.name.as_deref(), Some("Test Addon"));
        assert_eq!(meta.author.as_deref(), Some("TestDev"));
        assert_eq!(meta.version.as_deref(), Some("1.2.3"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
