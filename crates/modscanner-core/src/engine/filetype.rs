use super::{DetectionEngine, FileContext, Finding, Severity};

/// Detects files where magic bytes don't match the file extension.
/// Example: an EXE disguised as a PNG texture.
pub struct FiletypeEngine;

impl FiletypeEngine {
    pub fn new() -> Self {
        Self
    }
}

/// Extensions that should never contain executable content
const DATA_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "tga", "dds", "blp", "tif", "tiff", "ico", "svg",
    "ogg", "wav", "mp3", "flac", "aac", "wma",
    "xml", "json", "toml", "yaml", "yml", "ini", "cfg", "txt", "md", "csv",
    "lua", "luac", "py", "cs", "js",
];

/// File types detected by magic bytes that are dangerous
fn is_dangerous_type(kind: &infer::Type) -> bool {
    matches!(
        kind.mime_type(),
        "application/x-executable"
            | "application/x-mach-binary"
            | "application/x-dosexec"
            | "application/x-elf"
            | "application/x-sharedlib"
            | "application/vnd.microsoft.portable-executable"
    )
}

/// Check for PE (MZ) header
fn has_pe_header(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

/// Check for ELF header
fn has_elf_header(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

/// Check for shell script shebang
fn has_shebang(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'#' && data[1] == b'!'
}

impl DetectionEngine for FiletypeEngine {
    fn name(&self) -> &'static str {
        "filetype"
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        // Scan files that have a data-like extension
        ctx.extension
            .is_some_and(|ext| DATA_EXTENSIONS.iter().any(|&e| e.eq_ignore_ascii_case(ext)))
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let ext = match ctx.extension {
            Some(e) => e.to_lowercase(),
            None => return findings,
        };

        if ctx.data.is_empty() {
            return findings;
        }

        // Check with infer crate for magic byte detection
        if let Some(kind) = infer::get(ctx.data) {
            if is_dangerous_type(&kind) {
                findings.push(Finding {
                    engine_name: self.name(),
                    severity: Severity::Critical,
                    title: format!(
                        "Executable disguised as .{ext}"
                    ),
                    description: format!(
                        "File has .{ext} extension but magic bytes identify it as {} ({}). \
                         This is a strong indicator of a malicious file attempting to hide \
                         its true nature.",
                        kind.mime_type(),
                        kind.extension()
                    ),
                    file_path: ctx.path.to_path_buf(),
                    byte_offset: Some(0),
                    line_number: None,
                    matched_rule: Some("FILETYPE-EXEC-DISGUISED".into()),
                });
                return findings;
            }
        }

        // Manual checks for cases infer might miss
        if has_pe_header(ctx.data) && !matches!(ext.as_str(), "dll" | "exe" | "sys" | "drv") {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::Critical,
                title: format!("PE executable disguised as .{ext}"),
                description: format!(
                    "File has .{ext} extension but starts with MZ header (Windows PE executable)."
                ),
                file_path: ctx.path.to_path_buf(),
                byte_offset: Some(0),
                line_number: None,
                matched_rule: Some("FILETYPE-PE-DISGUISED".into()),
            });
        } else if has_elf_header(ctx.data) && !matches!(ext.as_str(), "so") {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::Critical,
                title: format!("ELF binary disguised as .{ext}"),
                description: format!(
                    "File has .{ext} extension but starts with ELF header (Linux/Unix executable)."
                ),
                file_path: ctx.path.to_path_buf(),
                byte_offset: Some(0),
                line_number: None,
                matched_rule: Some("FILETYPE-ELF-DISGUISED".into()),
            });
        } else if has_shebang(ctx.data)
            && matches!(
                ext.as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tga" | "dds" | "blp" | "ogg" | "wav"
                    | "mp3"
            )
        {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::High,
                title: format!("Shell script disguised as .{ext}"),
                description: format!(
                    "File has .{ext} extension but starts with a shebang (#!) indicating a script."
                ),
                file_path: ctx.path.to_path_buf(),
                byte_offset: Some(0),
                line_number: None,
                matched_rule: Some("FILETYPE-SHEBANG-DISGUISED".into()),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn make_ctx<'a>(path: &'a Path, data: &'a [u8]) -> FileContext<'a> {
        FileContext {
            path,
            extension: path.extension().and_then(|e| e.to_str()),
            size: data.len() as u64,
            data,
            is_text: false,
        }
    }

    #[test]
    fn test_pe_disguised_as_png() {
        let path = Path::new("texture.png");
        // MZ header (minimal PE)
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00";
        let ctx = make_ctx(path, data);
        let engine = FiletypeEngine::new();
        assert!(engine.should_scan(&ctx));
        let findings = engine.scan(&ctx);
        assert!(!findings.is_empty());
        assert!(findings[0].severity >= Severity::Critical);
    }

    #[test]
    fn test_elf_disguised_as_jpg() {
        let path = Path::new("image.jpg");
        let data = b"\x7fELF\x02\x01\x01\x00";
        let ctx = make_ctx(path, data);
        let engine = FiletypeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_legit_dll_not_flagged() {
        let path = Path::new("Assembly.dll");
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        let ctx = make_ctx(path, data);
        let engine = FiletypeEngine::new();
        // dll is not in DATA_EXTENSIONS, so should_scan returns false
        assert!(!engine.should_scan(&ctx));
    }

    #[test]
    fn test_normal_png_not_flagged() {
        let path = Path::new("texture.png");
        // PNG magic bytes
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let ctx = make_ctx(path, data);
        let engine = FiletypeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_shebang_in_media_file() {
        let path = Path::new("sound.ogg");
        let data = b"#!/bin/bash\nrm -rf /";
        let ctx = make_ctx(path, data);
        let engine = FiletypeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
    }
}
