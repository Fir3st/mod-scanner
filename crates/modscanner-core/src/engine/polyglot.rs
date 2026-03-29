use super::{DetectionEngine, FileContext, Finding, Severity};

/// Detects polyglot files - files that are simultaneously valid as multiple formats.
/// Common attack: append a ZIP/JAR to a PNG (data after IEND is ignored by image viewers
/// but processed by ZIP tools). Also detects trailing data after format end markers.
pub struct PolyglotEngine;

impl Default for PolyglotEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolyglotEngine {
    pub fn new() -> Self {
        Self
    }
}

// --- Magic byte signatures ---

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const PNG_IEND: &[u8] = b"IEND\xaeB`\x82";
const ZIP_LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const PE_MAGIC: &[u8] = b"MZ";
const ELF_MAGIC: &[u8] = b"\x7fELF";
const PDF_MAGIC: &[u8] = b"%PDF";
const JAVA_CLASS_MAGIC: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
const GIF_MAGIC_87: &[u8] = b"GIF87a";
const GIF_MAGIC_89: &[u8] = b"GIF89a";
const BMP_MAGIC: &[u8] = b"BM";
const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const JPEG_END: &[u8] = &[0xFF, 0xD9];

/// Find a byte pattern in a slice, starting from an offset
fn find_pattern(data: &[u8], pattern: &[u8], start: usize) -> Option<usize> {
    if pattern.is_empty() || start + pattern.len() > data.len() {
        return None;
    }
    data[start..]
        .windows(pattern.len())
        .position(|w| w == pattern)
        .map(|pos| pos + start)
}

/// Check if data starts with a pattern
fn starts_with(data: &[u8], pattern: &[u8]) -> bool {
    data.len() >= pattern.len() && &data[..pattern.len()] == pattern
}

impl DetectionEngine for PolyglotEngine {
    fn name(&self) -> &'static str {
        "polyglot"
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        // Scan image files, archives, and any file large enough to contain appended data
        ctx.size > 64 && !ctx.is_text
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let data = ctx.data;

        // --- PNG polyglot detection ---
        if starts_with(data, PNG_MAGIC) {
            // Find IEND chunk (end of PNG data)
            if let Some(iend_pos) = find_pattern(data, PNG_IEND, 8) {
                let png_end = iend_pos + PNG_IEND.len();
                let trailing = data.len() - png_end;

                if trailing > 16 {
                    // Check what's appended after the PNG
                    let trail = &data[png_end..];

                    if starts_with(trail, ZIP_LOCAL_HEADER) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "PNG+ZIP polyglot detected".into(),
                            description: format!(
                                "File is a valid PNG with a ZIP archive appended after the IEND \
                                 chunk ({trailing} bytes of hidden data). This is a common technique \
                                 to smuggle executable content inside image files."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-ZIP".into()),
                        });
                    } else if starts_with(trail, PE_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "PNG+PE polyglot detected".into(),
                            description: format!(
                                "File is a valid PNG with a Windows executable appended after \
                                 the IEND chunk ({trailing} bytes). Extremely suspicious."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-PE".into()),
                        });
                    } else if starts_with(trail, ELF_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "PNG+ELF polyglot detected".into(),
                            description: format!(
                                "File is a valid PNG with a Linux executable appended ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-ELF".into()),
                        });
                    } else if starts_with(trail, PDF_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::High,
                            title: "PNG+PDF polyglot detected".into(),
                            description: format!(
                                "File is a valid PNG with a PDF appended ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-PDF".into()),
                        });
                    } else if starts_with(trail, JAVA_CLASS_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "PNG+Java class polyglot detected".into(),
                            description: format!(
                                "File is a valid PNG with a Java class file appended ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-JAVA".into()),
                        });
                    } else if trailing > 1024 {
                        // Large unknown trailing data
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Medium,
                            title: "PNG with significant trailing data".into(),
                            description: format!(
                                "File is a valid PNG but has {trailing} bytes of unrecognized \
                                 data appended after the IEND chunk. This could be hidden content."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(png_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-PNG-TRAILING".into()),
                        });
                    }
                }
            }
        }

        // --- JPEG polyglot detection ---
        if starts_with(data, JPEG_MAGIC) {
            // Find last JPEG end marker
            if let Some(eoi_pos) = find_last_pattern(data, JPEG_END) {
                let jpeg_end = eoi_pos + JPEG_END.len();
                let trailing = data.len() - jpeg_end;

                if trailing > 1024 {
                    let trail = &data[jpeg_end..];
                    if starts_with(trail, ZIP_LOCAL_HEADER) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "JPEG+ZIP polyglot detected".into(),
                            description: format!(
                                "JPEG with ZIP archive appended after EOI marker ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(jpeg_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-JPEG-ZIP".into()),
                        });
                    } else if starts_with(trail, PE_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "JPEG+PE polyglot detected".into(),
                            description: format!(
                                "JPEG with Windows executable appended ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(jpeg_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-JPEG-PE".into()),
                        });
                    }
                }
            }
        }

        // --- GIF polyglot detection ---
        if starts_with(data, GIF_MAGIC_87) || starts_with(data, GIF_MAGIC_89) {
            // GIF ends with 0x3B trailer
            if let Some(trailer_pos) = data.iter().rposition(|&b| b == 0x3B) {
                let gif_end = trailer_pos + 1;
                let trailing = data.len() - gif_end;

                if trailing > 1024 {
                    let trail = &data[gif_end..];
                    if starts_with(trail, ZIP_LOCAL_HEADER) || starts_with(trail, PE_MAGIC) {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "GIF polyglot detected".into(),
                            description: format!(
                                "GIF with executable/archive data appended after trailer ({trailing} bytes)."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(gif_end as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-GIF".into()),
                        });
                    }
                }
            }
        }

        // --- BMP polyglot detection ---
        if starts_with(data, BMP_MAGIC) && data.len() > 14 {
            // BMP file size is stored at bytes 2-5 (little-endian)
            let bmp_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            if bmp_size > 0 && bmp_size < data.len() {
                let trailing = data.len() - bmp_size;
                if trailing > 64 {
                    let trail = &data[bmp_size..];
                    if starts_with(trail, ZIP_LOCAL_HEADER)
                        || starts_with(trail, PE_MAGIC)
                        || starts_with(trail, ELF_MAGIC)
                    {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "BMP polyglot detected".into(),
                            description: format!(
                                "BMP file with executable/archive data appended ({trailing} bytes \
                                 beyond declared BMP size of {bmp_size})."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: Some(bmp_size as u64),
                            line_number: None,
                            matched_rule: Some("POLYGLOT-BMP".into()),
                        });
                    }
                }
            }
        }

        // --- Embedded ZIP in non-ZIP files ---
        // ZIP files can be detected by scanning for the central directory signature
        // at the end of the file, even if the file starts with different magic bytes
        if !starts_with(data, ZIP_LOCAL_HEADER) && data.len() > 256 {
            // Check last 256 bytes for ZIP end-of-central-directory
            let search_start = data.len().saturating_sub(256);
            if find_pattern(data, b"PK\x05\x06", search_start).is_some() {
                // Also verify there's a local file header somewhere
                if find_pattern(data, ZIP_LOCAL_HEADER, 1).is_some() {
                    let primary_type = if starts_with(data, PNG_MAGIC) {
                        "PNG"
                    } else if starts_with(data, JPEG_MAGIC) {
                        "JPEG"
                    } else if starts_with(data, GIF_MAGIC_87)
                        || starts_with(data, GIF_MAGIC_89)
                    {
                        "GIF"
                    } else if starts_with(data, BMP_MAGIC) {
                        "BMP"
                    } else if starts_with(data, PE_MAGIC) {
                        "PE"
                    } else {
                        "unknown"
                    };

                    if primary_type != "unknown" {
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::High,
                            title: format!("Embedded ZIP in {primary_type} file"),
                            description: format!(
                                "File starts as a valid {primary_type} but contains an embedded \
                                 ZIP archive. This is a polyglot file that can be extracted as a ZIP."
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: None,
                            line_number: None,
                            matched_rule: Some(format!("POLYGLOT-{primary_type}-ZIP-EMBEDDED")),
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Find the last occurrence of a pattern in data
fn find_last_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    // Search from the end
    let search_start = data.len().saturating_sub(65536); // Last 64KB for JPEG
    data[search_start..]
        .windows(pattern.len())
        .rposition(|w| w == pattern)
        .map(|pos| pos + search_start)
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
    fn test_png_zip_polyglot() {
        // Minimal PNG + ZIP appended after IEND
        let mut data = Vec::new();
        // PNG header
        data.extend_from_slice(PNG_MAGIC);
        // Minimal IHDR + IEND
        data.extend_from_slice(&[0; 50]);
        data.extend_from_slice(PNG_IEND);
        // ZIP local file header after PNG
        data.extend_from_slice(ZIP_LOCAL_HEADER);
        data.extend_from_slice(&[0; 100]);

        let path = Path::new("texture.png");
        let ctx = make_ctx(path, &data);
        let engine = PolyglotEngine::new();
        assert!(engine.should_scan(&ctx));
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("POLYGLOT-PNG-ZIP"))
        );
    }

    #[test]
    fn test_png_pe_polyglot() {
        let mut data = Vec::new();
        data.extend_from_slice(PNG_MAGIC);
        data.extend_from_slice(&[0; 50]);
        data.extend_from_slice(PNG_IEND);
        data.extend_from_slice(PE_MAGIC);
        data.extend_from_slice(&[0; 100]);

        let path = Path::new("icon.png");
        let ctx = make_ctx(path, &data);
        let engine = PolyglotEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("POLYGLOT-PNG-PE"))
        );
    }

    #[test]
    fn test_clean_png_not_flagged() {
        let mut data = Vec::new();
        data.extend_from_slice(PNG_MAGIC);
        data.extend_from_slice(&[0; 50]);
        data.extend_from_slice(PNG_IEND);
        // Only a few bytes of padding (< 16)
        data.extend_from_slice(&[0; 4]);

        let path = Path::new("clean.png");
        let ctx = make_ctx(path, &data);
        let engine = PolyglotEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_text_file_skipped() {
        let path = Path::new("readme.txt");
        let data = b"Hello world";
        let ctx = FileContext {
            path,
            extension: Some("txt"),
            size: data.len() as u64,
            data,
            is_text: true,
        };
        let engine = PolyglotEngine::new();
        assert!(!engine.should_scan(&ctx));
    }
}
