use super::{DetectionEngine, FileContext, Finding, Severity};

/// Detects Unicode-based attacks in source code files:
/// - Bidirectional override characters (trojan source)
/// - Zero-width characters (hidden variable name differences)
/// - Mixed-script tokens (Latin+Cyrillic in same word = homoglyph attack)
/// - Non-printable control characters
pub struct UnicodeEngine;

impl Default for UnicodeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl UnicodeEngine {
    pub fn new() -> Self {
        Self
    }
}

const SOURCE_EXTENSIONS: &[&str] = &[
    "lua", "py", "cs", "js", "ts", "xml", "json", "toml", "yaml", "yml", "cfg", "ini", "txt",
    "toc", "md",
];

/// Bidirectional override characters — trojan source attack
const BIDI_CHARS: &[(char, &str)] = &[
    ('\u{202A}', "LRE (Left-to-Right Embedding)"),
    ('\u{202B}', "RLE (Right-to-Left Embedding)"),
    ('\u{202C}', "PDF (Pop Directional Formatting)"),
    ('\u{202D}', "LRO (Left-to-Right Override)"),
    ('\u{202E}', "RLO (Right-to-Left Override)"),
    ('\u{2066}', "LRI (Left-to-Right Isolate)"),
    ('\u{2067}', "RLI (Right-to-Left Isolate)"),
    ('\u{2068}', "FSI (First Strong Isolate)"),
    ('\u{2069}', "PDI (Pop Directional Isolate)"),
];

/// Zero-width characters that can hide in identifiers
const ZERO_WIDTH_CHARS: &[(char, &str)] = &[
    ('\u{200B}', "Zero Width Space"),
    ('\u{200C}', "Zero Width Non-Joiner"),
    ('\u{200D}', "Zero Width Joiner"),
    ('\u{2060}', "Word Joiner"),
    ('\u{00AD}', "Soft Hyphen"),
];

/// Check if a character is Cyrillic
fn is_cyrillic(c: char) -> bool {
    matches!(c,
        '\u{0400}'..='\u{04FF}' |  // Cyrillic
        '\u{0500}'..='\u{052F}' |  // Cyrillic Supplement
        '\u{2DE0}'..='\u{2DFF}' |  // Cyrillic Extended-A
        '\u{A640}'..='\u{A69F}'    // Cyrillic Extended-B
    )
}

/// Check if a character is Greek
fn is_greek(c: char) -> bool {
    matches!(c, '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}')
}

/// Script classification for a character
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn char_script(c: char) -> Script {
    if c.is_ascii_alphabetic() || matches!(c, '\u{00C0}'..='\u{024F}') {
        Script::Latin
    } else if is_cyrillic(c) {
        Script::Cyrillic
    } else if is_greek(c) {
        Script::Greek
    } else {
        Script::Other
    }
}

/// Check if a token (word) mixes Latin with Cyrillic/Greek characters.
/// This is the real homoglyph signal: "Мain" (Cyrillic М + Latin ain)
/// Pure Cyrillic "Холодильник" is fine (legitimate translation).
/// Pure Latin "Main" is fine.
/// Mixed "Мain" is suspicious.
fn find_mixed_script_tokens(line: &str) -> Vec<(String, Script, Script)> {
    let mut results = Vec::new();

    // Split into word-like tokens (sequences of letters/digits/underscore)
    let mut token_start = None;
    let chars: Vec<char> = line.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        let is_word_char = ch.is_alphanumeric() || ch == '_';

        if is_word_char {
            if token_start.is_none() {
                token_start = Some(i);
            }
        } else if let Some(start) = token_start {
            check_token(&chars[start..i], &mut results);
            token_start = None;
        }
    }

    // Handle last token
    if let Some(start) = token_start {
        check_token(&chars[start..], &mut results);
    }

    results
}

/// Latin-Cyrillic confusable pairs (chars that look identical).
/// Reserved for future per-character confusable detection.
#[allow(dead_code)]
/// Format: (Cyrillic char, Latin lookalike)
const CONFUSABLES: &[(char, char)] = &[
    ('\u{0410}', 'A'), // А
    ('\u{0412}', 'B'), // В
    ('\u{0421}', 'C'), // С
    ('\u{0415}', 'E'), // Е
    ('\u{041D}', 'H'), // Н
    ('\u{041A}', 'K'), // К
    ('\u{041C}', 'M'), // М
    ('\u{041E}', 'O'), // О
    ('\u{0420}', 'P'), // Р
    ('\u{0422}', 'T'), // Т
    ('\u{0425}', 'X'), // Х
    ('\u{0430}', 'a'), // а
    ('\u{0441}', 'c'), // с
    ('\u{0435}', 'e'), // е
    ('\u{043E}', 'o'), // о
    ('\u{0440}', 'p'), // р
    ('\u{0445}', 'x'), // х
    ('\u{0443}', 'y'), // у
    ('\u{0455}', 's'), // ѕ
    ('\u{0456}', 'i'), // і
    ('\u{0458}', 'j'), // ј
];

/// Check if a char is a known confusable (looks like a Latin char but isn't)
#[allow(dead_code)]
fn is_confusable(ch: char) -> bool {
    CONFUSABLES.iter().any(|&(cyr, _)| cyr == ch)
}

fn check_token(chars: &[char], results: &mut Vec<(String, Script, Script)>) {
    // Skip tokens shorter than 3 chars (not meaningful for homoglyph detection)
    if chars.len() < 3 {
        return;
    }

    // Skip WoW/game color code artifacts: tokens starting with hex-like prefix
    // e.g. "cff69ccf0" from "|cff69ccf0Text" after stripping the pipe
    if chars.len() >= 9
        && (chars[0] == 'c' || chars[0] == 'C')
        && chars[1..9].iter().all(|c| c.is_ascii_hexdigit())
    {
        return;
    }
    // Also skip "cFFFFFD00Text" pattern (uppercase variant)
    if chars.len() >= 10 && (chars[0] == 'c' || chars[0] == 'C') && chars[1] == 'f'
        || chars[1] == 'F'
    {
        let hex_prefix: String = chars[1..].iter().take(8).collect();
        if hex_prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return;
        }
    }

    // Classify each character's script
    let scripts: Vec<Script> = chars.iter().map(|&ch| char_script(ch)).collect();

    let has_latin = scripts.contains(&Script::Latin);
    let has_cyrillic = scripts.contains(&Script::Cyrillic);
    let has_greek = scripts.contains(&Script::Greek);

    if !has_latin || (!has_cyrillic && !has_greek) {
        return;
    }

    // Key insight: in a homoglyph attack, scripts are INTERLEAVED.
    //   "Мain"      → [Cyr, Lat, Lat, Lat] → scripts change: YES → attack
    //   "ClеanMod"  → [Lat, Lat, Cyr, Lat, Lat, Lat, Lat, Lat] → change in middle → attack
    //   "nОкно"     → [Lat, Cyr, Cyr, Cyr, Cyr] → one change at pos 1 → NOT attack
    //                  (just "n" prefix from \n escape + Cyrillic word)
    //   "nДобавлено" → [Lat, Cyr, ...] → same pattern → NOT attack
    //
    // Rule: flag only if scripts are INTERLEAVED (change more than once),
    // OR if the minority script chars are surrounded by the majority script
    // (a char sandwiched between different-script chars on both sides).

    let mut transitions = 0u32;
    let mut last_meaningful = Script::Other;
    for &s in &scripts {
        if s == Script::Other {
            continue;
        }
        if last_meaningful != Script::Other && s != last_meaningful {
            transitions += 1;
        }
        last_meaningful = s;
    }

    // 1 transition = "nОкно" (Latin→Cyrillic) or "Мain" (Cyrillic→Latin)
    //   → could be either escape artifact or single-char substitution
    // 2+ transitions = "ClеanMod" (Lat→Cyr→Lat) — definitely interleaved
    //   → this is the strong signal

    let token: String = chars.iter().collect();

    if transitions >= 2 {
        // Scripts are interleaved — strong homoglyph signal
        if has_cyrillic {
            results.push((token.clone(), Script::Latin, Script::Cyrillic));
        }
        if has_greek {
            results.push((token, Script::Latin, Script::Greek));
        }
    }
    // For single transition: only flag if it looks like a substitution,
    // not an escape artifact. A substitution replaces 1-2 chars in an
    // otherwise Latin word: the Latin portion should be the majority.
    // "Мain" = 1 Cyr + 3 Latin → Latin is majority → flag
    // "nОкно" = 1 Latin + 4 Cyr → Cyrillic is majority → skip
    else if transitions == 1 {
        let latin_count = scripts.iter().filter(|&&s| s == Script::Latin).count();
        let non_latin_count = scripts
            .iter()
            .filter(|&&s| s == Script::Cyrillic || s == Script::Greek)
            .count();

        if latin_count > non_latin_count {
            // Minority non-Latin chars in a Latin word → likely substitution
            if has_cyrillic {
                results.push((token.clone(), Script::Latin, Script::Cyrillic));
            }
            if has_greek {
                results.push((token, Script::Latin, Script::Greek));
            }
        }
        // If non-Latin is majority (like "nОкно"), skip — likely escape artifact
    }
}

impl DetectionEngine for UnicodeEngine {
    fn name(&self) -> &'static str {
        "unicode"
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        ctx.is_text
            && ctx.extension.is_some_and(|ext| {
                SOURCE_EXTENSIONS
                    .iter()
                    .any(|&e| e.eq_ignore_ascii_case(ext))
            })
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let text = match std::str::from_utf8(ctx.data) {
            Ok(t) => t,
            Err(_) => return findings,
        };

        let mut bidi_count = 0u32;
        let mut zero_width_count = 0u32;
        let mut control_char_count = 0u32;
        let mut first_bidi_line: Option<u32> = None;
        let mut first_zw_line: Option<u32> = None;

        for (line_idx, line) in text.lines().enumerate() {
            let line_num = (line_idx + 1) as u32;

            for ch in line.chars() {
                // Check bidi overrides — always dangerous, any file
                if let Some((_, bidi_name)) = BIDI_CHARS.iter().find(|(c, _)| *c == ch) {
                    bidi_count += 1;
                    if first_bidi_line.is_none() {
                        first_bidi_line = Some(line_num);
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::Critical,
                            title: "Bidirectional text override detected".into(),
                            description: format!(
                                "Found {bidi_name} (U+{:04X}) character. This can be used \
                                 in trojan source attacks to make code appear different than \
                                 what actually executes.",
                                ch as u32
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: None,
                            line_number: Some(line_num),
                            matched_rule: Some("UNICODE-BIDI-OVERRIDE".into()),
                        });
                    }
                }

                // Check zero-width chars — always dangerous, any file
                if let Some((_, zw_name)) = ZERO_WIDTH_CHARS.iter().find(|(c, _)| *c == ch) {
                    zero_width_count += 1;
                    if first_zw_line.is_none() {
                        first_zw_line = Some(line_num);
                        findings.push(Finding {
                            engine_name: self.name(),
                            severity: Severity::High,
                            title: "Zero-width character in source code".into(),
                            description: format!(
                                "Found {zw_name} (U+{:04X}). Zero-width characters can create \
                                 visually identical but functionally different identifiers.",
                                ch as u32
                            ),
                            file_path: ctx.path.to_path_buf(),
                            byte_offset: None,
                            line_number: Some(line_num),
                            matched_rule: Some("UNICODE-ZERO-WIDTH".into()),
                        });
                    }
                }

                // Non-printable control characters (excluding \t, \n, \r)
                if ch.is_control() && !matches!(ch, '\t' | '\n' | '\r') {
                    control_char_count += 1;
                }
            }

            // Mixed-script token detection (the real homoglyph signal)
            // "Мain" (Cyrillic М + Latin ain) is ALWAYS suspicious,
            // even in translation files. Pure "Холодильник" is fine.
            let mixed_tokens = find_mixed_script_tokens(line);
            for (token, script_a, script_b) in &mixed_tokens {
                let script_name = match script_b {
                    Script::Cyrillic => "Cyrillic",
                    Script::Greek => "Greek",
                    _ => "non-Latin",
                };
                findings.push(Finding {
                    engine_name: self.name(),
                    severity: Severity::High,
                    title: format!("Mixed-script token: \"{token}\""),
                    description: format!(
                        "Token \"{token}\" mixes {script_a:?} and {script_name} characters. \
                         This is a strong homoglyph attack indicator — visually identical \
                         characters from different scripts in the same identifier.",
                    ),
                    file_path: ctx.path.to_path_buf(),
                    byte_offset: None,
                    line_number: Some(line_num),
                    matched_rule: Some("UNICODE-MIXED-SCRIPT".into()),
                });
            }
        }

        // Summary finding for multiple bidi characters
        if bidi_count > 1 {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::Critical,
                title: format!("{bidi_count} bidirectional override characters found"),
                description: "Multiple bidi override characters detected. This strongly \
                              suggests a trojan source attack."
                    .into(),
                file_path: ctx.path.to_path_buf(),
                byte_offset: None,
                line_number: first_bidi_line,
                matched_rule: Some("UNICODE-BIDI-MULTIPLE".into()),
            });
        }

        // Summary for zero-width
        if zero_width_count > 3 {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::High,
                title: format!("{zero_width_count} zero-width characters found"),
                description: "Multiple zero-width characters detected in source code. \
                              This may indicate hidden identifier manipulation."
                    .into(),
                file_path: ctx.path.to_path_buf(),
                byte_offset: None,
                line_number: first_zw_line,
                matched_rule: Some("UNICODE-ZERO-WIDTH-MULTIPLE".into()),
            });
        }

        // Control characters
        if control_char_count > 0 {
            findings.push(Finding {
                engine_name: self.name(),
                severity: Severity::Low,
                title: format!("{control_char_count} non-printable control characters"),
                description: "Control characters (other than tab/newline) found in source file."
                    .into(),
                file_path: ctx.path.to_path_buf(),
                byte_offset: None,
                line_number: None,
                matched_rule: Some("UNICODE-CONTROL-CHARS".into()),
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
            is_text: true,
        }
    }

    #[test]
    fn test_bidi_override_detected() {
        let path = Path::new("script.lua");
        let data = "local x = \u{202E}true-- \u{202C}".as_bytes();
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_zero_width_detected() {
        let path = Path::new("addon.lua");
        let data = "local a\u{200B}b = 42".as_bytes();
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("UNICODE-ZERO-WIDTH"))
        );
    }

    #[test]
    fn test_mixed_script_homoglyph() {
        // "М" is Cyrillic (U+041C), "ain" is Latin → mixed token "Мain"
        let path = Path::new("code.cs");
        let data = "public void \u{041C}ain() {}".as_bytes();
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("UNICODE-MIXED-SCRIPT"))
        );
    }

    #[test]
    fn test_pure_cyrillic_in_translation_ok() {
        // Pure Cyrillic word "Холодильник" should NOT trigger — no mixed scripts
        let path = Path::new("Languages/Russian/Keyed/RimFridge.xml");
        let data = "<label>Холодильник</label>".as_bytes();
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            !findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("UNICODE-MIXED-SCRIPT")),
            "Pure Cyrillic text in translations should not be flagged"
        );
    }

    #[test]
    fn test_mixed_script_in_translation_still_flagged() {
        // Even in a translation file, "Мain" (mixed Cyrillic+Latin) IS suspicious
        let path = Path::new("Languages/Russian/Keyed/Evil.xml");
        let data = "<defName>Cl\u{0435}anMod</defName>".as_bytes(); // е is Cyrillic
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("UNICODE-MIXED-SCRIPT")),
            "Mixed-script tokens should be flagged even in translation files"
        );
    }

    #[test]
    fn test_clean_ascii_file() {
        let path = Path::new("clean.lua");
        let data = b"local function hello()\n  print('world')\nend\n";
        let ctx = make_ctx(path, data);
        let engine = UnicodeEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_source_file_skipped() {
        let path = Path::new("texture.png");
        let data = b"\x89PNG data with \xe2\x80\xae bidi";
        let ctx = FileContext {
            path,
            extension: Some("png"),
            size: data.len() as u64,
            data,
            is_text: false,
        };
        let engine = UnicodeEngine::new();
        assert!(!engine.should_scan(&ctx));
    }
}
