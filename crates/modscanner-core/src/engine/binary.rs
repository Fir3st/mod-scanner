use super::{DetectionEngine, FileContext, Finding, Severity};
use goblin::Object;

/// Analyzes binary files (DLL, EXE, ELF) for suspicious characteristics:
/// - Shannon entropy analysis (detect packers/encrypted payloads)
/// - PE import analysis (suspicious .NET/Win32 API usage)
/// - Section anomalies (packer signatures, unusual section names)
/// - .NET metadata strings for dangerous API patterns
pub struct BinaryEngine;

impl Default for BinaryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryEngine {
    pub fn new() -> Self {
        Self
    }
}

const BINARY_EXTENSIONS: &[&str] = &["dll", "exe", "so", "dylib"];

/// Compute Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max random)
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Suspicious PE import DLLs (for native Windows binaries)
const SUSPICIOUS_NATIVE_IMPORTS: &[(&str, &str, Severity)] = &[
    ("ws2_32.dll", "Windows Sockets (networking)", Severity::High),
    ("wininet.dll", "Windows Internet API", Severity::High),
    ("winhttp.dll", "Windows HTTP Services", Severity::High),
    ("crypt32.dll", "Windows Cryptography", Severity::Medium),
    (
        "bcrypt.dll",
        "Windows Cryptography (Next Gen)",
        Severity::Medium,
    ),
];

/// Suspicious .NET API patterns found as strings in managed DLLs.
/// These indicate dangerous capabilities for a game mod.
const SUSPICIOUS_DOTNET_STRINGS: &[(&str, &str, Severity)] = &[
    // Network access
    (
        "System.Net.Http",
        "HTTP client  - network access",
        Severity::High,
    ),
    (
        "System.Net.Sockets",
        "Raw socket access",
        Severity::Critical,
    ),
    (
        "System.Net.WebClient",
        "Web client  - can download/upload data",
        Severity::High,
    ),
    ("HttpClient", "HTTP client usage", Severity::High),
    (
        "WebRequest",
        "Web request  - network access",
        Severity::High,
    ),
    (
        "TcpClient",
        "TCP client  - raw network connection",
        Severity::Critical,
    ),
    (
        "UdpClient",
        "UDP client  - raw network connection",
        Severity::High,
    ),
    // Process execution
    (
        "System.Diagnostics.Process",
        "Can launch external processes",
        Severity::Critical,
    ),
    (
        "ProcessStartInfo",
        "Process launch configuration",
        Severity::Critical,
    ),
    ("cmd.exe", "Command shell reference", Severity::Critical),
    ("powershell", "PowerShell reference", Severity::Critical),
    ("/bin/sh", "Unix shell reference", Severity::Critical),
    ("/bin/bash", "Bash shell reference", Severity::Critical),
    // File system beyond game scope
    (
        "Microsoft.Win32.Registry",
        "Windows Registry access",
        Severity::High,
    ),
    ("RegistryKey", "Registry key manipulation", Severity::High),
    (
        "Environment.GetFolderPath",
        "Accessing system folders",
        Severity::Medium,
    ),
    ("AppData", "AppData directory reference", Severity::Medium),
    // Credential theft patterns (fractureiser-style)
    (
        ".minecraft",
        "Minecraft directory reference (credential theft?)",
        Severity::High,
    ),
    (
        "discord",
        "Discord reference (token theft?)",
        Severity::Medium,
    ),
    (
        "chrome",
        "Chrome reference (cookie/credential theft?)",
        Severity::Medium,
    ),
    (
        "firefox",
        "Firefox reference (cookie/credential theft?)",
        Severity::Medium,
    ),
    ("wallet", "Cryptocurrency wallet reference", Severity::High),
    ("bitcoin", "Bitcoin reference", Severity::Medium),
    ("ethereum", "Ethereum reference", Severity::Medium),
    ("metamask", "MetaMask reference", Severity::High),
    (
        "Login Data",
        "Browser login database reference (credential theft?)",
        Severity::High,
    ),
    (
        "cookies.sqlite",
        "Browser cookies database reference",
        Severity::High,
    ),
    (
        "leveldb",
        "LevelDB reference (Discord/browser token storage)",
        Severity::Medium,
    ),
    (
        "Steam\\config",
        "Steam config directory reference",
        Severity::High,
    ),
    // Dynamic code loading
    ("Assembly.Load", "Dynamic assembly loading", Severity::High),
    (
        "Assembly.LoadFrom",
        "Loading assembly from path",
        Severity::High,
    ),
    (
        "Assembly.LoadFile",
        "Loading assembly from file",
        Severity::High,
    ),
    (
        "Activator.CreateInstance",
        "Dynamic object instantiation",
        Severity::Medium,
    ),
    (
        "Type.InvokeMember",
        "Reflection-based method invocation",
        Severity::Medium,
    ),
    ("DllImport", "P/Invoke native code", Severity::Medium),
    (
        "GetEnvironmentVariable",
        "Reading environment variables (credential/token theft?)",
        Severity::Medium,
    ),
    (
        "File.ReadAllBytes",
        "Reading entire file contents into memory",
        Severity::Medium,
    ),
    (
        "File.ReadAllText",
        "Reading entire file contents as text",
        Severity::Medium,
    ),
    (
        "Directory.GetFiles",
        "Enumerating files in directory (reconnaissance?)",
        Severity::Low,
    ),
    // Clipboard (crypto address swapping)
    (
        "Clipboard",
        "Clipboard access (address swapping?)",
        Severity::Medium,
    ),
    ("SetClipboardData", "Setting clipboard data", Severity::High),
    (
        "GetClipboardData",
        "Reading clipboard data",
        Severity::Medium,
    ),
];

/// Known packer section names
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX packer"),
    ("UPX1", "UPX packer"),
    ("UPX2", "UPX packer"),
    (".ndata", "NSIS installer"),
    (".aspack", "ASPack packer"),
    (".adata", "ASPack packer"),
    ("themida", "Themida protector"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
];

fn analyze_pe(
    data: &[u8],
    pe: &goblin::pe::PE,
    findings: &mut Vec<Finding>,
    path: &std::path::Path,
) {
    // Check PE imports for suspicious DLLs
    for import in &pe.imports {
        let dll_lower = import.dll.to_lowercase();
        for &(suspicious_dll, desc, severity) in SUSPICIOUS_NATIVE_IMPORTS {
            if dll_lower == suspicious_dll {
                findings.push(Finding {
                    engine_name: "binary",
                    severity,
                    title: format!("Suspicious PE import: {}", import.dll),
                    description: format!(
                        "Binary imports from {} ({}). Game mods typically should not \
                         need direct access to this system library.",
                        import.dll, desc
                    ),
                    file_path: path.to_path_buf(),
                    byte_offset: None,
                    line_number: None,
                    matched_rule: Some(format!(
                        "BINARY-PE-IMPORT-{}",
                        suspicious_dll.to_uppercase().replace('.', "-")
                    )),
                });
            }
        }
    }

    // Check section names for packer signatures
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).replace('\0', "");
        for &(packer_name, packer_desc) in PACKER_SECTIONS {
            if name.eq_ignore_ascii_case(packer_name) {
                findings.push(Finding {
                    engine_name: "binary",
                    severity: Severity::High,
                    title: format!("Packer detected: {packer_desc}"),
                    description: format!(
                        "Section \"{name}\" indicates the binary is packed with {packer_desc}. \
                         Packed binaries hide their true contents and are commonly used by malware.",
                    ),
                    file_path: path.to_path_buf(),
                    byte_offset: None,
                    line_number: None,
                    matched_rule: Some("BINARY-PACKER-SECTION".into()),
                });
            }
        }

        // Entropy analysis per section
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if offset + size <= data.len() && size > 256 {
            let entropy = shannon_entropy(&data[offset..offset + size]);
            if entropy > 7.2 {
                findings.push(Finding {
                    engine_name: "binary",
                    severity: Severity::High,
                    title: format!("High entropy section \"{name}\" ({entropy:.2})"),
                    description: format!(
                        "Section \"{name}\" has entropy {entropy:.2}/8.0, suggesting \
                         encrypted or compressed content. Normal code sections have \
                         entropy ~5.5-6.5. This may indicate a packed/encrypted payload.",
                    ),
                    file_path: path.to_path_buf(),
                    byte_offset: Some(offset as u64),
                    line_number: None,
                    matched_rule: Some("BINARY-HIGH-ENTROPY".into()),
                });
            }
        }
    }

    // Scan for suspicious .NET strings in the binary data
    scan_dotnet_strings(data, findings, path);
}

/// Scan binary data for suspicious .NET API strings
fn scan_dotnet_strings(data: &[u8], findings: &mut Vec<Finding>, path: &std::path::Path) {
    // .NET managed DLLs store metadata as UTF-8/UTF-16 strings
    // We search for both encodings
    for &(pattern, desc, severity) in SUSPICIOUS_DOTNET_STRINGS {
        // UTF-8 search
        if let Some(pos) = find_bytes(data, pattern.as_bytes()) {
            findings.push(Finding {
                engine_name: "binary",
                severity,
                title: format!("Suspicious .NET API: {pattern}"),
                description: format!(
                    "Found reference to \"{pattern}\" ({desc}). \
                     This capability is unusual for a game mod and may indicate malicious behavior.",
                ),
                file_path: path.to_path_buf(),
                byte_offset: Some(pos as u64),
                line_number: None,
                matched_rule: Some(format!("BINARY-DOTNET-{}", pattern.replace('.', "-").to_uppercase())),
            });
        }
    }
}

/// Check for MZ header (PE binary)
fn has_mz_header(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

/// Simple byte pattern search
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn analyze_elf(
    data: &[u8],
    _elf: &goblin::elf::Elf,
    findings: &mut Vec<Finding>,
    path: &std::path::Path,
) {
    // Overall entropy check
    if data.len() > 1024 {
        let entropy = shannon_entropy(data);
        if entropy > 7.2 {
            findings.push(Finding {
                engine_name: "binary",
                severity: Severity::High,
                title: format!("High entropy ELF binary ({entropy:.2})"),
                description: format!(
                    "ELF binary has overall entropy {entropy:.2}/8.0, suggesting \
                     encrypted or compressed content.",
                ),
                file_path: path.to_path_buf(),
                byte_offset: None,
                line_number: None,
                matched_rule: Some("BINARY-HIGH-ENTROPY".into()),
            });
        }
    }
}

/// Known legitimate DLLs that are part of the modding framework/runtime.
/// These contain references to dangerous APIs as part of their normal operation.
const WHITELISTED_DLLS: &[&str] = &[
    "0harmony",
    "harmony",
    "harmonylib",
    "harmonymod",
    "hugslib",
    "hugslogpublisher",
    "unityengine",
    "assembly-csharp",
    "mscorlib",
    "system",
    "mono.cecil",
    "mono.security",
    "cecil",
    "lunarframework",
    "lunarloader",
];

fn is_whitelisted_dll(path: &std::path::Path) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|name| {
            let lower = name.to_lowercase();
            WHITELISTED_DLLS
                .iter()
                .any(|&w| lower == w || lower.starts_with(&format!("{w}.")))
        })
}

impl DetectionEngine for BinaryEngine {
    fn name(&self) -> &'static str {
        "binary"
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        // Scan files with binary extensions OR files detected as PE/ELF by magic bytes
        let has_binary_ext = ctx.extension.is_some_and(|ext| {
            BINARY_EXTENSIONS
                .iter()
                .any(|&e| e.eq_ignore_ascii_case(ext))
        });

        if has_binary_ext {
            return true;
        }

        // Also scan if magic bytes indicate a binary regardless of extension
        // (this catches disguised binaries that passed filetype engine)
        ctx.data.len() >= 4
            && ((ctx.data[0] == b'M' && ctx.data[1] == b'Z')  // PE
                || (ctx.data[0] == 0x7f && ctx.data[1] == b'E' && ctx.data[2] == b'L' && ctx.data[3] == b'F')) // ELF
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        if ctx.data.is_empty() {
            return findings;
        }

        // Skip .NET string scanning for known legitimate framework DLLs
        // (they contain references to dangerous APIs as part of normal operation)
        // Still check entropy and packer sections though.
        let skip_string_scan = is_whitelisted_dll(ctx.path);

        match Object::parse(ctx.data) {
            Ok(Object::PE(pe)) => {
                if skip_string_scan {
                    // Only check sections for entropy/packers, skip string scanning
                    let mut section_findings = Vec::new();
                    analyze_pe(ctx.data, &pe, &mut section_findings, ctx.path);
                    // Keep only entropy and packer findings
                    findings.extend(section_findings.into_iter().filter(|f| {
                        f.matched_rule.as_deref().is_some_and(|r| {
                            r.starts_with("BINARY-HIGH-ENTROPY") || r.starts_with("BINARY-PACKER")
                        })
                    }));
                } else {
                    analyze_pe(ctx.data, &pe, &mut findings, ctx.path);
                }
            }
            Ok(Object::Elf(elf)) => {
                analyze_elf(ctx.data, &elf, &mut findings, ctx.path);
            }
            _ => {
                // Goblin couldn't parse the binary, but if it has an MZ header
                // it's still worth scanning for .NET strings (synthetic/minimal PEs)
                if !skip_string_scan && has_mz_header(ctx.data) {
                    scan_dotnet_strings(ctx.data, &mut findings, ctx.path);
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All zeros → low entropy
        let data = vec![0u8; 1024];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "Uniform data should have ~0 entropy, got {e}");
    }

    #[test]
    fn test_shannon_entropy_random() {
        // All possible byte values equally distributed → ~8.0
        let mut data = Vec::new();
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(
            e > 7.9,
            "Uniform random data should have ~8.0 entropy, got {e}"
        );
    }

    #[test]
    fn test_find_bytes() {
        let data = b"hello System.Net.Http world";
        assert!(find_bytes(data, b"System.Net.Http").is_some());
        assert!(find_bytes(data, b"NotHere").is_none());
    }

    #[test]
    fn test_should_scan_dll() {
        let path = std::path::Path::new("Assembly.dll");
        let data = b"MZ\x90\x00";
        let ctx = FileContext {
            path,
            extension: Some("dll"),
            size: data.len() as u64,
            data,
            is_text: false,
        };
        let engine = BinaryEngine::new();
        assert!(engine.should_scan(&ctx));
    }

    #[test]
    fn test_should_not_scan_lua() {
        let path = std::path::Path::new("script.lua");
        let data = b"local x = 1";
        let ctx = FileContext {
            path,
            extension: Some("lua"),
            size: data.len() as u64,
            data,
            is_text: true,
        };
        let engine = BinaryEngine::new();
        assert!(!engine.should_scan(&ctx));
    }
}
