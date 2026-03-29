use super::{DetectionEngine, FileContext, Finding, Severity};
use regex::Regex;

/// Regex-based static analysis of script files for suspicious patterns.
/// Detects dangerous API calls in Lua, C#, Python code.
pub struct StaticAnalysisEngine {
    rules: Vec<StaticRule>,
}

struct StaticRule {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    pattern: Regex,
    description: &'static str,
    extensions: &'static [&'static str],
}

impl Default for StaticAnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticAnalysisEngine {
    pub fn new() -> Self {
        Self {
            rules: build_rules(),
        }
    }
}

fn build_rules() -> Vec<StaticRule> {
    let mut rules = Vec::new();

    // === LUA RULES ===
    let lua_ext: &[&str] = &["lua"];

    rules.push(StaticRule {
        id: "LUA-EXEC-001",
        name: "Lua OS command execution",
        severity: Severity::Critical,
        pattern: Regex::new(r#"os\s*\.\s*execute\s*\("#).unwrap(),
        description: "os.execute() runs shell commands  - extremely dangerous in a mod",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-EXEC-002",
        name: "Lua process spawning via io.popen",
        severity: Severity::Critical,
        pattern: Regex::new(r#"io\s*\.\s*popen\s*\("#).unwrap(),
        description: "io.popen() spawns a process  - extremely dangerous in a mod",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-EXEC-003",
        name: "Lua dynamic code loading",
        severity: Severity::High,
        pattern: Regex::new(r#"\bloadstring\s*\("#).unwrap(),
        description: "loadstring() executes arbitrary code from a string",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-EXEC-004",
        name: "Lua dynamic code loading via load()",
        severity: Severity::High,
        pattern: Regex::new(r#"\bload\s*\("#).unwrap(),
        description: "load() can execute arbitrary code from a string or function",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-NET-001",
        name: "Lua HTTP request",
        severity: Severity::High,
        pattern: Regex::new(r#"(socket\.http|http\.request|require\s*\(?['\"]socket)"#).unwrap(),
        description: "Network request from Lua code  - mods should not need internet access",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-FS-001",
        name: "Lua file system access",
        severity: Severity::Medium,
        pattern: Regex::new(r#"io\s*\.\s*(open|read|write|lines)\s*\("#).unwrap(),
        description: "Direct file I/O  - verify this accesses only expected mod directories",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-SANDBOX-001",
        name: "Lua sandbox escape attempt",
        severity: Severity::Critical,
        pattern: Regex::new(
            r#"(getfenv|setfenv|debug\.(getinfo|sethook|setlocal|getlocal|setupvalue))\s*\("#,
        )
        .unwrap(),
        description: "Attempting to access/modify execution environment  - possible sandbox escape",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-OBFUSC-001",
        name: "Lua heavy string encoding",
        severity: Severity::Medium,
        pattern: Regex::new(r#"string\s*\.\s*char\s*\(.*,.*,.*,.*,"#).unwrap(),
        description: "Long string.char() sequence  - common obfuscation pattern to hide strings",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-OBFUSC-006",
        name: "Lua table.concat byte assembly",
        severity: Severity::Medium,
        pattern: Regex::new(r#"table\s*\.\s*concat\s*\(\s*\{.*string\s*\.\s*char"#).unwrap(),
        description: "table.concat with string.char — assembling strings byte-by-byte to hide content",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-EXEC-005",
        name: "Lua dofile/loadfile from variable",
        severity: Severity::High,
        pattern: Regex::new(r#"(dofile|loadfile)\s*\(\s*[a-zA-Z_]"#).unwrap(),
        description: "dofile/loadfile with variable path — loading code from a dynamic location",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-OBFUSC-004",
        name: "Lua string.reverse obfuscation",
        severity: Severity::High,
        pattern: Regex::new(r#"string\s*\.\s*reverse\s*\("#).unwrap(),
        description: "string.reverse() — commonly used to obfuscate strings and evade pattern matching",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-OBFUSC-005",
        name: "Lua string.gsub heavy transformation",
        severity: Severity::Medium,
        pattern: Regex::new(r#"string\s*\.\s*gsub\s*\([^,]+,\s*['\"]."#).unwrap(),
        description: "string.gsub with single-char replacement — may be decoding obfuscated strings",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-EVASION-001",
        name: "Lua error-suppressed code execution",
        severity: Severity::High,
        pattern: Regex::new(r#"pcall\s*\(\s*(loadstring|load|dofile)"#).unwrap(),
        description: "pcall wrapping loadstring/load — error suppression around dynamic code execution",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-OBFUSC-003",
        name: "Lua function serialization",
        severity: Severity::High,
        pattern: Regex::new(r#"string\s*\.\s*dump\s*\("#).unwrap(),
        description: "string.dump() serializes a function to binary — used for obfuscation",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-ENV-001",
        name: "Lua environment manipulation",
        severity: Severity::High,
        pattern: Regex::new(r#"\b_ENV\s*[\[=]"#).unwrap(),
        description: "Direct _ENV manipulation — can override all global functions in Lua 5.2+",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-FFI-001",
        name: "Lua FFI access",
        severity: Severity::Critical,
        pattern: Regex::new(r#"require\s*\(?['\"]ffi['\"]"#).unwrap(),
        description: "Lua FFI module — allows calling native C functions, bypassing all sandboxing",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-GLOBAL-001",
        name: "Lua global table manipulation",
        severity: Severity::Medium,
        pattern: Regex::new(r#"rawset\s*\(\s*_G"#).unwrap(),
        description: "Direct manipulation of global table — may inject or override functions",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "LUA-NET-002",
        name: "Lua dofile/loadfile with URL",
        severity: Severity::Critical,
        pattern: Regex::new(r#"(dofile|loadfile)\s*\(\s*['\"]https?://"#).unwrap(),
        description: "dofile/loadfile with a URL argument — loading and executing remote code",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "LUA-OBFUSC-002",
        name: "Lua Base64 decode pattern",
        severity: Severity::Medium,
        pattern: Regex::new(r#"(base64|b64|decode|from_base64)\s*\("#).unwrap(),
        description: "Base64 decoding pattern — may be hiding malicious payload",
        extensions: lua_ext,
    });

    // === C# RULES (for RimWorld Assemblies DLLs decompiled or source) ===
    let cs_ext: &[&str] = &["cs"];

    rules.push(StaticRule {
        id: "CS-NET-001",
        name: "C# network access",
        severity: Severity::High,
        pattern: Regex::new(r#"(WebClient|HttpClient|WebRequest|HttpWebRequest)\s*[\(.]"#).unwrap(),
        description: "Network client usage  - game mods should not need internet access",
        extensions: cs_ext,
    });
    rules.push(StaticRule {
        id: "CS-EXEC-001",
        name: "C# process execution",
        severity: Severity::Critical,
        pattern: Regex::new(r#"Process\s*\.\s*Start\s*\("#).unwrap(),
        description: "Launching external process  - extremely dangerous in a mod",
        extensions: cs_ext,
    });
    rules.push(StaticRule {
        id: "CS-REG-001",
        name: "C# registry access",
        severity: Severity::High,
        pattern: Regex::new(r#"(Registry\s*\.|RegistryKey\s*\.)"#).unwrap(),
        description: "Windows Registry access  - unusual for a game mod",
        extensions: cs_ext,
    });
    rules.push(StaticRule {
        id: "CS-REFLECT-001",
        name: "C# dynamic assembly loading",
        severity: Severity::High,
        pattern: Regex::new(r#"Assembly\s*\.\s*(Load|LoadFrom|LoadFile)\s*\("#).unwrap(),
        description: "Dynamic assembly loading via reflection",
        extensions: cs_ext,
    });

    rules.push(StaticRule {
        id: "CS-UNSAFE-001",
        name: "C# unsafe code block",
        severity: Severity::Medium,
        pattern: Regex::new(r#"\bunsafe\s*\{"#).unwrap(),
        description: "Unsafe code block — direct memory manipulation, unusual for game mods",
        extensions: cs_ext,
    });
    rules.push(StaticRule {
        id: "CS-MARSHAL-001",
        name: "C# Marshal interop",
        severity: Severity::Medium,
        pattern: Regex::new(r#"Marshal\s*\.\s*(Copy|PtrToStructure|AllocHGlobal|ReadByte|WriteByte)"#)
            .unwrap(),
        description: "Marshal interop — low-level memory manipulation, unusual for game mods",
        extensions: cs_ext,
    });

    rules.push(StaticRule {
        id: "CS-REFLECT-002",
        name: "C# runtime code generation",
        severity: Severity::High,
        pattern: Regex::new(r#"(Reflection\.Emit|DynamicMethod|ILGenerator)"#).unwrap(),
        description: "Runtime IL code generation via Reflection.Emit — can create executable code at runtime",
        extensions: cs_ext,
    });
    rules.push(StaticRule {
        id: "CS-RECON-001",
        name: "C# system reconnaissance",
        severity: Severity::Medium,
        pattern: Regex::new(
            r#"Environment\s*\.\s*(UserName|MachineName|UserDomainName|OSVersion)"#,
        )
        .unwrap(),
        description: "Querying system identity info — may be fingerprinting the host",
        extensions: cs_ext,
    });

    // === PYTHON RULES ===
    let py_ext: &[&str] = &["py"];

    rules.push(StaticRule {
        id: "PY-EXEC-001",
        name: "Python command execution",
        severity: Severity::Critical,
        pattern: Regex::new(
            r#"(subprocess\.(call|run|Popen|check_output)|os\.(system|popen|exec))"#,
        )
        .unwrap(),
        description: "Executing system commands from Python",
        extensions: py_ext,
    });
    rules.push(StaticRule {
        id: "PY-EXEC-002",
        name: "Python eval/exec",
        severity: Severity::High,
        pattern: Regex::new(r#"\b(eval|exec)\s*\("#).unwrap(),
        description: "Dynamic code execution  - can run arbitrary code",
        extensions: py_ext,
    });
    rules.push(StaticRule {
        id: "PY-NET-001",
        name: "Python network access",
        severity: Severity::High,
        pattern: Regex::new(r#"(urllib|requests\.(get|post|put)|http\.client|socket\.socket)"#)
            .unwrap(),
        description: "Network access from Python  - mods should not need internet",
        extensions: py_ext,
    });

    // === VDF/STEAM RULES ===
    let vdf_ext: &[&str] = &["vdf", "acf"];

    rules.push(StaticRule {
        id: "STEAM-INSTALL-001",
        name: "Steam InstallScript detected",
        severity: Severity::High,
        pattern: Regex::new(r#"(?i)"InstallScript""#).unwrap(),
        description: "Steam VDF InstallScript — runs arbitrary commands during mod installation",
        extensions: vdf_ext,
    });
    rules.push(StaticRule {
        id: "STEAM-RUN-001",
        name: "Steam VDF Run entry",
        severity: Severity::Critical,
        pattern: Regex::new(r#"(?i)"Run"\s+"[^"]*\.(exe|bat|cmd|ps1|sh)"#).unwrap(),
        description: "Steam VDF Run entry pointing to executable — auto-execution on install",
        extensions: vdf_ext,
    });

    // === XML RULES ===
    let xml_ext: &[&str] = &["xml"];

    rules.push(StaticRule {
        id: "XML-SCRIPT-001",
        name: "Script tag in XML",
        severity: Severity::High,
        pattern: Regex::new(r#"<script[\s>]"#).unwrap(),
        description: "Script tag in XML file — possible XSS or code injection in mod metadata",
        extensions: xml_ext,
    });

    // === JAVASCRIPT RULES ===
    let js_ext: &[&str] = &["js", "ts"];

    rules.push(StaticRule {
        id: "JS-EXEC-001",
        name: "JavaScript eval()",
        severity: Severity::High,
        pattern: Regex::new(r#"\beval\s*\("#).unwrap(),
        description: "eval() executes arbitrary code — common obfuscation technique",
        extensions: js_ext,
    });
    rules.push(StaticRule {
        id: "JS-EXEC-002",
        name: "JavaScript Function constructor",
        severity: Severity::High,
        pattern: Regex::new(r#"new\s+Function\s*\("#).unwrap(),
        description: "new Function() creates executable code from strings",
        extensions: js_ext,
    });
    rules.push(StaticRule {
        id: "JS-NET-001",
        name: "JavaScript fetch/XMLHttpRequest",
        severity: Severity::Medium,
        pattern: Regex::new(r#"(fetch\s*\(\s*['\"]https?://|new\s+XMLHttpRequest|\.open\s*\(\s*['\"](?:GET|POST))"#).unwrap(),
        description: "Network request from mod code — mods should not need internet access",
        extensions: js_ext,
    });
    rules.push(StaticRule {
        id: "JS-EXEC-003",
        name: "JavaScript child_process",
        severity: Severity::Critical,
        pattern: Regex::new(r#"require\s*\(\s*['\"]child_process['\"]"#).unwrap(),
        description: "Node.js child_process — can execute system commands",
        extensions: js_ext,
    });

    // === POWERSHELL RULES ===
    let ps_ext: &[&str] = &["ps1", "psm1", "psd1"];

    rules.push(StaticRule {
        id: "PS-ENCODED-001",
        name: "PowerShell encoded command",
        severity: Severity::Critical,
        pattern: Regex::new(r#"(?i)(-EncodedCommand|-enc|-e)\s+[A-Za-z0-9+/=]{20,}"#).unwrap(),
        description: "PowerShell encoded command — commonly used to hide malicious payloads",
        extensions: ps_ext,
    });
    rules.push(StaticRule {
        id: "PS-DOWNLOAD-001",
        name: "PowerShell download cradle",
        severity: Severity::Critical,
        pattern: Regex::new(
            r#"(?i)(Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString|DownloadFile|wget|curl)"#,
        )
        .unwrap(),
        description: "PowerShell download cradle — fetching remote content",
        extensions: ps_ext,
    });

    rules.push(StaticRule {
        id: "PY-FFI-001",
        name: "Python ctypes FFI",
        severity: Severity::High,
        pattern: Regex::new(r#"ctypes\.(windll|cdll|CDLL|WinDLL)"#).unwrap(),
        description: "ctypes FFI — calling native code from Python, bypasses sandboxing",
        extensions: py_ext,
    });
    rules.push(StaticRule {
        id: "PY-IMPORT-001",
        name: "Python dynamic import",
        severity: Severity::Medium,
        pattern: Regex::new(r#"__import__\s*\(|importlib\.import_module\s*\("#).unwrap(),
        description: "Dynamic module import — can load arbitrary Python modules at runtime",
        extensions: py_ext,
    });
    rules.push(StaticRule {
        id: "PY-KEYLOG-001",
        name: "Python keyboard hooking",
        severity: Severity::Critical,
        pattern: Regex::new(r#"(pynput|keyboard\.on_press|SetWindowsHookEx)"#).unwrap(),
        description: "Keyboard hooking/keylogging capability detected",
        extensions: py_ext,
    });

    // === WOW-SPECIFIC LUA RULES ===
    rules.push(StaticRule {
        id: "WOW-SANDBOX-001",
        name: "WoW Lua sandbox escape attempt",
        severity: Severity::Critical,
        pattern: Regex::new(r#"\b(io\.\w+|os\.\w+|loadfile|dofile)\s*\("#).unwrap(),
        description: "Reference to blocked Lua functions  - possible sandbox escape attempt in WoW addon",
        extensions: lua_ext,
    });
    rules.push(StaticRule {
        id: "WOW-COVERT-001",
        name: "Suspicious addon message channel",
        severity: Severity::Medium,
        pattern: Regex::new(r#"SendAddonMessage\s*\(\s*['\"][^'\"]{20,}['\"]"#).unwrap(),
        description: "SendAddonMessage with a long prefix  - possible covert communication channel",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "WOW-SECURITY-001",
        name: "WoW securecall bypass attempt",
        severity: Severity::High,
        pattern: Regex::new(r#"(hooksecurefunc|issecurevariable)\s*\("#).unwrap(),
        description: "Hooking or checking secure functions — possible Blizzard API abuse",
        extensions: lua_ext,
    });

    rules.push(StaticRule {
        id: "WOW-INJECT-001",
        name: "WoW RunScript code injection",
        severity: Severity::High,
        pattern: Regex::new(r#"RunScript\s*\(\s*[^)]*\.\."#).unwrap(),
        description: "RunScript with string concatenation — dynamic code injection in WoW addon",
        extensions: lua_ext,
    });

    rules
}

impl DetectionEngine for StaticAnalysisEngine {
    fn name(&self) -> &'static str {
        "static-analysis"
    }

    fn should_scan(&self, ctx: &FileContext) -> bool {
        ctx.is_text
            && ctx.extension.is_some_and(|ext| {
                self.rules
                    .iter()
                    .any(|r| r.extensions.iter().any(|&e| e.eq_ignore_ascii_case(ext)))
            })
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let text = match std::str::from_utf8(ctx.data) {
            Ok(t) => t,
            Err(_) => return findings,
        };

        let ext = match ctx.extension {
            Some(e) => e.to_lowercase(),
            None => return findings,
        };

        let applicable_rules: Vec<&StaticRule> = self
            .rules
            .iter()
            .filter(|r| r.extensions.iter().any(|&e| e == ext))
            .collect();

        for (line_idx, line) in text.lines().enumerate() {
            let line_num = (line_idx + 1) as u32;

            // Skip comment lines (basic heuristic)
            let trimmed = line.trim();
            if trimmed.starts_with("--")
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            for rule in &applicable_rules {
                if rule.pattern.is_match(line) {
                    findings.push(Finding {
                        engine_name: self.name(),
                        severity: rule.severity,
                        title: rule.name.to_string(),
                        description: format!(
                            "{}. Found in: {}",
                            rule.description,
                            trimmed.chars().take(120).collect::<String>()
                        ),
                        file_path: ctx.path.to_path_buf(),
                        byte_offset: None,
                        line_number: Some(line_num),
                        matched_rule: Some(rule.id.to_string()),
                    });
                }
            }
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
    fn test_lua_os_execute() {
        let path = Path::new("evil.lua");
        let data = b"os.execute('rm -rf /')";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("LUA-EXEC-001"))
        );
    }

    #[test]
    fn test_lua_loadstring() {
        let path = Path::new("mod.lua");
        let data = b"local fn = loadstring(encodedCode)";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("LUA-EXEC-003"))
        );
    }

    #[test]
    fn test_cs_process_start() {
        let path = Path::new("Patch.cs");
        let data = b"Process.Start(\"cmd.exe\", \"/c malware\");";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_clean_lua_not_flagged() {
        let path = Path::new("clean.lua");
        let data = b"local x = 42\nprint('hello world')\n";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_comments_skipped() {
        let path = Path::new("commented.lua");
        let data = b"-- os.execute('test')\nlocal x = 1\n";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_python_subprocess() {
        let path = Path::new("script.py");
        let data = b"import subprocess\nsubprocess.call(['evil'])";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("PY-EXEC-001"))
        );
    }

    #[test]
    fn test_wow_sandbox_escape() {
        let path = Path::new("addon.lua");
        let data = b"local f = io.open('/etc/passwd')";
        let ctx = make_ctx(path, data);
        let engine = StaticAnalysisEngine::new();
        let findings = engine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.matched_rule.as_deref() == Some("WOW-SANDBOX-001"))
        );
    }
}
