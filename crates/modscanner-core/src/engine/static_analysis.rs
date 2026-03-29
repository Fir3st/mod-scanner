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
