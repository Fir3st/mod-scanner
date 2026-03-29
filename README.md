# ModScanner

Security scanner for game mods. Detects supply chain attacks, malware, and suspicious code in mods for RimWorld, World of Warcraft, and other games.

No game mod scanner existed before this. Python/npm packages get scanned for supply chain attacks daily, but the same threat vector in game mods (which run with full system access in many games) was completely unaddressed.

## Why this matters

- **RimWorld mods** load C# DLLs with **zero sandboxing** - full access to filesystem, network, registry, processes
- **WoW addons** are sandboxed in Lua, but obfuscation, covert channels, and social engineering are real threats
- The **fractureiser** incident (2023) infected thousands of Minecraft mods, stealing credentials and crypto wallets
- No existing tool scans game mods for these threats

## Installation

Download the latest binary from [Releases](https://github.com/Fir3st/mod-scanner/releases), or build from source:

```bash
cargo install --path crates/modscanner-cli
```

Single binary, no runtime dependencies.

## Usage

```bash
# Scan a specific directory
modscanner scan /path/to/mod/directory

# Auto-detect and scan all RimWorld mods
modscanner scan --platform rimworld

# Scan all WoW addons
modscanner scan --platform wow

# Scan everything detected
modscanner scan --platform all

# List detected game platforms
modscanner platforms

# Real-time monitoring (scans on file changes)
modscanner watch

# JSON output for CI/automation
modscanner scan --platform rimworld --format json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean - no medium+ findings |
| 1 | Findings at medium severity or above |
| 2 | Critical findings detected |
| 3 | Scanner error |

## Detection Engines

### Filetype Validation
Detects executables disguised as data files (PE/ELF binary with .png extension, shell scripts as media files).

### Unicode Analysis
- **Bidirectional text overrides** - trojan source attacks where code appears different than what executes
- **Zero-width characters** - hidden identifier manipulation
- **Mixed-script homoglyphs** - Cyrillic/Greek characters substituted for Latin lookalikes (e.g., Cyrillic 'e' in an otherwise Latin identifier)

### Binary Analysis
- **.NET API scanning** - detects dangerous capabilities in DLLs (System.Net, Process.Start, Registry access, credential theft patterns)
- **Shannon entropy** - identifies packed/encrypted payloads (entropy > 7.2)
- **PE import analysis** - flags suspicious native imports (networking, crypto)
- **Packer detection** - UPX, ASPack, VMProtect, Themida signatures
- **Framework whitelist** - skips known legitimate DLLs (Harmony, HugsLib, UnityEngine)

### Static Analysis
18 regex-based rules for:
- **Lua**: `os.execute`, `io.popen`, `loadstring`, sandbox escape, network requests
- **C#**: `Process.Start`, `WebClient`, Registry access, dynamic assembly loading
- **Python**: `subprocess`, `eval`/`exec`, network access
- **WoW-specific**: sandbox escape attempts (`io.*`, `os.*`), suspicious addon message channels

### Polyglot Detection
Detects files that are simultaneously valid as multiple formats:
- PNG+ZIP, PNG+PE, PNG+ELF (data appended after IEND chunk)
- JPEG+ZIP, JPEG+PE (data after EOI marker)
- GIF polyglots
- Embedded ZIP archives in non-ZIP files

## Supported Platforms

| Platform | Auto-detection | Sources |
|----------|---------------|---------|
| **RimWorld** | Steam Workshop + GOG + manual Mods/ | About.xml parsing |
| **World of Warcraft** | Retail, Classic, Classic Era | TOC file parsing |
| **Steam Workshop** | All games with workshop content | VDF/ACF manifest parsing |

## Architecture

Modular Rust workspace with a clean separation between:
- **`modscanner-core`** - detection engines, scanning, reporting (platform-agnostic)
- **`modscanner-platform`** - Platform trait interface
- **`modscanner-rimworld`** / **`modscanner-wow`** / **`modscanner-steam`** - platform adapters
- **`modscanner-monitor`** - filesystem watching with debounce
- **`modscanner-cli`** - CLI binary

Adding a new platform = implement the `Platform` trait in a new crate.

## Building from source

```bash
git clone https://github.com/Fir3st/mod-scanner.git
cd mod-scanner
cargo build --release
./target/release/modscanner platforms
```

Requires Rust 2024 edition (1.85+).

## License

MIT
