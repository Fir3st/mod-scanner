use clap::{Parser, Subcommand, ValueEnum};
use modscanner_core::{default_engines, report, scanner};
use modscanner_platform::Platform;
use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "modscanner",
    about = "Security scanner for game mods - detects supply chain attacks, malware, and suspicious code",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or platform for threats
    Scan {
        /// Path to scan (directory)
        path: Option<PathBuf>,

        /// Platform to scan: rimworld, wow, all
        #[arg(short, long)]
        platform: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: OutputFormat,
    },

    /// List detected game platforms
    Platforms,
}

fn all_platforms() -> Vec<Box<dyn Platform>> {
    vec![
        Box::new(modscanner_rimworld::RimWorldPlatform::new()),
        Box::new(modscanner_wow::WowPlatform::new()),
        Box::new(modscanner_steam::SteamPlatform::new()),
        Box::new(modscanner_curseforge::CurseForgePlatform::new()),
    ]
}

fn find_platform(name: &str) -> Option<Box<dyn Platform>> {
    match name.to_lowercase().as_str() {
        "rimworld" | "rw" => Some(Box::new(modscanner_rimworld::RimWorldPlatform::new())),
        "wow" | "warcraft" | "worldofwarcraft" => {
            Some(Box::new(modscanner_wow::WowPlatform::new()))
        }
        "steam" => Some(Box::new(modscanner_steam::SteamPlatform::new())),
        "curseforge" | "cf" => Some(Box::new(modscanner_curseforge::CurseForgePlatform::new())),
        _ => None,
    }
}

fn print_report(r: &scanner::ScanReport, format: &OutputFormat) {
    match format {
        OutputFormat::Terminal => report::print_terminal_report(r),
        OutputFormat::Json => report::print_json_report(r),
    }
}

fn cmd_scan(path: Option<PathBuf>, platform: Option<String>, format: OutputFormat) {
    let engines = default_engines();

    // Direct path scan
    if let Some(ref dir) = path {
        if !dir.is_dir() {
            eprintln!(
                "{} Path does not exist or is not a directory: {}",
                "Error:".red().bold(),
                dir.display()
            );
            process::exit(3);
        }

        if matches!(format, OutputFormat::Terminal) {
            println!(
                "{}",
                format!("Scanning {}...", dir.display()).dimmed()
            );
        }
        let r = scanner::scan_directory(dir, &engines);
        print_report(&r, &format);
        process::exit(report::exit_code(&r));
    }

    // Platform-based scan
    let platforms_to_scan: Vec<Box<dyn Platform>> = match platform.as_deref() {
        Some("all") => all_platforms(),
        Some(name) => match find_platform(name) {
            Some(p) => vec![p],
            None => {
                eprintln!(
                    "{} Unknown platform '{}'. Available: rimworld, wow, steam, curseforge",
                    "Error:".red().bold(),
                    name
                );
                process::exit(3);
            }
        },
        None => {
            eprintln!(
                "{} Specify a path or --platform. See --help for usage.",
                "Error:".red().bold()
            );
            process::exit(3);
        }
    };

    let mut overall_exit = 0;

    for plat in &platforms_to_scan {
        let instances = plat.detect();
        if instances.is_empty() {
            println!(
                "  {} {} not detected on this system",
                "·".dimmed(),
                plat.name()
            );
            continue;
        }

        for instance in &instances {
            println!(
                "\n{} {} ({})",
                "▶".bold(),
                plat.name().bold(),
                instance.variant
            );
            println!(
                "  Root: {}",
                instance.root_path.display().dimmed()
            );

            let mod_dirs = plat.mod_directories(instance);
            if mod_dirs.is_empty() {
                println!("  No mods found.");
                continue;
            }

            println!("  Found {} mod(s)", mod_dirs.len());

            for mod_dir in &mod_dirs {
                let metadata = plat.mod_metadata(mod_dir);
                let mod_name = metadata
                    .as_ref()
                    .and_then(|m| m.name.as_deref())
                    .unwrap_or_else(|| {
                        mod_dir
                            .path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                    });

                println!(
                    "\n  {} {}",
                    "→".dimmed(),
                    mod_name
                );

                let r = scanner::scan_directory(&mod_dir.path, &engines);

                if r.findings.is_empty() {
                    if matches!(format, OutputFormat::Terminal) {
                        println!(
                            "    {} clean ({} files, {:.1}s)",
                            "✓".green(),
                            r.scanned_files,
                            r.duration.as_secs_f64()
                        );
                    }
                } else {
                    print_report(&r, &format);
                    let code = report::exit_code(&r);
                    if code > overall_exit {
                        overall_exit = code;
                    }
                }
            }
        }
    }

    process::exit(overall_exit);
}

fn cmd_platforms() {
    println!("{}", "Detecting installed platforms...".dimmed());
    println!();

    let platforms = all_platforms();
    let mut found_any = false;

    for plat in &platforms {
        let instances = plat.detect();
        if instances.is_empty() {
            println!(
                "  {} {} - {}",
                "·".dimmed(),
                plat.name(),
                "not found".dimmed()
            );
        } else {
            found_any = true;
            for instance in &instances {
                println!(
                    "  {} {} ({}) - {}",
                    "✓".green(),
                    plat.name().bold(),
                    instance.variant,
                    instance.root_path.display()
                );

                let mod_dirs = plat.mod_directories(&instance);
                println!(
                    "    {} mod(s) found",
                    mod_dirs.len()
                );
            }
        }
    }

    if !found_any {
        println!();
        println!("  No supported game platforms detected.");
        println!("  Use `modscanner scan <PATH>` to scan a specific directory.");
    }
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, platform, format } => cmd_scan(path, platform, format),
        Commands::Platforms => cmd_platforms(),
    }
}
