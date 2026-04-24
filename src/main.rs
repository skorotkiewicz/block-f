use clap::Parser;
use colored::*;
use glob::Pattern;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(
    name = "block-f",
    about = "Block edits to files/dirs listed in config",
    version
)]
struct Args {
    #[clap(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[clap(short, long)]
    verbose: bool,
}

#[derive(Deserialize, Debug)]
struct BlockedConfigFile {
    blocked: BlockedSection,
}

#[derive(Deserialize, Debug)]
struct BlockedSection {
    files: Vec<String>,
}

fn parse_config(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config '{}': {}", path.display(), e))?;

    let config: BlockedConfigFile = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config '{}': {}", path.display(), e))?;

    Ok(config.blocked.files)
}

struct BlockConfig {
    patterns: Vec<String>,
}

impl BlockConfig {
    fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    fn is_blocked(&self, path: &Path) -> Option<&str> {
        let path_str = path.to_string_lossy();
        for pattern in &self.patterns {
            let p = pattern.trim_end_matches('/');
            if pattern.ends_with('/') {
                let prefix = format!("{}/", p);
                if path_str.starts_with(&prefix) || path_str == p {
                    return Some(pattern);
                }
            }
            if let Ok(glob) = Pattern::new(p) {
                if glob.matches(&path_str) {
                    return Some(pattern);
                }
            }
            if path_str == p || path_str.ends_with(&format!("/{}", p)) {
                return Some(pattern);
            }
        }
        None
    }

    fn watch_paths(&self, base: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for pattern in &self.patterns {
            let p = pattern.trim_end_matches('/');
            let candidate = base.join(p);
            if candidate.exists() {
                paths.push(candidate);
            }
        }
        paths
    }
}

// Protection trait - abstracts both root and non-root modes
trait Protection {
    fn protect(&mut self, path: &Path);
    fn check_and_reprotect(&mut self, path: &Path) -> bool;
    fn restore_all(&self);
    fn mode_name(&self) -> &'static str;
}

// Root mode: uses kernel-level immutable bit (chattr +i)
struct ImmutableProtection {
    protected: HashSet<PathBuf>,
}

impl ImmutableProtection {
    fn new() -> Self {
        Self {
            protected: HashSet::new(),
        }
    }

    fn set_immutable(&mut self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();

        if path.is_symlink() {
            println!(
                "  {} Removing symlink {} (attack blocked)",
                "⚠".yellow(),
                path.display().to_string().bold()
            );
            let _ = fs::remove_file(path);
            return false;
        }

        if !path.exists() {
            return false;
        }

        self.protected.insert(path.to_path_buf());

        let output = Command::new("chattr").args(&["+i", &path_str]).output();

        match output {
            Ok(result) if result.status.success() => {
                let item_type = if path.is_dir() { "dir" } else { "file" };
                println!(
                    "  {} {} {} {}",
                    "🔒".green(),
                    path.display().to_string().bold(),
                    "immutable".dimmed(),
                    format!("({})", item_type).dimmed()
                );
                true
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                eprintln!(
                    "  {} Failed to protect {}: {}",
                    "✗".red(),
                    path.display(),
                    stderr.trim()
                );
                false
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to run chattr on {}: {}",
                    "✗".red(),
                    path.display(),
                    e
                );
                false
            }
        }
    }

    fn remove_immutable(&self, path: &Path) {
        let path_str = path.to_string_lossy().to_string();
        let _ = Command::new("chattr").args(&["-i", &path_str]).output();
    }

    fn is_immutable(&self, path: &Path) -> bool {
        let output = Command::new("lsattr").arg(path).output();

        match output {
            Ok(result) if result.status.success() => {
                let attrs = String::from_utf8_lossy(&result.stdout);
                attrs.contains('i')
            }
            _ => false,
        }
    }
}

impl Protection for ImmutableProtection {
    fn protect(&mut self, path: &Path) {
        self.set_immutable(path);
    }

    fn check_and_reprotect(&mut self, path: &Path) -> bool {
        if !self.is_immutable(path) {
            println!(
                "{} {} {}",
                "ATTACK".red().bold(),
                path.display().to_string().white(),
                "→ re-protecting".dimmed()
            );
            self.set_immutable(path);
            return true;
        }
        false
    }

    fn restore_all(&self) {
        println!("\n{} Restoring...", "→".cyan());
        for path in &self.protected {
            self.remove_immutable(path);
        }
        println!("{}", "Restored".green());
    }

    fn mode_name(&self) -> &'static str {
        "kernel-level immutable"
    }
}

// Non-root mode: uses read-only permissions (chmod 444/555)
struct ReadonlyProtection {
    protected: HashMap<PathBuf, u32>, // path -> original mode
}

impl ReadonlyProtection {
    fn new() -> Self {
        Self {
            protected: HashMap::new(),
        }
    }

    fn set_readonly(&mut self, path: &Path) {
        if let Ok(meta) = fs::metadata(path) {
            let perms = meta.permissions();
            let mode = perms.mode() & 0o777;
            let is_dir = meta.is_dir();

            // Skip if already read-only
            if mode & 0o200 == 0 {
                return;
            }

            // Save original
            let path_buf = path.to_path_buf();
            if !self.protected.contains_key(&path_buf) {
                self.protected.insert(path_buf, mode);
            }

            // Set read-only: files 444, dirs 555
            let readonly_mode = if is_dir { 0o555 } else { 0o444 };
            let mut new_perms = perms;
            new_perms.set_mode(readonly_mode);

            if fs::set_permissions(path, new_perms).is_ok() {
                let item_type = if is_dir { "dir" } else { "file" };
                println!(
                    "  {} {} {} {}",
                    "🔒".yellow(),
                    path.display().to_string().bold(),
                    "read-only".dimmed(),
                    format!("({})", item_type).dimmed()
                );
            }
        }
    }

    fn is_readonly(&self, path: &Path) -> bool {
        if let Ok(meta) = fs::metadata(path) {
            let perms = meta.permissions();
            let mode = perms.mode() & 0o777;
            mode & 0o200 == 0
        } else {
            false
        }
    }
}

impl Protection for ReadonlyProtection {
    fn protect(&mut self, path: &Path) {
        self.set_readonly(path);
    }

    fn check_and_reprotect(&mut self, path: &Path) -> bool {
        if !self.is_readonly(path) {
            println!(
                "{} {} {}",
                "WRITE BLOCKED".red().bold(),
                path.display().to_string().white(),
                "→ reset to read-only".dimmed()
            );
            self.set_readonly(path);
            return true;
        }
        false
    }

    fn restore_all(&self) {
        println!("\n{} Restoring...", "→".cyan());
        for (path, original_mode) in &self.protected {
            if let Ok(meta) = fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(*original_mode);
                let _ = fs::set_permissions(path, perms);
            }
        }
        println!("{}", "Restored".green());
    }

    fn mode_name(&self) -> &'static str {
        "read-only permissions"
    }
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn print_banner(config_path: &Path, patterns: &[String], is_root_user: bool) {
    println!(
        "{} {}",
        "Config:".dimmed(),
        config_path.display().to_string().white().bold()
    );
    println!("{}", "Blocked patterns:".dimmed());
    for p in patterns {
        println!("  {} {}", "▸".red(), p.yellow());
    }
    println!();

    if is_root_user {
        println!(
            "{} {}",
            "Mode:".dimmed(),
            "Root (kernel-level immutable)".green().bold()
        );
    } else {
        println!(
            "{} {}",
            "Mode:".dimmed(),
            "User (read-only permissions)".yellow().bold()
        );
        println!("{}", "Tip: Run with sudo for stronger protection".dimmed());
    }
    println!();
}

fn protect_all(config: &BlockConfig, base: &Path, protection: &mut dyn Protection) {
    fn protect_recursive(
        path: &Path,
        config: &BlockConfig,
        base: &Path,
        protection: &mut dyn Protection,
    ) {
        let rel = path.strip_prefix(base).unwrap_or(path);

        if path.is_symlink() {
            let _ = fs::remove_file(path);
            return;
        }

        if config.is_blocked(rel).is_some() {
            protection.protect(path);
        }

        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let entry_rel = entry_path.strip_prefix(base).unwrap_or(&entry_path);

                    if entry_path.is_symlink() {
                        let _ = fs::remove_file(&entry_path);
                        continue;
                    }

                    if config.is_blocked(entry_rel).is_some() {
                        protection.protect(&entry_path);
                    }

                    if entry_path.is_dir() {
                        protect_recursive(&entry_path, config, base, protection);
                    }
                }
            }
        }
    }

    protect_recursive(base, config, base, protection);
}

fn main() {
    let args = Args::parse();
    let root_mode = is_root();

    let patterns = match parse_config(&args.config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    if patterns.is_empty() {
        eprintln!(
            "{} No patterns found in [blocked] section.",
            "Warning:".yellow().bold()
        );
    }

    print_banner(&args.config, &patterns, root_mode);

    let config = BlockConfig::new(patterns);

    let base = args
        .config
        .canonicalize()
        .unwrap_or_else(|_| args.config.clone())
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // Create appropriate protection based on privileges
    let protection: Arc<Mutex<dyn Protection + Send>> = if root_mode {
        Arc::new(Mutex::new(ImmutableProtection::new()))
    } else {
        Arc::new(Mutex::new(ReadonlyProtection::new()))
    };

    let protection_clone = Arc::clone(&protection);

    // Set up signal handler
    ctrlc::set_handler(move || {
        println!("\n{} Ctrl+C received, shutting down...", "→".yellow());
        let guard = protection_clone.lock().unwrap();
        guard.restore_all();
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Protect all blocked files
    {
        let mut guard = protection.lock().unwrap();
        protect_all(&config, &base, &mut *guard);
    }

    let mode_str = protection.lock().unwrap().mode_name();
    println!("{} {}", "Protected:".green().bold(), mode_str.green());
    println!("{}", "(Will restore on exit)".dimmed());
    println!();
    println!("{}", "Watching for changes… (Ctrl+C to stop)".green());
    println!();

    let watch_paths = config.watch_paths(&base);

    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(
        tx,
        Config::default().with_poll_interval(Duration::from_millis(100)),
    )
    .expect("Failed to create watcher");

    let mut _watched: HashSet<PathBuf> = HashSet::new();
    for p in &watch_paths {
        let mode = if p.is_dir() {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        if let Err(e) = watcher.watch(p, mode) {
            eprintln!(
                "{} Could not watch '{}': {}",
                "Warning:".yellow(),
                p.display(),
                e
            );
        } else {
            _watched.insert(p.clone());
            if args.verbose {
                println!("{} Watching: {}", "►".blue(), p.display());
            }
        }
    }

    // Also watch base dir
    let _ = watcher.watch(&base, RecursiveMode::Recursive);

    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                // Check each path that triggered an event
                for path in &event.paths {
                    let rel = path.strip_prefix(&base).unwrap_or(path);
                    if config.is_blocked(rel).is_some() && path.exists() {
                        let mut guard = protection.lock().unwrap();
                        guard.check_and_reprotect(path);
                    }
                }
            }
            Ok(Err(e)) => eprintln!("{} Watch error: {}", "Error:".red(), e),
            Err(e) => {
                eprintln!("{} Channel closed: {}", "Error:".red(), e);
                break;
            }
        }
    }

    // Restore on exit
    let guard = protection.lock().unwrap();
    guard.restore_all();
}
