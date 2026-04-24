use clap::Parser;
use colored::*;
use glob::Pattern;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(name = "block-f", about = "Block edits to files/dirs listed in config", version)]
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

// Store original immutable state
struct ProtectionStore {
    protected: HashSet<PathBuf>,
}

impl ProtectionStore {
    fn new() -> Self {
        Self {
            protected: HashSet::new(),
        }
    }

    fn set_immutable(&mut self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();

        // Check if it's a symlink - if so, remove it
        if path.is_symlink() {
            println!("  {} Removing symlink {} (redirect attack blocked)",
                "⚠".yellow(),
                path.display().to_string().bold());
            let _ = fs::remove_file(path);
            return false;
        }

        // Check if file/dir exists
        if !path.exists() {
            return false;
        }

        // Save to our list
        self.protected.insert(path.to_path_buf());

        // Set immutable using chattr +i
        let output = Command::new("chattr")
            .args(&["+i", &path_str])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                let item_type = if path.is_dir() { "directory" } else { "file" };
                println!("  {} Set {} immutable ({})",
                    "🔒".green(),
                    path.display().to_string().bold(),
                    item_type.dimmed());
                true
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                eprintln!("  {} Failed to protect {}: {}",
                    "✗".red(),
                    path.display(),
                    stderr.trim());
                false
            }
            Err(e) => {
                eprintln!("  {} Failed to run chattr on {}: {}",
                    "✗".red(),
                    path.display(),
                    e);
                false
            }
        }
    }

    fn remove_immutable(&self, path: &Path) {
        let path_str = path.to_string_lossy().to_string();
        let _ = Command::new("chattr")
            .args(&["-i", &path_str])
            .output();
    }

    fn restore_all(&self) {
        println!("\n{} Restoring all protected files...", "→".cyan());
        for path in &self.protected {
            self.remove_immutable(path);
        }
        println!("{}", "All files restored".green());
    }
}

fn print_banner(config_path: &Path, patterns: &[String]) {
    println!("{} {}", "Config:".dimmed(), config_path.display().to_string().white().bold());
    println!("{}", "Blocked patterns:".dimmed());
    for p in patterns {
        println!("  {} {}", "▸".red(), p.yellow());
    }
    println!();
}

fn protect_all(config: &BlockConfig, base: &Path, store: &mut ProtectionStore) {
    fn protect_recursive(path: &Path, config: &BlockConfig, base: &Path, store: &mut ProtectionStore) {
        let rel = path.strip_prefix(base).unwrap_or(path);

        if path.is_symlink() {
            // Remove symlinks to blocked paths
            let _ = fs::remove_file(path);
            return;
        }

        if config.is_blocked(rel).is_some() {
            store.set_immutable(path);
        }

        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let entry_rel = entry_path.strip_prefix(base).unwrap_or(&entry_path);

                    // Check if this is a symlink attack
                    if entry_path.is_symlink() {
                        // Remove symlinks inside blocked directories
                        let _ = fs::remove_file(&entry_path);
                        continue;
                    }

                    if config.is_blocked(entry_rel).is_some() {
                        store.set_immutable(&entry_path);
                    }

                    if entry_path.is_dir() {
                        protect_recursive(&entry_path, config, base, store);
                    }
                }
            }
        }
    }

    protect_recursive(base, config, base, store);
}

fn main() {
    let args = Args::parse();

    let patterns = match parse_config(&args.config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    if patterns.is_empty() {
        eprintln!("{} No patterns found in [blocked] section.", "Warning:".yellow().bold());
    }

    print_banner(&args.config, &patterns);

    let config = BlockConfig::new(patterns);

    let base = args.config
        .canonicalize()
        .unwrap_or_else(|_| args.config.clone())
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // Create protection store
    let store = Arc::new(Mutex::new(ProtectionStore::new()));
    let store_clone = Arc::clone(&store);

    // Set up signal handler
    ctrlc::set_handler(move || {
        println!("\n{} Ctrl+C received, shutting down...", "→".yellow());
        let store = store_clone.lock().unwrap();
        store.restore_all();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    // Protect all blocked files
    {
        let mut store_guard = store.lock().unwrap();
        protect_all(&config, &base, &mut *store_guard);
    }

    println!("{}", "All blocked files are now protected (kernel-level immutable)".green());
    println!("{}", "(Permissions will be restored on exit)".dimmed());
    println!();
    println!("{}", "Watching for attacks… (Ctrl+C to stop)".green());
    println!();

    let watch_paths = config.watch_paths(&base);

    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(
        tx,
        Config::default().with_poll_interval(Duration::from_millis(100)),
    ).expect("Failed to create watcher");

    let mut _watched: HashSet<PathBuf> = HashSet::new();
    for p in &watch_paths {
        let mode = if p.is_dir() { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
        if let Err(e) = watcher.watch(p, mode) {
            eprintln!("{} Could not watch '{}': {}", "Warning:".yellow(), p.display(), e);
        } else {
            _watched.insert(p.clone());
            if args.verbose {
                println!("{} Watching: {}", "►".blue(), p.display());
            }
        }
    }

    // Also watch base dir for new files and symlinks
    let _ = watcher.watch(&base, RecursiveMode::Recursive);

    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                for path in &event.paths {
                    let rel = path.strip_prefix(&base).unwrap_or(path).to_path_buf();

                    // Check for symlink attacks
                    if path.is_symlink() {
                        if let Some(pattern) = config.is_blocked(&rel) {
                            println!(
                                "{} {} {} {}",
                                "SYMLINK ATTACK".red().bold(),
                                path.display().to_string().white(),
                                "→ matched:".dimmed(),
                                pattern.yellow()
                            );
                            let _ = fs::remove_file(path);
                            println!("  {} Symlink removed", "→".green());
                        }
                        continue;
                    }

                    // Check if this is a blocked path that needs protection
                    if let Some(pattern) = config.is_blocked(&rel) {
                        if path.exists() {
                            // Check if immutable bit is still set
                            let output = Command::new("lsattr")
                                .arg(path)
                                .output();

                            let is_immutable = match output {
                                Ok(result) if result.status.success() => {
                                    let attrs = String::from_utf8_lossy(&result.stdout);
                                    attrs.contains('i')
                                }
                                _ => false,
                            };

                            if !is_immutable {
                                println!(
                                    "{} {} {} {}",
                                    "ATTACK DETECTED".red().bold(),
                                    path.display().to_string().white(),
                                    "→ matched:".dimmed(),
                                    pattern.yellow()
                                );
                                let mut store_guard = store.lock().unwrap();
                                store_guard.set_immutable(path);
                            }
                        }
                    } else if args.verbose {
                        println!("{} {}", "allowed:".dimmed(), path.display().to_string().dimmed());
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
    let store_guard = store.lock().unwrap();
    store_guard.restore_all();
}
