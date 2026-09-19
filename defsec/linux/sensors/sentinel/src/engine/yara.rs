// ==============================================================================
// File:        yara.rs
// Component:   Linux Sentinel — File Integrity & Malware Engine
// Description: Integrates the YARA C-library for static payload analysis.
// Role:        Compiles YARA signatures into memory and continuously monitors
//              critical file paths. Includes a context-aware autonomous poller
//              to hot-swap threat intelligence without restarting the agent.
// Author:      Robert Weber
// ==============================================================================

use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use crate::ReloadCommand;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};
use yara::{Compiler, Rules};

pub struct YaraEngine {
    config: Arc<RwLock<MasterConfig>>,
    pub endpoint_id: Arc<String>,
    rules: Arc<RwLock<Rules>>,
    rule_count: Arc<AtomicUsize>,
    tx: mpsc::Sender<SecurityAlert>,
    reload_rx: broadcast::Receiver<ReloadCommand>,
    memory_scan_rx: mpsc::Receiver<u32>,
}

impl YaraEngine {
    pub fn new(
        config: Arc<RwLock<MasterConfig>>,
        rules_path: &str,
        tx: mpsc::Sender<SecurityAlert>,
        reload_rx: broadcast::Receiver<ReloadCommand>,
        memory_scan_rx: mpsc::Receiver<u32>,
    ) -> Result<Self> {
        info!("Compiling baseline YARA rules from directory: {}", rules_path);
        let mut compiler = Compiler::new().context("Failed to create YARA compiler")?;

        let _ = compiler.define_variable("filename", "");
        let _ = compiler.define_variable("filepath", "");
        let _ = compiler.define_variable("extension", "");
        let _ = compiler.define_variable("filetype", "");
        let _ = compiler.define_variable("owner", "");
        let _ = compiler.define_variable("is__elf", false);
        let _ = compiler.define_variable("is__pe", false);
        let _ = compiler.define_variable("is__macho", false);
        let _ = compiler.define_variable("is_sandbox", false);
        let _ = compiler.define_variable("is_generic", true);

        let path = PathBuf::from(rules_path);
        let mut valid_rules_compiled = 0;

        if path.is_dir() {
            let mut walk_queue = vec![path];
            while let Some(dir) = walk_queue.pop() {
                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let file_path = entry.path();
                        if file_path.is_dir() {
                            walk_queue.push(file_path);
                        } else if let Some(_ext) = file_path.extension() {
                            if _ext == "yar" || _ext == "yara" {
                                compiler = match compiler.add_rules_file(&file_path) {
                                    Ok(c) => {
                                        valid_rules_compiled += 1;
                                        c
                                    },
                                    Err(e) => {
                                        return Err(anyhow::anyhow!(
                                            "FATAL: Invalid baseline YARA rule at {:?}. Aborting YARA boot: {}",
                                            file_path, e
                                        ));
                                    }
                                };
                            }
                        }
                    }
                }
            }
        }

        if valid_rules_compiled == 0 {
            warn!("No valid YARA rules found in {}", rules_path);
        }

        let rules = compiler.compile_rules().context("Failed to compile baseline YARA rules")?;

        let engine = Self {
            config,
            rules: Arc::new(RwLock::new(rules)),
            rule_count: Arc::new(AtomicUsize::new(valid_rules_compiled)),
            tx,
            reload_rx,
            memory_scan_rx,
            endpoint_id: Arc::new(crate::engine::scanner::ScannerEngine::generate_endpoint_id()),
        };

        engine.spawn_yara_intel_sync();
        engine.verify_alert_pipeline();
        tracing::info!(count = valid_rules_compiled, "Compiled baseline YARA rules into active memory.");
        Ok(engine)
    }

    /// The Context-Aware Parsing Engine
    /// Recursively walks the orchestration directory, parses .yar/.yara files via C-FFI,
    /// and performs a thread-safe memory hot-swap of the active rule signatures.
    pub fn reload_rules(&self, staging_dir: &str) {
        let rules_ref = Arc::clone(&self.rules);
        let count_ref = Arc::clone(&self.rule_count);
        let dir_path_owned = staging_dir.to_string();

        // Offloaded to a blocking thread to prevent tokio runtime starvation
        tokio::task::spawn_blocking(move || {
            info!(path = %dir_path_owned, "Initiating local YARA context-aware parsing");
            let mut compiler = match Compiler::new() {
                Ok(c) => c,
                Err(e) => {
                    error!("YARA Compiler init failed during intel sync: {}", e);
                    return;
                }
            };

            let _ = compiler.define_variable("filename", "");
            let _ = compiler.define_variable("filepath", "");
            let _ = compiler.define_variable("extension", "");
            let _ = compiler.define_variable("filetype", "");
            let _ = compiler.define_variable("owner", "");
            let _ = compiler.define_variable("is__elf", false);
            let _ = compiler.define_variable("is__pe", false);
            let _ = compiler.define_variable("is__macho", false);
            let _ = compiler.define_variable("is_sandbox", false);
            let _ = compiler.define_variable("is_generic", true);

            let mut valid_rules_compiled = 0;
            let mut walk_queue = vec![PathBuf::from(&dir_path_owned)];

            while let Some(dir) = walk_queue.pop() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            walk_queue.push(path);
                        } else if let Some(ext) = path.extension() {
                            if ext == "yar" || ext == "yara" {
                                compiler = match compiler.add_rules_file(&path) {
                                    Ok(c) => {
                                        valid_rules_compiled += 1;
                                        c
                                    },
                                    Err(e) => {
                                        error!("FATAL: YARA rule syntax error in {:?}. Aborting intel sync to prevent partial protection: {}", path, e);
                                        return;
                                    }
                                };
                            }
                        }
                    }
                }
            }

            if valid_rules_compiled > 0 {
                if let Ok(new_rules) = compiler.compile_rules() {
                    // Safe lock unwrap with poison recovery
                    let mut lock = rules_ref.write().unwrap_or_else(|e| e.into_inner());
                    *lock = new_rules;
                    count_ref.store(valid_rules_compiled, Ordering::SeqCst);
                    info!(count = valid_rules_compiled, "Threat Intel Sync Complete: Context-aware vectors mapped into memory.");
                }
            } else {
                warn!("YARA sync aborted: No valid signatures found in orchestration directory.");
            }
        });
    }

    /// Autonomous Background Poller
    /// Automatically detects if the orchestrator (or a cron job) updates the mounted
    /// signature definitions, keeping the memory state fresh without requiring an API trigger.
    fn spawn_yara_intel_sync(&self) {
        let sync_interval_secs = 86400; // 24-hour baseline cycle
        let target_dir = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            lock.engine.yara_rules_path.clone()
        };

        let rules_ref = Arc::clone(&self.rules);
        let count_ref = Arc::clone(&self.rule_count);

        tokio::spawn(async move {
            info!("Initializing Autonomous Yara Local Sync (Interval: {}s)...", sync_interval_secs);
            let mut update_interval = interval(Duration::from_secs(sync_interval_secs));

            loop {
                update_interval.tick().await;
                debug!("Running scheduled local signature compilation pass...");

                let rules_clone = Arc::clone(&rules_ref);
                let count_clone = Arc::clone(&count_ref);
                let dir_clone = target_dir.clone();

                tokio::task::spawn_blocking(move || {
                    let mut compiler = match Compiler::new() {
                        Ok(c) => c,
                        Err(e) => {
                            error!("YARA Compiler init failed in sync thread: {}", e);
                            return;
                        }
                    };

                    let _ = compiler.define_variable("filename", "");
                    let _ = compiler.define_variable("filepath", "");
                    let _ = compiler.define_variable("extension", "");
                    let _ = compiler.define_variable("filetype", "");
                    let _ = compiler.define_variable("owner", "");
                    let _ = compiler.define_variable("is__elf", false);
                    let _ = compiler.define_variable("is__pe", false);
                    let _ = compiler.define_variable("is__macho", false);

                    let mut valid_rules_compiled = 0;
                    let mut walk_queue = vec![PathBuf::from(&dir_clone)];

                    while let Some(dir) = walk_queue.pop() {
                        if let Ok(entries) = fs::read_dir(dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.is_dir() {
                                    walk_queue.push(path);
                                } else if let Some(ext) = path.extension() {
                                    if ext == "yar" || ext == "yara" {
                                        compiler = match compiler.add_rules_file(&path) {
                                            Ok(c) => {
                                                valid_rules_compiled += 1;
                                                c
                                            },
                                            Err(e) => {
                                                error!("Scheduled YARA rule failed {:?}: {}", path, e);
                                                return;
                                            }
                                        };
                                    }
                                }
                            }
                        }
                    }

                    if valid_rules_compiled > 0 {
                        if let Ok(new_rules) = compiler.compile_rules() {
                            let mut lock = rules_clone.write().unwrap_or_else(|e| e.into_inner());
                            *lock = new_rules;
                            count_clone.store(valid_rules_compiled, Ordering::SeqCst);
                        }
                    }
                }).await.unwrap_or_else(|e| error!("Scheduled YARA sync task panicked: {}", e));
            }
        });
    }

    /// Lock-free inspection of the active YARA signature count.
    pub fn get_rule_count(&self) -> usize {
        self.rule_count.load(Ordering::SeqCst)
    }

    /// Verifies the alert routing pipeline by attempting to send a diagnostic alert.
    /// Returns true if the channel is open and actively receiving alerts.
    pub fn verify_alert_pipeline(&self) -> bool {
        if self.get_rule_count() == 0 {
            tracing::error!("YARA diagnostic failed: Cannot verify pipeline with 0 rules loaded.");
            return false;
        }
        let test_alert = SecurityAlert::new(
            self.endpoint_id.to_string(),
            AlertLevel::Info,
            "Diagnostic: YARA Engine Pipeline Verification".to_string(),
            MitreTactic::Unknown,
            "T0000 Diagnostic",
        );

        match self.tx.try_send(test_alert) {
            Ok(_) => {
                tracing::info!(count = self.get_rule_count(), "YARA diagnostic passed: Alert channel is open and responsive.");
                true
            }
            Err(e) => {
                tracing::error!("YARA diagnostic failed: Alert channel is blocked or closed. Error: {}", e);
                false
            }
        }
    }

    pub async fn run(mut self) {
        let is_enabled = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            lock.engine.enable_yara
        };

        if !is_enabled {
            info!("YARA scanning engine is disabled in master.toml");
            return;
        }

        info!("YARA scanning engine active. Monitoring critical paths.");
        let mut scan_interval = interval(Duration::from_secs(300));

        let max_concurrent_scans = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let scan_throttle = Arc::new(tokio::sync::Semaphore::new(max_concurrent_scans));
        info!("YARA engine concurrency capped at {} simultaneous scans.", max_concurrent_scans);

        loop {
            tokio::select! {
                _ = scan_interval.tick() => {
                    let critical_paths = {
                        let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                        lock.files.critical_paths.clone()
                    };

                    for path_str in critical_paths {
                        let path = PathBuf::from(path_str);
                        if !path.exists() || !path.is_file() { continue; }

                        let rules_arc = self.rules.clone();
                        let tx = self.tx.clone();
                        let endpoint_id_scan = self.endpoint_id.clone();

                        let permit = match scan_throttle.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        tokio::task::spawn_blocking(move || {
                            let lock = rules_arc.read().unwrap_or_else(|e| e.into_inner());

                            let mut scanner = match lock.scanner() {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("YARA Fatal: Failed to allocate scanner state: {}", e);
                                    return;
                                }
                            };

                            if let Ok(results) = scanner.scan_file(&path) {
                                for result in results {
                                    let alert = SecurityAlert::new(
                                        endpoint_id_scan.to_string(),
                                        AlertLevel::Critical,
                                        format!("YARA Match: {} on {}", result.identifier, path.display()),
                                        MitreTactic::Execution,
                                        "T1204 User Execution",
                                    );

                                    if let Err(e) = tx.try_send(alert) {
                                        error!(path = %path.display(), error = %e, "Pipeline Failure: Failed to route YARA alert");
                                    }
                                }
                            }
                            drop(permit);
                        }).await.unwrap_or_else(|e| error!(error = %e, "YARA scan task panicked"));
                    }
                }

                Ok(cmd) = self.reload_rx.recv() => {
                    if let ReloadCommand::Rules = cmd {
                        info!("API Command Received: Triggering live YARA rule hot-swap...");
                        let yara_path = {
                            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                            lock.engine.yara_rules_path.clone()
                        };
                        self.reload_rules(&yara_path);
                    }
                }

                Some(target_pid) = self.memory_scan_rx.recv() => {
                    let is_armed = {
                        let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                        lock.engine.enable_active_mitigation // ArmedMode toggle
                    };

                    if !is_armed {
                        debug!(pid = target_pid, "System unarmed. Bypassing targeted YARA memory scan to preserve resources.");
                        continue;
                    }

                    info!(pid = target_pid, "Armed Mode Active: Initiating deep memory C2 payload extraction.");

                    let rules_arc = self.rules.clone();
                    let tx_arc = self.tx.clone();
                    let endpoint_id_mem = self.endpoint_id.clone();

                    tokio::task::spawn_blocking(move || {
                        let maps_path = format!("/proc/{}/maps", target_pid);
                        let mem_path = format!("/proc/{}/mem", target_pid);

                        let maps_content = match std::fs::read_to_string(&maps_path) {
                            Ok(c) => c,
                            Err(_) => return, // Process likely terminated already
                        };

                        let mut mem_file = match std::fs::File::open(&mem_path) {
                            Ok(f) => f,
                            Err(_) => return,
                        };

                        let lock = rules_arc.read().unwrap_or_else(|e| e.into_inner());
                        let mut scanner = match lock.scanner() {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                        // Parse memory regions and scan executable/readable segments
                        for line in maps_content.lines() {
                            if line.contains("r-xp") || line.contains("rwxp") { // Target executable memory
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if let Some(range) = parts.first() {
                                    let addresses: Vec<&str> = range.split('-').collect();
                                    if addresses.len() == 2 {
                                        if let (Ok(start), Ok(end)) = (
                                            usize::from_str_radix(addresses[0], 16),
                                            usize::from_str_radix(addresses[1], 16)
                                        ) {
                                            use std::io::{Seek, SeekFrom, Read};
                                            let length = end - start;

                                            // Prevent excessive memory allocation (Cap at 50MB per segment)
                                            if length > 50_000_000 { continue; }

                                            let mut buffer = vec![0u8; length];
                                            if mem_file.seek(SeekFrom::Start(start as u64)).is_ok() {
                                                if mem_file.read_exact(&mut buffer).is_ok() {
                                                    if let Ok(results) = scanner.scan_mem(&buffer) {
                                                        for result in results {
                                                            let alert = SecurityAlert::new(
                                                                endpoint_id_mem.to_string(),
                                                                AlertLevel::Critical,
                                                                format!("In-Memory C2 Payload Detected: {} at 0x{:x} inside PID {}", result.identifier, start, target_pid),
                                                                MitreTactic::DefenseEvasion,
                                                                "T1620 Reflective Code Loading",
                                                            );
                                                            let _ = tx_arc.try_send(alert);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    }
}