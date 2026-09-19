// ==============================================================================
// File:        fim.rs
// Component:   Linux Sentinel — File Integrity Monitoring (FIM)
// Description: Monitors static, high-value OS assets for unauthorized modification.
// Role:        Maintains SHA-256 baselines of files designated in `master.toml`.
//              Utilizes spawn_blocking to prevent async runtime starvation during
//              heavy cryptographic I/O tasks.
// Author:      Robert Weber
// ==============================================================================

use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};
use ring::digest;

pub struct FimEngine {
    config: Arc<RwLock<MasterConfig>>,
    endpoint_id: Arc<String>,
    tx: mpsc::Sender<SecurityAlert>,
}

impl FimEngine {
    pub fn new(config: Arc<RwLock<MasterConfig>>, tx: mpsc::Sender<SecurityAlert>) -> Self {
        Self {
            config,
            endpoint_id: Arc::new(crate::engine::scanner::ScannerEngine::generate_endpoint_id()),
            tx
        }
    }

    /// Computes the SHA-256 hash of a file. Must be called from inside a blocking thread.
    fn compute_sha256(path: &PathBuf) -> anyhow::Result<String> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut context = digest::Context::new(&digest::SHA256);
        let mut buffer = [0; 8192];

        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break; }
            context.update(&buffer[..count]);
        }

        let hash = context.finish();
        Ok(hex::encode(hash.as_ref()))
    }

    pub async fn run(self) {
        let is_enabled = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            lock.engine.enable_fim
        };

        if !is_enabled {
            info!("FIM Engine is explicitly disabled via engine.enable_fim in master.toml.");
            return;
        }

        info!("File Integrity Monitoring (FIM) active. Establishing baseline...");
        let mut scan_interval = interval(Duration::from_secs(600)); // Run every 10 minutes
        let mut baseline_hashes: HashMap<String, String> = HashMap::new();

        loop {
            scan_interval.tick().await;
            debug!("Executing FIM cryptographic baseline pass...");

            let critical_paths = {
                let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                lock.files.critical_paths.clone()
            };

            for path_str in critical_paths {
                let path = PathBuf::from(&path_str);
                let current_baseline = baseline_hashes.get(&path_str).cloned();

                // LOGIC ANCHOR: Wrap CPU-bound hashing and blocking I/O in spawn_blocking
                let hash_result = tokio::task::spawn_blocking(move || {
                    if !path.exists() || !path.is_file() {
                        return (path_str.clone(), None, current_baseline);
                    }

                    match Self::compute_sha256(&path) {
                        Ok(new_hash) => (path_str.clone(), Some(new_hash), current_baseline),
                        Err(e) => {
                            warn!(path = %path.display(), "FIM Access Denied or read failure: {}", e);
                            (path_str.clone(), None, current_baseline)
                        }
                    }
                }).await;

                match hash_result {
                    Ok((path_key, Some(new_hash), Some(old_hash))) => {
                        if new_hash != old_hash {
                            warn!(path = %path_key, "FIM Alert: Critical system file integrity violation.");
                            let endpoint_id_scan = self.endpoint_id.clone();

                            let alert = SecurityAlert::new(
                                endpoint_id_scan.to_string(),
                                AlertLevel::Critical,
                                format!("File Integrity Violation: Unauthorized modification detected on {}", path_key),
                                MitreTactic::DefenseEvasion,
                                "T1562 Impair Defenses",
                            );

                            if let Err(e) = self.tx.try_send(alert) {
                                error!(path = %path_key, "Pipeline Failure: Failed to route FIM alert: {}", e);
                            }

                            // Update the baseline so we don't spam alerts for the exact same hash
                            baseline_hashes.insert(path_key, new_hash);
                        }
                    },
                    Ok((path_key, Some(new_hash), None)) => {
                        // First time seeing this file, record baseline
                        trace!(path = %path_key, "FIM Baseline established");
                        baseline_hashes.insert(path_key, new_hash);
                    },
                    Ok(_) => {}, // File unreadable or missing, safely ignore
                    Err(e) => error!("FIM blocking task panicked: {}", e),
                }
            }
        }
    }
}