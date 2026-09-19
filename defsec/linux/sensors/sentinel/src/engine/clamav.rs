// ==============================================================================
// File:        clamav.rs
// Component:   Linux Sentinel — Static Signature Orchestrator
// Description: Asynchronously manages the ClamAV daemon and freshclam updates.
// Role:        Routinely synchronizes signature definitions and performs
//              scheduled static scans of high-risk directories when the system
//              is fully armed. Matches are routed to the SIEM transmitter.
// ==============================================================================

use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use anyhow::Result;
use std::sync::{Arc, RwLock};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

pub struct ClamavEngine {
    config: Arc<RwLock<MasterConfig>>,
    endpoint_id: Arc<String>,
    tx: mpsc::Sender<SecurityAlert>,
}

impl ClamavEngine {
    pub fn new(config: Arc<RwLock<MasterConfig>>, tx: mpsc::Sender<SecurityAlert>) -> Self {
        Self {
            config,
            endpoint_id: Arc::new(crate::engine::scanner::ScannerEngine::generate_endpoint_id()),
            tx
        }
    }

    pub async fn run(self) -> Result<()> {
        let (is_enabled, sync_enabled, armed_only, target_paths, scan_interval, sync_interval) = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            (
                lock.clamav.enable_clamav,
                lock.clamav.enable_freshclam_sync,
                lock.clamav.armed_mode_only,
                lock.clamav.target_paths.clone(),
                lock.clamav.scan_interval_sec,
                lock.clamav.sync_interval_sec
            )
        };

        if !is_enabled {
            info!("ClamAV static scanning is explicitly disabled in the configuration.");
            return Ok(());
        }

        info!("ClamAV Engine active. Orchestrating asynchronous sync and scan tasks.");

        // ----------------------------------------------------------------------
        // Task A: The freshclam Synchronizer
        // ----------------------------------------------------------------------
        let endpoint_id_sync = self.endpoint_id.clone();
        let tx_sync = self.tx.clone();
        let sync_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if !sync_enabled {
                info!("freshclam signature synchronization is explicitly disabled in the configuration.");
                return;
            }

            let mut ticker = interval(Duration::from_secs(sync_interval));
            loop {
                ticker.tick().await;
                debug!("Triggering scheduled freshclam signature synchronization...");

                match Command::new("freshclam")
                    .arg("--config-file=/etc/clamav/freshclam.conf")
                    .arg("--foreground")
                    .arg("--stdout")
                    .status()
                    .await {
                    Ok(status) if status.success() => {
                        info!("ClamAV signatures successfully synchronized.");
                    }
                    Ok(status) => {
                        warn!("freshclam exited with non-zero status: {}", status);
                        let alert = SecurityAlert::new(
                            endpoint_id_sync.to_string(),
                            AlertLevel::Medium,
                            "Threat Intelligence Sync Failure: freshclam was unable to update definitions.".to_string(),
                            MitreTactic::DefenseEvasion,
                            "T1562 Impair Defenses",
                        );
                        let _ = tx_sync.try_send(alert);
                    }
                    Err(e) => error!("Failed to spawn freshclam process: {}", e),
                }
            }
        });

        // ----------------------------------------------------------------------
        // Task B: The Static Scanner
        // ----------------------------------------------------------------------
        let tx_scan = self.tx.clone();
        let config_ref = self.config.clone();
        let endpoint_id_scan = self.endpoint_id.clone();

        let scan_task = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(scan_interval));
            loop {
                ticker.tick().await;

                // Evaluate armed mode constraint dynamically
                let is_armed = {
                    let lock = config_ref.read().unwrap_or_else(|e| e.into_inner());
                    lock.engine.enable_active_mitigation // Mapping ArmedMode to active mitigation state
                };

                if armed_only && !is_armed {
                    debug!("System is not armed. Bypassing scheduled ClamAV scan to preserve resources.");
                    continue;
                }

                debug!("Initiating ClamAV static file scan on designated paths...");

                for path in &target_paths {
                    match Command::new("clamscan")
                        .arg("--infected")
                        .arg("--recursive")
                        .arg("--no-summary")
                        .arg(path)
                        .output()
                        .await
                    {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            for line in stdout.lines() {
                                if line.contains("FOUND") {
                                    let alert = SecurityAlert::new(
                                        endpoint_id_scan.to_string(),
                                        AlertLevel::Critical,
                                        format!("ClamAV Signature Match: {}", line.trim()),
                                        MitreTactic::Execution,
                                        "T1204 User Execution",
                                    );
                                    if let Err(e) = tx_scan.try_send(alert) {
                                        error!("Pipeline Failure: Failed to route ClamAV alert: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => error!("Failed to execute clamscan on path {}: {}", path, e),
                    }
                }
            }
        });

        let _ = tokio::join!(sync_task, scan_task);
        Ok(())
    }
}