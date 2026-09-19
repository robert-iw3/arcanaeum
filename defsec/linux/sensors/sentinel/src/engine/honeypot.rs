// ===================================================================================
// File:        honeypot.rs
// Component:   Linux Sentinel — Active Defense Engine
// Description: Deploys asynchronous listeners on frequently targeted network ports.
// Role:        Acts as a tarpit for automated scanners and lateral movement.
//              Intercepts unauthorized connections (e.g., SSH, Redis, Docker API),
//              rate-limits the adversaries, and generates high-fidelity T1046 alerts.
// Author:      Robert Weber
// ===================================================================================

use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use anyhow::Result;
use std::sync::{Arc, RwLock};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use std::collections::VecDeque;
use tokio::time::Instant;
use tracing::{error, info, warn};

// Linux Threat Landscape & Cloud-Native Scanner Traps
const TARGET_PORTS: &[u16] = &[
    21,    // FTP (Legacy cleartext brute-forcing)
    22,    // SSH (Primary target. Note: Will gracefully fail to bind if host sshd is active)
    23,    // Telnet (Mirai and legacy IoT botnet variants)
    111,   // RPCbind (DDoS reflection / legacy Linux vulnerabilities)
    445,   // Samba/SMB (Cross-platform ransomware worms)
    2222,  // Alternate SSH (Frequently scanned to bypass standard port 22 blocks)
    2375,  // Docker API [Unencrypted] (Massive target for cryptojackers)
    3306,  // MySQL/MariaDB (Brute-force and CVE exploitation)
    3389,  // RDP (xRDP on Linux, generic scanner traps)
    5432,  // PostgreSQL (Automated brute-force)
    5900,  // VNC (Unauthenticated access scanning)
    6379,  // Redis (Unauthenticated RCE / Living-off-the-Land mining campaigns)
    6443,  // Kubernetes API (Container orchestration compromise)
    9200,  // Elasticsearch (Data extortion / automated wiping bots)
    10000, // Webmin (Frequent CVE target for Linux management panel RCE)
    27017, // MongoDB (Automated database wiping/ransom attacks)
];

pub struct HoneypotEngine {
    config: Arc<RwLock<MasterConfig>>,
    endpoint_id: Arc<String>,
    tx: mpsc::Sender<SecurityAlert>,
}

impl HoneypotEngine {
    pub fn new(config: Arc<RwLock<MasterConfig>>, tx: mpsc::Sender<SecurityAlert>) -> Self {
        Self {
            config,
            endpoint_id: Arc::new(crate::engine::scanner::ScannerEngine::generate_endpoint_id()),
            tx
        }
    }

    pub async fn run(self) -> Result<()> {
        let (is_enabled, bind_addr, max_concurrent, max_per_min) = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            (
                lock.engine.enable_honeypots,
                lock.honeypot.honeypot_bind_addr.clone(),
                lock.honeypot.max_concurrent_per_port,
                lock.honeypot.max_connections_per_minute,
            )
        };

        if !is_enabled {
            info!("Honeypot engine is disabled in master.toml");
            return Ok(());
        }

        info!(addr = %bind_addr, "Initializing asynchronous honeypot listeners...");

        for &port in TARGET_PORTS {
            let tx_clone = self.tx.clone();
            let bind_addr_clone = bind_addr.clone();
            let endpoint_id_shared = self.endpoint_id.clone();

            tokio::spawn(async move {
                let addr = format!("{}:{}", bind_addr_clone, port);
                let semaphore = Arc::new(Semaphore::new(max_concurrent));
                let rate_limiter = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));
                let last_limit_log = Arc::new(tokio::sync::Mutex::new(Instant::now() - tokio::time::Duration::from_secs(60)));

                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        info!(port = port, "Honeypot active");
                        loop {
                            if let Ok((mut socket, peer_addr)) = listener.accept().await {
                                let ip = peer_addr.ip().to_string();
                                let now = Instant::now();
                                let mut limit_exceeded = false;

                                {
                                    let mut timestamps = rate_limiter.lock().await;
                                    while let Some(&ts) = timestamps.front() {
                                        if now.duration_since(ts).as_secs() > 60 {
                                            timestamps.pop_front();
                                        } else {
                                            break;
                                        }
                                    }
                                    if timestamps.len() >= max_per_min {
                                        limit_exceeded = true;
                                    } else {
                                        timestamps.push_back(now);
                                    }
                                }

                                if limit_exceeded {
                                    let mut ll = last_limit_log.lock().await;
                                    if ll.elapsed().as_secs() >= 60 {
                                        warn!(port = port, limit = max_per_min, "Honeypot port connection rate limit exceeded. Suppressing further drops for 60s.");
                                        *ll = Instant::now();
                                    }
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Tarpit
                                    continue;
                                }

                                let permit = match semaphore.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(port = port, ip = %ip, "Honeypot port concurrent capacity overloaded. Dropping connection");
                                        continue;
                                    }
                                };

                                let tx_inner = tx_clone.clone();
                                let endpoint_id_clone = endpoint_id_shared.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut buffer = [0; 128];
                                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut buffer)).await;

                                    warn!(port = port, ip = %ip, "Honeypot connection attempt");

                                    let alert = SecurityAlert::new(
                                        endpoint_id_clone.to_string(),
                                        AlertLevel::High,
                                        format!("Honeypot connection attempt on port {} from IP: {}", port, ip),
                                        MitreTactic::DefenseEvasion,
                                        "T1046 Network Service Scanning",
                                    );

                                    let _ = tx_inner.try_send(alert);
                                });
                            }
                        }
                    }
                    Err(e) => error!(port = port, error = %e, "Failed to bind honeypot"),
                }
            });
        }
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}