// ==============================================================================
// File:        scanner.rs
// Component:   Linux Sentinel — UEBA & ML Anomaly Engine
// Description: The 19D User and Entity Behavior Analytics (UEBA) pipeline.
// Role:        Ingests raw eBPF telemetry, maintains execution profiles using
//              Welford's Algorithm (O(1) memory variance tracking), and scores
//              events through an Extended Isolation Forest to detect 'Living off
//              the Land' (LotL) execution anomalies and hidden rootkits.
// Author:      Robert Weber
// ==============================================================================

use crate::config::MasterConfig;
use crate::engine::rules::{RawKernelEvent, RulesEngine};
use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch, SecurityAlert};
use crate::engine::baselines::BaselineStore;
use extended_isolation_forest::{Forest, ForestOptions};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, Duration as StdDuration};
use tokio::sync::{mpsc, broadcast};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};

#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileStateExt {
    ts: VecDeque<u64>,
    types: VecDeque<u32>,
    hll: Vec<u8>,
    distinct: [bool; 16],
    last_evt: u32,
    transitions: [[u32; 16]; 16],
    total_trans: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleProfile {
    pub instance_count: u64,
    pub mean_timing: f64,
    pub m2_timing: f64,
    pub mean_entropy: f64,
    pub m2_entropy: f64,
    pub aggregate_transitions: [[u32; 16]; 16],
    pub max_observed_velocity: f64,
}

impl Default for RoleProfile {
    fn default() -> Self {
        Self {
            instance_count: 0,
            mean_timing: 0.0, m2_timing: 0.0,
            mean_entropy: 0.0, m2_entropy: 0.0,
            aggregate_transitions: [[0; 16]; 16],
            max_observed_velocity: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessProfile {
    event_count: u64,
    last_seen_ns: u64, // Kernel time (bpf_ktime_get_ns)
    last_seen_wall_sec: u64, // Wall clock time (SystemTime)
    recent_timestamps: VecDeque<u64>,
    recent_event_types: VecDeque<u32>,

    // WELFORD'S ONLINE ALGORITHM: O(1) Memory Temporal Baselining
    mean_delta: f64,
    m2_delta: f64,
    mean_entropy: f64,
    max_velocity: f64,

    // Enriched Behavioral State
    distinct_event_types: [bool; 16],
    historical_std_dev: f64,
    initial_uid: u32,
    uid_changed: bool,
    network_hll: [u8; 64],
    max_write_depth: usize,
    child_spawns_this_minute: u16,

    // Payload Entropy Welford's State
    mean_payload_entropy: f64,
    m2_payload_entropy: f64,

    // Dual-band EWMA (Timing & Entropy)
    ewma_timing_slow: f64,
    ewma_timing_fast: f64,
    ewma_timing_var_slow: f64,
    ewma_entropy_slow: f64,
    ewma_entropy_fast: f64,
    ewma_entropy_var_slow: f64,

    // Markov Sequence Modeling
    last_event_type: u32,
    transition_counts: [[u32; 16]; 16],
    total_transitions: u64,

    // LotL Temporal Debouncing
    lotl_consecutive_anomalies: u16,
}

struct ContainerResolver {
    // Cache: cgroup_id -> (container_id, container_name)
    cache: Arc<RwLock<HashMap<u64, (String, String)>>>,
}

impl ContainerResolver {
    fn new() -> Self {
        Self { cache: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Asynchronously resolves the cgroup_id to Docker/Podman context
    async fn resolve(&self, cgroup_id: u64, pid: u32) -> (String, String) {
        // Fast path: cached lookup
        if let Some(meta) = self.cache.read().unwrap_or_else(|e| e.into_inner()).get(&cgroup_id) {
            return meta.clone();
        }

        // Slow path: resolve via /proc/<pid>/cgroup
        let path = format!("/proc/{}/cgroup", pid);
        let mut cid = String::from("host");
        let mut cname = String::from("host");

        if let Ok(contents) = tokio::fs::read_to_string(&path).await {
            for line in contents.lines() {
                if line.contains("/docker/") {
                    let parts: Vec<&str> = line.split("/docker/").collect();
                    if parts.len() > 1 {
                        cid = parts[1].to_string();
                        let short_id = if cid.len() >= 12 { &cid[..12] } else { &cid };
                        cname = format!("docker-{}", short_id);
                        break;
                    }
                } else if line.contains("libpod-") && line.contains(".scope") {
                    if let Some(start) = line.find("libpod-") {
                        let substr = &line[start + 7..];
                        if let Some(end) = substr.find(".scope") {
                            cid = substr[..end].to_string();
                            let short_id = if cid.len() >= 12 { &cid[..12] } else { &cid };
                            cname = format!("podman-{}", short_id);
                            break;
                        }
                    }
                }
            }
        }

        self.cache.write().unwrap_or_else(|e| e.into_inner()).insert(cgroup_id, (cid.clone(), cname.clone()));
        (cid, cname)
    }
}

/// HyperLogLog Sketch implementation for O(1) IP cardinality estimation
fn hll_add(sketch: &mut [u8; 64], ip: &str) {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    let hash = hasher.finish();

    let bucket = (hash & 0x3F) as usize; // 6 bits -> 64 buckets
    let remaining = hash >> 6;
    let leading_zeros = remaining.leading_zeros() as u8 + 1;
    sketch[bucket] = sketch[bucket].max(leading_zeros);
}

fn hll_estimate(sketch: &[u8; 64]) -> f64 {
    let m = 64.0;
    let alpha = 0.7213 / (1.0 + 1.079 / m);
    let sum: f64 = sketch.iter().map(|&v| 2.0_f64.powi(-(v as i32))).sum();
    let raw = alpha * m * m / sum;

    let zeros = sketch.iter().filter(|&&v| v == 0).count() as f64;
    if raw <= 2.5 * m && zeros > 0.0 {
        m * (m / zeros).ln()
    } else {
        raw
    }
}

/*
/// Computes lag-1 autocorrelation for Jitter-Aware Beaconing detection
fn streaming_autocorrelation(deltas: &VecDeque<f64>) -> f64 {
    if deltas.len() < 10 { return 0.0; }
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    let mut numerator = 0.0;
    let mut denominator = 0.0;

    for i in 0..deltas.len() - 1 {
        numerator += (deltas[i] - mean) * (deltas[i + 1] - mean);
        denominator += (deltas[i] - mean).powi(2);
    }

    if denominator == 0.0 { 0.0 } else { numerator / denominator }
}
*/
/// Command-Line Obfuscation Analyzer
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "base64", "\\x", "$IFS", "$((", "${!", "/dev/tcp/", "/dev/udp/",
    "eval ", "exec ", " | sh", " | bash", "python -c", "python3 -c",
    "perl -e", "ruby -e", "curl", "wget"
];

fn suspicious_pattern_count(cmd: &str) -> u8 {
    let lower = cmd.to_lowercase();
    SUSPICIOUS_PATTERNS.iter()
        .filter(|&&p| lower.contains(p))
        .count() as u8
}

/// Computes the log-probability of a syscall transition (Markov Chain)
fn transition_surprise(counts: &[[u32; 16]; 16], from: usize, to: usize) -> f64 {
    let row_total: u32 = counts[from].iter().map(|&c| c as u32).sum();
    if row_total < 10 { return 0.0; } // Not enough data to judge

    let count = counts[from][to] as f64;
    let probability = (count + 1.0) / (row_total as f64 + 16.0); // Laplace smoothing
    -probability.log2() // Information content in bits
}

/// Computes how far a specific process deviates from the global norm for its binary
fn role_deviation_score(process_mean: f64, role_mean: f64, role_m2: f64, role_count: f64) -> f64 {
    if role_count < 5.0 { return 0.0; } // Wait for global convergence
    let variance = (role_m2 / (role_count - 1.0)).max(0.0);
    let std_dev = variance.sqrt().max(0.001);
    ((process_mean - role_mean).abs() / std_dev).min(10.0) // Clamp to prevent vector explosion
}

/// Hash-based jitter to break degenerate splits in Isolation Forest training.
/// Uses a simple FNV-1a hash seeded with vector index and dimension to produce
/// deterministic-per-run but well-distributed perturbation, avoiding the need
/// for an external `rand` crate.
fn apply_training_jitter(history: &mut Vec<[f64; 19]>, seed: u64) {
    for (i, vec) in history.iter_mut().enumerate() {
        for (j, val) in vec.iter_mut().enumerate() {
            // FNV-1a mixing: combine seed, row index, and column index
            let mut h: u64 = 14695981039346656037_u64.wrapping_add(seed);
            h = h.wrapping_mul(1099511628211) ^ (i as u64);
            h = h.wrapping_mul(1099511628211) ^ (j as u64);
            // Map to [-0.001, +0.001] proportional to magnitude, with a small floor
            let fraction = (h % 10000) as f64 / 10_000_000.0; // [0, 0.001)
            let sign = if h & 1 == 0 { 1.0 } else { -1.0 };
            let jitter = (val.abs() * fraction + 0.00001) * sign;
            *val += jitter;
        }
    }
}

/// Pre-filters a history buffer to remove degenerate vectors that would cause
/// Isolation Forest splits to fail (all-zero, near-duplicate clusters).
fn filter_degenerate_vectors(history: &[&[f64; 19]]) -> Vec<[f64; 19]> {
    let mut filtered = Vec::with_capacity(history.len());
    for &vec in history {
        // Skip all-zero vectors (common during cold start)
        let magnitude: f64 = vec.iter().map(|v| v * v).sum();
        if magnitude < 1e-12 { continue; }
        filtered.push(*vec);
    }
    filtered
}

pub struct ScannerEngine {
    config: Arc<RwLock<MasterConfig>>,
    pub endpoint_id: Arc<String>,
    raw_rx: mpsc::Receiver<RawKernelEvent>,
    alert_tx: mpsc::Sender<SecurityAlert>,
    rules_engine: RulesEngine,
    termination_timestamps: VecDeque<u64>,
    reload_rx: broadcast::Receiver<crate::ReloadCommand>,
    container_resolver: ContainerResolver,
    pub yara_scan_tx: mpsc::Sender<u32>,

    // ML ENGINE STATE
    ueba_profiles: HashMap<String, ProcessProfile>,
    role_profiles: HashMap<String, RoleProfile>,
    tuple_freq: HashMap<String, u64>,
    rule_baseline_cache: HashMap<String, u64>,
    history: VecDeque<[f64; 19]>,
    cached_forest: Arc<RwLock<Option<Forest<f64, 19>>>>,
    is_training: Arc<RwLock<bool>>,
    fit_counter: usize,
    lineage_cache: HashMap<u32, (u32, String)>,

    // ML PERSISTENCE & ADAPTIVE THRESHOLDS
    baseline_store: Arc<BaselineStore>,
    adaptive_p95_threshold: f64,
    alert_cache: HashMap<String, Instant>,
    threshold_needs_update: Arc<AtomicBool>,
    pending_vectors: VecDeque<[f64; 19]>,
    consecutive_training_failures: Arc<std::sync::atomic::AtomicU32>,
}

impl ScannerEngine {
    pub fn generate_endpoint_id() -> String {
        use sha2::{Sha256, Digest};
        let mut id_str = std::fs::read_to_string("/sys/class/dmi/id/product_uuid").unwrap_or_default();

        if id_str.trim().is_empty() {
            id_str = std::fs::read_to_string("/etc/machine-id")
                .unwrap_or_else(|_| "FATAL_UNKNOWN_MACHINE_ID".to_string());
        }

        let mac = std::fs::read_dir("/sys/class/net").ok().and_then(|mut entries| {
            while let Some(Ok(entry)) = entries.next() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name != "lo" {
                    if let Ok(mac) = std::fs::read_to_string(entry.path().join("address")) {
                        return Some(mac.trim().to_string());
                    }
                }
            }
            None
        }).unwrap_or_else(|| "00:00:00:00:00:00".to_string());

        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}", id_str.trim(), mac.trim()).as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(
        config: Arc<RwLock<MasterConfig>>,
        raw_rx: mpsc::Receiver<RawKernelEvent>,
        alert_tx: mpsc::Sender<SecurityAlert>,
        reload_rx: broadcast::Receiver<crate::ReloadCommand>,
        baseline_store: Arc<BaselineStore>,
        yara_scan_tx: mpsc::Sender<u32>,
    ) -> Self {
        let endpoint_id = Arc::new(Self::generate_endpoint_id());
        let (sigma_path, intel_path) = {
            let lock = config.read().unwrap_or_else(|e| e.into_inner());
            (lock.engine.sigma_rules_path.clone(), lock.engine.malicious_ips_path.clone())
        };
        Self {
            config: config.clone(),
            endpoint_id,
            raw_rx,
            alert_tx,
            rules_engine: RulesEngine::new(config.clone(), &sigma_path, &intel_path),
            termination_timestamps: VecDeque::new(),
            reload_rx,
            container_resolver: ContainerResolver::new(),
            ueba_profiles: HashMap::new(),
            role_profiles: HashMap::new(),
            tuple_freq: HashMap::new(),
            rule_baseline_cache: HashMap::new(),
            history: VecDeque::with_capacity(5000),
            cached_forest: Arc::new(RwLock::new(None)),
            is_training: Arc::new(RwLock::new(false)),
            fit_counter: 0,
            threshold_needs_update: Arc::new(AtomicBool::new(false)),
            lineage_cache: HashMap::new(),
            baseline_store,
            adaptive_p95_threshold: 0.60, // Default until adaptive baseline warms up
            alert_cache: HashMap::new(),
            pending_vectors: VecDeque::with_capacity(5000),
            yara_scan_tx,
            consecutive_training_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    fn is_termination_safe(pid: u32) -> bool {
        if pid <= 1 { return false; }
        if pid < 100 { return false; }  // kernel threads
        if pid == std::process::id() { return false; }  // self
        true
    }

    fn reconstruct_lineage(&self, pid: u32) -> String {
        let mut chain = Vec::new();
        let mut current_pid = pid;

        for _ in 0..5 {
            if let Some((ppid, comm)) = self.lineage_cache.get(&current_pid) {
                chain.push(format!("{}({})", comm, current_pid));
                if *ppid <= 1 { break; }
                current_pid = *ppid;
            } else {
                break;
            }
        }
        chain.reverse();
        chain.join(" -> ")
    }

    pub fn calculate_path_depth(path: &str) -> usize {
        path.split('/').filter(|s| !s.is_empty()).count()
    }

    pub async fn run(mut self) {
        {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            if !lock.engine.enable_anti_evasion {
                info!("Anti-evasion and UEBA scanner explicitly disabled in master.toml.");
                return;
            }
        }

        info!("Starting 5D UEBA & Telemetry Routing Pipeline...");
        let mut scan_interval = interval(Duration::from_secs(60));

        // Restore persisted Welford profiles from previous session
        match self.baseline_store.load_profiles().await {
            Ok(saved) => {
                for (hash, (count, mean, m2, m_ent, m2_ent, t_slow, t_fast, e_slow, e_fast, tv_slow, ev_slow, last_ns, state_json)) in saved {

                    let ext: ProfileStateExt = serde_json::from_str(&state_json).unwrap_or_else(|_| ProfileStateExt {
                        ts: VecDeque::with_capacity(100),
                        types: VecDeque::with_capacity(10),
                        hll: vec![0; 64],
                        distinct: [false; 16],
                        last_evt: 0,
                        transitions: [[0; 16]; 16],
                        total_trans: 0,
                    });

                    self.ueba_profiles.insert(hash, ProcessProfile {
                        event_count: count,
                        last_seen_ns: last_ns,
                        last_seen_wall_sec: 0,
                        recent_timestamps: ext.ts,
                        recent_event_types: ext.types,
                        mean_delta: mean,
                        m2_delta: m2,
                        mean_entropy: 0.0,
                        max_velocity: 0.0,
                        distinct_event_types: ext.distinct,
                        historical_std_dev: if count > 1 { (m2 / (count as f64 - 1.0)).sqrt() } else { 0.0 },
                        initial_uid: 0,
                        uid_changed: false,
                        network_hll: ext.hll.try_into().unwrap_or([0; 64]),
                        max_write_depth: 0,
                        child_spawns_this_minute: 0,
                        mean_payload_entropy: m_ent,
                        m2_payload_entropy: m2_ent,
                        ewma_timing_slow: t_slow,
                        ewma_timing_fast: t_fast,
                        ewma_timing_var_slow: tv_slow,
                        ewma_entropy_slow: e_slow,
                        ewma_entropy_fast: e_fast,
                        ewma_entropy_var_slow: ev_slow,
                        last_event_type: ext.last_evt,
                        transition_counts: ext.transitions,
                        total_transitions: ext.total_trans,
                        lotl_consecutive_anomalies: 0,
                    });
                }
                info!("Restored {} UEBA profiles from persistent store.", self.ueba_profiles.len());
            }
            Err(e) => warn!("Could not restore UEBA profiles (cold start): {}", e),
        }

        if let Ok(roles) = self.baseline_store.load_role_profiles().await {
            for (binary, (count, m_time, m2_time, m_ent, m2_ent, max_vel, trans_json)) in roles {
                let transitions: [[u32; 16]; 16] = serde_json::from_str(&trans_json).unwrap_or([[0u32; 16]; 16]);

                self.role_profiles.insert(binary, RoleProfile {
                    instance_count: count,
                    mean_timing: m_time,
                    m2_timing: m2_time,
                    mean_entropy: m_ent,
                    m2_entropy: m2_ent,
                    max_observed_velocity: max_vel,
                    aggregate_transitions: transitions,
                });
            }
            info!("Successfully mapped {} Global Role Profiles into ML Engine.", self.role_profiles.len());
        }

        self.bootstrap_forest().await;

        loop {
            tokio::select! {
                Some(raw_event) = self.raw_rx.recv() => {
                    trace!("Pipeline Ingest: Received RawKernelEvent (PID: {})", raw_event.pid);
                    self.process_kernel_event(raw_event).await;
                }
                _ = scan_interval.tick() => {
                    debug!("Initiating periodic system baselining and integrity checks.");
                    self.monitor_users().await;
                    self.monitor_memory().await;
                    self.check_hidden_processes().await;
                    self.check_ld_preload().await;
                    self.prune_ueba_baselines().await;
                    self.flush_profiles_to_disk().await;
                    self.flush_pending_vectors().await;
                    debug!("Periodic system baseline complete.");
                }
                Ok(cmd) = self.reload_rx.recv() => {
                    if let crate::ReloadCommand::Rules = cmd {
                        let (s_path, i_path) = {
                            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                            (lock.engine.sigma_rules_path.clone(), lock.engine.malicious_ips_path.clone())
                        };
                        self.rules_engine.reload_sigma_rules(&s_path);
                        self.rules_engine.reload_intel(&i_path);
                    }
                }
            }
        }
    }

    async fn process_kernel_event(&mut self, mut event: RawKernelEvent) {
        event.comm = event.comm.trim_matches(char::from(0)).to_string();
        event.target = event.target.trim_matches(char::from(0)).to_string();
        event.dest_ip = event.dest_ip.trim_matches(char::from(0)).to_string();
        event.parent_comm = self.lineage_cache.get(&event.ppid)
            .map(|(_, comm)| comm.clone())
            .unwrap_or_else(|| "unknown".to_string());
        event.user_name = if event.uid == 0 { "root".to_string() } else { event.uid.to_string() };

        {
            let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());

            let is_whitelisted = config_lock.process.whitelist_processes.iter()
                .any(|w| event.comm.starts_with(w) || w.starts_with(&event.comm));

            if is_whitelisted { return; }

            if !event.dest_ip.is_empty() && config_lock.network.whitelist_connections.contains(&event.dest_ip) {
                return;
            }
        }

        self.lineage_cache.insert(event.pid, (event.ppid, event.comm.clone()));
        let lineage_path = self.reconstruct_lineage(event.pid);
        trace!(pid = event.pid, lineage = %lineage_path, "Updated lineage cache for PID");

        if self.ueba_profiles.len() >= 100_000 {
            warn!("UEBA profile capacity reached 100k. Forcing immediate memory prune.");
            self.prune_ueba_baselines().await;
        }

        if self.threshold_needs_update.load(Ordering::Acquire) {
            self.recalculate_adaptive_threshold();
            self.threshold_needs_update.store(false, Ordering::Release);
        }

        let process_hash = format!("{}|{}|{}|{}", event.cgroup_id, event.pid, event.uid, event.comm);
        trace!(process_hash = %process_hash, "Processing telemetry for Context Hash");

        // 2. SIGMA AST EVALUATION
        let mut matched_rule = self.rules_engine.evaluate(&event);

        if let Some(ref rule) = matched_rule {
            let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            let is_excepted = config_lock.exceptions.iter().any(|ex| {
                (event.comm.starts_with(&ex.comm) || ex.comm.starts_with(&event.comm))
                && rule.mitre_technique.contains(&ex.technique)
                && ex.targets.iter().any(|t| event.target.contains(t))
            });
            if is_excepted {
                matched_rule = None; // nullify rather than return,
            }                        // so UEBA/ML scoring still runs
        }

        if let Some(rule) = &matched_rule {
            let cache_key = format!("{}|{}", rule.mitre_technique, event.comm);
            let current_wall_sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

            if let Some(&last_alert) = self.rule_baseline_cache.get(&cache_key) {
                // If alerted on this exact static rule/process in the last 1 hour,
                // suppress the static SIEM alert so the feed doesn't flood.
                // The event WILL still cascade down into the UEBA Welford Math and ML Forest
                // below, allowing the system to statistically baseline the frequency/velocity.
                if current_wall_sec.saturating_sub(last_alert) < 3600 {
                    trace!("Flood Control: Suppressing duplicate static alert for {}. Delegating to UEBA.", cache_key);
                    matched_rule = None;
                } else {
                    self.rule_baseline_cache.insert(cache_key, current_wall_sec);
                }
            } else {
                self.rule_baseline_cache.insert(cache_key, current_wall_sec);
            }
        }

        if matched_rule.is_none() {
            let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            if config_lock.process.whitelist_processes.contains(&event.comm) {
                return;
            }
            if !event.dest_ip.is_empty() && config_lock.network.whitelist_connections.contains(&event.dest_ip) {
                return;
            }
        }

        // Entropy and Path Depth
        let entropy = RulesEngine::calculate_shannon_entropy(&event.payload);
        let path_depth = Self::calculate_path_depth(&event.target);

        let current_ts_ns = event.ts_ns;
        let current_wall_sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        // --- MEMORY STATE & WELFORD'S ALGORITHM ---
        let profile = self.ueba_profiles.entry(process_hash.clone()).or_insert_with(|| {
            ProcessProfile {
                event_count: 0, last_seen_ns: current_ts_ns, last_seen_wall_sec: current_wall_sec,
                recent_timestamps: VecDeque::with_capacity(100),
                recent_event_types: VecDeque::with_capacity(10),
                mean_delta: 0.0, m2_delta: 0.0, mean_entropy: 0.0, max_velocity: 0.0,
                distinct_event_types: [false; 16],
                historical_std_dev: 0.0,
                initial_uid: event.uid,
                uid_changed: false,
                network_hll: [0; 64],
                max_write_depth: 0,
                child_spawns_this_minute: 0,
                mean_payload_entropy: 0.0,
                m2_payload_entropy: 0.0,
                ewma_timing_slow: 0.0,
                ewma_timing_fast: 0.0,
                ewma_timing_var_slow: 0.0,
                ewma_entropy_slow: 0.0,
                ewma_entropy_fast: 0.0,
                ewma_entropy_var_slow: 0.0,
                last_event_type: event.event_type,
                transition_counts: [[0u32; 16]; 16],
                total_transitions: 0,
                lotl_consecutive_anomalies: 0,
            }
        });

        let delta_t_ns = current_ts_ns.saturating_sub(profile.last_seen_ns);
        let delta_sec = delta_t_ns as f64 / 1_000_000_000.0;

        profile.last_seen_ns = current_ts_ns;
        profile.last_seen_wall_sec = current_wall_sec;

        profile.event_count += 1;

        // Welford's Math for streaming variance
        let count_f = profile.event_count as f64;
        let delta_mean = delta_sec - profile.mean_delta;
        profile.mean_delta += delta_mean / count_f;
        let delta_mean2 = delta_sec - profile.mean_delta;
        profile.m2_delta += delta_mean * delta_mean2;
        profile.mean_entropy += (entropy - profile.mean_entropy) / count_f;

        // Welford's for payload entropy (parallel to timing Welford)
        let payload_ent_delta = entropy - profile.mean_payload_entropy;
        profile.mean_payload_entropy += payload_ent_delta / count_f;
        let payload_ent_delta2 = entropy - profile.mean_payload_entropy;
        profile.m2_payload_entropy += payload_ent_delta * payload_ent_delta2;

        // Maintain Sliding Windows for TTPs and Velocity
        if profile.recent_timestamps.len() >= 100 {
            profile.recent_timestamps.pop_front();
        }
        if profile.recent_event_types.len() >= 10 {
            profile.recent_event_types.pop_front();
        }
        profile.recent_timestamps.push_back(current_ts_ns);
        profile.recent_event_types.push_back(event.event_type);

        // Cap velocity to prevent Infinity poisoning the Isolation Forest
        let mut velocity = if delta_sec > 0.0 { (1.0 / delta_sec).min(100_000.0) } else { 0.0 };
        if let Some(&first) = profile.recent_timestamps.front() {
            if profile.recent_timestamps.len() > 1 {
                let time_delta_s = (current_ts_ns - first) as f64 / 1_000_000_000.0;
                if time_delta_s > 0.0 {
                    velocity = ((profile.recent_timestamps.len() as f64) / time_delta_s).min(100_000.0);
                }
            }
        }
        if velocity > profile.max_velocity {
            profile.max_velocity = velocity;
        }

        // Tuple Rarity (Parent PID -> Child Comm)
        let pc_tuple = format!("{}->{}", event.parent_comm, event.comm);
        let tuple_count = self.tuple_freq.entry(pc_tuple).or_insert(0);
        *tuple_count += 1;
        let tuple_rarity = 1.0 / (*tuple_count as f64);

        // --- Z-SCORE EVALUATION (LOTL DETECTION) ---
        let variance = if profile.event_count > 1 { (profile.m2_delta / (count_f - 1.0)).max(0.0) } else { 0.0 };
        let std_dev = variance.sqrt();
        let mut z_score = 0.0;

        // Statistically Mature Validation: Require 200 events for Welford convergence
        // (raised from 50 — bursty processes need longer to stabilize their variance)
        if profile.event_count >= 200 && std_dev > 0.0 {
            // Apply a strict 10ms variance floor to prevent micro-variance division explosions
            let safe_std_dev = std_dev.max(0.01);
            z_score = (delta_sec - profile.mean_delta).abs() / safe_std_dev;
        }

        // Velocity-Scaled Threshold: High-frequency async processes naturally jitter
        let dynamic_threshold = if velocity > 10.0 { 15.0 } else { 5.0 };

        if z_score > dynamic_threshold {
            // Temporal debouncing: require 5 consecutive anomalous intervals to suppress
            // micro-bursts from bursty processes (browsers, container runtimes, daemons)
            profile.lotl_consecutive_anomalies = profile.lotl_consecutive_anomalies.saturating_add(1);
            if profile.lotl_consecutive_anomalies >= 5 {
                debug!(process_hash = %process_hash, z_score = z_score,
                    streak = profile.lotl_consecutive_anomalies,
                    "LotL Temporal Anomaly: sustained execution baseline deviation");
            }
        } else {
            profile.lotl_consecutive_anomalies = 0;
        }

        // --- PHASE A/B: BEHAVIORAL STATE HYDRATION ---
        if event.uid != profile.initial_uid {
            profile.uid_changed = true;
        }

        if event.event_type < 16 {
            profile.distinct_event_types[event.event_type as usize] = true;
        }

        if !event.dest_ip.is_empty() {
            hll_add(&mut profile.network_hll, &event.dest_ip);
        }

        if event.event_type == 2 || event.event_type == 10 || event.event_type == 11 {
            if path_depth > profile.max_write_depth {
                profile.max_write_depth = path_depth;
            }
        }

        // Dual-Band EWMA
        let alpha_slow = 0.02;
        let alpha_fast = 0.15;

        let prev_slow_timing = profile.ewma_timing_slow;
        profile.ewma_timing_fast = alpha_fast * delta_sec + (1.0 - alpha_fast) * profile.ewma_timing_fast;
        profile.ewma_timing_slow = alpha_slow * delta_sec + (1.0 - alpha_slow) * profile.ewma_timing_slow;
        profile.ewma_timing_var_slow = (1.0 - alpha_slow) * (profile.ewma_timing_var_slow + alpha_slow * (delta_sec - prev_slow_timing).powi(2));

        let prev_slow_entropy = profile.ewma_entropy_slow;
        profile.ewma_entropy_fast = alpha_fast * entropy + (1.0 - alpha_fast) * profile.ewma_entropy_fast;
        profile.ewma_entropy_slow = alpha_slow * entropy + (1.0 - alpha_slow) * profile.ewma_entropy_slow;
        profile.ewma_entropy_var_slow = (1.0 - alpha_slow) * (profile.ewma_entropy_var_slow + alpha_slow * (entropy - prev_slow_entropy).powi(2));

        // --- Markov Sequence Modeling ---
        let from_evt = profile.last_event_type as usize;
        let to_evt = event.event_type as usize;
        let mut markov_surprise = 0.0;

        if from_evt < 16 && to_evt < 16 {
            profile.transition_counts[from_evt][to_evt] = profile.transition_counts[from_evt][to_evt].saturating_add(1);
            profile.total_transitions += 1;
            markov_surprise = transition_surprise(&profile.transition_counts, from_evt, to_evt);
        }
        profile.last_event_type = event.event_type;

        // --- Peer Intelligence (Role Profiles) ---
        // Fetch or initialize the global aggregate for this specific binary name
        let role = self.role_profiles.entry(event.comm.clone()).or_insert_with(RoleProfile::default);
        role.instance_count += 1;

        // Aggregate Welford for Role Timing
        let role_delta_diff = delta_sec - role.mean_timing;
        role.mean_timing += role_delta_diff / role.instance_count as f64;
        role.m2_timing += role_delta_diff * (delta_sec - role.mean_timing);

        // Aggregate Welford for Role Entropy
        let role_ent_diff = entropy - role.mean_entropy;
        role.mean_entropy += role_ent_diff / role.instance_count as f64;
        role.m2_entropy += role_ent_diff * (entropy - role.mean_entropy);

        if velocity > role.max_observed_velocity {
            role.max_observed_velocity = velocity;
        }

        // Calculate Process vs. Global Role Deviation
        let role_timing_dev = role_deviation_score(profile.mean_delta, role.mean_timing, role.m2_timing, role.instance_count as f64);
        let role_entropy_dev = role_deviation_score(profile.mean_payload_entropy, role.mean_entropy, role.m2_entropy, role.instance_count as f64);
        let combined_role_dev = (role_timing_dev * role_entropy_dev).sqrt();

        // --- PREPARE 19D FEATURE VECTOR ---
        let (cmd_entropy, susp_patterns, cmd_len_anomaly) = if event.event_type == 1 {
            (
                RulesEngine::calculate_shannon_entropy(event.target.as_bytes()),
                suspicious_pattern_count(&event.target) as f64,
                if event.target.len() > 500 { 1.0 } else { 0.0 }
            )
        } else {
            (0.0, 0.0, 0.0)
        };

        let std_dev_slow_timing = profile.ewma_timing_var_slow.max(0.0).sqrt().max(0.001);
        let std_dev_slow_entropy = profile.ewma_entropy_var_slow.max(0.0).sqrt().max(0.001);
        let current_variance = if profile.event_count > 1 { (profile.m2_delta / (count_f - 1.0)).max(0.0) } else { 0.0 };

        // --- EXTENDED ISOLATION FOREST (UNSUPERVISED ML) ---
        let current_feat: [f64; 19] = [
            entropy,                                                                                                    // 1. Base Payload Entropy
            tuple_rarity,                                                                                               // 2. Tuple Rarity
            path_depth as f64,                                                                                          // 3. Path Depth
            velocity,                                                                                                   // 4. Velocity
            profile.max_velocity,                                                                                       // 5. Max Velocity
            profile.distinct_event_types.iter().filter(|&&v| v).count() as f64,                                         // 6. Syscall Diversity
            if profile.historical_std_dev > 0.0 { current_variance.sqrt() / profile.historical_std_dev } else { 1.0 },  // 7. Timing Variance Ratio
            if profile.uid_changed { 1.0 } else { 0.0 },                                                                // 8. UID Stability
            hll_estimate(&profile.network_hll),                                                                         // 9. Network Fanout
            profile.max_write_depth as f64,                                                                             // 10. File Write Depth
            profile.child_spawns_this_minute as f64,                                                                    // 11. Child Spawn Rate
            (entropy - profile.mean_payload_entropy).abs(),                                                             // 12. Payload Entropy Delta
            (profile.ewma_timing_fast - profile.ewma_timing_slow).abs() / std_dev_slow_timing,                          // 13. EWMA Timing Drift
            (profile.ewma_entropy_fast - profile.ewma_entropy_slow).abs() / std_dev_slow_entropy,                       // 14. EWMA Entropy Drift
            if profile.mean_delta > 0.0 { current_variance.sqrt() / profile.mean_delta } else { 1000.0 },               // 15. Timing CV (Beaconing)
            cmd_entropy,                                                                                                // 16. Command Entropy
            susp_patterns + cmd_len_anomaly,                                                                            // 17. Obfuscation/Length Combined
            markov_surprise,                                                                                            // 18. Sequence Transition Surprise (Phase C)
            combined_role_dev                                                                                           // 19. Global Role Deviation (Phase D)
        ];

        // Establish strict vector sanitization before it hits the model
        if current_feat.iter().any(|v| v.is_nan() || v.is_infinite()) {
            error!("Invalid ML vector generated (NaN/Infinity detected). Discarding to maintain model stability.");
            return;
        }

        if self.history.len() >= 5000 {
            self.history.pop_front();
        }
        self.history.push_back(current_feat);
        self.fit_counter += 1;

        // Background Async Training Trigger
        let needs_rebuild = {
            let forest_read = self.cached_forest.read().unwrap_or_else(|e| e.into_inner());
            let failures = self.consecutive_training_failures.load(Ordering::Acquire);
            // Exponential backoff: after N failures, wait 20K * 2^N events before retrying
            let backoff_threshold = if failures > 0 { 20000_usize << failures.min(4) } else { 20000 };

            self.history.len() > 200
                && (forest_read.is_none() || self.fit_counter > backoff_threshold)
                && !*self.is_training.read().unwrap_or_else(|e| e.into_inner())
        };

        if needs_rebuild {
            let mut is_training_lock = self.is_training.write().unwrap_or_else(|e| e.into_inner());
            if !*is_training_lock {
                *is_training_lock = true;
                self.fit_counter = 0;

                // Pre-filter degenerate vectors before training
                let refs: Vec<&[f64; 19]> = self.history.iter().collect();
                let mut history_vec = filter_degenerate_vectors(&refs);

                if history_vec.len() < 200 {
                    *is_training_lock = false;
                    // Not enough clean data; skip this training cycle
                } else {
                    let forest_arc = Arc::clone(&self.cached_forest);
                    let training_flag = Arc::clone(&self.is_training);
                    let threshold_flag = Arc::clone(&self.threshold_needs_update);
                    let failure_counter = Arc::clone(&self.consecutive_training_failures);
                    let failure_counter_inner = Arc::clone(&failure_counter);

                    let timeout_sec = {
                        let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                        lock.engine.ml_forest_training_timeout_sec
                    };

                    let training_handle = tokio::task::spawn_blocking(move || {
                        let seed = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_nanos() as u64;
                        apply_training_jitter(&mut history_vec, seed);

                        let sample_size = std::cmp::min(256, history_vec.len().saturating_sub(1).max(2));

                        let options = ForestOptions {
                            n_trees: 50,
                            sample_size,
                            max_tree_depth: Some(10),
                            extension_level: 0,
                        };

                        match Forest::from_slice(&history_vec, &options) {
                            Ok(forest) => {
                                let mut w_forest = forest_arc.write().unwrap_or_else(|e| e.into_inner());
                                *w_forest = Some(forest);
                                failure_counter_inner.store(0, Ordering::Release);
                                true
                            }
                            Err(e) => {
                                error!("Forest training failed: {}", e);
                                failure_counter_inner.fetch_add(1, Ordering::AcqRel);
                                false
                            }
                        }
                    });

                    tokio::spawn(async move {
                        match tokio::time::timeout(Duration::from_secs(timeout_sec), training_handle).await {
                            Ok(Ok(true)) => {
                                *training_flag.write().unwrap_or_else(|e| e.into_inner()) = false;
                                threshold_flag.store(true, Ordering::Release);
                            }
                            Ok(Ok(false)) => {
                                *training_flag.write().unwrap_or_else(|e| e.into_inner()) = false;
                            }
                            Ok(Err(e)) => {
                                error!("Forest training task panicked: {}. Resetting training flag.", e);
                                *training_flag.write().unwrap_or_else(|e| e.into_inner()) = false;
                                failure_counter.fetch_add(1, Ordering::AcqRel);
                            }
                            Err(_) => {
                                error!("Forest training timed out after {}s. Resetting training flag.", timeout_sec);
                                *training_flag.write().unwrap_or_else(|e| e.into_inner()) = false;
                                failure_counter.fetch_add(1, Ordering::AcqRel);
                            }
                        }
                    });
                }
            }
        }

        // Score current telemetry against the model
        let mut anomaly_score = 0.0;
        if let Some(forest) = &*self.cached_forest.read().unwrap_or_else(|e| e.into_inner()) {
            anomaly_score = forest.score(&current_feat);
        }

        // --- PIPELINE ROUTING ---

        // Adaptive Percentile Thresholds
        let is_anomaly = self.evaluate_anomaly(anomaly_score, z_score);

        // Buffer vectors for periodic batch persistence (capped to prevent memory growth)
        if self.pending_vectors.len() >= 5000 {
            self.pending_vectors.pop_front();
        }
        self.pending_vectors.push_back(current_feat);

        // If the ML engine flags an anomaly, escalate it even if static rules missed it
        if is_anomaly && matched_rule.is_none() {
            matched_rule = Some(RuleMatch {
                level: if anomaly_score > 0.75 { AlertLevel::High } else { AlertLevel::Medium },
                mitre_tactic: MitreTactic::Unknown,
                mitre_technique: "Behavioral ML Anomaly".to_string(),
                message: format!("Isolation Forest Outlier (Score: {:.2}, Z-Score: {:.2})", anomaly_score, z_score),
            });
        }

        // Single-pass enrichment allocation
        if let Some(mut rule) = matched_rule {
            let should_terminate = {
                let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                config_lock.engine.enable_active_mitigation
            } && (rule.level == AlertLevel::Critical || anomaly_score > 0.90);

            let (container_id, container_name) = self.container_resolver.resolve(event.cgroup_id, event.pid).await;

            if container_name != "host" {
                rule.message = format!("{} [Container: {}]", rule.message, container_name);
            }

            let deduplication_key = format!("{}|{}", rule.mitre_technique, event.comm);

            let alert = SecurityAlert::from_rule(
                self.endpoint_id.to_string(),
                rule,
                event.pid,
                event.ppid,
                event.uid,
                event.cgroup_id,
                container_id,
                container_name,
                event.comm.clone(),
                lineage_path,
                event.parent_comm.clone(),
                event.user_name.clone(),
                Some(event.source_port),
                Some(event.target.clone()),
                Some(event.dest_ip.clone()),
                Some(event.dest_port),
                entropy,
                velocity,
                tuple_rarity,
                path_depth,
                anomaly_score
            );

            // Alert Deduplication
            if self.is_alert_suppressed(&deduplication_key) {
                trace!(
                    key = %deduplication_key,
                    "Suppressing redundant high-frequency alert."
                );
            } else if let Err(e) = self.alert_tx.try_send(alert) {
                error!(
                    key = %deduplication_key,
                    reason = %e,
                    "SIEM Gateway Disconnect: Failed to route enriched alert."
                );
            }

            // --- ACTIVE MITIGATION TRIGGER ---
            if should_terminate && Self::is_termination_safe(event.pid) {

                // Dispatch PID to YARA for deep memory C2 payload extraction
                // This respects the ArmedMode toggle internally within the YARA engine.
                if let Err(e) = self.yara_scan_tx.try_send(event.pid) {
                    tracing::error!("Failed to route anomalous PID to YARA memory scanner: {}", e);
                }

                let current_ts_sec = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Prune timestamps older than 60 seconds
                while let Some(&ts) = self.termination_timestamps.front() {
                    if current_ts_sec.saturating_sub(ts) > 60 {
                        self.termination_timestamps.pop_front();
                    } else {
                        break;
                    }
                }

                // Enforce Mitigation Storm Limit: Max 10 terminations per rolling minute
                if self.termination_timestamps.len() < 10 {
                    self.termination_timestamps.push_back(current_ts_sec);
                    warn!(pid = event.pid, "ACTIVE MITIGATION TRIGGERED: Terminating malicious PID.");
                    unsafe {
                        if libc::kill(event.pid as i32, libc::SIGTERM) != 0 {
                            error!("Failed to terminate PID {}. Error code: {}", event.pid, std::io::Error::last_os_error());
                        }
                    }
                } else {
                    error!(pid = event.pid, "Active Mitigation Throttled: Termination storm detected (>10/min). Suppressing SIGTERM to protect host stability.");
                }
            }
        }

        // EXTENDED TTP CORRELATION (State Machine)
        // Scenario A: DNS / DGA Detection
        if event.event_type == 8 && event.dest_port == 53 {
            let domains = crate::engine::dns::parse_dns_payload(&event.payload);
            for domain in domains {
                let dom_entropy = RulesEngine::calculate_shannon_entropy(domain.as_bytes());

                if dom_entropy > 4.0 {
                    tracing::warn!(process_hash = %process_hash, domain = %domain, "DGA Detection: High entropy domain resolution.");

                    let alert = SecurityAlert::from_rule(
                        self.endpoint_id.to_string(),
                        RuleMatch {
                            level: AlertLevel::High,
                            mitre_tactic: MitreTactic::CommandAndControl,
                            mitre_technique: "T1568.002 Domain Generation Algorithms".to_string(),
                            message: format!("DGA Protocol Detection: High entropy DNS query for '{}' (Entropy: {:.2})", domain, dom_entropy),
                        },
                        event.pid,
                        event.ppid,
                        event.uid,
                        event.cgroup_id,
                        String::new(), "host".to_string(),
                        event.comm.clone(),
                        event.target.clone(),
                        event.parent_comm.clone(),
                        event.user_name.clone(),
                        Some(event.source_port),
                        None,
                        Some(event.dest_ip.clone()),
                        Some(event.dest_port),
                        dom_entropy,
                        velocity,
                        tuple_rarity,
                        path_depth,
                        anomaly_score
                    );

                    if let Err(e) = self.alert_tx.try_send(alert) {
                        tracing::error!("Pipeline Failure: Failed to route DGA alert: {}", e);
                    }
                }
            }
        }

        // Re-acquire the profile reference for TTP state machine checks
        let profile = match self.ueba_profiles.get_mut(&process_hash) {
            Some(p) => p,
            None => return,
        };

        // Scenario B: Fileless memory allocation (5) followed by an outbound network connection (3 or 8)
        if event.event_type == 8 /* EVENT_UDP_SEND */ || event.event_type == 3 /* EVENT_CONNECT */ {

            if profile.recent_event_types.contains(&5 /* EVENT_MEMFD */) {
                tracing::warn!(process_hash = %process_hash, "Complex TTP Detected: Process executed fileless memory allocation followed by network comms.");

                let ttp_alert = SecurityAlert::from_rule(
                    self.endpoint_id.to_string(),
                    RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1573 Encrypted Channel (Correlated)".to_string(),
                        message: format!("Correlated TTP: Fileless code execution (memfd) followed immediately by network out in {}", process_hash),
                    },
                    event.pid,
                    event.ppid,
                    event.uid,
                    event.cgroup_id,
                    String::new(),
                    "host".to_string(),
                    event.comm.clone(),
                    event.target.clone(),
                    event.parent_comm.clone(),
                    event.user_name.clone(),
                    Some(event.source_port),
                    None,
                    Some(event.dest_ip.clone()),
                    Some(event.dest_port),
                    entropy,
                    velocity,
                    0.0,
                    path_depth,
                    0.0
                );

                if let Err(e) = self.alert_tx.try_send(ttp_alert) {
                    tracing::error!("Pipeline Failure: Failed to route complex TTP alert: {}", e);
                }

                // Clear the state buffer to prevent duplicate alerts for the same sequence
                profile.recent_event_types.clear();
            }
        }
    }

    async fn prune_ueba_baselines(&mut self) {
        let current_wall_sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let initial_count = self.ueba_profiles.len();

        trace!("Executing aggressive UEBA memory pruning. Target TTL: 1 hour.");
        // Evict profiles inactive for 1 hour (3.6 trillion nanoseconds)
        self.ueba_profiles.retain(|_, profile| current_wall_sec.saturating_sub(profile.last_seen_wall_sec) < 3600);

        // Prune the static flood control cache (1-hour TTL)
        self.rule_baseline_cache.retain(|_, &mut last_alert| current_wall_sec.saturating_sub(last_alert) < 3600);

        if self.tuple_freq.len() > 50_000 {
            warn!("tuple_freq capacity reached 50k. Pruning one-off tuples...");
            self.tuple_freq.retain(|_, &mut count| count > 2);

            // Fallback second-tier eviction if still saturated
            if self.tuple_freq.len() > 50_000 {
                self.tuple_freq.retain(|_, &mut count| count > 10);
            }
        }

        // Prune lineage cache: If a PID has no active UEBA profile,
        self.lineage_cache.retain(|pid, _| {
            self.ueba_profiles.keys().any(|k| k.starts_with(&format!("{}|", pid)))
        });

        let dedup_window = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            StdDuration::from_secs(lock.engine.ml_deduplication_window_sec)
        };
        let now = Instant::now();
        self.alert_cache.retain(|_, last| now.duration_since(*last) < dedup_window);

        let pruned = initial_count - self.ueba_profiles.len();
        if pruned > 0 {
            info!("Garbage Collection: Evicted {} stale process models from UEBA memory. Active Models: {}", pruned, self.ueba_profiles.len());
        }
    }

    async fn monitor_users(&self) {
        trace!("Running user integrity check (/etc/passwd)");
        if let Ok(passwd) = tokio::fs::read_to_string("/etc/passwd").await {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 2 && parts[0] != "root" && parts[2].parse::<u32>().unwrap_or(9999) == 0 {
                    warn!(uid = %parts[0], "Rogue root UID detected");

                    let alert = SecurityAlert::from_rule(
                        self.endpoint_id.to_string(),
                        RuleMatch {
                            level: AlertLevel::Critical,
                            mitre_tactic: MitreTactic::PrivilegeEscalation,
                            mitre_technique: "T1078 Valid Accounts".to_string(),
                            message: format!("Rogue root UID user detected: {}", parts[0]),
                        },
                        0, 0, 0,
                        0, String::new(), "host".to_string(),
                        "SYSTEM".to_string(), "".to_string(),
                        "unknown".to_string(), "system".to_string(), None,
                        None, None, None,
                        0.0, 0.0, 0.0, 0, 0.0
                    );

                    if let Err(e) = self.alert_tx.try_send(alert) {
                        error!("Pipeline Failure: Failed to route rogue user alert: {}", e);
                    }
                }
            }
        }
    }

    async fn monitor_memory(&self) {
        if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
            if let Some(available) = meminfo.lines().find(|l| l.starts_with("MemAvailable"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok())) {
                if available < 1_000_000 { // Less than ~1GB available
                    error!("Critical Memory Starvation: Host OS has less than 1GB RAM remaining.");
                }
            }
        }
    }

    async fn check_hidden_processes(&self) {
        trace!("Running kernel vs user-space PID integrity check");

        // User-Space View: Async directory iteration
        let mut proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(dir) => dir,
            Err(e) => {
                error!("Rootkit Check: Failed to read /proc: {}", e);
                return;
            }
        };

        let mut proc_count = 0;
        let mut anomaly_count = 0;

        while let Ok(Some(entry)) = proc_dir.next_entry().await {
            if entry.file_name().to_string_lossy().parse::<u32>().is_ok() {
                proc_count += 1;

                let status_path = entry.path().join("status");
                // If a PID directory exists but 'status' cannot be read,
                // a kernel-level rootkit might be unlinking it mid-flight.
                if !status_path.exists() {
                    anomaly_count += 1;
                }
            }
        }

        if anomaly_count > 5 {
            // Explicitly label synthetic alerts as "SYSTEM" instead of leaving comm blank
            let alert = SecurityAlert::from_rule(
                self.endpoint_id.to_string(),
                RuleMatch {
                    level: AlertLevel::High,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1014 Rootkit".to_string(),
                    message: format!("Rootkit Anomaly: {} /proc PIDs lack accessible status files.", anomaly_count),
                },
                0, 0, 0,
                0, String::new(), "host".to_string(),
                "SYSTEM".to_string(), "".to_string(),
                "unknown".to_string(), "system".to_string(), None,
                None, None, None,
                0.0, 0.0, 0.0, 0, 0.0
            );
            if let Err(e) = self.alert_tx.try_send(alert) {
                error!("Pipeline Failure: Failed to route rootkit anomaly alert: {}", e);
            }
        }

        let current_wall_sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        let active_kernel_count = self.ueba_profiles.values()
            .filter(|p| current_wall_sec.saturating_sub(p.last_seen_wall_sec) <= 2 && p.event_count > 5)
            .count();

        if active_kernel_count > proc_count + 40 {
            warn!(active_kernel_count = active_kernel_count, proc_count = proc_count, "Rootkit Anomaly: Kernel (eBPF) vs User-space (/proc) mismatch");

            let alert = SecurityAlert::from_rule(
                self.endpoint_id.to_string(),
                RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1014 Rootkit".to_string(),
                    message: format!("Kernel/User-space PID mismatch. eBPF active: {}, /proc: {}", active_kernel_count, proc_count),
                },
                0, 0, 0,
                0, String::new(), "host".to_string(),
                "SYSTEM".to_string(), "".to_string(),
                "unknown".to_string(), "system".to_string(), None,
                None, None, None,
                0.0, 0.0, 0.0, 0, 0.0
            );

            if let Err(e) = self.alert_tx.try_send(alert) {
                error!("Pipeline Failure: Failed to route rootkit alert: {}", e);
            }
        }
    }

    async fn check_ld_preload(&self) {
        trace!("Checking /etc/ld.so.preload for dynamic linker hijacking");
        if let Ok(contents) = tokio::fs::read_to_string("/etc/ld.so.preload").await {
            if !contents.trim().is_empty() {
                warn!("LD_PRELOAD tampering detected.");

                let alert = SecurityAlert::from_rule(
                    self.endpoint_id.to_string(),
                    RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::Persistence,
                        mitre_technique: "T1574.006 Dynamic Linker Hijacking".to_string(),
                        message: format!("Suspicious LD_PRELOAD injection: {}", contents.trim()),
                    },
                    0, 0, 0,
                    0, String::new(), "host".to_string(),
                    "SYSTEM".to_string(), "".to_string(),
                    "unknown".to_string(), "system".to_string(), None,
                    None, None, None,
                    0.0, 0.0, 0.0, 0, 0.0
                );

                if let Err(e) = self.alert_tx.try_send(alert) {
                    error!("Pipeline Failure: Failed to route LD_PRELOAD alert: {}", e);
                }
            }
        }
    }

    // Isolation Forest Warm-Starts
    pub async fn bootstrap_forest(&mut self) {
        trace!("Warming up Isolation Forest from persistent baselines...");

        match self.baseline_store.get_recent_vectors(5000).await {
            Ok(vectors) => {
                if vectors.is_empty() { return; }

                for vec in &vectors {
                    if vec.iter().any(|v| v.is_nan() || v.is_infinite()) { continue; }

                    if self.history.len() >= 5000 { self.history.pop_front(); }
                    self.history.push_back(*vec);
                }

                if self.history.len() >= 200 {
                    // Pre-filter degenerate vectors
                    let refs: Vec<&[f64; 19]> = self.history.iter().collect();
                    let mut history_copy = filter_degenerate_vectors(&refs);

                    if history_copy.len() < 200 {
                        info!("Insufficient non-degenerate vectors for forest warm-start ({}/200).", history_copy.len());
                        return;
                    }

                    let forest_arc = Arc::clone(&self.cached_forest);
                    let failure_counter = Arc::clone(&self.consecutive_training_failures);

                    let timeout_sec = {
                        let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
                        lock.engine.ml_forest_training_timeout_sec
                    };

                    let training_handle = tokio::task::spawn_blocking(move || {
                        // Hash-based jitter seeded with current time
                        let seed = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_nanos() as u64;
                        apply_training_jitter(&mut history_copy, seed);

                        // Dynamic sample sizing: never exceed available data minus 1
                        let sample_size = std::cmp::min(256, history_copy.len().saturating_sub(1).max(2));

                        let options = ForestOptions {
                            n_trees: 50,
                            sample_size,
                            max_tree_depth: Some(10),
                            extension_level: 0,
                        };

                        match Forest::from_slice(&history_copy, &options) {
                            Ok(forest) => {
                                let mut w_forest = forest_arc.write().unwrap_or_else(|e| e.into_inner());
                                *w_forest = Some(forest);
                                failure_counter.store(0, Ordering::Release);
                                true
                            }
                            Err(e) => {
                                error!("Forest warm-start training failed: {}", e);
                                failure_counter.fetch_add(1, Ordering::AcqRel);
                                false
                            }
                        }
                    });

                    match tokio::time::timeout(Duration::from_secs(timeout_sec), training_handle).await {
                        Ok(Ok(true)) => {
                            info!("Isolation Forest warm-start complete.");
                            self.recalculate_adaptive_threshold();
                        }
                        Ok(Ok(false)) => { /* failure already logged and counted */ }
                        Ok(Err(e)) => {
                            error!("Forest warm-start task panicked: {}", e);
                            self.consecutive_training_failures.fetch_add(1, Ordering::AcqRel);
                        }
                        Err(_) => {
                            error!("Forest warm-start timed out after {}s.", timeout_sec);
                            self.consecutive_training_failures.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }
            }
            Err(e) => error!("Failed to retrieve persistent ML baselines: {}", e),
        }
    }

    async fn flush_profiles_to_disk(&self) {
        let process_snapshot: HashMap<String, (u64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, u64, String)> = self.ueba_profiles.iter()
            .map(|(k, p)| {
                let ext = ProfileStateExt {
                    ts: p.recent_timestamps.clone(),
                    types: p.recent_event_types.clone(),
                    hll: p.network_hll.to_vec(),
                    distinct: p.distinct_event_types,
                    last_evt: p.last_event_type,
                    transitions: p.transition_counts,
                    total_trans: p.total_transitions,
                };
                let state_json = serde_json::to_string(&ext).unwrap_or_else(|_| "{}".to_string());

                (k.clone(), (
                    p.event_count, p.mean_delta, p.m2_delta,
                    p.mean_payload_entropy, p.m2_payload_entropy,
                    p.ewma_timing_slow, p.ewma_timing_fast,
                    p.ewma_entropy_slow, p.ewma_entropy_fast,
                    p.ewma_timing_var_slow, p.ewma_entropy_var_slow,
                    p.last_seen_ns, state_json
                ))
            })
            .collect();
        self.baseline_store.flush_profiles(&self.endpoint_id, &process_snapshot).await;

        let role_snapshot: HashMap<String, (u64, f64, f64, f64, f64, f64, String)> = self.role_profiles.iter()
            .map(|(k, p)| {
                let trans_json = serde_json::to_string(&p.aggregate_transitions).unwrap_or_else(|_| "[[]]".to_string());
                (k.clone(), (
                    p.instance_count, p.mean_timing, p.m2_timing,
                    p.mean_entropy, p.m2_entropy, p.max_observed_velocity, trans_json
                ))
            })
            .collect();
        self.baseline_store.flush_role_profiles(&role_snapshot).await;
    }

    async fn flush_pending_vectors(&mut self) {
        if self.pending_vectors.is_empty() { return; }
        let batch: Vec<[f64; 19]> = self.pending_vectors.iter().copied().collect();
        self.baseline_store.save_vectors_batch(&batch).await;
        self.pending_vectors.clear();
    }

    /// Recalculates the adaptive anomaly threshold from the current forest
    /// by scoring the history buffer and taking the 95th percentile.
    fn recalculate_adaptive_threshold(&mut self) {

        let enabled = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            lock.engine.ml_adaptive_thresholds
        };
        if !enabled { return; }

        let forest_guard = self.cached_forest.read().unwrap_or_else(|e| e.into_inner());
        let forest = match forest_guard.as_ref() {
            Some(f) => f,
            None => return,
        };

        if self.history.len() < 200 { return; }

        let mut scores: Vec<f64> = self.history.iter()
            .map(|v| forest.score(v))
            .collect();
        scores.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p95_idx = (scores.len() as f64 * 0.95) as usize;
        let new_threshold = scores.get(p95_idx).copied().unwrap_or(0.60);

        // Clamp: never let the threshold drift below the safety floor or above diminishing returns
        self.adaptive_p95_threshold = new_threshold.clamp(0.45, 0.85);

        debug!(
            "Adaptive P95 threshold recalculated: {:.4} (from {} scored vectors)",
            self.adaptive_p95_threshold, scores.len()
        );
    }

    // Adaptive Percentile Thresholds
    fn evaluate_anomaly(&self, current_score: f64, z_score: f64) -> bool {
        // Enforce a hard floor guard so attackers cannot poison the baseline
        // to artificially raise the P95 ceiling.
        let trigger_threshold = self.adaptive_p95_threshold.max(0.45);
        (current_score > trigger_threshold && z_score > 1.5) || current_score > 0.85
    }

    // Alert Deduplication
    fn is_alert_suppressed(&mut self, deduplication_key: &str) -> bool {
        let window = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            StdDuration::from_secs(lock.engine.ml_deduplication_window_sec)
        };
        let now = Instant::now();
        if let Some(last_alert_time) = self.alert_cache.get(deduplication_key) {
            if now.duration_since(*last_alert_time) < window {
                return true;
            }
        }
        self.alert_cache.insert(deduplication_key.to_string(), now);
        false
    }
}