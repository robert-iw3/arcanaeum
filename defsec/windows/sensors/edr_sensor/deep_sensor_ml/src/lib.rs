/*=============================================================================================
 * SYSTEM:          Deep Visibility Sensor v2.1
 * COMPONENT:       lib.rs (Native FFI Behavioral ML Engine)
 * AUTHOR:          Robert Weber
 *
 * DESCRIPTION:
 * Compiled as a C-compatible Dynamic Link Library (cdylib). This allows the C# ETW
 * sensor to bypass standard IO pipes entirely and directly map the Rust behavioral
 * math engine into its memory space via [DllImport].
 *=============================================================================================
 * UEBA ENGINE DESIGN & RATIONALE
 *
 * Core Philosophy:
 * A hybrid, multi-stage machine learning pipeline designed for high-dimensional,
 * unlabeled OS telemetry. It fuses real-time statistical heuristics with unsupervised
 * anomaly detection (Isolation Forests) to minimize false-positive fatigue while
 * maintaining high recall for novel, and Living-off-the-Land (LotL) behaviors.
 *
 * Pipeline & Algorithmic Design:
 *
 * 1. Multi-Dimensional Feature Engineering (N=5)
 * - Raw and aggregated OS events are vectorized into a continuous 5D feature space:
 * [X1: Shannon Entropy, X2: Tuple Rarity, X3: Path Depth, X4: Execution Velocity, X5: Max Velocity].
 * - This captures string obfuscation, structural lineage, temporal anomalies, and burst behavior
 * simultaneously without relying on static signatures.
 * - Supports both single events and micro-batched aggregated events from the C# UebaAggregator
 *   (including event count, rate per second, average entropy, max velocity, and unique thread count).
 *
 * 2. The "Fast-Path": Heuristic & Statistical Bypasses
 * - Extreme Outliers: Instantly flags mathematically impossible human behaviors
 * (e.g., delta_sec < 1.0s) or severe obfuscation (Entropy > 5.5) before model evaluation.
 * - Rule Degradation Gate: Identifies decaying signal-to-noise ratios. If a rule fires
 * across 5+ unique processes, it is globally suppressed (Score -2.0) to prevent alerts storms.
 * - High-Volume Burst Detection: Special handling for aggregated events (≥10 events in 5s window)
 *   with elevated suspicion scoring when combined with high entropy, velocity, or thread diversity.
 *
 * 3. Temporal Baselining & Z-Score Evaluation (LotL Detection)
 * - Utilizes Welford’s Online Algorithm to maintain a numerically stable, O(1) memory
 * calculation of streaming mean and variance for specific execution contexts.
 * - Offensive Application: Calculates the Z-Score of incoming execution deltas.
 * Events deviating > 4.0 standard deviations from their historical baseline are
 * flagged as stealthy LotL scheduling anomalies.
 *
 * 4. Unsupervised Anomaly Detection (Extended Isolation Forest)
 * - Evaluates the 5D feature vector using an Isolation Forest (extension_level=2).
 *   Chosen for its robust performance on sparse, noisy OS telemetry where "normal" is highly variable.
 * - Randomly partitions the data space; anomalies are isolated in fewer splits (shorter
 * path lengths), yielding a normalized anomaly score (0.0 to 1.0).
 * - Operates on a sliding window of 5,000 events with asynchronous, non-blocking tree rebuilds.
 * - Gentle scoring boost applied to aggregated events to improve detection of sudden bursts.
 *
 * 5. Model Lifecycle & Concept Drift Management
 * - In-Memory Time-Decay: A garbage collection loop runs periodically, applying a halving
 * factor to tuple frequencies. This organically phases out "dead" baselines, ensuring
 * the model continuously adapts to concept drift (e.g., new administrative habits).
 * - Persistent State Enrichments: Survives reboots via an optimized SQLite WAL database,
 * which tracks longitudinal features including User Context and Mean Entropy.
 *
 * Architecture Highlights:
 * - Zero-allocation Inter-Process Communication (IPC) via C# FFI -> Rust.
 * - Centralized Hyperparameter Tuning (TuningProfile) for instant sensitivity adjustments.
 * - Strict threshold-gating ensures only high-confidence outliers reach the SIEM.
 * - Native support for aggregated telemetry to handle high-volume ETW environments efficiently.
=============================================================================================*/

mod native_defense;

use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use md5::{Md5, Digest};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use extended_isolation_forest::{Forest, ForestOptions};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, Arc, RwLock};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::fs::OpenOptions;
use std::io::Write;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use serde_json::Value;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

pub type NativeLogCallback = extern "C" fn(*const std::os::raw::c_char);
pub static LOG_CALLBACK: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Deserialize, Debug, Clone)]
struct IncomingEvent {
    #[serde(alias = "Type", default)]
    event_type: String,
    #[serde(alias = "Category", default)]
    category: String,
    #[serde(alias = "Process", default)]
    process: String,
    #[serde(alias = "Parent", default)]
    parent: String,
    #[serde(alias = "Cmd", default)]
    cmd: String,
    #[serde(alias = "Path", default)]
    path: String,
    #[serde(alias = "Destination", default)]
    destination: String,
    #[serde(alias = "Port", default)]
    port: i32,
    #[serde(alias = "PID", default)]
    pid: i32,
    #[serde(alias = "TID", default)]
    tid: i32,
    #[serde(alias = "MatchedIndicator", default)]
    matched_indicator: String,
    #[serde(alias = "SignatureName", default)]
    signature_name: String,
    #[serde(alias = "Tactic", default)]
    tactic: String,
    #[serde(alias = "Technique", default)]
    technique: String,
    #[serde(alias = "Procedure", default)]
    procedure: String,
    #[serde(alias = "Severity", default)]
    severity: String,
    #[serde(alias = "EventUser", default)]
    event_user: String,
    #[serde(alias = "Details", default)]
    details: String,
    #[serde(alias = "ParentPID", default)]
    parent_pid: i32,
    #[serde(alias = "ATTCKMappings", default)]
    tags: String,
    #[serde(alias = "ComputerName", default)]
    computer_name: String,
    #[serde(alias = "IP", default)]
    ip: String,
    #[serde(alias = "OS", default)]
    os: String,
    #[serde(alias = "SensorUser", default)]
    sensor_user: String,
    #[serde(default)]
    count: i32,
    #[serde(default)]
    rate_per_sec: f64,
    #[serde(default)]
    avg_entropy: f64,
    #[serde(default)]
    max_velocity: f64,
    #[serde(default)]
    unique_tids: i32,
}

#[derive(Serialize, Debug, Clone)]
pub struct Alert {
    pub process: String,
    pub parent: String,
    pub cmd: String,
    pub destination: String,
    pub port: i32,
    pub pid: i32,
    pub tid: i32,
    pub score: f64,
    pub confidence: f64,
    pub severity: String,
    pub reason: String,
    pub matched_indicator: String,
    pub signature_name: String,
    pub tactic: String,
    pub technique: String,
    pub procedure: String,
    pub timestamp: String,
    pub host: String,
    pub ip: String,
    pub os: String,
    pub category: String,
    pub event_type: String,
    pub parent_pid: i32,
    pub event_user: String,
    pub sensor_user: String,
    pub path: String,
    pub details: String,
    pub tags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_alert_note: Option<String>,
}

impl Alert {
    fn new(evt: &IncomingEvent, score: f64, confidence: f64, severity: &str, reason: String) -> Self {
        let final_severity = if !evt.severity.is_empty() && severity != "CRITICAL" {
            evt.severity.clone()
        } else {
            severity.to_string()
        };

        let hostname = if !evt.computer_name.is_empty() { evt.computer_name.clone() } else { std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UnknownHost".to_string()) };
        let current_time = chrono::Utc::now().to_rfc3339();

        Alert {
            timestamp: current_time,
            host: hostname,
            ip: evt.ip.clone(),
            os: evt.os.clone(),
            category: evt.category.clone(),
            event_type: evt.event_type.clone(),
            parent_pid: evt.parent_pid,
            event_user: evt.event_user.clone(),
            sensor_user: evt.sensor_user.clone(),
            path: evt.path.clone(),
            details: evt.details.clone(),
            tags: evt.tags.clone(),
            process: evt.process.clone(),
            parent: evt.parent.clone(),
            cmd: evt.cmd.clone(),
            destination: evt.destination.clone(),
            port: evt.port,
            pid: evt.pid,
            tid: evt.tid,
            score,
            confidence,
            severity: final_severity,
            reason,
            matched_indicator: evt.matched_indicator.clone(),
            signature_name: evt.signature_name.clone(),
            tactic: evt.tactic.clone(),
            technique: evt.technique.clone(),
            procedure: evt.procedure.clone(),
            first_alert_note: None, // default
        }
    }
}

#[derive(Serialize, Debug)]
struct OutgoingResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<Vec<Alert>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_error: Option<String>,
}

struct UebaBaseline {
    count: i32,
    last_seen: f64,
    mean_delta: f64,
    m2_delta: f64,
    mean_entropy: f64,
}

struct IoTracker {
    count: i32,
    start_time: f64,
    entropy_sum: f64,
}

// ============================================================================
// BEHAVIORAL ENGINE
// ============================================================================

#[derive(Clone)]
pub struct TuningProfile {
    pub velocity_sec: f64,        // Threshold for machine-speed execution
    pub entropy_critical: f64,    // Threshold for severe obfuscation
    pub lotl_z_score: f64,        // Standard deviations required to flag LotL
    pub iso_forest_anomaly: f64,  // Isolation forest outlier boundary (0.0 to 1.0)
    pub min_baseline_events: i32, // Events required before enforcing Z-Scores
}

impl TuningProfile {
    // Default "Balanced" profile for standard workstations/servers
    pub fn default_balanced() -> Self {
        TuningProfile {
            velocity_sec: 1.0,         // < 1 second triggers velocity alert
            entropy_critical: 5.5,     // > 5.5 Shannon entropy
            lotl_z_score: 4.0,         // > 4 standard deviations from normal
            iso_forest_anomaly: 0.60,  // Standard IF outlier threshold
            min_baseline_events: 5,    // Need 5 runs to establish a valid baseline
        }
    }
}

pub struct BehavioralEngine {
    trusted_binaries: HashSet<String>,
    tuple_freq: HashMap<String, i32>,
    pid_io_tracker: HashMap<i32, IoTracker>,
    ueba_baseline: HashMap<String, UebaBaseline>,
    rule_process_map: HashMap<String, HashSet<String>>,
    conn: Connection,
    last_process_execution: HashMap<String, f64>,
    alert_cooldown: HashMap<String, f64>,
    #[allow(dead_code)]
    last_prune_time: f64,
    pub tuning: TuningProfile,
    history: VecDeque<[f64; 5]>,
    fit_counter: usize,
    cached_forest: Arc<RwLock<Option<Forest<f64, 5>>>>,
    is_training: Arc<RwLock<bool>>,
    suppression_count_min: i32,
    decay_days: f64,
    regex_guid: Regex,
    regex_hex: Regex,
    regex_num: Regex,
    regex_temp: Regex,
    regex_pipe: Regex,
    regex_hash: Regex,
    pub tx: mpsc::Sender<Value>,
    pub rt: Runtime,
}

fn emit_log(msg: &str) {
    use std::sync::atomic::Ordering;
    let cb_ptr = LOG_CALLBACK.load(Ordering::SeqCst);
    if cb_ptr.is_null() { return; }
    let cb: NativeLogCallback = unsafe { std::mem::transmute(cb_ptr) };
    if let Ok(c_str) = std::ffi::CString::new(msg) {
        cb(c_str.as_ptr());
    }
}

impl BehavioralEngine {
    fn new() -> Self {
        let secure_dir = r"C:\ProgramData\DeepSensor\Data";
        std::fs::create_dir_all(secure_dir).unwrap_or_default();
        let db_path = format!(r"{}\DeepSensor_UEBA.db", secure_dir);

        let conn = match Connection::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                emit_log(&format!(
                    "[ML ENGINE] WARNING: SQLite on-disk open failed ({}); falling back to :memory:. UEBA baselines will NOT persist across restarts.",
                    e
                ));
                Connection::open_in_memory().expect("in-memory SQLite open failed -- cannot continue")
            }
        };

        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -16000;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 1000;
        ").expect("Failed to optimize SQLite DB pragmas");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ueba_temporal_baselines (
                context_hash TEXT PRIMARY KEY,
                user_context TEXT,
                parent_process TEXT,
                process TEXT,
                rule TEXT,
                target_struct TEXT,
                event_count INTEGER DEFAULT 1,
                last_seen REAL,
                mean_delta REAL DEFAULT 0.0,
                m2_delta REAL DEFAULT 0.0,
                mean_entropy REAL DEFAULT 0.0
            )",
            [],
        ).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS DeepLedger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                timestamp TEXT,
                computer_name TEXT,
                host_ip TEXT,
                sensor_user TEXT,
                event_type TEXT,
                process TEXT,
                command_line TEXT,
                alert_reason TEXT,
                confidence REAL,
                action TEXT,
                payload TEXT
            )",
            [],
        ).unwrap();

        let _ = conn.execute_batch("
            PRAGMA wal_checkpoint(FULL);
            PRAGMA optimize;
            VACUUM;
        ");

        let (tx, rx) = mpsc::channel(15000);
        let rt = Runtime::new().unwrap();
        let config_path = r"C:\ProgramData\DeepSensor\DeepSensor_Config.ini".to_string();

        rt.spawn(async move {
            transmission::start_transmission_worker(config_path, rx, |msg| {
                let log_path = r"C:\ProgramData\DeepSensor\Logs\DeepSensor_Diagnostic.log";
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                    let _ = writeln!(file, "[{}] [TRANSMISSION] {}", ts, msg);
                }
            }).await;
        });

        let mut engine = BehavioralEngine {
            trusted_binaries: HashSet::new(),
            tuple_freq: HashMap::new(),
            pid_io_tracker: HashMap::new(),
            ueba_baseline: HashMap::new(),
            rule_process_map: HashMap::new(),
            conn,
            last_process_execution: HashMap::new(),
            alert_cooldown: HashMap::new(),
            last_prune_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            tuning: TuningProfile::default_balanced(),
            history: VecDeque::with_capacity(5000),
            fit_counter: 0,
            cached_forest: Arc::new(RwLock::new(None)),
            is_training: Arc::new(RwLock::new(false)),
            suppression_count_min: 8,
            decay_days: 14.0,
            regex_guid: Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            regex_hex: Regex::new(r"(?i)\b0x[0-9a-f]+\b").unwrap(),
            regex_num: Regex::new(r"\b\d{6,}\b").unwrap(),
            regex_temp: Regex::new(r"(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\[^\\]+").unwrap(),
            regex_pipe: Regex::new(r"(?i)\\\\.\\pipe\\[\w.-]+").unwrap(),
            regex_hash: Regex::new(r"(?i)\b[a-f0-9]{16,64}\b").unwrap(),
            tx,
            rt,
        };

        engine.load_baselines();

        // Add known benign noise directly to trust
        let default_trust = [
            "svchost.exe", "wmiprvse.exe", "taskhostw.exe", "dllhost.exe", "msedge.exe", "chrome.exe",
            "explorer.exe", "searchindexer.exe", "searchprotocolhost.exe", "taskmgr.exe", "system.exe",
            "microsoftsecurityapp.exe", "screenclippinghost.exe", "wudfhost.exe", "adobecollabsync.exe"
        ];
        for proc in default_trust.iter() {
            engine.trusted_binaries.insert(proc.to_string());
        }

        engine
    }

    fn load_baselines(&mut self) {
        // Flush RAM before repopulating to prevent dead contexts from leaking memory
        self.ueba_baseline.clear();
        self.rule_process_map.clear();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let mut stmt = self.conn.prepare("SELECT context_hash, process, rule, event_count, last_seen, mean_delta, m2_delta, mean_entropy FROM ueba_temporal_baselines").unwrap();

        let baselines: Vec<_> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?, row.get::<_, f64>(4)?, row.get::<_, f64>(5)?, row.get::<_, f64>(6)?, row.get::<_, f64>(7)?))
        }).unwrap().filter_map(Result::ok).collect();

        for (ctx_hash, proc, rule, mut count, last_seen, mean_delta, m2_delta, mean_entropy) in baselines {
            let days_unseen = (now - last_seen) / 86400.0;
            if days_unseen > self.decay_days {
                let decay_factor = (days_unseen / self.decay_days) as i32;
                count = std::cmp::max(0, count - (4 * decay_factor));
            }

            if count > 0 {
                self.ueba_baseline.insert(ctx_hash, UebaBaseline { count, last_seen, mean_delta, m2_delta, mean_entropy });
                self.rule_process_map.entry(rule).or_insert_with(HashSet::new).insert(proc);
            } else {
                self.conn.execute("DELETE FROM ueba_temporal_baselines WHERE context_hash = ?", params![ctx_hash]).unwrap();
            }
        }
    }

    fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = HashMap::new();
        for c in data.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let len = data.len() as f64;
        counts.values().fold(0.0, |acc, &count| {
            let p = count as f64 / len;
            acc - (p * p.log2())
        })
    }

    fn log_ueba_audit(action: &str, proc: &str, rule: &str, count: i32, std_dev: f64) {
        let log_path = r"C:\ProgramData\DeepSensor\Logs\DeepSensor_UEBA_Diagnostic.log";
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let entry = format!("[{}] [{:<12}] PROC: {:<20} | RULE: {} | CNT: {} | STDEV: {:.2}s",
                            ts, action, proc, rule, count, std_dev);

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let _ = writeln!(file, "{}", entry);
        }
    }

    fn generate_structural_hash(&self, parent: &str, process: &str, target_data: &str, rule: &str) -> (String, String) {
        let mut clean = self.regex_guid.replace_all(target_data, "<GUID>").to_string();
        clean = self.regex_hex.replace_all(&clean, "<HEX>").to_string();
        clean = self.regex_num.replace_all(&clean, "<NUM>").to_string();
        clean = self.regex_temp.replace_all(&clean, "<TEMP>").to_string();
        clean = self.regex_pipe.replace_all(&clean, "<PIPE>").to_string();
        clean = self.regex_hash.replace_all(&clean, "<HASH>").to_string();

        let raw_context = format!("{}|{}|{}|{}", parent, process, clean, rule).to_lowercase();
        let hash = hex::encode(Md5::digest(raw_context.as_bytes()));
        (hash, clean)
    }

    fn evaluate_single(&mut self, evt: IncomingEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let cmd_lower = evt.cmd.to_lowercase();
        let proc_lower = evt.process.to_lowercase();
        let mut already_alerted = false;

        // === DAILY GARBAGE COLLECTION & CONCEPT DRIFT ===
        if now - self.last_prune_time > 86400.0 {
            self.last_prune_time = now;

            self.alert_cooldown.retain(|_, &mut last_alert| now - last_alert < 86400.0);
            self.last_process_execution.retain(|_, &mut last_exec| now - last_exec < 86400.0);
            self.pid_io_tracker.retain(|_, tracker| now - tracker.start_time < 3600.0);

            for count in self.tuple_freq.values_mut() {
                *count /= 2;
            }

            self.tuple_freq.retain(|_, &mut v| v > 0);
            self.load_baselines();
        }

        // === HIGH-FIDELITY RULES (TTP + Sigma) - FIRST ALERT GATE ===
        let is_high_fidelity = evt.category == "TTP_Match" || evt.event_type == "TTP_Match" ||
                               evt.category == "Sigma_Match" || evt.event_type == "Sigma_Match" ||
                               evt.category == "AdvancedDetection" || evt.event_type == "AdvancedDetection" ||
                               evt.category.starts_with("T1") || evt.event_type.starts_with("T1");

        if is_high_fidelity {
            let is_ttp = evt.category == "TTP_Match" || evt.event_type == "TTP_Match" ||
                         evt.category == "AdvancedDetection" || evt.event_type == "AdvancedDetection" ||
                         evt.category.starts_with("T1") || evt.event_type.starts_with("T1");

            let is_sigma = evt.category == "Sigma_Match" || evt.event_type == "Sigma_Match" ||
                           evt.category == "Sigma_UserMode" || evt.event_type == "Sigma_UserMode" ||
                           evt.category.contains("Sigma") || evt.event_type.contains("Sigma");

            let rule_key = if !evt.matched_indicator.is_empty() {
                evt.matched_indicator.clone()
            } else if !evt.signature_name.is_empty() {
                evt.signature_name.clone()
            } else if !evt.event_type.is_empty() && evt.event_type != "AggregatedUEBA" {
                evt.event_type.clone()
            } else {
                evt.category.clone()
            };

            let procs = self.rule_process_map.entry(rule_key.clone()).or_insert_with(HashSet::new);
            let is_first_alert = !procs.contains(&proc_lower);

            // TTPs are critical attack chains. They ALWAYS alert.
            // Sigma rules are noisy and degrade after 5 processes.
            if is_ttp || (is_sigma && procs.len() < 5 && is_first_alert) {
                let sig_name = if !evt.signature_name.is_empty() {
                    &evt.signature_name
                } else if !evt.matched_indicator.is_empty() {
                    &evt.matched_indicator
                } else if evt.category != "AggregatedUEBA" {
                    &evt.category
                } else {
                    &evt.event_type
                };

                let mut reason_str;

                if is_ttp {
                    reason_str = format!("[TTP] {}", sig_name);
                    if !evt.tactic.is_empty() && evt.tactic != "N/A" { reason_str.push_str(&format!(" | {}", evt.tactic)); }
                    if !evt.technique.is_empty() && evt.technique != "N/A" { reason_str.push_str(&format!(" | {}", evt.technique)); }
                } else {
                    reason_str = format!("[FIRST ALERT] [SIGMA] {}", sig_name);
                    if !evt.event_type.is_empty() && evt.event_type != "AggregatedUEBA" && evt.event_type != "Sigma_Match" && evt.event_type != "Sigma_UserMode" {
                        reason_str.push_str(&format!(" | {}", evt.event_type));
                    }
                }

                alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", reason_str));
                already_alerted = true;
            }
        }

        // === Normal single-event processing continues below ===
        let text_data = format!("{}{}", evt.cmd, evt.path);
        let entropy = Self::shannon_entropy(&text_data);

        let effective_entropy = if evt.count > 1 { evt.avg_entropy } else { entropy };

        let mut delta_sec = 9999.0;
        if let Some(&last_time) = self.last_process_execution.get(&proc_lower) {
            delta_sec = now - last_time;
        }
        self.last_process_execution.insert(proc_lower.clone(), now);

        // --- VELOCITY SCORING ---
        let velocity_score = if delta_sec < 1.0 { 1.0 } else { 1.0 / delta_sec };
        let effective_velocity = if evt.count > 1 { evt.rate_per_sec } else { velocity_score };

        let is_aggregated = evt.category == "AggregatedUEBA" || evt.count > 1;
        let is_trusted = self.trusted_binaries.contains(&proc_lower);

        // === HIGH-VOLUME BURST ESCALATION ===
        // Evaluates grouped events to instantly catch rapid attacks (like Ransomware)
        if is_aggregated && evt.count >= 10 {
            if !is_trusted && (effective_entropy > 5.0 || effective_velocity > 10.0 || evt.unique_tids > 5) {
                alerts.push(Alert::new(
                    &evt,
                    1.0,
                    94.0,
                    "HIGH",
                    format!(
                        "High-Volume Aggregated Burst: {} events / {} threads in 5s (Entropy: {:.2}, Rate: {:.1}/s, MaxVel: {:.1})",
                        evt.count, evt.unique_tids, effective_entropy, effective_velocity, evt.max_velocity
                    )
                ));
            }
        }

        // --- HIGH-CONFIDENCE TTP OVERRIDES (THE GLASS) ---
        if evt.event_type == "ProcessStart" || evt.event_type == "RegistryWrite" || evt.event_type == "FileIOCreate" {

            let is_lsass_dump = (cmd_lower.contains("comsvcs") && cmd_lower.contains("minidump")) ||
                                (cmd_lower.contains("procdump") && cmd_lower.contains("lsass")) ||
                                cmd_lower.contains("mimikatz") || cmd_lower.contains("sekurlsa::") ||
                                cmd_lower.contains("dumpert");

            if is_lsass_dump {
                alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", format!("[T1003.001] CRITICAL: Confirmed LSASS Dump | Proc: {}", proc_lower)));
                return alerts;
            }

            if proc_lower == "reg.exe" && cmd_lower.contains("save") && (cmd_lower.contains("sam") || cmd_lower.contains("system")) {
                alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", format!("[T1003.002] CRITICAL: Registry Hive Dump | Proc: {}", proc_lower)));
                return alerts;
            }

            let is_shadow_delete = (proc_lower == "vssadmin.exe" && cmd_lower.contains("delete") && cmd_lower.contains("shadows")) ||
                                   (proc_lower == "wmic.exe" && cmd_lower.contains("shadowcopy") && cmd_lower.contains("delete"));
            let is_log_clear = (proc_lower == "wevtutil.exe" && cmd_lower.contains("cl") && (cmd_lower.contains("system") || cmd_lower.contains("security"))) ||
                               ((proc_lower == "powershell.exe" || proc_lower == "pwsh.exe") && cmd_lower.contains("clear-eventlog"));

            if is_shadow_delete || is_log_clear {
                alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", format!("[T1070] CRITICAL: Defense Evasion (Log/Shadow Deletion) | Proc: {}", proc_lower)));
                return alerts;
            }

            if proc_lower == "powershell.exe" || proc_lower == "pwsh.exe" {
                let is_downloader = cmd_lower.contains("net.webclient") || cmd_lower.contains("downloadstring") || cmd_lower.contains("invoke-webrequest");
                let is_hidden = cmd_lower.contains("-windowstyle hidden") || cmd_lower.contains("-w hidden") || cmd_lower.contains("-enc");

                if is_downloader && is_hidden {
                    alerts.push(Alert::new(&evt, 10.0, 100.0, "CRITICAL", format!("[T1059.001] CRITICAL: Weaponized PS Downloader | Proc: {}", proc_lower)));
                    return alerts;
                }
            }
        }

        // Ransomware burst detection
        if evt.event_type == "FileIOCreate" || evt.event_type == "FileIOWrite" {
            let filename = evt.path.split('\\').last().unwrap_or(&evt.path);
            let effective_path_entropy = Self::shannon_entropy(filename);
            let event_volume = if evt.count > 0 { evt.count } else { 1 };

            let tracker = self.pid_io_tracker.entry(evt.pid).or_insert(IoTracker { count: 0, start_time: now, entropy_sum: 0.0 });

            tracker.count += event_volume;
            tracker.entropy_sum += effective_path_entropy * event_volume as f64;

            // 1. Reset the 1-second window if it has expired
            if now - tracker.start_time > 1.0 {
                tracker.count = event_volume;
                tracker.start_time = now;
                tracker.entropy_sum = effective_path_entropy * event_volume as f64;
            }

            // 2. Evaluate thresholds independently
            if tracker.count > 50 {
                let avg_entropy = tracker.entropy_sum / tracker.count as f64;

                // Threshold lowered to 3.8 to reliably catch anomalous file hashes.
                if avg_entropy > 3.8 {
                    alerts.push(Alert::new(&evt, avg_entropy, 95.0, "CRITICAL", format!("[T1486] Ransomware/Wiper Burst: {} I/O ops/sec (Entropy: {:.2})", tracker.count, avg_entropy)));
                    // Reset so it doesn't spam alerts continuously
                    tracker.count = 0;
                    tracker.entropy_sum = 0.0;
                    tracker.start_time = now;
                }
            }
        }

        // Route orchestrated events (Sigma, TTPs, ML Anomalies) into the UEBA Temporal Baselining Engine
        if evt.category != "RawEvent" {

            let rule = if evt.matched_indicator.is_empty() { evt.event_type.clone() } else { evt.matched_indicator.clone() };

            // --- 1. UNIVERSAL SILENT DEGRADATION GATE ---
            let procs = self.rule_process_map.entry(rule.clone()).or_insert_with(HashSet::new);
            procs.insert(proc_lower.clone());

            let is_ttp = evt.category == "TTP_Match" || evt.event_type == "TTP_Match" ||
                         evt.category == "AdvancedDetection" || evt.event_type == "AdvancedDetection" ||
                         evt.category.starts_with("T1") || evt.event_type.starts_with("T1");

            if !is_ttp && procs.len() >= 5 {
                if procs.len() == 5 {
                    Self::log_ueba_audit("SUPPRESSED", &proc_lower, &rule, procs.len() as i32, 0.0);
                    alerts.push(Alert::new(&evt, -2.0, 100.0, "INFO", format!("Globally Suppressed: {} reached 5-process noise limit.", rule)));
                }
                return alerts;
            }

            // Unifies OS and Network Telemetry
            let target_data = if !evt.destination.is_empty() {
                format!("{}:{}", evt.destination, evt.port)
            } else if !evt.cmd.is_empty() {
                evt.cmd.clone()
            } else {
                evt.path.clone()
            };

            let (ctx_hash, target_struct) = self.generate_structural_hash(&evt.parent, &proc_lower, &target_data, &rule);

            let b_data = self.ueba_baseline.entry(ctx_hash.clone()).or_insert(UebaBaseline {
                count: 0, last_seen: now, mean_delta: 0.0, m2_delta: 0.0, mean_entropy: 0.0
            });

            let delta_t = now - b_data.last_seen;
            b_data.count += 1;
            b_data.last_seen = now;
            let count_f = b_data.count as f64;

            let delta_mean = delta_t - b_data.mean_delta;
            b_data.mean_delta += delta_mean / count_f;
            let delta_mean2 = delta_t - b_data.mean_delta;
            b_data.m2_delta += delta_mean * delta_mean2;
            b_data.mean_entropy += (entropy - b_data.mean_entropy) / count_f;

            let variance = if b_data.count > 1 { b_data.m2_delta / (count_f - 1.0) } else { 0.0 };
            let std_dev = variance.sqrt();

            // --- LIVING OFF THE LAND HISTORICAL Z-SCORE ---
            let mut z_score = 0.0;
            if b_data.count >= self.tuning.min_baseline_events && std_dev > 0.0 {
                z_score = (delta_t - b_data.mean_delta).abs() / std_dev;
            }

            if z_score > self.tuning.lotl_z_score && evt.event_type != "Synthetic_Health_Check" && !already_alerted {
                 alerts.push(Alert::new(&evt, 1.0, 90.0, "HIGH", format!("LotL Temporal Anomaly: {} broke baseline (Z-Score: {:.2})", proc_lower, z_score)));
                 already_alerted = true;
            }

            // --- UEBA EARLY ANOMALY DETECTION (NOVELTY RISK) ---
            if b_data.count <= 3 && evt.event_type != "Synthetic_Health_Check" && !already_alerted {
                let mut novelty_risk = 0.0;

                if cmd_lower.contains(r"\\") || cmd_lower.contains("http://") || cmd_lower.contains("https://") { novelty_risk += 0.5; }
                if cmd_lower.contains("-windowstyle hidden") || cmd_lower.contains("-w hidden") || cmd_lower.contains("-enc") { novelty_risk += 0.4; }
                if cmd_lower.contains(r"software\classes\clsid") || cmd_lower.contains("inprocserver32") { novelty_risk += 0.5; }
                if ["winword.exe", "excel.exe", "powerpnt.exe"].contains(&proc_lower.as_str()) && (evt.path.to_lowercase().ends_with(".dll") || evt.path.to_lowercase().ends_with(".exe") || evt.path.to_lowercase().ends_with(".vbs")) { novelty_risk += 0.9; }
                if ["rundll32.exe", "regsvr32.exe", "certutil.exe"].contains(&proc_lower.as_str()) { novelty_risk += 0.3; }
                if entropy > 5.2 { novelty_risk += 0.3; }

                if novelty_risk >= 0.7 {
                    alerts.push(Alert::new(&evt, 1.0, 95.0, "CRITICAL", format!("Early UEBA Risk (Score: {:.1}): {} exhibited highly anomalous sequencing", novelty_risk, proc_lower)));
                    already_alerted = true;
                }
            }

            self.conn.execute(
                "INSERT INTO ueba_temporal_baselines (context_hash, user_context, parent_process, process, rule, target_struct, event_count, last_seen, mean_delta, m2_delta, mean_entropy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(context_hash) DO UPDATE SET event_count=excluded.event_count, last_seen=excluded.last_seen, mean_delta=excluded.mean_delta, m2_delta=excluded.m2_delta, mean_entropy=excluded.mean_entropy",
                params![ctx_hash, evt.event_user, evt.parent, proc_lower, rule, target_struct, b_data.count, b_data.last_seen, b_data.mean_delta, b_data.m2_delta, b_data.mean_entropy]
            ).unwrap_or_default();

            // --- 2. INTELLIGENT SIEM ROLLUP ROUTING ---
            let is_automated = std_dev < 300.0;
            let trust_threshold = if is_automated { self.suppression_count_min } else { (self.suppression_count_min as f64 * 2.5) as i32 };
            let cumulative_count = b_data.count * std::cmp::max(1, evt.count);

            if b_data.count == trust_threshold {
                Self::log_ueba_audit("THRESHOLD", &proc_lower, &rule, cumulative_count, std_dev);
                alerts.push(Alert::new(&evt, -1.0, 100.0, "INFO", format!("System Behavior Secured: {} ({}) | Mode: {} Baseline.", proc_lower, rule, if is_automated { "Automated" } else { "Manual" })));
            } else if b_data.count > trust_threshold && cumulative_count % 500 == 0 {
                Self::log_ueba_audit("ROLLUP", &proc_lower, &rule, cumulative_count, std_dev);
                alerts.push(Alert::new(&evt, -3.0, 100.0, "INFO", format!("Rollup Heartbeat: {} ({}) reached {} executions", proc_lower, rule, cumulative_count)));
            }

            // REDUNDANCY CURATION: Only drop a "Learning Started" log on the VERY FIRST execution.
            // No need to spam the cold index with counts 2, 3, 4, etc.
            if b_data.count < trust_threshold && !already_alerted {
                if b_data.count == 1 {
                    Self::log_ueba_audit("LEARNING", &proc_lower, &rule, cumulative_count, std_dev);
                    alerts.push(Alert::new(&evt, -4.0, 100.0, "INFO", format!("Learning Started: {} ({}) - Targeting {} executions to secure.", proc_lower, rule, trust_threshold)));
                }
            }
        }

        // Track the Parent->Child execution tuple for anomaly scoring
        let pc_tuple = format!("{}->{}", evt.parent.to_lowercase(), proc_lower);
        let tuple_count = self.tuple_freq.entry(pc_tuple).or_insert(0);
        *tuple_count += 1;
        let tuple_score = 1.0 / *tuple_count as f64;
        let path_depth = evt.path.chars().filter(|&c| c == '\\').count() as f64;

        // ML TUNING: Bypass the static T1027 entropy override if the command line contains structured JSON/Telemetry markers
        let is_structured_telemetry = cmd_lower.contains("telemetrysession") ||
                                      cmd_lower.contains("{\"") ||
                                      cmd_lower.contains("appinsights") ||
                                      cmd_lower.contains("xmlns=");

        // Only flag T1027 if entropy is high AND it doesn't look like standard developer telemetry
        if text_data.len() > 50 && entropy > 5.2 && !is_structured_telemetry && (evt.event_type == "ProcessStart" || evt.event_type == "RegistryWrite") {
            let severity_str = if entropy > 5.5 { "CRITICAL" } else { "HIGH" };
            alerts.push(Alert::new(
                &evt,
                entropy,
                85.0,
                severity_str,
                format!("[T1027] Suspicious packed/encoded payload in {} (Entropy {:.2})", evt.event_type, entropy)
            ));
        }

        let current_feat = [
            effective_entropy,
            tuple_score,
            path_depth,
            effective_velocity,
            evt.max_velocity.max(0.0)
        ];

        if self.history.len() >= 5000 {
            self.history.pop_front();
        }
        self.history.push_back(current_feat);

        self.fit_counter = self.fit_counter.saturating_add(1);

        // Asynchronous Forest Rebuild
        let needs_rebuild = {
            let forest_read = self.cached_forest.read().unwrap();
            self.history.len() > 200
                && (forest_read.is_none() || self.fit_counter > 20000)
                && !*self.is_training.read().unwrap()
        };

        if needs_rebuild {
            let mut is_training = self.is_training.write().unwrap();
            if !*is_training {
                *is_training = true;
                self.fit_counter = 0;

                let history_vec: Vec<[f64; 5]> = self.history.iter().cloned().collect();
                let forest_arc = Arc::clone(&self.cached_forest);
                let training_flag = Arc::clone(&self.is_training);

                std::thread::spawn(move || {
                    let options = ForestOptions {
                    n_trees: 50,
                    sample_size: std::cmp::min(256, history_vec.len()),
                    max_tree_depth: None,
                    extension_level: 2,
                };

                if let Ok(forest) = Forest::from_slice(&history_vec, &options) {
                        let mut w_forest = forest_arc.write().unwrap();
                        *w_forest = Some(forest);
                    }
                    *training_flag.write().unwrap() = false;
                });
            }
        }

        // Safely read from the RwLock for scoring
        if let Some(forest) = &*self.cached_forest.read().unwrap() {
            let raw_score = forest.score(&current_feat);

            let mut anomaly_score = raw_score;
            if evt.count > 1 {
                let boost = (evt.count as f64).ln().min(2.5);
                anomaly_score = (raw_score + boost * 0.08).min(1.0);
            }

            if anomaly_score >= self.tuning.iso_forest_anomaly {
                let severity = if anomaly_score > (self.tuning.iso_forest_anomaly + 0.10) || entropy > self.tuning.entropy_critical { "CRITICAL" } else { "HIGH" };

                // --- 3. ML HUD ROLLUP & COOLDOWN ---
                let last_alert = *self.alert_cooldown.get(&proc_lower).unwrap_or(&0.0);

                if now - last_alert > 300.0 { // 5-Minute UI Cooldown
                    self.alert_cooldown.insert(proc_lower.clone(), now);

                    let details = if self.trusted_binaries.contains(&proc_lower) {
                        format!("Behavioral Outlier (Trusted Context): Anomalous chain by {} (Score: {:.2})", proc_lower, anomaly_score)
                    } else {
                        format!("Behavioral Lineage Outlier: Anomalous chain by {} (Score: {:.2})", proc_lower, anomaly_score)
                    };

                    alerts.push(Alert::new(&evt, 1.0, anomaly_score * 100.0, severity, details));
                } else {
                    // It is within the 5-minute cooldown. Silently route it to events.jsonl
                    // by using a score of 0.5 (which bypasses the HUD display in PowerShell
                    // but still writes to the backend log for SIEM correlation).
                    alerts.push(Alert::new(&evt, 0.5, anomaly_score * 100.0, "INFO", format!("Rollup: Continued anomalous activity by {}", proc_lower)));
                }
            }
        }
        alerts
    }
}

// ============================================================================
// NATIVE C-FFI BOUNDARY
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn init_engine(log_cb: Option<NativeLogCallback>) -> *mut Mutex<BehavioralEngine> {
    if let Some(cb) = log_cb {
        LOG_CALLBACK.store(cb as *mut _, Ordering::SeqCst);
    }

    std::panic::catch_unwind(|| {
        let engine = BehavioralEngine::new();
        Box::into_raw(Box::new(Mutex::new(engine)))
    }).unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn evaluate_telemetry(
    engine_ptr: *mut Mutex<BehavioralEngine>,
    json_payload: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || json_payload.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(json_payload) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let events: Vec<IncomingEvent> = match serde_json::from_str::<Vec<IncomingEvent>>(json_str) {
        Ok(evts) => evts,
        Err(_) => {
            match serde_json::from_str::<IncomingEvent>(json_str) {
                Ok(single_evt) => vec![single_evt],
                Err(e) => {
                    let err_msg = format!("JSON Parse Error (Array & Single fallback failed): {}", e);
                    let response = OutgoingResponse { alerts: None, daemon_error: Some(err_msg) };

                    match serde_json::to_string(&response) {
                        Ok(safe_json) => return CString::new(safe_json).unwrap().into_raw(),
                        Err(_) => return std::ptr::null_mut(),
                    }
                }
            }
        }
    };

    let engine_mutex = unsafe { &*engine_ptr };

    let result = std::panic::catch_unwind(|| {
        let mut engine = match engine_mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        };

        // Start a bulk transaction to eliminate disk thrashing
        let _ = engine.conn.execute_batch("BEGIN IMMEDIATE;");
        let mut batch_alerts = Vec::new();

        for evt in events {
            batch_alerts.extend(engine.evaluate_single(evt));
        }

        // Commit the entire batch to the WAL in a single I/O operation
        let _ = engine.conn.execute_batch("COMMIT;");
        batch_alerts
    });

    match result {
        Ok(alerts) if !alerts.is_empty() => {
            let response = OutgoingResponse { alerts: Some(alerts.clone()), daemon_error: None };

            match serde_json::to_string(&response) {
                Ok(resp_str) => CString::new(resp_str)
                    .unwrap_or_else(|_| CString::new(r#"{"daemon_error":"serialize_failed"}"#).unwrap())
                    .into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn submit_orchestrator_alert(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) {
    if engine_ptr.is_null() || json_payload.is_null() { return; }

    let _ = std::panic::catch_unwind(|| {
        let c_str = unsafe { CStr::from_ptr(json_payload) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                let engine_mutex = unsafe { &*engine_ptr };
                let engine = match engine_mutex.lock() { Ok(g) => g, Err(p) => p.into_inner() };

                let event_id = val.get("EventID").and_then(|v| v.as_str()).unwrap_or_default();
                let timestamp = val.get("Timestamp_UTC").and_then(|v| v.as_str()).unwrap_or_default();
                let computer_name = val.get("ComputerName").and_then(|v| v.as_str()).unwrap_or_default();
                let host_ip = val.get("HostIP").and_then(|v| v.as_str()).unwrap_or_default();
                let sensor_user = val.get("SensorUser").and_then(|v| v.as_str()).unwrap_or_default();
                let event_type = val.get("EventType").and_then(|v| v.as_str()).unwrap_or_default();
                let process = val.get("Image").and_then(|v| v.as_str()).unwrap_or_default();
                let command_line = val.get("CommandLine").and_then(|v| v.as_str()).unwrap_or_default();
                let alert_reason = val.get("SuspiciousFlags").and_then(|v| v.as_str()).unwrap_or_default();
                let confidence = val.get("Confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let action = val.get("Action").and_then(|v| v.as_str()).unwrap_or_default();

                let _ = engine.conn.execute(
                    "INSERT INTO DeepLedger (
                        event_id,
                        timestamp,
                        computer_name,
                        host_ip,
                        sensor_user,
                        event_type,
                        process,
                        command_line,
                        alert_reason,
                        confidence,
                        action,
                        payload
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        event_id,
                        timestamp,
                        computer_name,
                        host_ip,
                        sensor_user,
                        event_type,
                        process,
                        command_line,
                        alert_reason,
                        confidence,
                        action,
                        json_str
                    ],
                );

                let _ = engine.tx.try_send(val);
            }
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn submit_ueba_audit(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) {
    if engine_ptr.is_null() || json_payload.is_null() { return; }

    let _ = std::panic::catch_unwind(|| {
        let c_str = unsafe { CStr::from_ptr(json_payload) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                let engine_mutex = unsafe { &*engine_ptr };
                let engine = match engine_mutex.lock() { Ok(g) => g, Err(p) => p.into_inner() };

                let ctx_hash = val.get("context_hash").and_then(|v| v.as_str()).unwrap_or_default();
                let user_ctx = val.get("user_context").or_else(|| val.get("user")).and_then(|v| v.as_str()).unwrap_or_default();
                let parent = val.get("parent_process").and_then(|v| v.as_str()).unwrap_or_default();
                let process = val.get("process").and_then(|v| v.as_str()).unwrap_or_default();
                let rule = val.get("rule").and_then(|v| v.as_str()).unwrap_or_default();
                let target = val.get("target_struct").and_then(|v| v.as_str()).unwrap_or_default();

                let count = val.get("event_count").and_then(|v| v.as_i64()).unwrap_or(1);
                let last_seen = val.get("last_seen").and_then(|v| v.as_f64()).unwrap_or_default();
                let mean_delta = val.get("mean_delta").and_then(|v| v.as_f64()).unwrap_or_default();
                let m2_delta = val.get("m2_delta").and_then(|v| v.as_f64()).unwrap_or_default();
                let mean_entropy = val.get("mean_entropy").and_then(|v| v.as_f64()).unwrap_or_default();

                let _ = engine.conn.execute(
                    "INSERT INTO ueba_temporal_baselines (
                        context_hash,
                        user_context,
                        parent_process,
                        process,
                        rule,
                        target_struct,
                        event_count,
                        last_seen,
                        mean_delta,
                        m2_delta,
                        mean_entropy
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                    ON CONFLICT(context_hash) DO UPDATE SET
                        event_count = excluded.event_count,
                        last_seen = excluded.last_seen,
                        mean_delta = excluded.mean_delta,
                        m2_delta = excluded.m2_delta,
                        mean_entropy = excluded.mean_entropy",
                    rusqlite::params![
                        ctx_hash, user_ctx, parent, process, rule, target,
                        count, last_seen, mean_delta, m2_delta, mean_entropy
                    ],
                );
            }
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<BehavioralEngine>) {
    if !engine_ptr.is_null() {
        unsafe {
            let engine_box = Box::from_raw(engine_ptr);
            {
                let mut engine = match engine_box.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner()
                };

                let _ = engine.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

                let dummy_tx = mpsc::channel(1).0;
                let _old_tx = std::mem::replace(&mut engine.tx, dummy_tx);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}