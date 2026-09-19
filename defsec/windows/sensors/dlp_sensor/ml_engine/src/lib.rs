/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       lib.rs (High-Performance FFI Engine)
 * DESCRIPTION:
 * Natively compiles as a C-compatible Dynamic Link Library (cdylib).
 * Implements micro-batched transactional logging and memory-mapped SQLite
 * PRAGMAs to handle massive ETW telemetry firehoses without I/O blocking.
 * @RW
 *============================================================================================*/

use lru::LruCache;
use regex::RegexSet;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::num::NonZeroUsize;
use std::os::raw::c_char;
use std::sync::Mutex;
use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use std::sync::atomic::{AtomicPtr, Ordering};
use serde_json::json;

// --- LOGGING ---

pub const ARCHIVE_EXTRACTOR_PROCESS: &str = "Archive_Extractor";
pub type NativeLogCallback = extern "C" fn(*const std::os::raw::c_char);
static LOG_CALLBACK: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

macro_rules! log_diag {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        let ptr = LOG_CALLBACK.load(Ordering::Relaxed);
        if !ptr.is_null() {
            #[allow(unused_unsafe)]
            let cb: NativeLogCallback = unsafe { std::mem::transmute(ptr) };
            if let Ok(c_str) = std::ffi::CString::new(msg) {
                cb(c_str.as_ptr());
            }
        }
    }};
}

// --- CONFIGURATION & FFI STRUCTURES ---

#[derive(Serialize, Deserialize, Default)]
pub struct DlpConfig {
    pub strict_strings: Vec<String>,
    pub regex_patterns: Vec<String>,

    // --- UEBA BASELINES ---
    #[serde(default = "default_min_samples")]
    pub ueba_min_samples: u64,
    #[serde(default = "default_z_score")]
    pub ueba_z_score: f64,

    // --- MEMORY BOUNDS ---
    #[serde(default = "default_max_entities")]
    pub max_tracked_entities: usize,
    #[serde(default = "default_decay_hours")]
    pub state_decay_hours: u64,
    #[serde(default = "default_min_bytes")]
    pub min_trackable_bytes: i64,
}

// Serde Default Fallback Functions
fn default_min_samples() -> u64 { 15 }
fn default_z_score() -> f64 { 3.0 }
fn default_max_entities() -> usize { 25000 }
fn default_decay_hours() -> u64 { 24 }
fn default_min_bytes() -> i64 { 512 }

#[derive(Deserialize)]
pub struct FfiPlatformEvent {
    pub timestamp: String,
    pub user: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub action: String,
    pub process: String,
    #[serde(default)]
    pub parent_process: String,
    #[serde(default)]
    pub command_line: String,
    pub filepath: String,
    pub destination: String,
    #[serde(default)]
    pub dest_port: String,
    pub bytes: i64,
    pub duration_ms: i64,
    #[serde(default)]
    pub is_dlp_hit: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DlpAlert {
    pub alert_type: String,
    pub details: String,
    pub confidence: i32,
    pub mitre_tactic: String,
    pub user: Option<String>,
    pub process: Option<String>,
    pub filepath: Option<String>,
    pub destination: Option<String>,
}

#[derive(Serialize)]
pub struct EngineResponse {
    pub alerts: Option<Vec<DlpAlert>>,
    pub daemon_error: Option<String>,
}

pub struct UebaBaseline {
    pub count: u64,
    pub mean_bytes: f64,
    pub m2_bytes: f64,
    pub mean_velocity: f64,
    pub m2_velocity: f64,
    pub last_seen: Instant,
}

pub struct DlpEngine {
    pub db_conn: Connection,
    pub config: DlpConfig,
    pub user_baselines: LruCache<String, UebaBaseline>,
    pub regex_set: RegexSet,
    pub patterns: Vec<String>,
    pub strict_set: std::collections::HashSet<String>,
    pub tx: mpsc::Sender<serde_json::Value>,
    pub rt: Runtime,
}

// --- NATIVE ENGINE INITIALIZATION ---

#[no_mangle]
pub extern "C" fn init_dlp_engine(
    config_json: *const c_char,
    log_cb: Option<NativeLogCallback>
) -> *mut Mutex<DlpEngine> {
    if let Some(cb) = log_cb {
        LOG_CALLBACK.store(cb as *mut _, Ordering::SeqCst);
    }
    let secure_dir = r"C:\ProgramData\DataSensor\Data";
    let _ = std::fs::create_dir_all(secure_dir);
    let db_path = format!(r"{}\DataLedger.db", secure_dir);

    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            log_diag!("[DataSensor ML] FATAL: Could not open DataLedger.db: {}", e);
            return std::ptr::null_mut();
        }
    };

    let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));

    if conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA mmap_size = 268435456;
        PRAGMA wal_autocheckpoint = 1000;
    ").is_err() {
        return std::ptr::null_mut();
    }

    if conn.execute(
        "CREATE TABLE IF NOT EXISTS DataLedger (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp TEXT,
            User TEXT,
            Process TEXT,
            FilePath TEXT,
            Destination TEXT,
            Bytes INTEGER,
            Velocity REAL,
            EventType TEXT DEFAULT '',
            IsDlpHit INTEGER NOT NULL DEFAULT 0,
            Action TEXT DEFAULT 'Unknown',
            ParentProcess TEXT DEFAULT '',
            CommandLine TEXT DEFAULT '',
            DestPort TEXT DEFAULT ''
        )",
        []
    ).is_err() {
        return std::ptr::null_mut();
    }

    let mut config = DlpConfig::default();
    if !config_json.is_null() {
        let c_str = unsafe { CStr::from_ptr(config_json) };
        if let Ok(json_str) = c_str.to_str() {
            match serde_json::from_str::<DlpConfig>(json_str) {
                Ok(parsed) => config = parsed,
                Err(e) => log_diag!(
                    "[DataSensor ML] WARNING: Config JSON parse failed: {}. \
                    Engine running with built-in defaults...", e
                ),
            }
        }
    }

    config.strict_strings.retain(|s| !s.trim().is_empty());
    config.regex_patterns.retain(|s| !s.trim().is_empty());

    let regex_set = RegexSet::new(&config.regex_patterns).unwrap_or_else(|e| {
        log_diag!("[DataSensor ML] WARNING: Failed to compile RegexSet: {}", e);
        RegexSet::empty()
    });

    let patterns = config.regex_patterns.clone();
    let strict_set: std::collections::HashSet<String> = config.strict_strings.iter().cloned().collect();

    let capacity = NonZeroUsize::new(config.max_tracked_entities)
        .unwrap_or_else(|| NonZeroUsize::new(25000).unwrap());

    let (tx, rx) = mpsc::channel(10000);
    let rt = Runtime::new().unwrap();

    rt.spawn(async move {
        transmission::start_transmission_worker(
            r"C:\ProgramData\DataSensor\config.ini".to_string(),
            rx,
            |msg| {
                let ptr = LOG_CALLBACK.load(Ordering::Relaxed);
                if !ptr.is_null() {
                    let cb: NativeLogCallback = unsafe { std::mem::transmute(ptr) };
                    if let Ok(c_str) = CString::new(msg) {
                        cb(c_str.as_ptr());
                    }
                }
            }
        ).await;
    });

    let engine = DlpEngine {
        db_conn: conn,
        config,
        user_baselines: LruCache::new(capacity),
        regex_set,
        patterns,
        strict_set,
        tx,
        rt,
    };

    Box::into_raw(Box::new(Mutex::new(engine)))
}

#[no_mangle]
pub extern "C" fn process_telemetry_batch(
    engine_ptr: *mut Mutex<DlpEngine>,
    batch_json: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || batch_json.is_null() {
        return std::ptr::null_mut();
    }

    let engine_mutex = unsafe { &*engine_ptr };
    let mut engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            log_diag!("[DataSensor ML] WARNING: Engine mutex was poisoned — recovering. State may be inconsistent.");
            p.into_inner()
        }
    };

    let engine = &mut *engine_guard;

    let json_str = unsafe { CStr::from_ptr(batch_json).to_string_lossy() };
    let events_slice: Vec<FfiPlatformEvent> = match serde_json::from_str(&json_str) {
        Ok(evts) => evts,
        Err(e) => return make_error_response(&format!("JSON Parse Error: {} | Payload: {}", e, json_str)),
    };
    let mut alerts = Vec::new();

    let tx = match engine.db_conn.transaction() {
        Ok(t) => t,
        Err(e) => return make_error_response(&format!("Transaction Error: {}", e)),
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO DataLedger (Timestamp, User, Process, FilePath, Destination, Bytes, Velocity, EventType, IsDlpHit, Action, ParentProcess, CommandLine, DestPort) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        ) {
            Ok(s) => s,
            Err(e) => return make_error_response(&format!("SQL Prepare Error: {}", e)),
        };

        for ffi_evt in events_slice {
            let usr = ffi_evt.user.clone();
            let proc = ffi_evt.process.clone();
            let path = ffi_evt.filepath.clone();
            let dest = ffi_evt.destination.clone();
            let bytes = ffi_evt.bytes;

            if ffi_evt.event_type == "Network" {
                let matched_ioc = engine.strict_set.iter().find(|ioc| {
                    dest == ioc.as_str() || dest.ends_with(&format!(".{}", ioc))
                });
                if let Some(ioc) = matched_ioc {
                    alerts.push(DlpAlert {
                        alert_type: "ACTION_REQUIRED".to_string(),
                        details: format!("NETWORK_INTEL_VIOLATION | Outbound connection to Threat Intel Indicator: {}", ioc),
                        user: Some(usr.clone()),
                        process: Some(proc.clone()),
                        filepath: Some(path.clone()),
                        destination: Some(dest.clone()),
                        confidence: 100,
                        mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
                    });
                }
            }

            let velocity = if ffi_evt.duration_ms > 0 {
                (bytes as f64 / ffi_evt.duration_ms as f64) * 1000.0
            } else {
                bytes as f64
            };

            let is_hit = ffi_evt.is_dlp_hit as i32;
            if let Err(e) = stmt.execute(rusqlite::params![ffi_evt.timestamp, ffi_evt.user, ffi_evt.process, ffi_evt.filepath, ffi_evt.destination, ffi_evt.bytes, velocity, ffi_evt.event_type, is_hit, ffi_evt.action, ffi_evt.parent_process, ffi_evt.command_line, ffi_evt.dest_port]) {
                return make_error_response(&format!("SQL Insert Error: {}", e));
            }

            // --- IN-MEMORY TRANSMISSION BRANCH ---
            let payload = serde_json::json!({
                "timestamp": ffi_evt.timestamp.clone(),
                "user": ffi_evt.user.clone(),
                "process": ffi_evt.process.clone(),
                "destination": ffi_evt.destination.clone(),
                "bytes": ffi_evt.bytes,
                "is_dlp_hit": ffi_evt.is_dlp_hit,
                "event_type": ffi_evt.event_type.clone(),
                "action": ffi_evt.action.clone(),
                "filepath": ffi_evt.filepath.clone()
            });

            let _ = engine.tx.try_send(payload);

            if bytes < engine.config.min_trackable_bytes {
                continue;
            }

            let baseline_category = if ffi_evt.event_type == "Network" { &ffi_evt.destination } else { &ffi_evt.destination };
            let baseline_key = format!("{}|{}|{}", ffi_evt.user, ffi_evt.action, baseline_category);

            let now = Instant::now();
            let mut reset_baseline = false;

            if let Some(existing) = engine.user_baselines.get(&baseline_key) {
                if now.duration_since(existing.last_seen).as_secs() > (engine.config.state_decay_hours * 3600) {
                    reset_baseline = true;
                }
            }

            if reset_baseline {
                engine.user_baselines.pop(&baseline_key);
            }

            let baseline = engine.user_baselines.get_or_insert_mut(
                baseline_key.clone(),
                || UebaBaseline {
                    count: 0, mean_bytes: 0.0, m2_bytes: 0.0, mean_velocity: 0.0, m2_velocity: 0.0, last_seen: now
                }
            );

            baseline.last_seen = now;

            let pre_count = baseline.count;
            let pre_mean_b = baseline.mean_bytes;
            let pre_mean_v = baseline.mean_velocity;
            let pre_std_dev_b = if pre_count > 1 { (baseline.m2_bytes / pre_count as f64).sqrt() } else { 0.0 };
            let pre_std_dev_v = if pre_count > 1 { (baseline.m2_velocity / pre_count as f64).sqrt() } else { 0.0 };

            // Update baseline with the new event (Welford's online algorithm)
            baseline.count += 1;
            let n = baseline.count as f64;

            let delta_b = bytes as f64 - baseline.mean_bytes;
            baseline.mean_bytes += delta_b / n;
            baseline.m2_bytes += delta_b * (bytes as f64 - baseline.mean_bytes);

            let delta_v = velocity - baseline.mean_velocity;
            baseline.mean_velocity += delta_v / n;
            baseline.m2_velocity += delta_v * (velocity - baseline.mean_velocity);

            // Evaluate anomaly against PRE-UPDATE baseline so the current event is scored honestly
            if pre_count > engine.config.ueba_min_samples {
                let z_score_b = if pre_std_dev_b > 0.0 { (bytes as f64 - pre_mean_b) / pre_std_dev_b } else { 0.0 };
                let z_score_v = if pre_std_dev_v > 0.0 { (velocity - pre_mean_v) / pre_std_dev_v } else { 0.0 };

                if z_score_b > engine.config.ueba_z_score || z_score_v > engine.config.ueba_z_score {
                    alerts.push(DlpAlert {
                        alert_type: "UEBA_ANOMALY".to_string(),
                        details: format!("Z-Score (Vol: {:.2}, Vel: {:.2}) | Bytes: {} | Velocity: {:.2} B/s", z_score_b, z_score_v, bytes, velocity),
                        user: Some(usr.clone()),
                        process: Some(proc.clone()),
                        filepath: Some(path.clone()),
                        destination: Some(dest.clone()),
                        confidence: 90,
                        mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
                    });
                }
            }
        }
    }

    if let Err(e) = tx.commit() {
        return make_error_response(&format!("SQL Commit Error: {}", e));
    }

    // --- UNIVERSAL GATEWAY DISPATCH ---
    for alert in &alerts {
        if let Ok(mut json_val) = serde_json::to_value(alert) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.insert("timestamp".into(), json!(chrono::Utc::now().to_rfc3339()));
                obj.insert("event_type".into(), json!(alert.alert_type.clone()));
                obj.insert("bytes".into(), json!(0));
                obj.insert("is_dlp_hit".into(), json!(true));
            }
            let _ = engine.tx.try_send(json_val);
        }
    }

    serialize_response(alerts)
}

#[no_mangle]
pub extern "C" fn scan_text_payload(
    engine_ptr: *mut Mutex<DlpEngine>,
    text_payload: *const c_char,
    source_process: *const c_char,
    user_name: *const c_char,
    source_filepath: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || text_payload.is_null() { return std::ptr::null_mut(); }

    let engine_mutex = unsafe { &*engine_ptr };

    let mut engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            eprintln!("[DataSensor ML] WARNING: Engine mutex was poisoned — recovering. State may be inconsistent.");
            p.into_inner()
        }
    };

    let engine = &mut *engine_guard;

    let text = unsafe { CStr::from_ptr(text_payload).to_string_lossy() };
    let process = if source_process.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(source_process).to_string_lossy().into_owned() } };
    let user = if user_name.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(user_name).to_string_lossy().into_owned() } };

    let filepath = if source_filepath.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(source_filepath).to_string_lossy().into_owned() }
    };

    let mut matched = false;
    let mut trigger_detail = String::new();

    // 1. Check literal string arrays
    for kw in &engine.config.strict_strings {
        if text.contains(kw) {
            matched = true;
            trigger_detail = format!("Literal Match: {}", kw);
            break;
        }
    }

    // 2. Check compiled regex set
    if !matched && engine.regex_set.is_match(&text) {
        matched = true;
        trigger_detail = "Regex Signature Match".to_string();
    }

    // 3. Return Alert if matched
    if matched {
        let is_archive = process == ARCHIVE_EXTRACTOR_PROCESS;
        let detail_msg = if is_archive { format!("Archive Content Match | {}", trigger_detail) } else { format!("Clipboard Intercepted | {}", trigger_detail) };
        let fp = if is_archive { filepath.as_str() } else { "Clipboard_Capture" };
        let dest = if is_archive { "Evidence_Vault" } else { "Memory_Buffer" };
        let tactic = if is_archive { "T1560 - Archive Collected Data" } else { "T1056 - Collection" };

        let alert = DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            details: detail_msg,
            confidence: 100,
            mitre_tactic: tactic.to_string(),
            user: Some(user),
            process: Some(process),
            filepath: Some(fp.to_string()),
            destination: Some(dest.to_string()),
        };

        // --- UNIVERSAL GATEWAY DISPATCH ---
        if let Ok(mut json_val) = serde_json::to_value(&alert) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.entry("timestamp").or_insert_with(|| serde_json::json!(chrono::Utc::now().to_rfc3339()));
                obj.entry("event_type").or_insert_with(|| serde_json::json!(&alert.alert_type));
                obj.entry("bytes").or_insert(serde_json::json!(text.len() as i64));
                obj.entry("is_dlp_hit").or_insert(serde_json::json!(true));
            }
            let _ = engine.tx.try_send(json_val);
        }
        return serialize_response(vec![alert]);
    }
    std::ptr::null_mut()
}

fn serialize_response(alerts: Vec<DlpAlert>) -> *mut c_char {
    let response = EngineResponse {
        alerts: if alerts.is_empty() { None } else { Some(alerts) },
        daemon_error: None,
    };
    match serde_json::to_string(&response) {
        Ok(s) => match CString::new(s.replace('\0', "")) {
            Ok(cs) => cs.into_raw(),
            Err(_)  => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

fn make_error_response(msg: &str) -> *mut c_char {
    let response = EngineResponse { alerts: None, daemon_error: Some(msg.to_string()) };
    match serde_json::to_string(&response) {
        Ok(s) => match CString::new(s.replace('\0', "")) {
            Ok(cs) => cs.into_raw(),
            Err(_)  => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}

#[no_mangle]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<DlpEngine>) {
    if !engine_ptr.is_null() {
        unsafe {
            let engine_box = Box::from_raw(engine_ptr);
            let mut engine = match engine_box.lock() { Ok(g) => g, Err(p) => p.into_inner() };

            let (dummy_tx, _) = mpsc::channel(1);
            let real_tx = std::mem::replace(&mut engine.tx, dummy_tx);
            drop(real_tx);

            std::thread::sleep(std::time::Duration::from_millis(500));

            let _ = engine.db_conn.execute_batch("PRAGMA optimize;");
            let _ = engine.db_conn.execute_batch("PRAGMA journal_mode=DELETE;");

            let db_conn = std::mem::replace(
                &mut engine.db_conn,
                Connection::open_in_memory().expect("in-memory fallback"),
            );

            if let Err(e) = db_conn.close() {
                log_diag!("[DataSensor ML] WARNING: DB close returned error: {:?}", e);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn groom_database(
    engine_ptr: *mut Mutex<DlpEngine>,
    days_to_keep: u32,
) -> i32 {
    if engine_ptr.is_null() { return -1; }

    let engine_mutex = unsafe { &*engine_ptr };
    let engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            eprintln!("[DataSensor ML] WARNING: Mutex poisoned during grooming.");
            p.into_inner()
        }
    };

    let cutoff_days = days_to_keep.max(1) as i64;

    let result = engine_guard.db_conn.execute(
        "DELETE FROM DataLedger
         WHERE julianday('now') - julianday(Timestamp) > ?1
           AND IsDlpHit = 0
           AND Destination NOT IN (
               SELECT DISTINCT Destination FROM DataLedger
               WHERE julianday('now') - julianday(Timestamp) <= 3
                 AND IsDlpHit = 1
           )",
        rusqlite::params![cutoff_days],
    );

    match result {
        Ok(rows_deleted) => rows_deleted as i32,
        Err(e) => {
            log_diag!("[DataSensor ML] Grooming error: {}", e);
            -1
        }
    }
}