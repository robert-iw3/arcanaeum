/*=============================================================================================
 * SYSTEM:          EDR Sensor - Transmission Layer
 * COMPONENT:       lib.rs (Durable SQLite WAL to Parquet Forwarder)
 * DESCRIPTION:
 * Subscribes to the orchestrator's alert channel, writes events securely to a local
 * SQLite WAL (DeepLedger), and asynchronously micro-batches rows into ZSTD-compressed
 * Parquet buffers for the Axum Zero-Trust Gateway. Schema mirrors Submit-SensorAlert's
 * gateway payload (Sigma/TTP/UEBA alert fields).
 * @RW
 *============================================================================================*/

pub mod parquet;

use chrono;
use ini::Ini;
use reqwest::{Client, header};
use serde_json::Value;
use sqlx::{sqlite::SqlitePoolOptions, Row};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;

use nexus_integrity::stamper::LineageStamper;
use nexus_integrity::{HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Clone)]
pub struct TransmissionConfig {
    pub endpoint: String,
    pub auth_token: String,
    pub sensor_type: String,
    pub batch_size: u32,
    pub db_path: String,
    pub trust_self_signed: bool,
    pub integrity_secret: String,
}

impl TransmissionConfig {
    pub fn load(path: &str) -> Self {
        let conf = Ini::load_from_file(path).unwrap_or_default();
        // rust-ini 0.21's `section` returns Option<&Properties>; a reference can't be
        // `unwrap_or_default`. Borrow an empty section so all `.get()` fall through to defaults.
        let empty = ini::Properties::default();
        let section = conf.section(Some("TRANSMISSION")).unwrap_or(&empty);

        Self {
            endpoint: section.get("MiddlewareEndpoint").unwrap_or("https://127.0.0.1:8443/api/v1/telemetry").to_string(),
            auth_token: section.get("AuthToken").unwrap_or("ChangeMe").to_string(),
            sensor_type: section.get("SensorType").unwrap_or("deepsensor").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("500").parse().unwrap_or(500),
            db_path: section.get("QueueDbPath").unwrap_or(r"C:\ProgramData\DeepSensor\Data\TransmissionQueue.db").to_string(),
            trust_self_signed: section.get("TrustSelfSignedCert").unwrap_or("False").eq_ignore_ascii_case("true"),
            integrity_secret: section.get("IntegritySecret").unwrap_or("Nexus-Integrity-SharedKey-Rotate-Me").to_string(),
        }
    }
}

// Mirrors Submit-SensorAlert's $alertObj (DeepSensor_Launcher.ps1) -- Sigma/TTP match fields
// plus the UEBA aggregation fields (count/avg_entropy/max_velocity/rate_per_sec/unique_tids).
pub struct EDRTelemetryRow {
    pub id: i64,
    pub event_id: String,
    pub timestamp: i64,   // Unix epoch milliseconds
    pub computer_name: String,
    pub sensor_user: String,
    pub host_ip: String,
    pub event_type: String,
    pub destination: String,
    pub image: String,
    pub command_line: String,
    pub suspicious_flags: String,
    pub matched_indicator: String,
    pub attck_mappings: String,
    pub confidence: i64,
    pub signature_name: String,
    pub tactic: String,
    pub technique: String,
    pub procedure: String,
    pub severity: String,
    pub action: String,
    pub count: i64,
    pub avg_entropy: f64,
    pub max_velocity: f64,
    pub rate_per_sec: f64,
    pub unique_tids: i64,
    pub payload_raw: String,
}

pub async fn start_transmission_worker<F>(config_path: String, mut rx: Receiver<Value>, mut log_cb: F)
where
    F: FnMut(String) + Send + Sync + 'static,
{
    let config = TransmissionConfig::load(&config_path);

    if let Some(parent) = Path::new(&config.db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let db_url = format!("sqlite://{}?mode=rwc", config.db_path);
    let pool = match SqlitePoolOptions::new()
        .max_connections(3)
        .connect(&db_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            log_cb(format!("[TRANSMISSION FATAL] Failed to mount EDR SQLite WAL: {}", e));
            return;
        }
    };

    let _ = sqlx::query(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS edr_ledger_queue (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             event_id TEXT,
             timestamp TEXT,
             computer_name TEXT,
             sensor_user TEXT,
             host_ip TEXT,
             event_type TEXT,
             destination TEXT,
             image TEXT,
             command_line TEXT,
             suspicious_flags TEXT,
             matched_indicator TEXT,
             attck_mappings TEXT,
             confidence INTEGER,
             signature_name TEXT,
             tactic TEXT,
             technique TEXT,
             procedure TEXT,
             severity TEXT,
             action TEXT,
             count INTEGER DEFAULT 1,
             avg_entropy REAL DEFAULT 0.0,
             max_velocity REAL DEFAULT 0.0,
             rate_per_sec REAL DEFAULT 0.0,
             unique_tids INTEGER DEFAULT 0,
             payload_raw TEXT
         );"
    ).execute(&pool).await;

    log_cb("[TRANSMISSION] Typed EDR SQLite WAL Durable Queue Mounted.".to_string());

    // -- Integrity: sequence counter + stamper --------------------------------
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS integrity_sequence (
            sensor_id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL DEFAULT 0
        )"
    ).execute(&pool).await;

    let sensor_id = format!("{}-deepsensor",
        std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string()));

    let initial_seq: u64 = sqlx::query("SELECT last_sequence FROM integrity_sequence WHERE sensor_id = ?")
        .bind(&sensor_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .map(|row| row.get::<i64, _>("last_sequence") as u64)
        .unwrap_or(0);

    let _ = sqlx::query("INSERT OR IGNORE INTO integrity_sequence (sensor_id, last_sequence) VALUES (?, ?)")
        .bind(&sensor_id)
        .bind(initial_seq as i64)
        .execute(&pool)
        .await;

    let mut stamper = LineageStamper::new(
        sensor_id.clone(), config.integrity_secret.as_bytes(), initial_seq
    );

    log_cb(format!("[INTEGRITY] Stamper online: sensor_id={}, seq={}", sensor_id, initial_seq));
    // -------------------------------------------------------------------------

    let pool_producer = pool.clone();

    // -------------------------------------------------------------------------
    // LOOP 1: JSON Destructuring & Local Persistence (Producer)
    // -------------------------------------------------------------------------
    tokio::spawn(async move {
        while let Some(alert) = rx.recv().await {
            let payload_str = alert.to_string();

            let event_id         = alert["EventID"].as_str().unwrap_or("");
            let timestamp         = alert["Timestamp_UTC"].as_str().unwrap_or("");
            let computer_name     = alert["ComputerName"].as_str().unwrap_or("");
            let sensor_user       = alert["SensorUser"].as_str().unwrap_or("");
            let host_ip           = alert["HostIP"].as_str().unwrap_or("");
            let event_type        = alert["EventType"].as_str().unwrap_or("");
            let destination       = alert["Destination"].as_str().unwrap_or("");
            let image             = alert["Image"].as_str().unwrap_or("");
            let command_line      = alert["CommandLine"].as_str().unwrap_or("");
            let suspicious_flags  = alert["SuspiciousFlags"].as_str().unwrap_or("");
            let matched_indicator = alert["MatchedIndicator"].as_str().unwrap_or("");
            let attck_mappings    = alert["ATTCKMappings"].as_str().unwrap_or("");
            let confidence        = alert["Confidence"].as_i64().unwrap_or(0);
            let signature_name    = alert["SignatureName"].as_str().unwrap_or("");
            let tactic             = alert["Tactic"].as_str().unwrap_or("");
            let technique          = alert["Technique"].as_str().unwrap_or("");
            let procedure          = alert["Procedure"].as_str().unwrap_or("");
            let severity            = alert["Severity"].as_str().unwrap_or("Medium");
            let action              = alert["Action"].as_str().unwrap_or("");
            let count               = alert["Count"].as_i64().unwrap_or(1);
            let avg_entropy         = alert["AvgEntropy"].as_f64().unwrap_or(0.0);
            let max_velocity        = alert["MaxVelocity"].as_f64().unwrap_or(0.0);
            let rate_per_sec        = alert["RatePerSec"].as_f64().unwrap_or(0.0);
            let unique_tids         = alert["UniqueTids"].as_i64().unwrap_or(0);

            let _ = sqlx::query(
                "INSERT INTO edr_ledger_queue (
                    event_id, timestamp, computer_name, sensor_user, host_ip, event_type,
                    destination, image, command_line, suspicious_flags, matched_indicator,
                    attck_mappings, confidence, signature_name, tactic, technique, procedure,
                    severity, action, count, avg_entropy, max_velocity, rate_per_sec,
                    unique_tids, payload_raw
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                          ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)"
            )
            .bind(event_id).bind(timestamp).bind(computer_name).bind(sensor_user).bind(host_ip)
            .bind(event_type).bind(destination).bind(image).bind(command_line).bind(suspicious_flags)
            .bind(matched_indicator).bind(attck_mappings).bind(confidence).bind(signature_name)
            .bind(tactic).bind(technique).bind(procedure).bind(severity).bind(action).bind(count)
            .bind(avg_entropy).bind(max_velocity).bind(rate_per_sec).bind(unique_tids).bind(payload_str)
            .execute(&pool_producer)
            .await;
        }
    });

    // -------------------------------------------------------------------------
    // LOOP 2: Parquet Micro-Batching & Gateway Forwarder (Consumer)
    // -------------------------------------------------------------------------
    let mut headers = header::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&format!("Bearer {}", config.auth_token)).unwrap());
    headers.insert("X-Sensor-Type", header::HeaderValue::from_str(&config.sensor_type).unwrap());
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/vnd.apache.parquet"));

    let mut client_builder = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(15));

    if config.trust_self_signed {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let client = client_builder.build().expect("Failed to build Transmission HTTP Client");
    let mut backoff = 1000;
    let mut flush_counter: u64 = 0;

    loop {
        let rows = match sqlx::query("SELECT * FROM edr_ledger_queue ORDER BY id ASC LIMIT ?")
            .bind(config.batch_size)
            .fetch_all(&pool)
            .await
        {
            Ok(r) => r,
            Err(_) => {
                sleep(Duration::from_millis(5000)).await;
                continue;
            }
        };

        if rows.is_empty() {
            backoff = 1000;
            sleep(Duration::from_millis(1000)).await;
            continue;
        }

        let mut batch = Vec::with_capacity(rows.len());
        let mut ids = Vec::with_capacity(rows.len());

        for row in rows {
            let id: i64 = row.get("id");
            ids.push(id);

            // Timestamp stored as ISO-8601 TEXT in SQLite; EDRTelemetryRow needs epoch_ms i64.
            let ts_raw: String = row.try_get("timestamp").unwrap_or_default();
            let ts_epoch_ms: i64 = chrono::DateTime::parse_from_rfc3339(&ts_raw)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());

            batch.push(EDRTelemetryRow {
                id,
                event_id:         row.get("event_id"),
                timestamp:        ts_epoch_ms,
                computer_name:    row.get("computer_name"),
                sensor_user:      row.get("sensor_user"),
                host_ip:          row.get("host_ip"),
                event_type:       row.get("event_type"),
                destination:      row.get("destination"),
                image:            row.get("image"),
                command_line:     row.get("command_line"),
                suspicious_flags: row.get("suspicious_flags"),
                matched_indicator:row.get("matched_indicator"),
                attck_mappings:   row.get("attck_mappings"),
                confidence:       row.get("confidence"),
                signature_name:   row.get("signature_name"),
                tactic:           row.get("tactic"),
                technique:        row.get("technique"),
                procedure:        row.get("procedure"),
                severity:         row.get("severity"),
                action:           row.get("action"),
                count:            row.try_get("count").unwrap_or(1),
                avg_entropy:      row.try_get("avg_entropy").unwrap_or(0.0),
                max_velocity:     row.try_get("max_velocity").unwrap_or(0.0),
                rate_per_sec:     row.try_get("rate_per_sec").unwrap_or(0.0),
                unique_tids:      row.try_get("unique_tids").unwrap_or(0),
                payload_raw:      row.get("payload_raw"),
            });
        }

        match parquet::serialize_to_parquet(&batch) {
            Ok(parquet_bytes) => {
                // -- Integrity: stamp + persist -----------------------
                let stamp = stamper.stamp(&parquet_bytes);
                let _ = sqlx::query(
                    "UPDATE integrity_sequence SET last_sequence = ? WHERE sensor_id = ?"
                )
                .bind(stamp.sequence as i64)
                .bind(&sensor_id)
                .execute(&pool)
                .await;

                let res = client.post(&config.endpoint)
                    .header(HDR_BATCH_SEQUENCE, stamp.sequence.to_string())
                    .header(HDR_BATCH_TIMESTAMP, stamp.timestamp.to_string())
                    .header(HDR_SENSOR_ID, &stamp.sensor_id)
                    .header(HDR_BATCH_HMAC, &stamp.hmac_hex)
                    .body(parquet_bytes)
                    .send()
                    .await;

                match res {
                    Ok(response) if response.status().is_success() => {
                        let id_list = ids.iter().map(|id| id.to_string()).collect::<Vec<String>>().join(",");
                        let _ = sqlx::query(&format!("DELETE FROM edr_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
                        log_cb(format!("[TRANSMISSION] Flushed {} EDR events via Parquet (seq={}).", ids.len(), stamp.sequence));
                        backoff = 1000;
                    }
                    Ok(response) if response.status() == reqwest::StatusCode::FORBIDDEN => {
                        log_cb("[INTEGRITY] Gateway returned 403 FORBIDDEN. Sensor may be banned. Halting.".to_string());
                        return;
                    }
                    Ok(response) => {
                        log_cb(format!("[TRANSMISSION WARN] Gateway rejected batch (HTTP {}). Retrying...", response.status()));
                        sleep(Duration::from_millis(backoff)).await;
                        if backoff < 60000 { backoff *= 2; }
                    }
                    Err(e) => {
                        log_cb(format!("[TRANSMISSION NETWORK ERROR] Axum unreachable: {}. Data safely queued in SQLite.", e));
                        sleep(Duration::from_millis(backoff)).await;
                        if backoff < 60000 { backoff *= 2; }
                    }
                }
            }
            Err(e) => {
                log_cb(format!("[TRANSMISSION FATAL] Parquet generation error: {}. Dropping corrupted batch.", e));
                let id_list = ids.iter().map(|id| id.to_string()).collect::<Vec<String>>().join(",");
                let _ = sqlx::query(&format!("DELETE FROM edr_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
            }
        }

        // -- Hourly WAL Maintenance (prevents unbounded disk growth) ---------
        flush_counter += 1;
        if flush_counter >= 3600 {
            let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)").execute(&pool).await;

            // Daily incremental vacuum in background thread (non-blocking)
            if flush_counter >= 86400 {
                let db_path_clone = config.db_path.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(conn) = rusqlite::Connection::open(&db_path_clone) {
                        let _ = conn.execute_batch("PRAGMA busy_timeout=30000;");
                        let mut freed = 1;
                        while freed > 0 {
                            match conn.query_row("PRAGMA incremental_vacuum(100);", [], |r| r.get::<_, i32>(0)) {
                                Ok(p) => freed = p,
                                Err(_) => break,
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                });
                flush_counter = 0;
            }
        }
    }
}
