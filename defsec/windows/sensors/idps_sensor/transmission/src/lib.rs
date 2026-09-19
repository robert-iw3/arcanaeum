/*=============================================================================================
 * SYSTEM:          IDPS Sensor - Transmission Layer
 * COMPONENT:       lib.rs (Durable SQLite WAL to Parquet Forwarder)
 * DESCRIPTION:
 * Subscribes to the sensor's alert channel, writes bi-directional network events securely to a
 * local SQLite WAL (DeepLedger), and asynchronously micro-batches rows into ZSTD-compressed
 * Parquet buffers for the Axum Zero-Trust Gateway. Schema mirrors IDPS telemetry (ingress+egress).
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
use std::sync::Arc;
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
            sensor_type: section.get("SensorType").unwrap_or("idpssensor").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("500").parse().unwrap_or(500),
            db_path: section.get("QueueDbPath").unwrap_or(r"C:\ProgramData\IDPSSensor\Data\TransmissionQueue.db").to_string(),
            trust_self_signed: section.get("TrustSelfSignedCert").unwrap_or("False").eq_ignore_ascii_case("true"),
            integrity_secret: section.get("IntegritySecret").unwrap_or("Nexus-Integrity-SharedKey-Rotate-Me").to_string(),
        }
    }
}

// Bi-directional IDPS network telemetry row (ingress + egress).
pub struct IDPSTelemetryRow {
    pub id: i64,
    pub event_id: String,
    pub timestamp: i64,          // Unix epoch milliseconds
    pub computer_name: String,
    pub sensor_user: String,
    pub host_ip: String,
    pub provider: String,        // ETW provider
    pub event_name: String,
    pub direction: String,       // ingress / egress / lateral
    pub source_ip: String,
    pub destination: String,
    pub port: String,
    pub query: String,           // DNS query
    pub size: i64,               // bytes
    pub image: String,           // process image
    pub command_line: String,
    pub pid: String,
    pub event_type: String,
    pub threat_intel: String,
    pub suspicious_flags: String,
    pub attck_mappings: String,
    pub confidence: i64,
    pub action: String,
    pub payload_raw: String,
}

pub async fn start_transmission_worker<F>(config_path: String, mut rx: Receiver<Arc<Value>>, mut log_cb: F)
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
            log_cb(format!("[TRANSMISSION FATAL] Failed to mount IDPS SQLite WAL: {}", e));
            return;
        }
    };

    let _ = sqlx::query(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS idps_ledger_queue (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             event_id TEXT,
             timestamp TEXT,
             computer_name TEXT,
             sensor_user TEXT,
             host_ip TEXT,
             provider TEXT,
             event_name TEXT,
             direction TEXT,
             source_ip TEXT,
             destination TEXT,
             port TEXT,
             query TEXT,
             size INTEGER DEFAULT 0,
             image TEXT,
             command_line TEXT,
             pid TEXT,
             event_type TEXT,
             threat_intel TEXT,
             suspicious_flags TEXT,
             attck_mappings TEXT,
             confidence INTEGER,
             action TEXT,
             payload_raw TEXT
         );"
    ).execute(&pool).await;

    log_cb("[TRANSMISSION] Typed IDPS SQLite WAL Durable Queue Mounted.".to_string());

    // -- Integrity: sequence counter + stamper --------------------------------
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS integrity_sequence (
            sensor_id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL DEFAULT 0
        )"
    ).execute(&pool).await;

    let sensor_id = format!("{}-idpssensor",
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

            // Accept both alert-schema and raw-telemetry field names for each column.
            let s = |keys: &[&str]| -> String {
                for k in keys {
                    if let Some(v) = alert[*k].as_str() { if !v.is_empty() { return v.to_string(); } }
                }
                String::new()
            };
            let num = |keys: &[&str]| -> i64 {
                for k in keys {
                    if let Some(n) = alert[*k].as_i64() { return n; }
                    if let Some(v) = alert[*k].as_str() { if let Ok(n) = v.parse::<i64>() { return n; } }
                }
                0
            };

            let event_id         = s(&["EventID", "event_id"]);
            let timestamp        = s(&["Timestamp_UTC", "TimeStamp", "timestamp"]);
            let computer_name    = s(&["ComputerName", "host"]);
            let sensor_user      = s(&["SensorUser", "user"]);
            let host_ip          = s(&["HostIP", "host_ip"]);
            let provider         = s(&["Provider"]);
            let event_name       = s(&["EventName"]);
            let direction        = s(&["Direction", "TrafficDirection"]);
            let source_ip        = s(&["SourceIp", "SrcIp"]);
            let destination      = s(&["Destination", "DestIp"]);
            let port             = s(&["Port"]);
            let query            = s(&["Query"]);
            let size             = num(&["Size"]);
            let image            = s(&["Image"]);
            let command_line     = s(&["CommandLine"]);
            let pid              = s(&["PID"]);
            let event_type       = s(&["EventType"]);
            let threat_intel     = s(&["ThreatIntel"]);
            let suspicious_flags = s(&["SuspiciousFlags", "alert_reason"]);
            let attck_mappings   = s(&["ATTCKMappings"]);
            let confidence       = num(&["Confidence", "confidence"]);
            let action           = s(&["Action"]);

            let _ = sqlx::query(
                "INSERT INTO idps_ledger_queue (
                    event_id, timestamp, computer_name, sensor_user, host_ip, provider, event_name,
                    direction, source_ip, destination, port, query, size, image, command_line, pid,
                    event_type, threat_intel, suspicious_flags, attck_mappings, confidence, action, payload_raw
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                          ?17, ?18, ?19, ?20, ?21, ?22, ?23)"
            )
            .bind(event_id).bind(timestamp).bind(computer_name).bind(sensor_user).bind(host_ip)
            .bind(provider).bind(event_name).bind(direction).bind(source_ip).bind(destination)
            .bind(port).bind(query).bind(size).bind(image).bind(command_line).bind(pid)
            .bind(event_type).bind(threat_intel).bind(suspicious_flags).bind(attck_mappings)
            .bind(confidence).bind(action).bind(payload_str)
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
        let rows = match sqlx::query("SELECT * FROM idps_ledger_queue ORDER BY id ASC LIMIT ?")
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

            // Timestamp stored as ISO-8601 TEXT in SQLite; row needs epoch_ms i64.
            let ts_raw: String = row.try_get("timestamp").unwrap_or_default();
            let ts_epoch_ms: i64 = chrono::DateTime::parse_from_rfc3339(&ts_raw)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());

            batch.push(IDPSTelemetryRow {
                id,
                event_id:         row.get("event_id"),
                timestamp:        ts_epoch_ms,
                computer_name:    row.get("computer_name"),
                sensor_user:      row.get("sensor_user"),
                host_ip:          row.get("host_ip"),
                provider:         row.get("provider"),
                event_name:       row.get("event_name"),
                direction:        row.get("direction"),
                source_ip:        row.get("source_ip"),
                destination:      row.get("destination"),
                port:             row.get("port"),
                query:            row.get("query"),
                size:             row.try_get("size").unwrap_or(0),
                image:            row.get("image"),
                command_line:     row.get("command_line"),
                pid:              row.get("pid"),
                event_type:       row.get("event_type"),
                threat_intel:     row.get("threat_intel"),
                suspicious_flags: row.get("suspicious_flags"),
                attck_mappings:   row.get("attck_mappings"),
                confidence:       row.get("confidence"),
                action:           row.get("action"),
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
                        let _ = sqlx::query(&format!("DELETE FROM idps_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
                        log_cb(format!("[TRANSMISSION] Flushed {} IDPS events via Parquet (seq={}).", ids.len(), stamp.sequence));
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
                let _ = sqlx::query(&format!("DELETE FROM idps_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
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
