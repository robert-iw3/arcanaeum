// ==============================================================================
// File:        baselines.rs
// Component:   Linux Sentinel — ML State Persistence
// Description: Persistent ML/UEBA state management via SQLite WAL.
//              Ensures execution profiles and Isolation Forest vectors survive
//              container restarts to track long-tail behavioral anomalies.
// Author:      Robert Weber
// ==============================================================================

use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row};
use tracing::{info, error};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct BaselineStore {
    pool: Pool<Sqlite>,
}

impl BaselineStore {
    pub async fn new(db_path: &PathBuf) -> anyhow::Result<Self> {
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _meta| Box::pin(async move {
                use sqlx::Executor;
                conn.execute("PRAGMA journal_mode=WAL;").await?;
                conn.execute("PRAGMA synchronous=NORMAL;").await?;
                conn.execute("PRAGMA busy_timeout=5000;").await?;
                Ok(())
            }))
            .connect(&db_url)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ueba_process_profiles (
                process_hash TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                event_count INTEGER,
                mean_delta REAL,
                m2_delta REAL,
                mean_payload_entropy REAL,
                m2_payload_entropy REAL,
                ewma_timing_slow REAL,
                ewma_timing_fast REAL,
                ewma_entropy_slow REAL,
                ewma_entropy_fast REAL,
                ewma_timing_var_slow REAL DEFAULT 0.0,
                ewma_entropy_var_slow REAL DEFAULT 0.0,
                last_seen_ns INTEGER,
                serialized_recent_events TEXT
            );
            CREATE TABLE IF NOT EXISTS isolation_forest_vectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                f1 REAL, f2 REAL, f3 REAL, f4 REAL, f5 REAL,
                f6 REAL, f7 REAL, f8 REAL, f9 REAL, f10 REAL,
                f11 REAL, f12 REAL, f13 REAL, f14 REAL, f15 REAL,
                f16 REAL, f17 REAL, f18 REAL, f19 REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ueba_role_profiles (
                binary_name TEXT PRIMARY KEY,
                instance_count INTEGER,
                mean_timing REAL,
                m2_timing REAL,
                mean_entropy REAL,
                m2_entropy REAL,
                max_velocity REAL,
                serialized_transitions TEXT
            );
            "#
        )
        .execute(&pool)
        .await?;

        let _ = sqlx::query("ALTER TABLE ueba_process_profiles ADD COLUMN ewma_timing_var_slow REAL DEFAULT 0.0")
            .execute(&pool).await;
        let _ = sqlx::query("ALTER TABLE ueba_process_profiles ADD COLUMN ewma_entropy_var_slow REAL DEFAULT 0.0")
            .execute(&pool).await;

        info!("Persistent UEBA baseline store initialized.");
        Ok(Self { pool })
    }

    /// Fetches the most recent feature vectors for Isolation Forest Warm-Starts
    pub async fn get_recent_vectors(&self, limit: usize) -> anyhow::Result<Vec<[f64; 19]>> {
        let rows = sqlx::query(
            "SELECT
                f1, f2, f3, f4, f5, f6, f7, f8, f9, f10,
                f11, f12, f13, f14, f15, f16, f17, f18, f19
             FROM isolation_forest_vectors ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut vectors = Vec::with_capacity(rows.len());
        for row in rows {
            vectors.push([
                row.try_get("f1")?, row.try_get("f2")?, row.try_get("f3")?, row.try_get("f4")?, row.try_get("f5")?,
                row.try_get("f6")?, row.try_get("f7")?, row.try_get("f8")?, row.try_get("f9")?, row.try_get("f10")?,
                row.try_get("f11")?, row.try_get("f12")?, row.try_get("f13")?, row.try_get("f14")?, row.try_get("f15")?,
                row.try_get("f16")?, row.try_get("f17")?, row.try_get("f18")?, row.try_get("f19")?
            ]);
        }
        Ok(vectors)
    }

    /// Persists a batch of 5D vectors in a single transaction
    pub async fn save_vectors_batch(&self, batch: &[[f64; 19]]) {
        if batch.is_empty() { return; }

        let mut tx = match self.pool.begin().await {
            Ok(tx) => tx,
            Err(e) => { error!("Failed to begin SQLite transaction: {}", e); return; }
        };

        for vector in batch {
            let result = sqlx::query(
                "INSERT INTO isolation_forest_vectors (
                    f1, f2, f3, f4, f5, f6, f7, f8, f9, f10,
                    f11, f12, f13, f14, f15, f16, f17, f18, f19
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(vector[0]).bind(vector[1]).bind(vector[2]).bind(vector[3]).bind(vector[4])
            .bind(vector[5]).bind(vector[6]).bind(vector[7]).bind(vector[8]).bind(vector[9])
            .bind(vector[10]).bind(vector[11]).bind(vector[12]).bind(vector[13]).bind(vector[14])
            .bind(vector[15]).bind(vector[16]).bind(vector[17]).bind(vector[18])
            .execute(&mut *tx).await;

            if let Err(e) = result {
                error!("Failed to persist Isolation Forest vector: {}", e);
            }
        }
        let _ = tx.commit().await;
    }

    /// Bulk-loads persisted Welford profiles into memory on startup
    pub async fn load_profiles(&self) -> anyhow::Result<HashMap<String, (u64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, u64, String)>> {
        let rows = sqlx::query(
            "SELECT process_hash, event_count, mean_delta, m2_delta, \
             mean_payload_entropy, m2_payload_entropy, \
             ewma_timing_slow, ewma_timing_fast, \
             ewma_entropy_slow, ewma_entropy_fast, \
             ewma_timing_var_slow, ewma_entropy_var_slow, \
             last_seen_ns, serialized_recent_events \
             FROM ueba_process_profiles"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut profiles = HashMap::with_capacity(rows.len());
        for row in rows {
            let hash: String = row.try_get("process_hash")?;
            profiles.insert(hash, (
                row.try_get::<i64, _>("event_count")? as u64,
                row.try_get("mean_delta")?,
                row.try_get("m2_delta")?,
                row.try_get("mean_payload_entropy")?,
                row.try_get("m2_payload_entropy")?,
                row.try_get("ewma_timing_slow")?,
                row.try_get("ewma_timing_fast")?,
                row.try_get("ewma_entropy_slow")?,
                row.try_get("ewma_entropy_fast")?,
                row.try_get::<f64, _>("ewma_timing_var_slow").unwrap_or(0.0),
                row.try_get::<f64, _>("ewma_entropy_var_slow").unwrap_or(0.0),
                row.try_get::<i64, _>("last_seen_ns")? as u64,
                row.try_get("serialized_recent_events")?,
            ));
        }
        info!("Loaded {} persistent UEBA profiles from disk.", profiles.len());
        Ok(profiles)
    }

    /// Flushes active Welford profiles to SQLite via UPSERT
    pub async fn flush_profiles(&self, endpoint_id: &str, profiles: &HashMap<String, (u64, f64, f64, f64, f64, f64, f64, f64, f64, f64, f64, u64, String)>) {
        for (hash, (count, mean, m2, m_ent, m2_ent, t_slow, t_fast, e_slow, e_fast, tv_slow, ev_slow, last_ns, recent)) in profiles {
            let result = sqlx::query(
                "INSERT INTO ueba_process_profiles (
                    process_hash, endpoint_id, event_count, mean_delta, m2_delta,
                    mean_payload_entropy, m2_payload_entropy,
                    ewma_timing_slow, ewma_timing_fast,
                    ewma_entropy_slow, ewma_entropy_fast,
                    ewma_timing_var_slow, ewma_entropy_var_slow,
                    last_seen_ns, serialized_recent_events
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(process_hash) DO UPDATE SET
                    endpoint_id = excluded.endpoint_id,
                    event_count = excluded.event_count,
                    mean_delta = excluded.mean_delta,
                    m2_delta = excluded.m2_delta,
                    mean_payload_entropy = excluded.mean_payload_entropy,
                    m2_payload_entropy = excluded.m2_payload_entropy,
                    ewma_timing_slow = excluded.ewma_timing_slow,
                    ewma_timing_fast = excluded.ewma_timing_fast,
                    ewma_entropy_slow = excluded.ewma_entropy_slow,
                    ewma_entropy_fast = excluded.ewma_entropy_fast,
                    ewma_timing_var_slow = excluded.ewma_timing_var_slow,
                    ewma_entropy_var_slow = excluded.ewma_entropy_var_slow,
                    last_seen_ns = excluded.last_seen_ns,
                    serialized_recent_events = excluded.serialized_recent_events"
            )
            .bind(hash)
            .bind(endpoint_id)
            .bind(*count as i64)
            .bind(mean)
            .bind(m2)
            .bind(m_ent)
            .bind(m2_ent)
            .bind(t_slow)
            .bind(t_fast)
            .bind(e_slow)
            .bind(e_fast)
            .bind(tv_slow)
            .bind(ev_slow)
            .bind(*last_ns as i64)
            .bind(recent)
            .execute(&self.pool).await;

            if let Err(e) = result {
                error!("Failed to persist UEBA profile {}: {}", hash, e);
            }
        }
    }

    /// Flushes global binary role profiles to SQLite
    pub async fn flush_role_profiles(&self, profiles: &HashMap<String, (u64, f64, f64, f64, f64, f64, String)>) {
        for (binary, (count, m_time, m2_time, m_ent, m2_ent, max_vel, trans_json)) in profiles {
            let res = sqlx::query(
                "INSERT INTO ueba_role_profiles (
                    binary_name, instance_count, mean_timing, m2_timing,
                    mean_entropy, m2_entropy, max_velocity, serialized_transitions
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(binary_name) DO UPDATE SET
                    instance_count = excluded.instance_count,
                    mean_timing = excluded.mean_timing,
                    m2_timing = excluded.m2_timing,
                    mean_entropy = excluded.mean_entropy,
                    m2_entropy = excluded.m2_entropy,
                    max_velocity = excluded.max_velocity,
                    serialized_transitions = excluded.serialized_transitions"
            )
            .bind(binary)
            .bind(*count as i64)
            .bind(m_time).bind(m2_time).bind(m_ent).bind(m2_ent).bind(max_vel)
            .bind(trans_json)
            .execute(&self.pool).await;

            if let Err(e) = res {
                    error!("Failed to flush role profile {}: {}", binary, e);
            }
        }
    }

    /// Loads global binary role profiles from SQLite on startup
    pub async fn load_role_profiles(&self) -> anyhow::Result<HashMap<String, (u64, f64, f64, f64, f64, f64, String)>> {
        let rows = sqlx::query(
            "SELECT binary_name, instance_count, mean_timing, m2_timing,
             mean_entropy, m2_entropy, max_velocity, serialized_transitions
             FROM ueba_role_profiles"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut profiles = HashMap::with_capacity(rows.len());
        for row in rows {
            let binary: String = row.try_get("binary_name")?;
            profiles.insert(binary, (
                row.try_get::<i64, _>("instance_count")? as u64,
                row.try_get("mean_timing")?,
                row.try_get("m2_timing")?,
                row.try_get("mean_entropy")?,
                row.try_get("m2_entropy")?,
                row.try_get("max_velocity")?,
                row.try_get("serialized_transitions")?,
            ));
        }
        info!("Loaded {} global role profiles from disk.", profiles.len());
        Ok(profiles)
    }
}