/*=============================================================================================
 * SYSTEM:          IDPS Sensor
 * COMPONENT:       lib.rs (Native FFI Behavioral ML Engine)
 * AUTHOR:          Robert Weber
 * * DESCRIPTION:
 * Native CDYLIB for anomalous flow detection. Monitors bidirectional Ingress/Egress
 * volumetric deviations, data asymmetry, and micro-bursting using K-Means and DBSCAN
 * spatial clustering.
 *============================================================================================*/

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

// Linfa Machine Learning Imports
use linfa::traits::{Fit, Predict, Transformer};
use linfa::Dataset;
use linfa_clustering::{Dbscan, KMeans};
use linfa_nn::distance::L2Dist;
use ndarray::{Array2, ArrayBase, OwnedRepr, Dim, Axis};
use rand::thread_rng;

// Heuristics Imports
use regex::Regex;

// Diagnostic Logging
use std::panic;
use std::backtrace::Backtrace;
use std::fs::OpenOptions;
use std::io::Write;

// ============================================================================
// DATA STRUCTURES (FFI BOUNDARY CONTRACTS)
// ============================================================================

#[derive(Deserialize, Debug, Clone)]
pub struct IncomingTelemetry {
    pub key: String,
    pub src_ip: String,
    pub dst_ips: Vec<String>,
    pub domain: Option<String>,
    pub direction: String,
    pub intervals: Vec<f64>,
    pub packet_sizes: Vec<f64>,
    pub asymmetry_ratio: Option<f64>,
    pub sparsity_index: Option<f64>,
    pub ttls: Option<Vec<i32>>,
    pub asns: Option<Vec<i32>>,
    pub payload_entropies: Option<Vec<f64>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct OutgoingAlert {
    pub key: String,
    pub alert_reason: String,
    pub confidence: f64,
}

#[derive(Serialize, Debug)]
struct OutgoingResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<Vec<OutgoingAlert>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_error: Option<String>,
}

// ============================================================================
// HEURISTICS ENGINE (DGA, ENTROPY, FAST-FLUX)
// ============================================================================

pub struct ThreatHeuristics {
    regex_trailing_digits: Regex,
    regex_hex_pattern: Regex,
}

impl ThreatHeuristics {
    pub fn new() -> Self {
        ThreatHeuristics {
            regex_trailing_digits: Regex::new(r"[a-z]{6,}[0-9]{2,5}$").unwrap(),
            regex_hex_pattern: Regex::new(r"^[a-f0-9]+$").unwrap(),
        }
    }

    pub fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts: HashMap<char, usize> = HashMap::new();
        for c in data.chars() { *counts.entry(c).or_insert(0) += 1; }
        let total_chars = counts.values().sum::<usize>() as f64;
        counts.values().fold(0.0, |acc, &count| {
            let p = count as f64 / total_chars;
            acc - (p * p.log2())
        })
    }

    pub fn detect_dga(&self, domain: &str) -> (bool, f64, String) {
        if domain.is_empty() || domain.len() < 6 { return (false, 0.0, String::new()); }

        let domain_lower = domain.to_lowercase();
        let parts: Vec<&str> = domain_lower.split('.').collect();
        let label = if parts.len() > 1 { parts[0] } else { &domain_lower };

        let entropy = Self::shannon_entropy(label);
        let length = label.len();

        let consonant_count = label.chars().filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c)).count();
        let cons_ratio = consonant_count as f64 / std::cmp::max(1, length) as f64;
        let hyphen_count = label.chars().filter(|&c| c == '-').count();

        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        if entropy > 3.8 { score += 45.0; reasons.push(format!("high_entropy({:.2})", entropy)); }
        if cons_ratio > 0.75 { score += 30.0; reasons.push("consonant_heavy".to_string()); }
        if entropy < 3.6 && length >= 15 {
            if hyphen_count >= 2 { score += 55.0; reasons.push(format!("dict_dga_hyphens({})", hyphen_count)); }
            if self.regex_trailing_digits.is_match(label) { score += 40.0; reasons.push("dict_dga_trailing_digits".to_string()); }
        }
        if self.regex_hex_pattern.is_match(label) && length >= 12 { score += 60.0; reasons.push("hex_dga_pattern".to_string()); }

        let is_dga = score >= 65.0;
        (is_dga, score.min(95.0), reasons.join("; "))
    }

    pub fn normalize_cidr(ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]) // IPv4 /24
        } else {
            ip.to_string() // Fallback IPv6
        }
    }

    pub fn detect_fast_flux(ips: &[String], ttls: Option<&[i32]>, asns: Option<&[i32]>) -> (bool, f64, String) {
        if ips.len() < 3 { return (false, 0.0, "insufficient_data".to_string()); }

        let unique_ips: Vec<_> = ips.iter().cloned().collect::<std::collections::HashSet<_>>().into_iter().collect();
        let unique_count = unique_ips.len();

        let avg_ttl = ttls.map(|t| if !t.is_empty() { t.iter().sum::<i32>() as f64 / t.len() as f64 } else { 300.0 }).unwrap_or(300.0);

        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        if unique_count >= 3 { score += 35.0; reasons.push(format!("high_churn({})", unique_count)); }
        if avg_ttl < 200.0 { score += 20.0; reasons.push(format!("low_ttl({:.0}s)", avg_ttl)); }

        if let Some(asn_list) = asns {
            let unique_asns: std::collections::HashSet<_> = asn_list.iter().cloned().collect();
            let asn_diversity = unique_asns.len() as f64 / unique_count as f64;
            if unique_asns.len() >= 3 && asn_diversity > 0.25 {
                score += 55.0; reasons.push(format!("botnet_asn_dispersion({}_ASNs)", unique_asns.len()));
            } else if unique_asns.len() <= 2 && unique_count > 6 {
                score -= 35.0; reasons.push("likely_cdn_infrastructure".to_string());
            }
        } else {
            let mut unique_subnets = Vec::new();
            for ip in ips {
                let subnet = Self::normalize_cidr(ip);
                if !unique_subnets.contains(&subnet) { unique_subnets.push(subnet); }
            }
            if unique_subnets.len() >= 2 {
                score += 45.0; reasons.push("multi_subnet_dispersion".to_string());
            }
        }

        let is_ff = score >= 55.0;
        (is_ff, score.clamp(0.0, 95.0), reasons.join("; "))
    }
}

// ============================================================================
// MATHEMATICAL CLUSTERING ENGINE (4D K-Means & DBSCAN)
// ============================================================================

pub struct MathEngine;

impl MathEngine {
    pub fn calculate_mean_std(data: &[f64]) -> (f64, f64) {
        if data.is_empty() { return (0.0, 0.0); }
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let variance = data.iter().map(|value| {
            let diff = mean - *value;
            diff * diff
        }).sum::<f64>() / data.len() as f64;
        (mean, variance.sqrt())
    }

    pub fn calculate_skewness(data: &[f64], mean: f64, std_dev: f64) -> f64 {
        if data.len() < 3 || std_dev == 0.0 { return 0.0; }
        let n = data.len() as f64;
        let sum_cubes: f64 = data.iter().map(|&x| (x - mean).powi(3)).sum();
        (n / ((n - 1.0) * (n - 2.0))) * (sum_cubes / std_dev.powi(3))
    }

    pub fn standard_scaler(matrix: &mut Array2<f64>) {
        // Native Z-Score normalization replicating sklearn.preprocessing.StandardScaler
        for mut column in matrix.columns_mut() {
            // Collect directly into a Vec to bypass non-contiguous memory slicing failures
            let vec: Vec<f64> = column.iter().cloned().collect();
            let (mean, std_dev) = Self::calculate_mean_std(&vec);
            if std_dev > 0.0 {
                column.mapv_inplace(|x| (x - mean) / std_dev);
            } else {
                column.mapv_inplace(|x| x - mean);
            }
        }
    }

    fn euclidean_distance(a: &ArrayBase<OwnedRepr<f64>, Dim<[usize; 1]>>, b: &ArrayBase<OwnedRepr<f64>, Dim<[usize; 1]>>) -> f64 {
        let mut sum = 0.0;
        for i in 0..a.len() {
            let diff = a[i] - b[i];
            sum += diff * diff;
        }
        sum.sqrt()
    }

    // Identical to sklearn.metrics.silhouette_score
    pub fn compute_silhouette(dataset: &Array2<f64>, labels: &[usize], k: usize) -> f64 {
        let n_samples = dataset.nrows();
        if n_samples < 2 || k < 2 || k >= n_samples { return -1.0; }

        let mut silhouette_sum = 0.0;
        for i in 0..n_samples {
            let point = dataset.row(i).to_owned();
            let label_i = labels[i];

            let mut a_sum = 0.0;
            let mut a_count = 0;
            let mut cluster_dists = vec![(0.0, 0_usize); k];

            for j in 0..n_samples {
                if i == j { continue; }
                let dist = Self::euclidean_distance(&point, &dataset.row(j).to_owned());
                let label_j = labels[j];

                if label_i == label_j {
                    a_sum += dist; a_count += 1;
                } else {
                    cluster_dists[label_j].0 += dist; cluster_dists[label_j].1 += 1;
                }
            }

            let a_i = if a_count > 0 { a_sum / a_count as f64 } else { 0.0 };
            let mut b_min = f64::MAX;

            for c in 0..k {
                if c != label_i && cluster_dists[c].1 > 0 {
                    let mean_dist = cluster_dists[c].0 / cluster_dists[c].1 as f64;
                    if mean_dist < b_min { b_min = mean_dist; }
                }
            }

            let s_i = if a_i < b_min { 1.0 - (a_i / b_min) }
                      else if a_i > b_min { (b_min / a_i) - 1.0 }
                      else { 0.0 };
            silhouette_sum += s_i;
        }
        silhouette_sum / n_samples as f64
    }

    pub fn calculate_dynamic_eps(dataset: &Array2<f64>, k_neighbors: usize) -> f64 {
        // Brute force K-NN to find the 90th percentile distance to the k-th nearest neighbor
        let n_samples = dataset.nrows();
        if n_samples == 0 { return 0.1; }

        let mut kth_distances = Vec::with_capacity(n_samples);
        for i in 0..n_samples {
            let point = dataset.row(i).to_owned();
            let mut dists = Vec::with_capacity(n_samples);
            for j in 0..n_samples {
                if i == j { continue; }
                dists.push(Self::euclidean_distance(&point, &dataset.row(j).to_owned()));
            }
            dists.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let k_idx = std::cmp::min(k_neighbors, dists.len().saturating_sub(1));
            kth_distances.push(dists[k_idx]);
        }

        kth_distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p90_idx = (kth_distances.len() as f64 * 0.90) as usize;
        let eps = kth_distances[std::cmp::min(p90_idx, kth_distances.len().saturating_sub(1))];
        eps.max(0.1) // Minimum floor
    }
}

// ============================================================================
// CORE BEHAVIORAL ENGINE
// ============================================================================

pub struct BehavioralEngine {
    conn: Connection,
    heuristics: ThreatHeuristics,
    last_groom_time: f64,
    tx: mpsc::Sender<Arc<serde_json::Value>>,
    _rt: Runtime,
}

impl BehavioralEngine {
    fn new(tx: mpsc::Sender<Arc<serde_json::Value>>, rt: Runtime) -> Self {
        let secure_dir = r"C:\ProgramData\IDPSSensor\Data";
        let _ = std::fs::create_dir_all(secure_dir);
        let db_path = format!(r"{}\IDPS_State.db", secure_dir);

        let conn = Connection::open(&db_path).unwrap_or_else(|_| {
            Connection::open_in_memory().expect("CRITICAL: Failed to initialize both disk and in-memory SQLite instances")
        });

        let _ = conn.execute("PRAGMA journal_mode = WAL", []);

        conn.execute_batch("
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 4294967296;
            PRAGMA wal_autocheckpoint = 1000;
        ").expect("Failed to apply performance pragmas");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS volumetric_flow_state (
                context_hash TEXT PRIMARY KEY,
                source_ip TEXT,
                destination_ip TEXT,
                direction TEXT,
                domain TEXT,
                packet_sizes TEXT,
                timestamps TEXT,
                last_seen REAL
            )",
            []
        ).expect("Failed to initialize state schema");

        if let Err(e) = conn.execute_batch("
            PRAGMA wal_checkpoint(FULL);
            PRAGMA optimize;
            VACUUM;
        ") {
            eprintln!("[DB MAINTENANCE WARN] Optimization failed: {}", e);
        }

        BehavioralEngine {
            conn,
            heuristics: ThreatHeuristics::new(),
            last_groom_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
            tx,
            _rt: rt,
        }
    }

    pub fn evaluate_flow(&mut self, flow: IncomingTelemetry) -> Option<OutgoingAlert> {
        // ========================================================================
        // STAGE 1: THE HEURISTIC GATE (2-Packet Minimum)
        // ========================================================================
        // Allows standard DNS (Query/Response) and quick API checks to be evaluated
        // without polluting the heavy Volumetric ML calculations later.
        if flow.intervals.len() < 2 || flow.packet_sizes.len() < 2 {
            return None;
        }

        // Prevent NaN/Infinity crashes in standard deviation calculations
        let has_invalid_math = flow.intervals.iter().any(|&x| x.is_nan() || x.is_infinite()) ||
                               flow.packet_sizes.iter().any(|&x| x.is_nan() || x.is_infinite());

        if has_invalid_math {
            return None;
        }

        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Index Maintenance
        if now_sec - self.last_groom_time > 3600.0 {
            // Drop flows older than 12 hours (43200 seconds) to maintain O(1) B-Tree lookups
            let stale_threshold = now_sec - 43200.0;
            let _ = self.conn.execute(
                "DELETE FROM volumetric_flow_state WHERE last_seen < ?1",
                params![stale_threshold],
            );

            // Analyze tables and update query planning statistics
            let _ = self.conn.execute_batch("PRAGMA optimize;");

            self.last_groom_time = now_sec;
        }

        let dest_ip = flow.dst_ips.last().cloned().unwrap_or_default();
        let domain = flow.domain.clone().unwrap_or_default();
        let packet_sizes_str = serde_json::to_string(&flow.packet_sizes).unwrap_or_else(|_| "[]".to_string());
        let intervals_str = serde_json::to_string(&flow.intervals).unwrap_or_else(|_| "[]".to_string());
        let last_seen = now_sec;

        // ------------------------------------------------------------------------
        // TRUE UPSERT (Live State Tracker)
        // Highly optimized: updates columns in place rather than deleting/re-inserting.
        // This eliminates index churn while logging all flows >= 2 packets.
        // ------------------------------------------------------------------------
        let _ = self.conn.execute(
            "INSERT INTO volumetric_flow_state
            (context_hash, source_ip, destination_ip, direction, domain, packet_sizes, timestamps, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(context_hash) DO UPDATE SET
                packet_sizes = excluded.packet_sizes,
                timestamps = excluded.timestamps,
                last_seen = excluded.last_seen",
            params![&flow.key, flow.src_ip, dest_ip, flow.direction, domain, packet_sizes_str, intervals_str, last_seen],
        );

        // Initialize variables early so they can be leveraged across both stages
        let mut flags = Vec::new();
        let mut apt_score_multiplier = 0.0;

        // 1a. Fast-Path Heuristics (DGA & Fast-Flux)
        // Executed immediately so short-lived 2-packet DNS traffic is not missed.
        if let Some(ref d) = flow.domain {
            let (is_dga, _score, reason) = self.heuristics.detect_dga(d);
            if is_dga {
                flags.push(format!("DGA: {}", reason));
                apt_score_multiplier += 1.5;
            }
        }

        if flow.dst_ips.len() >= 3 {
            let (is_ff, _score, reason) = ThreatHeuristics::detect_fast_flux(
                &flow.dst_ips, flow.ttls.as_deref(), flow.asns.as_deref()
            );
            if is_ff {
                flags.push(format!("FAST_FLUX: {}", reason));
                apt_score_multiplier += 1.5;
            }
        }

        // ========================================================================
        // STAGE 2: THE VOLUMETRIC ML GATE (8-Packet Minimum)
        // ========================================================================
        let n_intervals = flow.intervals.len();

        if n_intervals < 8 {
            // Flow is too short for meaningful K-Means/DBSCAN clustering.
            // If DGA/Fast-Flux triggered above, generate the alert immediately.
            if !flags.is_empty() {
                return Some(OutgoingAlert {
                    key: flow.key,
                    alert_reason: flags.join("; "),
                    // Fix E0689: Explicitly define the float types so the compiler knows it's an f64
                    confidence: (85.0_f64 + apt_score_multiplier).clamp(0.0_f64, 98.0_f64).round(),
                });
            }
            // Otherwise, exit safely without executing heavy math on small flows.
            return None;
        }

        // --- At this point, flow is >= 8 packets. Proceed with Volumetric ML ---
        let observed_duration: f64 = flow.intervals.iter().sum();
        let (mean_int, std_int) = MathEngine::calculate_mean_std(&flow.intervals);
        let (mean_size, std_size) = MathEngine::calculate_mean_std(&flow.packet_sizes);
        let cv_size = if mean_size > 0.0 { std_size / mean_size } else { 0.0 };

        // 1. DIRECTIONAL VOLUMETRIC HEURISTICS
        let is_ingress = flow.direction.eq_ignore_ascii_case("Ingress");
        let is_egress = flow.direction.eq_ignore_ascii_case("Egress");

        // 1.1. Massive Payload Spikes (Volumetric Deviation)
        // High Coefficient of Variation in packet sizes indicates a sudden burst of data
        // (e.g., unexpected file transfer) rather than standard browsing/API traffic.
        if cv_size > 1.5 && mean_size > 1500.0 {
            flags.push(format!("Anomalous {} Payload Spike (Size CV: {:.2}, Mean: {:.0}B)", flow.direction, cv_size, mean_size));
            apt_score_multiplier += 30.0;
        }

        // 1.2. Ingress vs. Egress Asymmetry Ratio
        // Evaluates the ratio of data moving in one direction.
        if let Some(asym) = flow.asymmetry_ratio {
            if is_egress && asym > 15.0 && observed_duration > 120.0 {
                // Massive outward skew
                flags.push(format!("Sustained Data Exfiltration (Out/In Asymmetry: {:.1}x)", asym));
                apt_score_multiplier += 45.0;
            } else if is_ingress && asym > 15.0 {
                // Massive inward skew (Potential Infiltration, Dropper, or DoS)
                flags.push(format!("Anomalous Data Ingress/Infiltration (In/Out Asymmetry: {:.1}x)", asym));
                apt_score_multiplier += 35.0;
            }
        }

        // 1.3. High-Frequency Micro-Bursting (Potential Scan/Flood)
        // Captures highly aggressive, rapid connections (very low mean interval) regardless of payload size.
        if mean_int < 0.1 && n_intervals > 50 {
            flags.push(format!("{} Micro-Burst / Flood Pattern (Mean Interval: {:.3}s)", flow.direction, mean_int));
            apt_score_multiplier += 40.0;
        }

        // 1.4. Unusual Continuous Flow (Skewness)
        // Normal web traffic is bursty. Continuous, unskewed traffic in either direction represents an active pipeline.
        let skewness = MathEngine::calculate_skewness(&flow.intervals, mean_int, std_int);
        if skewness.abs() < 0.3 && observed_duration > 300.0 {
            flags.push(format!("Continuous {} Volumetric Pipeline (Skewness: {:.2})", flow.direction, skewness));
            apt_score_multiplier += 20.0;
        }

        let mut flux_score = 0.0;
        let mut dga_score = 0.0;

        // 2. Fast Flux Detection
        if flow.dst_ips.len() >= 3 {
            let (is_ff, f_score, ff_reason) = ThreatHeuristics::detect_fast_flux(
                &flow.dst_ips, flow.ttls.as_deref(), flow.asns.as_deref()
            );
            flux_score = f_score;
            if is_ff { flags.push(format!("FAST_FLUX: {}", ff_reason)); }
        }

        // 3. DGA Detection
        if let Some(domain) = &flow.domain {
            let (is_dga, d_score, dga_reason) = self.heuristics.detect_dga(domain);
            dga_score = d_score;
            if is_dga { flags.push(format!("DGA: {}", dga_reason)); }
        }

        // 4–6. 4D Feature Matrix + K-Means + DBSCAN
        let mut features: Vec<Array2<f64>> = Vec::new();

        if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), flow.intervals.clone()) { features.push(arr); }

        if let Some(entropies) = &flow.payload_entropies {
            if entropies.len() == n_intervals {
                if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), entropies.clone()) { features.push(arr); }
            }
        }
        if flow.packet_sizes.len() == n_intervals {
            if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), flow.packet_sizes.clone()) { features.push(arr); }
        }

        let mut subnet_score = 12.0;
        if flow.dst_ips.len() == n_intervals {
            let mut unique_subnets = Vec::new();
            for ip in &flow.dst_ips {
                let subnet = ThreatHeuristics::normalize_cidr(ip);
                if !unique_subnets.contains(&subnet) { unique_subnets.push(subnet); }
            }
            let diversity_ratio = unique_subnets.len() as f64 / n_intervals as f64;
            if unique_subnets.len() > 1 {
                subnet_score = (diversity_ratio * 75.0 + unique_subnets.len() as f64 * 5.5).min(88.0);
            }
        }
        if let Ok(arr) = Array2::from_shape_vec((n_intervals, 1), vec![subnet_score; n_intervals]) { features.push(arr); }

        if features.is_empty() { return None; }

        let views: Vec<_> = features.iter().map(|a| a.view()).collect();
        let mut dataset = ndarray::concatenate(Axis(1), &views).unwrap_or_else(|_| features[0].clone());

        // ========================================================================
        // KD-Tree requires contiguous rows. Concatenating columns creates column-major arrays.
        // Rebuilding from the iterator forces the array into standard C-layout.
        // ========================================================================
        let c_contiguous_data: Vec<f64> = dataset.iter().cloned().collect();
        dataset = Array2::from_shape_vec((dataset.nrows(), dataset.ncols()), c_contiguous_data)
            .unwrap_or(dataset);

        MathEngine::standard_scaler(&mut dataset);

        // NaN/Inf guard
        let mut has_valid_data = true;
        for &v in dataset.iter() {
            if v.is_nan() || v.is_infinite() {
                has_valid_data = false;
                break;
            }
        }

        if has_valid_data {
            // K-Means
            let rng = thread_rng();
            let max_k = std::cmp::min(4, dataset.nrows().saturating_sub(1));
            let mut best_score = -1.0;
            let mut best_k = 0;

            if max_k > 1 {
                for k in 2..=max_k {
                    let dataset_wrapped = Dataset::from(dataset.clone());
                    if let Ok(model) = KMeans::params_with(k, rng.clone(), L2Dist).max_n_iterations(100).fit(&dataset_wrapped) {
                        let labels = model.predict(dataset.view());
                        if let Some(targets) = labels.targets.as_slice() {
                            let score = MathEngine::compute_silhouette(&dataset, targets, k);
                            if score > 0.45 && score > best_score {
                                best_score = score; best_k = k;
                            }
                        }
                    }
                }
            }

            if best_k > 0 {
                flags.push(format!("ML Anomalous Flow Cluster (K={})", best_k));
            }

            // DBSCAN
            if dataset.nrows() >= 8 {
                let k_neighbors = std::cmp::min(8, dataset.nrows() - 1);
                let dynamic_eps = MathEngine::calculate_dynamic_eps(&dataset, k_neighbors);

                let dataset_wrapped = Dataset::from(dataset.clone());
                if let Ok(labels_dataset) = Dbscan::params(k_neighbors).tolerance(dynamic_eps).transform(dataset_wrapped) {
                    let dbscan_targets = &labels_dataset.targets;

                    let mut unique_clusters: Vec<usize> = dbscan_targets.iter().filter_map(|&l| l).collect();
                    unique_clusters.sort_unstable();
                    unique_clusters.dedup();

                    for c in unique_clusters {
                        let cluster_intervals: Vec<f64> = flow.intervals.iter().enumerate()
                            .filter_map(|(i, &val)| if dbscan_targets[i] == Some(c) { Some(val) } else { None })
                            .collect();
                        if cluster_intervals.len() >= 8 {
                            let (_, c_std) = MathEngine::calculate_mean_std(&cluster_intervals);
                            if c_std <= 10.0 {
                                flags.push(format!("ML 4D DBSCAN Anomalous Flow (Core StdDev: {:.2})", c_std));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if flags.is_empty() { return None; }

        // Confidence Math: Start lower to punish noise, but scale aggressively for APT traits
        let mut base_conf = 35.0 + apt_score_multiplier;
        if observed_duration < 180.0 && std_int > 2.0 { base_conf -= 15.0; }

        let mut confidence = base_conf + (flags.len() as f64 * 20.0) + (flux_score * 0.45) + (dga_score * 0.35);

        if confidence > 70.0 && flags.len() == 1 && flux_score < 30.0 && dga_score < 30.0 {
            confidence -= 15.0;
        }

        confidence = confidence.clamp(0.0, 98.0);

        Some(OutgoingAlert {
            key: flow.key,
            alert_reason: flags.join("; "),
            confidence: confidence.round(),
        })
    }
}

// ============================================================================
// NATIVE C-FFI BOUNDARY
// ============================================================================
fn setup_custom_panic_hook() {
    // Force Rust to resolve memory symbols for the backtrace.
    // set_var is unsafe in edition 2024 (env mutation must not race other threads);
    // this runs during single-threaded FFI init before any worker starts.
    unsafe { std::env::set_var("RUST_BACKTRACE", "1"); }

    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::force_capture();

        // Safely extract the panic payload
        let payload = panic_info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown ML Engine internal panic (Likely KD-Tree Zero-Variance)".to_string()
        };

        // Get the exact file and line number where the math failed
        let location = if let Some(loc) = panic_info.location() {
            format!("{}:{}", loc.file(), loc.line())
        } else {
            "unknown location".to_string()
        };

        let log_entry = format!(
            "\n================================================================\n\
             [RUST ML ENGINE FATAL PANIC]\n\
             Timestamp: {:?}\n\
             Location: {}\n\
             Error: {}\n\
             Backtrace:\n{}\n\
             ================================================================\n",
            std::time::SystemTime::now(), location, msg, backtrace
        );

        // Bypass the FFI and write directly to the PowerShell orchestrator's log
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"C:\ProgramData\IDPSSensor\Logs\IDPSSensor_Diagnostic.log")
        {
            let _ = write!(file, "{}", log_entry);
        }
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn init_engine() -> *mut Mutex<BehavioralEngine> {
    setup_custom_panic_hook();

    // Map the Behavioral Engine into memory + spawn the async transmission worker.
    let result = std::panic::catch_unwind(|| {
        let (tx, rx) = mpsc::channel(10000);
        let rt = Runtime::new().expect("Failed to create Tokio runtime");

        rt.spawn(async move {
            transmission::start_transmission_worker(
                r"C:\ProgramData\IDPSSensor\IDPSSensor_Config.ini".to_string(),
                rx,
                |msg| {
                    // No native callback at this FFI boundary -> append worker logs to a file.
                    if let Ok(mut f) = OpenOptions::new().create(true).append(true)
                        .open(r"C:\ProgramData\IDPSSensor\Logs\Transmission.log")
                    {
                        let _ = writeln!(f, "{}", msg);
                    }
                }
            ).await;
        });

        Box::into_raw(Box::new(Mutex::new(BehavioralEngine::new(tx, rt))))
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn evaluate_telemetry(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) -> *mut c_char {
    if engine_ptr.is_null() || json_payload.is_null() {
        return make_error_response("FFI: Null pointer received");
    }

    let engine_mutex = unsafe { &*engine_ptr };

    // Wrap EVERYTHING (including JSON parsing) inside the panic catcher
    let result = std::panic::catch_unwind(|| {
        let c_str = unsafe { CStr::from_ptr(json_payload) };
        let payload_bytes = c_str.to_bytes();

        // CWE-400 HARD LIMIT - Reject payloads over 1MB before string allocation
        if payload_bytes.len() > 1_048_576 {
            return Err("CRITICAL: FFI Payload exceeds 1MB safety threshold".to_string());
        }

        let json_str = match std::str::from_utf8(payload_bytes) {
            Ok(s) => s,
            Err(_) => return Err("FFI: Invalid UTF-8 in payload".to_string()),
        };

        let events: Vec<IncomingTelemetry> = match serde_json::from_str(json_str) {
            Ok(e) => e,
            Err(e) => return Err(format!("JSON parse error: {}", e)),
        };

        let mut engine = match engine_mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut batch_alerts = Vec::new();

        for evt in events {
            if let Some(alert) = engine.evaluate_flow(evt) {
                batch_alerts.push(alert);
            }
        }
        Ok(batch_alerts)
    });

    match result {
        Ok(Ok(mut alerts)) => {
            alerts.retain(|a| a.confidence >= 90.0);

            if alerts.is_empty() {
                let empty_response = OutgoingResponse { alerts: Some(vec![]), daemon_error: None };
                let s = serde_json::to_string(&empty_response).unwrap_or_else(|_| "{}".to_string());
                return CString::new(s).unwrap().into_raw();
            }

            let response = OutgoingResponse {
                alerts: Some(alerts),
                daemon_error: None,
            };

            match serde_json::to_string(&response) {
                Ok(resp_str) => {
                    let clean_str = resp_str.replace('\0', "");
                    CString::new(clean_str).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
                },
                Err(e) => make_error_response(&format!("Serialization error: {}", e)),
            }
        },
        Ok(Err(err_msg)) => make_error_response(&err_msg), // Handled internal limit/parse errors
        Err(panic_info) => {
            let msg = match panic_info.downcast_ref::<String>() {
                Some(s) => s.clone(),
                None => match panic_info.downcast_ref::<&str>() {
                    Some(s) => s.to_string(),
                    None => "Unknown panic (kdtree / linfa error)".to_string(),
                },
            };
            make_error_response(&format!("Rust panic: {}", msg))
        }
    }
}

// Helper to always return a proper error JSON
fn make_error_response(msg: &str) -> *mut c_char {
    let response = OutgoingResponse {
        alerts: None,
        daemon_error: Some(msg.replace('\0', "")),
    };
    match serde_json::to_string(&response) {
        Ok(s) => {
            let clean_str = s.replace('\0', "");
            CString::new(clean_str).unwrap_or_else(|_| CString::new("{\"daemon_error\": \"Critical serialization failure\"}").unwrap()).into_raw()
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<BehavioralEngine>) {
    if !engine_ptr.is_null() {
        unsafe {
            let engine_box = Box::from_raw(engine_ptr);
            let engine = match engine_box.lock() { Ok(guard) => guard, Err(p) => p.into_inner() };
            // Execute PRAGMAs individually to prevent batch-abort on result rows
            let _ = engine.conn.execute("PRAGMA optimize;", []);
            // Force the Write-Ahead Log to commit to the main DB and shrink to 0 bytes
            let _ = engine.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);", []);
        }
    }
}

// Orchestrator alert submission: the PowerShell launcher forwards each enriched IDPS alert
// JSON here; it is pushed onto the transmission channel -> SQLite WAL -> Parquet -> gateway.
#[unsafe(no_mangle)]
pub extern "C" fn submit_orchestrator_alert(engine_ptr: *mut Mutex<BehavioralEngine>, json_payload: *const c_char) {
    if engine_ptr.is_null() || json_payload.is_null() { return; }

    let _ = std::panic::catch_unwind(|| {
        let c_str = unsafe { CStr::from_ptr(json_payload) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                let engine_mutex = unsafe { &*engine_ptr };
                let engine = match engine_mutex.lock() { Ok(g) => g, Err(p) => p.into_inner() };
                let _ = engine.tx.try_send(Arc::new(val));
            }
        }
    });
}