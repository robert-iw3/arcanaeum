#!/usr/bin/env python3
"""
baseline_learner.py - Advanced Behavioral Learning Engine

Features:
- Per-process, per-destination (/24), per-hour, per-weekday/weekend baselines
- Batch database inserts with timeout handling
- Hybrid statistical + Isolation Forest models (batch-fitted for large data)
- Automatic data retention (30 days)
- Model versioning
- UEBA False-Positive Suppression + Performance Tuning
- BeaconML integration (detect_beaconing_list called per flow group)
- IPv6-aware prefix grouping (/48 for v6, /24 for v4)
- Exfiltration detection (volumetric anomaly per process+destination)
- Real outbound_ratio aggregation (not per-event boolean)
- UEBA process/role profile population
- Process hash allowlisting
"""

import sqlite3
import time
import gc
import logging
import setproctitle
import ipaddress

setproctitle.setproctitle("c2-ml-engine")
logger = logging.getLogger(__name__)
import numpy as np
from pathlib import Path
from collections import defaultdict, Counter
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import queue

import sys
sys.path.insert(0, str(Path(__file__).parent))
from BeaconML import detect_beaconing_list

DB_PATH = Path("data/baseline.db")
MODEL_PATH = Path("data/baseline_model.joblib")

LEARNING_INTERVAL = 3600
RETENTION_DAYS = 30
BATCH_SIZE = 5000
QUEUE_TIMEOUT = 1.0
EXFIL_THRESHOLD_BYTES = 10_000_000   # 10 MB per process+destination per hour


class BaselineLearner:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL;')
        self.db.execute('PRAGMA synchronous=NORMAL;')
        self.db.execute('PRAGMA cache_size=-64000;')
        self.db.execute('PRAGMA auto_vacuum = INCREMENTAL;')
        self.db.execute('PRAGMA busy_timeout = 10000;')
        self._init_db()
        self._migrate_schema()
        self._create_indexes()
        self.flow_queue = queue.Queue()
        self.running = True
        self.writer_thread = threading.Thread(target=self._queue_writer, daemon=True)
        self.writer_thread.start()

    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                process_name TEXT,
                dst_ip TEXT,
                dst_port INTEGER DEFAULT 0,
                interval REAL DEFAULT 0.0,
                cv REAL DEFAULT 0.0,
                outbound_ratio REAL DEFAULT 0.0,
                entropy REAL DEFAULT 0.0,
                packet_size_mean REAL DEFAULT 0.0,
                packet_size_std REAL DEFAULT 0.0,
                packet_size_min INTEGER DEFAULT 0,
                packet_size_max INTEGER DEFAULT 0,
                packet_count INTEGER DEFAULT 0,
                mitre_tactic TEXT DEFAULT '',
                pid INTEGER DEFAULT 0,
                uid INTEGER DEFAULT 0,
                cmd_entropy REAL DEFAULT 0.0,
                suppressed INTEGER DEFAULT 0,
                score INTEGER DEFAULT 0,
                cmd_snippet TEXT DEFAULT '',
                process_tree TEXT DEFAULT '',
                masquerade_detected INTEGER DEFAULT 0,
                reasons TEXT DEFAULT '[]',
                mitre_technique TEXT DEFAULT '',
                mitre_name TEXT DEFAULT '',
                description TEXT DEFAULT '',
                ml_result TEXT DEFAULT NULL,
                process_hash TEXT DEFAULT '',
                dns_query TEXT DEFAULT '',
                event_type TEXT DEFAULT 'unknown',
                dns_flags INTEGER DEFAULT 0,
                ja3_hash TEXT DEFAULT '',
                sensor_id TEXT DEFAULT 'unknown'
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT,
                target_value TEXT,
                mitigated_at REAL,
                reason TEXT
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                process_hash TEXT PRIMARY KEY,
                added_on REAL,
                reason TEXT
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS ueba_process_profiles (
                process_hash TEXT PRIMARY KEY,
                event_count INTEGER DEFAULT 0,
                mean_delta REAL DEFAULT 0.0,
                m2_delta REAL DEFAULT 0.0
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS ueba_role_profiles (
                binary_name TEXT PRIMARY KEY,
                instance_count INTEGER DEFAULT 0,
                max_velocity REAL DEFAULT 0.0,
                mean_entropy REAL DEFAULT 0.0
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS flow_volumes (
                uid INTEGER,
                process_name TEXT,
                dst_ip TEXT,
                window_start REAL,
                outbound_bytes REAL DEFAULT 0.0,
                inbound_bytes REAL DEFAULT 0.0,
                flow_count INTEGER DEFAULT 0,
                PRIMARY KEY (uid, process_name, dst_ip, window_start)
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_thresholds (
                id INTEGER PRIMARY KEY DEFAULT 1,
                entropy_high REAL DEFAULT 7.5,
                beacon_interval_min REAL DEFAULT 10.0,
                beacon_interval_max REAL DEFAULT 90.0,
                beacon_cv_max REAL DEFAULT 0.35,
                updated_at REAL
            )
        """)
        self.db.commit()

    def _migrate_schema(self):
        migrations = [
            ("packet_count", "INTEGER DEFAULT 0"),
            ("score", "INTEGER DEFAULT 0"),
            ("cmd_snippet", "TEXT DEFAULT ''"),
            ("process_tree", "TEXT DEFAULT ''"),
            ("masquerade_detected", "INTEGER DEFAULT 0"),
            ("reasons", "TEXT DEFAULT '[]'"),
            ("mitre_technique", "TEXT DEFAULT ''"),
            ("mitre_name", "TEXT DEFAULT ''"),
            ("description", "TEXT DEFAULT ''"),
            ("ml_result", "TEXT DEFAULT NULL"),
            ("process_hash", "TEXT DEFAULT ''"),
            ("dns_query", "TEXT DEFAULT ''"),
            ("event_type", "TEXT DEFAULT 'unknown'"),
            ("dns_flags", "INTEGER DEFAULT 0"),
            ("ja3_hash", "TEXT DEFAULT ''"),
            ("sensor_id", "TEXT DEFAULT 'unknown'"),
        ]
        for col_name, col_def in migrations:
            while True:
                try:
                    self.db.execute(f"ALTER TABLE flows ADD COLUMN {col_name} {col_def}")
                    break
                except sqlite3.OperationalError as e:
                    if "duplicate column" in str(e).lower():
                        break  # Safe to move on
                    elif "locked" in str(e).lower():
                        time.sleep(0.5)  # Wait for Rust to yield the transaction
                    else:
                        logger.error(f"Migration error for {col_name}: {e}")
                        break
        self.db.commit()

    def _create_indexes(self):
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_uid_proc_net ON flows(uid, process_name, dst_ip, dst_port)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_score_suppressed ON flows(score, suppressed, timestamp DESC)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_proc_dst_ts ON flows(process_name, dst_ip, timestamp)")
        self.db.commit()

    def _queue_writer(self):
        while self.running:
            batch = []
            try:
                while len(batch) < BATCH_SIZE:
                    batch.append(self.flow_queue.get(timeout=QUEUE_TIMEOUT))
            except queue.Empty:
                pass

            if batch:
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        cursor = self.db.cursor()
                        cursor.executemany("""
                            INSERT INTO flows (timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                                            packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                                            mitre_tactic, pid, uid, cmd_entropy,
                                            process_hash, dns_query, event_type, dns_flags, ja3_hash, sensor_id,
                                            suppressed)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                    ?, ?, ?, ?, ?, ?, 0)
                        """, batch)
                        self.db.commit()
                        break
                    except sqlite3.OperationalError as e:
                        if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                            sleep_time = 0.1 * (2 ** attempt)
                            logger.warning(f"Database locked, retrying batch insert in {sleep_time}s...")
                            time.sleep(sleep_time)
                        else:
                            logger.error(f"Batch insert failed after {max_retries} attempts, dropping data: {e}")

    def record_flow(self, process_name, dst_ip, interval=0.0, cv=0.0, outbound_ratio=0.0,
                    entropy=0.0, packet_size_mean=0, packet_size_std=0,
                    packet_size_min=0, packet_size_max=0, mitre_tactic="C2_Beaconing",
                    pid=0, uid=0, cmd_entropy=0.0, process_hash='', dns_query='',
                    event_type='unknown', dns_flags=0, ja3_hash='', sensor_id='unknown'):
        ts = time.time()
        self.flow_queue.put((ts, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                             packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                             mitre_tactic, pid, uid, cmd_entropy, process_hash, dns_query,
                             event_type, dns_flags, ja3_hash, sensor_id))

    @staticmethod
    def _ip_prefix(ip_str):
        """Return /24 prefix for IPv4 or /48 prefix for IPv6."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                return str(net.network_address)
            else:
                net = ipaddress.ip_network(f"{ip_str}/48", strict=False)
                return str(net.network_address)
        except ValueError:
            return ip_str

    @staticmethod
    def _ip_like_pattern(prefix_str):
        if ':' in prefix_str:
            # IPv6 /48: match the first 3 hextets (e.g. "2001:db8:abcd:%")
            parts = prefix_str.split(':')
            return ':'.join(parts[:3]) + ':%'
        else:
            # IPv4 /24: match the first 3 octets (e.g. "192.168.1.%")
            return prefix_str.rsplit('.', 1)[0] + '.%'

    def learn(self):
        cursor = self.db.cursor()

        try:
            cursor.execute("""
                UPDATE flows SET suppressed = 1
                WHERE suppressed = 0 AND process_hash IN (SELECT process_hash FROM allowlist)
            """)
            self.db.commit()
        except sqlite3.OperationalError as e:
            logger.error(f"Failed to update allowlist suppression: {e}")

        cursor.execute("""
            SELECT timestamp, process_name, dst_ip, interval, cv, outbound_ratio,
                   entropy, packet_size_mean, packet_size_std, packet_size_min,
                   packet_size_max, mitre_tactic, pid, uid, cmd_entropy, suppressed,
                   process_hash, ja3_hash, sensor_id, dns_query, dns_flags
            FROM flows
            WHERE suppressed = 0
            ORDER BY timestamp DESC
            LIMIT 50000
        """)
        data = cursor.fetchall()

        model = {"version": 2, "profiles": {}, "beacon_aggregates": {}}
        profiles = defaultdict(lambda: {
            "intervals": [], "cvs": [], "outbound_ratios": [], "entropies": [],
            "packet_means": [], "packet_stds": [], "packet_mins": [], "packet_maxs": [],
            "mitre_tactics": Counter(), "hashes": Counter(), "outbound_flags": [],
        })

        beacon_aggregates = defaultdict(lambda: {
            "intervals": [], "cvs": [], "outbound_ratios": [], "entropies": [],
            "packet_means": [], "packet_stds": [], "packet_mins": [], "packet_maxs": [],
            "timestamps": [],
        })

        for row in data:
            (ts, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
             p_mean, p_std, p_min, p_max, tactic, pid, uid, cmd_entropy,
             suppressed, process_hash, ja3_hash, sensor_id,
             dns_query, dns_flags) = row

            prefix = self._ip_prefix(dst_ip)
            event_dt = datetime.fromtimestamp(ts)
            hour = event_dt.hour
            is_weekend = event_dt.weekday() >= 5

            key = f"{uid}|{process_name}|{prefix}|{hour:02d}|{'weekend' if is_weekend else 'weekday'}"
            coarse_key = f"{uid}|{process_name}|{prefix}"

            prof = profiles[key]
            prof["intervals"].append(interval)
            prof["cvs"].append(cv)
            prof["outbound_ratios"].append(outbound_ratio)
            prof["entropies"].append(entropy)
            prof["packet_means"].append(p_mean)
            prof["packet_stds"].append(p_std)
            prof["packet_mins"].append(p_min)
            prof["packet_maxs"].append(p_max)
            prof["mitre_tactics"][tactic] += 1
            if process_hash:
                prof["hashes"][process_hash] += 1
            prof["outbound_flags"].append(1 if outbound_ratio > 0.5 else 0)

            # Accumulate for long-term ML processing
            b_prof = beacon_aggregates[coarse_key]
            b_prof["intervals"].append(interval)
            b_prof["timestamps"].append(ts)
            b_prof["cvs"].append(cv)
            b_prof["outbound_ratios"].append(outbound_ratio)
            b_prof["entropies"].append(entropy)
            b_prof["packet_means"].append(p_mean)
            b_prof["packet_stds"].append(p_std)
            b_prof["packet_mins"].append(p_min)
            b_prof["packet_maxs"].append(p_max)

        # ---------------------------------------------------------
        # PASS 1: Coarse Identity Evaluation (Machine Learning)
        # ---------------------------------------------------------
        coarse_results = {}
        for coarse_key, b_prof in beacon_aggregates.items():
            # Sliding window: keep only events from the last 6 hours for ML evaluation
            # (longer than any single UEBA hour-slice, short enough to drop stale beacons)
            if b_prof["timestamps"]:
                cutoff_ts = time.time() - 21600  # 6 hours
                mask = [t >= cutoff_ts for t in b_prof["timestamps"]]
                if any(mask) and not all(mask):
                    for field in ("intervals", "cvs", "outbound_ratios", "entropies",
                                "packet_means", "packet_stds", "packet_mins", "packet_maxs", "timestamps"):
                        b_prof[field] = [v for v, m in zip(b_prof[field], mask) if m]

            if len(b_prof["intervals"]) < 50:
                continue

            intervals_list = b_prof["intervals"]
            entropies_list = b_prof["entropies"] if len(b_prof["entropies"]) == len(intervals_list) else None
            packet_list = b_prof["packet_means"] if len(b_prof["packet_means"]) == len(intervals_list) else None

            try:
                ml_result, confidence = detect_beaconing_list(
                    intervals_list,
                    payload_entropies=entropies_list,
                    packet_sizes=packet_list,
                    min_samples=5,
                )

                if ml_result and confidence >= 50:
                    # Execute Threat Envelope Logic directly against the Coarse Aggregate Stats
                    mean_cv = float(np.mean(b_prof["cvs"]))
                    mean_ent = float(np.mean(b_prof["entropies"]))
                    mean_out_ratio = float(np.mean(b_prof["outbound_ratios"]))

                    if mean_cv < 0.05 and mean_ent < 5.0:
                        pkt_cv = float(np.std(b_prof["packet_means"]) / (np.mean(b_prof["packet_means"]) + 1e-6))
                        mean_pkt = float(np.mean(b_prof["packet_means"]))
                        # Fixed-size encrypted heartbeats: low timing CV + low entropy + uniform packet sizes
                        # This combination is suspicious — don't suppress, flag for review
                        if pkt_cv < 0.05 and mean_pkt > 100:
                            confidence = max(confidence, 55)
                            ml_result = f"Encrypted Heartbeat Candidate (CV: {mean_cv:.3f}, PktCV: {pkt_cv:.3f}, AvgSize: {mean_pkt:.0f}B)"
                        else:
                            confidence = int(confidence * 0.1)
                            ml_result = f"Mechanical Polling (CV: {mean_cv:.3f}, Ent: {mean_ent:.2f})"
                    elif mean_cv > 0.40:
                        confidence = int(confidence * 0.4)
                        ml_result = f"Organic Bursty Traffic (CV: {mean_cv:.3f})"
                    elif 0.05 <= mean_cv <= 0.35 and mean_ent >= 6.5 and mean_out_ratio >= 0.7:
                        confidence = 98
                        ml_result = f"CONFIRMED BEACON: Evasive Jitter ({mean_cv*100:.1f}%) w/ Packed Payload"

                    parts = coarse_key.split("|")
                    if ml_result and len(parts) >= 3:
                        uid_val, proc_name, prefix_val = parts[0], parts[1], parts[2]
                        ip_pattern = self._ip_like_pattern(prefix_val)
                        time_cutoff = time.time() - 86400

                        if confidence < 50 and ("Mechanical" in ml_result or "Organic" in ml_result):
                            cursor.execute("""
                                UPDATE flows
                                SET ml_result = ?, score = 0, suppressed = 1
                                WHERE uid = ? AND process_name = ? AND dst_ip LIKE ?
                                  AND timestamp > ?
                            """, (ml_result, uid_val, proc_name, ip_pattern, time_cutoff))
                        elif confidence >= 50:
                            cursor.execute("""
                                UPDATE flows
                                SET ml_result = ?,
                                    score = MIN(100, score + CAST((? * 0.4) AS INTEGER))
                                WHERE uid = ? AND process_name = ? AND dst_ip LIKE ?
                                  AND suppressed = 0
                                  AND timestamp > ?
                            """, (ml_result, confidence, uid_val, proc_name, ip_pattern, time_cutoff))

                coarse_results[coarse_key] = {"ml_result": ml_result, "confidence": confidence}

            except Exception as e:
                logger.warning(f"BeaconML evaluation failed for {coarse_key}: {e}")

            # --- Isolation Forest (Shifted to Coarse Identity) ---
            training_data = np.column_stack((
                b_prof["intervals"], b_prof["cvs"], b_prof["outbound_ratios"], b_prof["entropies"],
                b_prof["packet_means"], b_prof["packet_stds"], b_prof["packet_mins"], b_prof["packet_maxs"]
            ))
            try:
                clf = IsolationForest(contamination=0.05, random_state=42)
                clf.fit(training_data)
                model["beacon_aggregates"][coarse_key] = {"isolation_forest": clf}

                predictions = clf.predict(training_data)
                anomaly_ratio = float((predictions == -1).sum()) / len(predictions)
                if anomaly_ratio > 0.10:
                    parts = coarse_key.split("|")
                    if len(parts) >= 3:
                        ip_pattern = self._ip_like_pattern(parts[2])
                        time_cutoff = time.time() - 86400
                        reason = f"IsolationForest anomaly ratio: {anomaly_ratio:.2f}"
                        cursor.execute("""
                            UPDATE flows
                            SET score = MIN(100, score + CAST(? AS INTEGER)),
                                reasons = json_insert(reasons, '$[#]', ?)
                            WHERE uid = ? AND process_name = ? AND dst_ip LIKE ?
                            AND suppressed = 0 AND timestamp > ?
                            AND score < 90
                        """, (int(anomaly_ratio * 30), reason,
                            parts[0], parts[1], ip_pattern, time_cutoff))
            except Exception as e:
                logger.warning(f"IsolationForest fit failed for {coarse_key}: {e}")


        # ---------------------------------------------------------
        # PASS 2: Fine Temporal Evaluation (UEBA & Stats)
        # ---------------------------------------------------------
        for key, prof in profiles.items():
            if len(prof["intervals"]) < 5:
                continue

            out_flags = prof["outbound_flags"]
            real_outbound_ratio = sum(out_flags) / len(out_flags) if out_flags else 0.0

            model["profiles"][key] = {
                "stats": {
                    "mean_interval": float(np.mean(prof["intervals"])),
                    "std_interval": float(np.std(prof["intervals"])),
                    "mean_cv": float(np.mean(prof["cvs"])),
                    "mean_outbound_ratio": real_outbound_ratio,
                    "mean_entropy": float(np.mean(prof["entropies"])),
                    "mean_packet_mean": float(np.mean(prof["packet_means"])),
                    "mean_packet_std": float(np.mean(prof["packet_stds"])),
                    "mean_packet_min": float(np.mean(prof["packet_mins"])),
                    "mean_packet_max": float(np.mean(prof["packet_maxs"])),
                    "top_mitre": prof["mitre_tactics"].most_common(1)[0][0] if prof["mitre_tactics"] else "Unknown",
                    "known_hashes": list(prof["hashes"].keys()),
                }
            }

            # --- False-Positive Suppression ---
            # Retrieve the overarching ML state by parsing the fine key back to the coarse structure
            coarse_key_reference = "|".join(key.split("|")[:3])
            ml_state = coarse_results.get(coarse_key_reference, {})
            ml_conf = ml_state.get("confidence", 0)
            ml_res = ml_state.get("ml_result", None)

            stability = 1.0 - (np.std(prof["intervals"]) / (np.mean(prof["intervals"]) + 1e-6))

            if stability > 0.85 and ml_conf < 50:
                parts = key.split("|")
                # Suppress only if the coarse ML evaluation confirmed it was not malicious
                if ml_res is None or "Mechanical" in ml_res or "Organic" in ml_res:
                    cursor.execute("""
                        UPDATE flows SET suppressed = 1
                        WHERE uid = ? AND process_name = ? AND dst_ip LIKE ? AND timestamp > ?
                        AND (ml_result IS NULL OR ml_result LIKE 'Mechanical%' OR ml_result LIKE 'Organic%')
                    """, (parts[0], parts[1], self._ip_like_pattern(parts[2]), time.time() - 86400))

        self.db.commit()

        self._detect_exfiltration(cursor)
        self._update_ueba_profiles(cursor)
        self._update_dynamic_thresholds(cursor)

        joblib.dump(model, MODEL_PATH)
        print(f"[{datetime.now()}] Baseline updated: {len(model['profiles'])} profiles, "
              f"BeaconML active, exfil detection enabled")

    def _detect_exfiltration(self, cursor):
        now = time.time()
        hour_ago = now - 3600

        cursor.execute("""
            SELECT process_name, dst_ip, uid,
                   SUM(CASE WHEN outbound_ratio > 0.5 THEN packet_size_mean * packet_count ELSE 0 END) as out_bytes,
                   SUM(CASE WHEN outbound_ratio <= 0.5 THEN packet_size_mean * packet_count ELSE 0 END) as in_bytes,
                   COUNT(*) as cnt
            FROM flows
            WHERE timestamp > ? AND suppressed = 0
            GROUP BY process_name, dst_ip, uid
            HAVING out_bytes > ?
        """, (hour_ago, EXFIL_THRESHOLD_BYTES))

        for row in cursor.fetchall():
            proc, dst, uid, out_bytes, in_bytes, cnt = row

            window = int(now / 3600) * 3600
            try:
                self.db.execute("""
                    INSERT OR REPLACE INTO flow_volumes
                        (uid, process_name, dst_ip, window_start, outbound_bytes, inbound_bytes, flow_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (uid, proc, dst, window, out_bytes, in_bytes, cnt))
            except sqlite3.OperationalError:
                pass

            cursor.execute("""
                SELECT AVG(outbound_bytes), AVG(outbound_bytes) + 3 * SQRT(COALESCE(
                    (SELECT AVG((fv2.outbound_bytes - sub.avg_ob) * (fv2.outbound_bytes - sub.avg_ob))
                    FROM flow_volumes fv2,
                        (SELECT AVG(outbound_bytes) as avg_ob FROM flow_volumes
                        WHERE process_name = ? AND dst_ip = ? AND uid = ? AND window_start < ?) sub
                    WHERE fv2.process_name = ? AND fv2.dst_ip = ? AND fv2.uid = ? AND fv2.window_start < ?),
                    ?)) as threshold
                FROM flow_volumes
                WHERE process_name = ? AND dst_ip = ? AND uid = ? AND window_start < ?
            """, (proc, dst, uid, window, proc, dst, uid, window, EXFIL_THRESHOLD_BYTES,
                proc, dst, uid, window))

            baseline_row = cursor.fetchone()
            if baseline_row and baseline_row[0] is not None:
                avg_baseline, threshold = baseline_row
                if out_bytes > threshold:
                    import json
                    reason = f"Exfiltration anomaly: {out_bytes/1e6:.1f}MB outbound (baseline: {avg_baseline/1e6:.1f}MB)"
                    cursor.execute("""
                        UPDATE flows SET
                            score = MAX(score, 80),
                            mitre_tactic = CASE WHEN score < 80 THEN 'Exfiltration' ELSE mitre_tactic END,
                            mitre_technique = CASE WHEN score < 80 THEN 'T1041' ELSE mitre_technique END,
                            mitre_name = CASE WHEN score < 80 THEN 'Exfiltration Over C2 Channel' ELSE mitre_name END,
                            reasons = json_insert(reasons, '$[#]', ?)
                        WHERE process_name = ? AND dst_ip = ? AND uid = ?
                          AND timestamp > ? AND suppressed = 0
                    """, (reason, proc, dst, uid, hour_ago))

        self.db.commit()

    def _update_ueba_profiles(self, cursor):
        cursor.execute("""
            SELECT f.process_hash, COUNT(*) as cnt,
                AVG(f.interval) as mean_d,
                SUM((f.interval - ph_avg.avg_int) * (f.interval - ph_avg.avg_int)) as m2
            FROM flows f
            INNER JOIN (
                SELECT process_hash, AVG(interval) as avg_int
                FROM flows
                WHERE process_hash != '' AND suppressed = 0
                GROUP BY process_hash
            ) ph_avg ON f.process_hash = ph_avg.process_hash
            WHERE f.process_hash != '' AND f.suppressed = 0
            GROUP BY f.process_hash
            ORDER BY cnt DESC LIMIT 100
        """)
        for row in cursor.fetchall():
            phash, cnt, mean_d, m2 = row
            try:
                self.db.execute("""
                    INSERT OR REPLACE INTO ueba_process_profiles (process_hash, event_count, mean_delta, m2_delta)
                    VALUES (?, ?, ?, ?)
                """, (phash, cnt, mean_d or 0.0, m2 or 0.0))
            except sqlite3.OperationalError:
                pass

        cursor.execute("""
            SELECT process_name, COUNT(DISTINCT pid) as instances,
                MAX(hourly_vel) as max_vel,
                AVG(entropy) as mean_ent
            FROM (
                SELECT process_name, pid, entropy,
                    SUM(packet_size_mean * packet_count) / MAX(1, SUM(packet_count)) as hourly_vel
                FROM flows
                WHERE suppressed = 0 AND timestamp > ?
                GROUP BY process_name, CAST((timestamp / 3600) AS INTEGER)
            )
            GROUP BY process_name
            ORDER BY instances DESC LIMIT 100
        """, (time.time() - 86400,))
        for row in cursor.fetchall():
            bname, inst, max_v, mean_e = row
            try:
                self.db.execute("""
                    INSERT OR REPLACE INTO ueba_role_profiles (binary_name, instance_count, max_velocity, mean_entropy)
                    VALUES (?, ?, ?, ?)
                """, (bname, inst, max_v or 0.0, mean_e or 0.0))
            except sqlite3.OperationalError:
                pass

        self.db.commit()

    def _update_dynamic_thresholds(self, cursor):
        """Phase 4.3: Compute per-environment thresholds from learned baselines."""
        try:
            # Entropy: mean + 2*std of entropy across all unsuppressed flows with score > 0
            cursor.execute("""
                SELECT AVG(entropy), AVG(entropy) + 2 * SQRT(COALESCE(
                    (SELECT AVG((f2.entropy - sub.avg_e) * (f2.entropy - sub.avg_e))
                    FROM flows f2,
                        (SELECT AVG(entropy) as avg_e FROM flows WHERE entropy > 0 AND suppressed = 0) sub
                    WHERE f2.entropy > 0 AND f2.suppressed = 0),
                    0))
                FROM flows
                WHERE entropy > 0 AND suppressed = 0 AND timestamp > ?
            """, (time.time() - 86400,))
            row = cursor.fetchone()
            entropy_high = row[1] if row and row[1] else 7.5
            entropy_high = max(6.0, min(9.0, entropy_high))  # Clamp to sane range

            # Beacon CV: compute the 95th percentile CV of scored beaconing flows
            cursor.execute("""
                SELECT cv FROM flows
                WHERE score > 15 AND cv > 0.01 AND suppressed = 0
                  AND timestamp > ?
                ORDER BY cv DESC
            """, (time.time() - 86400,))
            cvs = [r[0] for r in cursor.fetchall()]
            if len(cvs) >= 10:
                p95_idx = int(len(cvs) * 0.05)
                beacon_cv_max = max(0.20, min(0.50, cvs[p95_idx]))
            else:
                beacon_cv_max = 0.35

            now = time.time()
            self.db.execute("""
                INSERT OR REPLACE INTO dynamic_thresholds
                    (id, entropy_high, beacon_interval_min, beacon_interval_max, beacon_cv_max, updated_at)
                VALUES (1, ?, 10.0, 90.0, ?, ?)
            """, (entropy_high, beacon_cv_max, now))
            self.db.commit()

            logger.info(f"Dynamic thresholds updated: entropy={entropy_high:.2f}, cv_max={beacon_cv_max:.3f}")
        except Exception as e:
            logger.warning(f"Dynamic threshold update failed (using defaults): {e}")

    def cleanup_old_data(self):
        cutoff = time.time() - 86400 * RETENTION_DAYS
        self.db.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff,))
        self.db.execute("DELETE FROM flow_volumes WHERE window_start < ?", (cutoff,))
        self.db.execute("PRAGMA incremental_vacuum;")
        self.db.commit()

    def run(self):
        while self.running:
            try:
                self.learn()
                self.cleanup_old_data()
                gc.collect()
            except Exception as e:
                print(f"Learning error: {e}")
                import traceback
                traceback.print_exc()
            time.sleep(LEARNING_INTERVAL)

    def stop(self):
        self.running = False
        self.writer_thread.join(timeout=3)


if __name__ == "__main__":
    learner = BaselineLearner()
    try:
        learner.run()
    except KeyboardInterrupt:
        learner.stop()