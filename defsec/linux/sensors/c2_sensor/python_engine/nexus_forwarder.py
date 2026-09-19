import asyncio
import sqlite3
import socket
import platform
import uuid
import time
import os
import json
import logging
import random
import tomllib
import requests
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path
from batch_integrity import LineageStamper, HDR_SENSOR_TYPE

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] [Nexus] %(message)s')
logger = logging.getLogger(__name__)

class NexusForwarder:
    def __init__(self, config_path="/app/config.toml", db_path="/app/data/baseline.db"):
        self.db_path = db_path
        self.config = self._load_config(config_path)

        nexus_cfg = self.config.get("nexus", {})

        self.gateway_url = nexus_cfg.get("gateway_url", "https://nexus-edge.local/api/v1/telemetry")
        if self.gateway_url.startswith("http://"):
            logger.warning("Gateway URL configured as HTTP. Forcing HTTPS.")
            self.gateway_url = self.gateway_url.replace("http://", "https://")

        self.spool_dir = Path(nexus_cfg.get("spool_dir", "/app/data/spool"))
        self.spool_dir.mkdir(parents=True, exist_ok=True)

        self.publish_delay_sec = float(nexus_cfg.get("publish_delay_sec", 0.2))
        self.initial_backoff_sec = float(nexus_cfg.get("initial_backoff_sec", 2.0))
        self.max_backoff_sec = float(nexus_cfg.get("max_backoff_sec", 60.0))
        self.max_spool_bytes = int(nexus_cfg.get("max_spool_bytes", 500 * 1024 * 1024))
        self.max_spool_files = int(nexus_cfg.get("max_spool_files", 2000))
        self._current_backoff = self.initial_backoff_sec

        tls_cfg = nexus_cfg.get("tls", {})
        self.tls_enabled = tls_cfg.get("enabled", False)
        self.tls_verify = tls_cfg.get("ca_path", True) if self.tls_enabled else False
        self.auth_token = nexus_cfg.get("auth_token", None)
        self.cursor_path = self.spool_dir / ".sync_cursor"

        self.host_meta = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "release": platform.release(),
            "sensor_id": str(uuid.getnode()),
            "sensor_version": "0.7.1"
        }

        # Integrity lineage stamper — sequence counter persisted to
        # integrity_sequence table inside the existing baseline.db.
        integrity_secret = nexus_cfg.get(
            "integrity_secret", "Nexus-Integrity-SharedKey-Rotate-Me"
        )
        self.stamper = LineageStamper(
            sensor_id=self.host_meta["sensor_id"],
            shared_secret=integrity_secret,
            db_path=self.db_path,
        )

        self.last_sync_id = self._load_sync_cursor()

    # ─── Config ──────────────────────────────────────────────

    def _load_config(self, path):
        try:
            with open(path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            logger.error(f"Failed to load config at {path}: {e}. Halting.")
            raise

    # ─── Persistent Sync Cursor ──────────────────────────────

    def _load_sync_cursor(self):
        """
        Load the last-synced row ID from persistent storage.
        Falls back to scanning spool filenames (legacy behavior),
        then falls back to 0 if nothing is found.
        """
        # Primary: read from cursor file
        if self.cursor_path.exists():
            try:
                raw = self.cursor_path.read_text().strip()
                cursor_id = int(raw)
                logger.info(f"Restored sync cursor from disk: {cursor_id}")
                return cursor_id
            except (ValueError, OSError) as e:
                logger.warning(f"Corrupt cursor file, falling back to spool scan: {e}")

        highest_id = self._scan_spool_max_id()
        if highest_id > 0:
            logger.info(f"Inferred sync cursor from spool files: {highest_id}")
            self._persist_sync_cursor(highest_id)
        return highest_id

    def _scan_spool_max_id(self):
        highest_id = 0
        for file in self.spool_dir.glob("*.parquet"):
            try:
                end_id = int(file.stem.split('_')[2])
                highest_id = max(highest_id, end_id)
            except (IndexError, ValueError):
                continue
        return highest_id

    def _persist_sync_cursor(self, row_id):
        tmp = self.cursor_path.with_suffix('.tmp')
        try:
            tmp.write_text(str(row_id))
            tmp.replace(self.cursor_path)
        except OSError as e:
            logger.error(f"Failed to persist sync cursor: {e}")

    # ─── Spool Disk Limits ───────────────────────────────────

    def _spool_within_limits(self):
        files = list(self.spool_dir.glob("*.parquet"))
        if len(files) >= self.max_spool_files:
            logger.warning(f"Spool file count ({len(files)}) at limit ({self.max_spool_files}), pausing extraction")
            return False

        total_bytes = sum(f.stat().st_size for f in files)
        if total_bytes >= self.max_spool_bytes:
            logger.warning(f"Spool size ({total_bytes / 1e6:.1f}MB) at limit ({self.max_spool_bytes / 1e6:.0f}MB), pausing extraction")
            return False

        return True

    # ─── Database Extraction ─────────────────────────────────

    def extract_to_spool(self):
        if not self._spool_within_limits():
            return

        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        conn.execute('PRAGMA busy_timeout = 5000;')

        # Parameterized query — all fields needed for nexus correlation
        query = """
            SELECT id,
                   timestamp,
                   process_name,
                   pid,
                   uid,
                   process_hash,
                   event_type,
                   dst_ip,
                   dst_port,
                   outbound_ratio,
                   packet_size_mean,
                   packet_size_std,
                   packet_size_min,
                   packet_size_max,
                   packet_count,
                   interval,
                   cv,
                   entropy,
                   cmd_entropy,
                   dns_query,
                   dns_flags,
                   mitre_tactic,
                   score,
                   ml_result,
                   reasons,
                   suppressed,
                   sensor_id
            FROM flows
            WHERE id > ?
            ORDER BY id ASC LIMIT 5000
        """
        cursor = conn.execute(query, (self.last_sync_id,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return

        start_id = rows[0][0]
        max_id = rows[-1][0]
        row_count = len(rows)

        def _str(val):
            return val if val is not None else ""

        def _float(val):
            return float(val) if val is not None else 0.0

        def _int(val):
            return int(val) if val is not None else 0

        arrays = [
            pa.array([r[0] for r in rows], type=pa.int64()),                # id
            pa.array([_float(r[1]) for r in rows], type=pa.float64()),      # timestamp
            pa.array([_str(r[2]) for r in rows], type=pa.string()),         # process_name
            pa.array([_int(r[3]) for r in rows], type=pa.int32()),          # pid
            pa.array([_int(r[4]) for r in rows], type=pa.int32()),          # uid
            pa.array([_str(r[5]) for r in rows], type=pa.string()),         # process_hash
            pa.array([_str(r[6]) for r in rows], type=pa.string()),         # event_type
            pa.array([_str(r[7]) for r in rows], type=pa.string()),         # dst_ip
            pa.array([_int(r[8]) for r in rows], type=pa.int32()),          # dst_port
            pa.array([_float(r[9]) for r in rows], type=pa.float64()),      # outbound_ratio
            pa.array([_float(r[10]) for r in rows], type=pa.float64()),     # packet_size_mean
            pa.array([_float(r[11]) for r in rows], type=pa.float64()),     # packet_size_std
            pa.array([_int(r[12]) for r in rows], type=pa.int32()),         # packet_size_min
            pa.array([_int(r[13]) for r in rows], type=pa.int32()),         # packet_size_max
            pa.array([_int(r[14]) for r in rows], type=pa.int32()),         # packet_count
            pa.array([_float(r[15]) for r in rows], type=pa.float64()),     # interval
            pa.array([_float(r[16]) for r in rows], type=pa.float64()),     # cv
            pa.array([_float(r[17]) for r in rows], type=pa.float64()),     # entropy
            pa.array([_float(r[18]) for r in rows], type=pa.float64()),     # cmd_entropy
            pa.array([_str(r[19]) for r in rows], type=pa.string()),        # dns_query
            pa.array([_int(r[20]) for r in rows], type=pa.int32()),         # dns_flags
            pa.array([_str(r[21]) for r in rows], type=pa.string()),        # mitre_tactic
            pa.array([_int(r[22]) for r in rows], type=pa.int32()),         # score
            pa.array([_str(r[23]) for r in rows], type=pa.string()),        # ml_result
            pa.array([_str(r[24]) for r in rows], type=pa.string()),        # reasons (JSON string)
            pa.array([_int(r[25]) for r in rows], type=pa.int32()),         # suppressed
            # Embedded sensor metadata
            pa.array([_str(r[26]) for r in rows], type=pa.string()),
            pa.array([self.host_meta["hostname"]] * row_count, type=pa.string()),
        ]

        names = [
            'id', 'timestamp', 'process_name', 'pid', 'uid', 'process_hash',
            'event_type', 'dst_ip', 'dst_port', 'outbound_ratio',
            'packet_size_mean', 'packet_size_std', 'packet_size_min', 'packet_size_max', 'packet_count',
            'interval', 'cv', 'entropy', 'cmd_entropy',
            'dns_query', 'dns_flags', 'mitre_tactic', 'score',
            'ml_result', 'reasons', 'suppressed',
            'sensor_id', 'hostname',
        ]

        table = pa.Table.from_arrays(arrays, names=names)

        file_path = self.spool_dir / f"sync_{start_id}_{max_id}.parquet"
        pq.write_table(table, str(file_path), compression='SNAPPY')

        self.last_sync_id = max_id
        self._persist_sync_cursor(max_id)

        logger.debug(f"Spooled {row_count} records to {file_path.name}")

    # ─── Spool Transmitter ───────────────────────────────────

    def _sorted_spool_files(self):
        valid = []
        for f in self.spool_dir.glob("*.parquet"):
            try:
                start_id = int(f.stem.split('_')[1])
                valid.append((start_id, f))
            except (IndexError, ValueError):
                logger.warning(f"Skipping malformed spool file: {f.name}")
                continue
        valid.sort(key=lambda x: x[0])
        return [f for _, f in valid]

    async def _backoff_wait(self, response=None):
        """Exponential backoff with full jitter. Respects Retry-After header on 503/429.

        Full jitter (uniform 0..cap) prevents thundering herd when multiple sensor
        instances restart together after a JetStream backpressure event.
        """
        if response is not None and response.status_code in (503, 429):
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = min(float(retry_after), self.max_backoff_sec)
                    logger.info(f"Gateway {response.status_code}: Retry-After={wait:.0f}s — honouring")
                    await asyncio.sleep(wait)
                    return
                except ValueError:
                    pass
        # Full jitter over [0, current_cap] — mean = cap/2, avoids synchronized retries
        wait = random.uniform(0, self._current_backoff)
        logger.debug(f"Backoff {wait:.1f}s (cap={self._current_backoff:.0f}s max={self.max_backoff_sec:.0f}s)")
        await asyncio.sleep(wait)
        self._current_backoff = min(self._current_backoff * 2, self.max_backoff_sec)

    async def spool_reader_loop(self):
        # Static headers on every request. The integrity headers
        # (X-Batch-Sequence, X-Batch-Timestamp, X-Sensor-Id, X-Batch-HMAC)
        # are computed per-batch and merged by stamper.build_headers().
        base_headers = {
            "Content-Type": "application/vnd.apache.parquet",
            "Authorization": f"Bearer {self.auth_token}" if self.auth_token else "",
            "X-Sensor-Hostname": self.host_meta["hostname"],
            HDR_SENSOR_TYPE: "linux-c2-sensor",
        }

        while True:
            files = self._sorted_spool_files()

            if not files:
                await asyncio.sleep(5)
                continue

            for file_path in files:
                try:
                    with open(file_path, 'rb') as f:
                        parquet_data = f.read()

                    stamp = self.stamper.stamp(parquet_data)
                    headers = self.stamper.build_headers(stamp, base_headers)

                    resp = await asyncio.to_thread(
                        requests.post,
                        self.gateway_url,
                        headers=headers,
                        data=parquet_data,
                        timeout=10.0,
                        verify=self.tls_verify
                    )

                    if resp.status_code in (200, 202):
                        os.remove(file_path)
                        logger.info(f"Transmitted and purged {file_path.name} (seq={stamp['sequence']})")
                        self._current_backoff = self.initial_backoff_sec  # reset on success

                    elif resp.status_code == 403:
                        logger.error(
                            f"[INTEGRITY] Gateway returned 403 FORBIDDEN for {file_path.name}. "
                            f"Sensor may be banned. Halting all transmission."
                        )
                        return

                    else:
                        logger.warning(
                            f"Gateway rejected payload: HTTP {resp.status_code} "
                            f"for {file_path.name} — backing off"
                        )
                        await self._backoff_wait(response=resp)
                        break

                    await asyncio.sleep(self.publish_delay_sec)
                except requests.RequestException as e:
                    logger.error(f"Gateway HTTPS connection failed: {e} — backing off")
                    await self._backoff_wait()
                    break
                except Exception as e:
                    logger.error(f"Unexpected error processing {file_path.name}: {e}")
                    await asyncio.sleep(5)

    # ─── Extraction Loop ─────────────────────────────────────

    async def database_extractor_loop(self):
        prune_counter = 0
        while True:
            try:
                self.extract_to_spool()

                prune_counter += 1
                if prune_counter > 100:
                    conn = sqlite3.connect(self.db_path, timeout=30.0)
                    conn.execute("PRAGMA incremental_vacuum(100)")
                    conn.close()
                    prune_counter = 0

            except Exception as e:
                logger.error(f"Database extraction error: {e}")
            await asyncio.sleep(10)

    # ─── Pipeline Entry ──────────────────────────────────────

    async def run_pipeline(self):
        if not self.config.get("nexus", {}).get("enabled", False):
            logger.info("Nexus Forwarder disabled in config.toml. Entering standby.")
            while True:
                await asyncio.sleep(3600)
        await asyncio.gather(
            asyncio.create_task(self.database_extractor_loop()),
            asyncio.create_task(self.spool_reader_loop())
        )

if __name__ == '__main__':
    config_location = os.environ.get("SENSOR_CONFIG_PATH", "/app/config.toml")
    forwarder = NexusForwarder(config_path=config_location)

    try:
        asyncio.run(forwarder.run_pipeline())
    except KeyboardInterrupt:
        logger.info("Nexus Forwarder terminating gracefully.")