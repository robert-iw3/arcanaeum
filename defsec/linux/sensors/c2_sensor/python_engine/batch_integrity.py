"""
batch_integrity.py — Cryptographic Lineage Stamping for the Nexus Telemetry Pipeline
@RW

Produces HMAC-SHA256 integrity envelopes for outbound Parquet batches.
The digest computation uses a canonical big-endian encoding that is
byte-identical to the Rust nexus_integrity crate, enabling cross-language
verification at the Axum ingress gateway.

Sequence counter is persisted to the sensor's existing baseline.db
(integrity_sequence table, created automatically on first use).
No new pip dependencies — hmac, hashlib, struct, sqlite3 are all stdlib.
"""

import hashlib
import hmac
import logging
import sqlite3
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Header Constants (must match nexus_integrity/src/lib.rs) ─────────────────

HDR_BATCH_SEQUENCE  = "X-Batch-Sequence"
HDR_BATCH_HMAC      = "X-Batch-HMAC"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_SENSOR_ID       = "X-Sensor-Id"
HDR_SENSOR_TYPE     = "X-Sensor-Type"


class LineageStamper:
    """
    Maintains a strictly monotonic sequence counter and computes the
    HMAC-SHA256 lineage stamp for each outbound Parquet batch.

    Crash-safe ordering: the sequence is persisted to SQLite BEFORE
    the caller transmits the payload. If the process crashes after
    persist but before POST, the sequence is consumed but the payload
    never arrives — the gateway sees a harmless gap and accepts the
    next valid sequence. The alternative (persist after POST) risks
    reusing a sequence number after a crash, which the gateway would
    reject as a replay.
    """

    def __init__(self, sensor_id: str, shared_secret: str, db_path: str):
        self.sensor_id = sensor_id
        self.shared_secret = shared_secret.encode("utf-8")
        self.db_path = db_path
        self._init_db()
        self.sequence = self._load_sequence()
        logger.info(f"[INTEGRITY] Stamper online: sensor_id={sensor_id}, initial_seq={self.sequence}")

    # ─── SQLite Persistence ───────────────────────────────────────────────────

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS integrity_sequence ("
            "  sensor_id TEXT PRIMARY KEY,"
            "  last_sequence INTEGER NOT NULL DEFAULT 0"
            ")"
        )
        conn.commit()
        conn.close()

    def _load_sequence(self) -> int:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT last_sequence FROM integrity_sequence WHERE sensor_id = ?",
            (self.sensor_id,),
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO integrity_sequence (sensor_id, last_sequence) VALUES (?, 0)",
                (self.sensor_id,),
            )
            conn.commit()
            conn.close()
            return 0

        conn.close()
        return int(row[0])

    def _persist_sequence(self, seq: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE integrity_sequence SET last_sequence = ? WHERE sensor_id = ?",
            (seq, self.sensor_id),
        )
        conn.commit()
        conn.close()

    # ─── Stamping ─────────────────────────────────────────────────────────────

    def stamp(self, parquet_bytes: bytes) -> dict:
        """
        Advance the sequence, compute the HMAC, persist to disk, and return
        the integrity envelope as a dict.

        Returns: {"sequence": int, "timestamp": int, "sensor_id": str, "hmac_hex": str}
        """
        self.sequence += 1
        timestamp = int(time.time())

        self._persist_sequence(self.sequence)

        hmac_hex = self._compute_hmac(parquet_bytes, self.sequence, timestamp)

        return {
            "sequence": self.sequence,
            "timestamp": timestamp,
            "sensor_id": self.sensor_id,
            "hmac_hex": hmac_hex,
        }

    def _compute_hmac(self, parquet_bytes: bytes, sequence: int, timestamp: int) -> str:
        """
        Canonical HMAC-SHA256 input (must match Rust compute_hmac byte-for-byte):

            HMAC(key, parquet_bytes || BE64(sequence) || sensor_id_utf8 || BE64(timestamp))

        - parquet_bytes: raw file bytes, no length prefix
        - sequence: unsigned 64-bit big-endian
        - sensor_id: UTF-8 bytes, no length prefix
        - timestamp: unsigned 64-bit big-endian
        """
        msg = bytearray()
        msg.extend(parquet_bytes)
        msg.extend(struct.pack(">Q", sequence))
        msg.extend(self.sensor_id.encode("utf-8"))
        msg.extend(struct.pack(">Q", timestamp))

        return hmac.new(self.shared_secret, bytes(msg), hashlib.sha256).hexdigest()

    # ─── Header Injection ─────────────────────────────────────────────────────

    def build_headers(self, stamp: dict, base_headers: Optional[dict] = None) -> dict:
        """
        Merge the four integrity headers into an existing header dict.
        Call this right before requests.post().
        """
        headers = dict(base_headers) if base_headers else {}
        headers[HDR_BATCH_SEQUENCE]  = str(stamp["sequence"])
        headers[HDR_BATCH_TIMESTAMP] = str(stamp["timestamp"])
        headers[HDR_SENSOR_ID]       = stamp["sensor_id"]
        headers[HDR_BATCH_HMAC]      = stamp["hmac_hex"]
        return headers