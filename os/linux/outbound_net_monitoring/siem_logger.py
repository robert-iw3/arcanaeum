#!/usr/bin/env python3
"""
Script to generate SIEM-compatible JSON logs from unique IPs.

RW
"""

import json
import logging
import time
import os
from datetime import datetime
from pathlib import Path
from filelock import FileLock
from pythonjsonlogger import jsonlogger

# Configuration
BASE_DIR = Path(os.getenv("OUTBOUND_BASE_DIR", "/var/log/outbound_collector"))
UNIQUE_IP_FILE = BASE_DIR / "unique_ips.json"
SIEM_LOG_FILE = Path("/var/log/siem/siem_outbound_ips.jsonl")
LOG_FILE = BASE_DIR / "siem_logger.log"
SIEM_LOG_INTERVAL = int(os.getenv("SIEM_LOG_INTERVAL", 3600))

# Setup JSON logging
logger = logging.getLogger(__name__)
log_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(jsonlogger.JsonFormatter(
    fmt="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
))
logger.addHandler(log_handler)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def log_to_siem():
    """Read unique IPs and append to SIEM JSONL log with retries."""
    lock_file = BASE_DIR / "lockfile"
    container_id = os.getenv("HOSTNAME", "unknown")
    max_retries = 3

    for attempt in range(max_retries):
        try:
            with FileLock(str(lock_file), timeout=10):
                if not UNIQUE_IP_FILE.exists():
                    logger.info({"event": "no_unique_ips_file", "container_id": container_id})
                    return

                with UNIQUE_IP_FILE.open("r") as f:
                    data = json.load(f)
                    ips = data.get("ips", [])
                    timestamp = data.get("timestamp", datetime.utcnow().isoformat() + "Z")

                for ip in ips:
                    log_entry = {
                        "event_type": "outbound_connection",
                        "destination_ip": ip,
                        "timestamp": timestamp,
                        "source": "outbound_monitor",
                        "container_id": container_id,
                        "interface": os.getenv("INTERFACE", "unknown")
                    }
                    with SIEM_LOG_FILE.open("a") as f:
                        f.write(json.dumps(log_entry) + "\n")
                logger.info({
                    "event": "siem_log_written",
                    "ip_count": len(ips),
                    "container_id": container_id
                })
                break
        except (IOError, json.JSONDecodeError) as e:
            logger.error({
                "event": "siem_log_error",
                "error": str(e),
                "attempt": attempt + 1,
                "container_id": container_id
            })
            if attempt == max_retries - 1:
                logger.error({"event": "siem_log_failed", "error": "Max retries reached"})
            time.sleep(2 ** attempt)  # Exponential backoff

def main():
    while True:
        log_to_siem()
        time.sleep(SIEM_LOG_INTERVAL)

if __name__ == "__main__":
    main()