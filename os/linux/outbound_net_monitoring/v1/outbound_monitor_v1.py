#!/usr/bin/env python3
"""
Python script to capture outbound network traffic and extract unique destination IPs.
Designed for network monitoring with rotating PCAPs and periodic IP extraction.
Licensed under the MIT License.
"""

import os
import sys
import subprocess
import re
import json
import logging
from datetime import datetime
from pathlib import Path
import shutil
import tempfile
import getpass
import schedule
import psutil
import time

# Configuration
BASE_DIR = Path("/var/log/outbound_collector")
PCAP_PATTERN = "conn-all-%Y%m%d%H%M.pcap"
UNIQUE_IP_FILE = BASE_DIR / "unique_ips.json"
LOG_FILE = BASE_DIR / "outbound_ip_collector.log"
STATE_FILE = BASE_DIR / "processed_pcaps.txt"
EXTRACT_SCRIPT = Path("/usr/local/bin/extract_unique_ips.py")
ROTATION_SECONDS = 3600
RETENTION_FILES = 24

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Check sudo privileges
try:
    subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True)
except subprocess.CalledProcessError:
    logger.error("This script requires sudo privileges.")
    sys.exit(1)

# Check dependencies
for cmd in ["tcpdump", "ip", "at", "jq"]:
    if not shutil.which(cmd):
        logger.error(f"Missing dependency: {cmd}")
        sys.exit(1)

# Check atd service
try:
    subprocess.run(["systemctl", "is-active", "--quiet", "atd"], check=True)
except subprocess.CalledProcessError:
    logger.error("atd service is not running. Start it with 'sudo systemctl start atd'.")
    sys.exit(1)

# Validate network interface
interfaces = subprocess.run(
    ["ip", "link", "show"], capture_output=True, text=True
).stdout.splitlines()
available_interfaces = [
    line.split(": ")[1] for line in interfaces if ": " in line and "lo:" not in line
]
IFACE = input(f"Available interfaces: {', '.join(available_interfaces)}\nEnter the network interface (e.g., eth0, ens5): ")
if IFACE not in available_interfaces:
    logger.error(f"Invalid interface: {IFACE}")
    sys.exit(1)

# Create base directory
BASE_DIR.mkdir(parents=True, exist_ok=True)
subprocess.run(["sudo", "chown", "root:root", str(BASE_DIR)], check=True)
subprocess.run(["sudo", "chmod", "750", str(BASE_DIR)], check=True)

# Ensure file permissions
for f in [LOG_FILE, UNIQUE_IP_FILE]:
    f.touch()
    subprocess.run(["sudo", "chown", "root:root", str(f)], check=True)
    subprocess.run(["sudo", "chmod", "640", str(f)], check=True)

# Check disk space (require 1GB free)
df = subprocess.run(["df", "--output=avail", str(BASE_DIR)], capture_output=True, text=True)
free_kb = int(df.stdout.splitlines()[-1])
if free_kb < 1048576:
    logger.error(f"Insufficient disk space in {BASE_DIR} (<1GB free).")
    sys.exit(1)

# Start tcpdump
logger.info(f"Starting tcpdump on {IFACE} (rotating every {ROTATION_SECONDS}s, keeping {RETENTION_FILES} files)")
tcpdump_proc = subprocess.Popen(
    [
        "sudo", "tcpdump", "-n", "-i", IFACE, "-s", "0",
        "not src net 127.0.0.0/8 and not src net 192.168.0.0/16",
        "-G", str(ROTATION_SECONDS), "-W", str(RETENTION_FILES),
        "-w", str(BASE_DIR / "conn-all-%Y%m%d%H%M.pcap")
    ],
    stdout=subprocess.DEVNULL,
    stderr=open(LOG_FILE, "a")
)

# Verify tcpdump
time.sleep(2)
if not psutil.pid_exists(tcpdump_proc.pid):
    logger.error(f"Failed to start tcpdump. Check {LOG_FILE} for details.")
    sys.exit(1)

# Create extraction script
EXTRACT_SCRIPT.write_text("""
#!/usr/bin/env python3
import os
import subprocess
import re
import json
from pathlib import Path
import logging
import tempfile
import fcntl

BASE_DIR = Path("/var/log/outbound_collector")
UNIQUE_IP_FILE = BASE_DIR / "unique_ips.json"
STATE_FILE = BASE_DIR / "processed_pcaps.txt"
LOG_FILE = BASE_DIR / "outbound_ip_collector.log"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Prevent concurrent runs
lock_file = BASE_DIR / "lockfile"
with open(lock_file, "w") as f:
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logger.error("Another instance is running, exiting.")
        exit(1)

logger.info("Starting IP extraction...")

# Initialize JSON
with tempfile.TemporaryDirectory() as tmpdir:
    temp_json = Path(tmpdir) / "recent_ips.json"
    temp_ips = Path(tmpdir) / "recent_ips.txt"
    temp_json.write_text(json.dumps({"ips": [], "timestamp": datetime.utcnow().isoformat() + "Z"}))

    # Process unprocessed PCAPs (last 12 hours)
    STATE_FILE.touch()
    processed = set(STATE_FILE.read_text().splitlines())
    for pcap in BASE_DIR.glob("conn-all-*.pcap"):
        if pcap.stat().st_mtime > time.time() - 12*3600 and str(pcap) not in processed:
            try:
                output = subprocess.run(
                    ["sudo", "tcpdump", "-nnr", str(pcap)],
                    capture_output=True, text=True, check=True
                ).stdout
                for line in output.splitlines():
                    if ">" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if ">" in part:
                                ip = parts[i+1].split(".")[:4]
                                ip = ".".join(ip)
                                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                                    with open(temp_ips, "a") as f:
                                        f.write(ip + "\n")
                with open(STATE_FILE, "a") as f:
                    f.write(str(pcap) + "\n")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to process {pcap}: {e}")

    # Deduplicate IPs
    if temp_ips.exists():
        with open(temp_ips) as f:
            ips = sorted(set(f.read().splitlines()))
        with open(temp_json, "w") as f:
            json.dump({"ips": ips, "timestamp": datetime.utcnow().isoformat() + "Z"}, f)

    # Merge with existing JSON
    if UNIQUE_IP_FILE.exists():
        with open(temp_json) as f1, open(UNIQUE_IP_FILE) as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)
            combined = {"ips": sorted(set(data1["ips"] + data2["ips"])), "timestamp": data1["timestamp"]}
        UNIQUE_IP_FILE.write_text(json.dumps(combined))
    else:
        UNIQUE_IP_FILE.write_text(temp_json.read_text())

logger.info(f"Unique IP list updated ({len(json.loads(UNIQUE_IP_FILE.read_text())['ips'])} entries).")
logger.info("Scheduling next extraction in 12 hours...")
subprocess.run(["at", "now + 12 hours"], input=f"python3 {EXTRACT_SCRIPT}", text=True)
""")
subprocess.run(["sudo", "chown", "root:root", str(EXTRACT_SCRIPT)], check=True)
subprocess.run(["sudo", "chmod", "750", str(EXTRACT_SCRIPT)], check=True)

# Schedule first run
logger.info("Scheduling first IP extraction in 12 hours...")
subprocess.run(["at", "now + 12 hours"], input=f"python3 {EXTRACT_SCRIPT}", text=True)

logger.info("Setup complete.")
logger.info(f"    • PCAPs: {BASE_DIR}/conn-all-*.pcap")
logger.info(f"    • Unique IPs: {UNIQUE_IP_FILE}")
logger.info(f"    • Log file: {LOG_FILE}")
logger.info(f"    • Extraction script: {EXTRACT_SCRIPT} (runs every 12 hrs via at)")