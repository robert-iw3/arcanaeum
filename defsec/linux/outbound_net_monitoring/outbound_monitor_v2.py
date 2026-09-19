#!/usr/bin/env python3
"""
Python script to capture outbound network traffic and extract unique destination IPs.
Designed for network monitoring with rotating PCAPs and periodic IP extraction.

Licensed under the MIT License.

pip install filelock psutil python-json-logger

RW
"""

import os
import sys
import subprocess
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from filelock import FileLock
import ipaddress
import psutil
import shutil
import time
from pythonjsonlogger import jsonlogger

# Configuration (loaded from environment variables with defaults)
BASE_DIR = Path(os.getenv("OUTBOUND_BASE_DIR", "/var/log/outbound_collector"))
UNIQUE_IP_FILE = BASE_DIR / "unique_ips.json"
LOG_FILE = BASE_DIR / "outbound_ip_collector.log"
STATE_FILE = BASE_DIR / "processed_pcaps.txt"
ROTATION_SECONDS = int(os.getenv("ROTATION_SECONDS", 3600))
RETENTION_FILES = int(os.getenv("RETENTION_FILES", 24))
SERVICE_UNIT_NAME = "outbound_ip_collector.service"

# Setup logging with JSON format
logger = logging.getLogger(__name__)
log_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(jsonlogger.JsonFormatter(
    fmt="%(asctime)s %(levelname)s pid:%(process)d %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
))
logger.addHandler(log_handler)
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)

# Private IP address ranges (RFC 1918)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8')
]

def is_public_ip(ip_str):
    """
    Check if an IP address is public (not private or loopback).

    Args:
        ip_str (str): The IP address to check.

    Returns:
        bool: True if the IP is public, False otherwise.
    """
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        for private_range in PRIVATE_IP_RANGES:
            if ip_addr in private_range:
                return False
        return True
    except ValueError:
        return False

def check_prerequisites():
    """
    Check for root privileges, required commands, and disk space.

    Exits if prerequisites are not met.
    """
    if os.geteuid() != 0:
        logger.error({"event": "privilege_error", "message": "This script requires root privileges."})
        sys.exit(1)

    for cmd in ["tcpdump", "ip", "tshark", "systemctl"]:
        if not shutil.which(cmd):
            logger.error({"event": "dependency_missing", "command": cmd})
            sys.exit(1)

    try:
        stat = os.statvfs(BASE_DIR)
        free_kb = stat.f_bavail * stat.f_bsize / 1024
        if free_kb < 1048576:  # Require 1GB free
            logger.error({"event": "disk_space_error", "free_kb": free_kb, "directory": str(BASE_DIR)})
            sys.exit(1)
    except OSError as e:
        logger.error({"event": "disk_space_check_failed", "error": str(e), "directory": str(BASE_DIR)})
        sys.exit(1)

def check_disk_space():
    """
    Check if sufficient disk space is available.

    Returns:
        bool: True if enough space, False otherwise.
    """
    try:
        stat = os.statvfs(BASE_DIR)
        free_kb = stat.f_bavail * stat.f_bsize / 1024
        if free_kb < 1048576:
            logger.error({"event": "disk_space_low", "free_kb": free_kb})
            return False
        return True
    except OSError as e:
        logger.error({"event": "disk_space_check_failed", "error": str(e)})
        return False

def validate_interface(iface):
    """
    Validate that the network interface is up and running.

    Args:
        iface (str): The network interface to validate.

    Returns:
        bool: True if valid and up, False otherwise.
    """
    try:
        subprocess.run(["ip", "link", "show", iface, "up"], capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError:
        logger.error({"event": "interface_validation_failed", "interface": iface})
        return False

def setup_environment():
    """
    Perform initial setup, validate interface, and start tcpdump.

    Exits on failure.
    """
    logger.info({"event": "setup_start"})
    check_prerequisites()

    # Validate network interface
    interfaces_output = subprocess.run(
        ["ip", "link", "show"], capture_output=True, text=True, check=True
    ).stdout
    available_interfaces = [
        line.split(": ")[1] for line in interfaces_output.splitlines() if ": " in line and "lo:" not in line
    ]
    if not available_interfaces:
        logger.error({"event": "no_interfaces_found"})
        sys.exit(1)

    iface = input(f"Available interfaces: {', '.join(available_interfaces)}\nEnter the network interface: ")
    if iface not in available_interfaces or not validate_interface(iface):
        logger.error({"event": "invalid_interface", "interface": iface})
        sys.exit(1)

    # Create base directory and set permissions
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["chown", "root:root", str(BASE_DIR)], check=True)
    subprocess.run(["chmod", "750", str(BASE_DIR)], check=True)

    # Ensure file permissions
    for f in [LOG_FILE, UNIQUE_IP_FILE, STATE_FILE]:
        f.touch()
        subprocess.run(["chown", "root:root", str(f)], check=True)
        subprocess.run(["chmod", "640", str(f)], check=True)

    # Start tcpdump with optimized filter
    logger.info({
        "event": "tcpdump_start",
        "interface": iface,
        "rotation_seconds": ROTATION_SECONDS,
        "retention_files": RETENTION_FILES
    })
    tcpdump_proc = subprocess.Popen(
        [
            "tcpdump", "-n", "-i", iface, "-s", "0",
            "tcp or udp",  # Optimized filter to capture only TCP/UDP
            "-G", str(ROTATION_SECONDS), "-W", str(RETENTION_FILES),
            "-w", str(BASE_DIR / "conn-all-%Y%m%d%H%M.pcap")
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    time.sleep(2)
    if not psutil.pid_exists(tcpdump_proc.pid):
        _, stderr = tcpdump_proc.communicate()
        logger.error({"event": "tcpdump_start_failed", "error": stderr.decode()})
        sys.exit(1)
    logger.info({"event": "setup_complete", "tcpdump_pid": tcpdump_proc.pid})

def cleanup_old_pcaps():
    """
    Move PCAP files older than retention period to quarantine.
    """
    time_threshold = time.time() - (RETENTION_FILES * ROTATION_SECONDS)
    quarantine_dir = BASE_DIR / "quarantine"
    quarantine_dir.mkdir(exist_ok=True)
    for pcap in BASE_DIR.glob("conn-all-*.pcap"):
        if pcap.stat().st_mtime < time_threshold:
            try:
                shutil.move(str(pcap), str(quarantine_dir / pcap.name))
                logger.info({"event": "pcap_cleanup", "file": str(pcap)})
            except OSError as e:
                logger.error({"event": "pcap_cleanup_failed", "file": str(pcap), "error": str(e)})

def extract_ips():
    """
    Extract unique public IPs from new PCAP files and update the master list.
    """
    if not check_disk_space():
        return

    lock_file = BASE_DIR / "lockfile"
    with FileLock(str(lock_file), timeout=10):
        logger.info({"event": "ip_extraction_start"})
        cleanup_old_pcaps()  # Clean up old PCAPs before processing
        processed_pcaps = set(STATE_FILE.read_text().splitlines() if STATE_FILE.exists() else [])
        recent_ips = set()
        time_threshold = time.time() - 24 * 3600
        quarantine_dir = BASE_DIR / "quarantine"
        quarantine_dir.mkdir(exist_ok=True)

        for pcap in sorted(BASE_DIR.glob("conn-all-*.pcap")):
            if pcap.stat().st_mtime > time_threshold and str(pcap) not in processed_pcaps:
                start_time = time.time()
                try:
                    tshark_cmd = [
                        "tshark", "-r", str(pcap),
                        "-Y", "ip and (tcp or udp)",  # Optimized filter
                        "-T", "fields", "-e", "ip.dst"
                    ]
                    output = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True).stdout
                    for ip_str in output.splitlines():
                        if is_public_ip(ip_str):
                            recent_ips.add(ip_str)
                    with STATE_FILE.open("a") as sf:
                        sf.write(str(pcap) + "\n")
                    logger.info({
                        "event": "pcap_processed",
                        "file": str(pcap),
                        "ip_count": len(recent_ips),
                        "process_time": time.time() - start_time
                    })
                except subprocess.CalledProcessError as e:
                    logger.warning({
                        "event": "pcap_process_failed",
                        "file": str(pcap),
                        "error": str(e),
                        "action": "moving_to_quarantine"
                    })
                    shutil.move(str(pcap), str(quarantine_dir / pcap.name))
                    continue

        # Load and merge existing IPs
        existing_ips = set()
        if UNIQUE_IP_FILE.exists():
            try:
                with UNIQUE_IP_FILE.open("r") as f:
                    data = json.load(f)
                    existing_ips.update(data.get("ips", []))
            except (IOError, json.JSONDecodeError) as e:
                logger.error({"event": "read_ips_failed", "error": str(e)})

        all_ips = sorted(list(existing_ips.union(recent_ips)))
        with UNIQUE_IP_FILE.open("w") as f:
            json.dump({"ips": all_ips, "timestamp": datetime.utcnow().isoformat() + "Z"}, f, indent=4)
        logger.info({
            "event": "ip_list_updated",
            "total_ips": len(all_ips),
            "new_ips": len(recent_ips),
            "process_time": time.time() - start_time
        })

def install_service():
    """
    Create and enable a systemd service and timer for periodic IP extraction.
    """
    logger.info({"event": "service_install_start"})
    service_content = f"""[Unit]
Description=Outbound IP Extractor
After=network.target

[Service]
Type=oneshot
ExecStart={shutil.which("python3")} {Path(__file__).resolve()} extract
User=root

[Install]
WantedBy=multi-user.target
"""
    timer_content = f"""[Unit]
Description=Periodic Outbound IP Extraction Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit={SERVICE_UNIT_NAME}

[Install]
WantedBy=timers.target
"""
    service_path = Path(f"/etc/systemd/system/{SERVICE_UNIT_NAME}")
    timer_path = Path(f"/etc/systemd/system/{SERVICE_UNIT_NAME.replace('.service', '.timer')}")
    try:
        with service_path.open("w") as f:
            f.write(service_content)
        with timer_path.open("w") as f:
            f.write(timer_content)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", SERVICE_UNIT_NAME.replace('.service', '.timer')], check=True)
        logger.info({"event": "service_install_success", "service": SERVICE_UNIT_NAME})
    except (IOError, subprocess.CalledProcessError) as e:
        logger.error({"event": "service_install_failed", "error": str(e)})
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "extract":
        extract_ips()
    else:
        setup_environment()
        install_service()